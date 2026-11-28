// 이 파일: 키 교체, 단일 호스트 예약, 오래된 MOK 요청 복구의 API 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func mokRotationServer(t *testing.T) *Server {
	t.Helper()
	s, _ := rebootFixture(t)
	addHost(t, s, "other", 1)
	cert := signingAdminCert(t, time.Now().AddDate(1, 0, 0))
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "old", Cert: cert, SignCommand: []string{"unused"}}, {ID: "new", Cert: cert, Active: true, SignCommand: []string{"unused"}}}}
	return s
}
func currentMOK(s *Server, host string) MOKEnrollment {
	var e MOKEnrollment
	s.store.View(func(st *State) {
		if saved := st.MOKRequests[host]; saved != nil {
			e = *saved
		}
	})
	return e
}
func TestRetiredMOKRequestRotation(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, tc := range []struct {
			outcome                 string
			pending, empty, replace bool
		}{
			{"unsupported", false, false, true}, {"failed", false, true, true}, {"enrolled", false, false, true},
			{"failed", true, false, false}, {"failed", false, false, false}, {"pending", false, true, false}, {"pending_existing", true, false, false}, {"pending_uncertain", false, true, false}, {"", false, true, false},
		} {
			name := "manual"
			if auto {
				name = "auto"
			}
			t.Run(name+"/"+tc.outcome, func(t *testing.T) {
				s := mokRotationServer(t)
				callAPI(t, s, "POST", "/api/signing/old/hosts/node/rollout-cert", "", http.StatusOK)
				old := currentMOK(s, "node")
				s.cfg.Signing.Keys = s.cfg.Signing.Keys[1:]
				status := signingHost(map[string]string{"new": "not_enrolled"}).Status
				status.MOKListEmpty, status.MOKPending = tc.empty, tc.pending
				if tc.outcome != "" {
					status.MOKImport = &model.MOKImportResult{ID: old.Request.ID, KeyID: "old", Status: tc.outcome}
				}
				raw := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status, AutoImportCert: auto}, http.StatusOK)
				if auto {
					var resp model.ReportResponse
					if err := json.Unmarshal([]byte(raw), &resp); err != nil {
						t.Fatal(err)
					}
					if sentNew := resp.MOKImport != nil && resp.MOKImport.KeyID == "new"; sentNew != tc.replace {
						t.Fatal("unexpected automatic delivery")
					}
				} else {
					code := http.StatusConflict
					if tc.replace {
						code = http.StatusOK
					}
					callAPI(t, s, "POST", "/api/signing/new/hosts/node/rollout-cert", "", code)
				}
				got := currentMOK(s, "node")
				if tc.replace {
					if got.Request.ID == old.Request.ID || got.Request.KeyID != "new" || got.Result != nil {
						t.Fatal("new request not scheduled")
					}
				} else if got.Request != old.Request || got.Password != old.Password {
					t.Fatal("existing credential changed")
				}
				if tc.outcome == "failed" && tc.pending {
					var credential map[string]string
					raw := callAPI(t, s, "GET", "/api/hosts/node/mok-password", "", 200)
					if json.Unmarshal([]byte(raw), &credential) != nil || credential["password"] != "" || credential["candidate_password"] != old.Password {
						t.Fatal("failed import lost the candidate credential")
					}
				}
				if currentMOK(s, "other").Request.ID != "" {
					t.Fatal("touched another host")
				}
			})
		}
	}
}

func TestScopedMOKRecoveryRequiresFreshEmptyListAndMatchingRequest(t *testing.T) {
	s := mokRotationServer(t)
	callAPI(t, s, "POST", "/api/signing/old/hosts/node/rollout-cert", "", 200)
	old := currentMOK(s, "node")
	s.cfg.Signing.Keys = s.cfg.Signing.Keys[1:]
	status := signingHost(map[string]string{"new": "not_enrolled"}).Status
	status.MOKImport = &model.MOKImportResult{KeyID: "old", ID: old.Request.ID, Status: "pending", PasswordSet: true}
	report := func() { agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, 200) }
	replace := "/api/signing/new/hosts/node/rollout-cert?replace_request="
	status.MOKPending = true
	report()
	callAPI(t, s, "POST", replace+old.Request.ID, "", 409)
	if !strings.Contains(callAPI(t, s, "GET", "/api/hosts/node/mok-password", "", 200), old.Password) {
		t.Fatal("lost pending credential")
	}
	status.MOKPending = false
	report()
	callAPI(t, s, "POST", replace+old.Request.ID, "", 409) // old-format or unreadable list
	status.MOKListEmpty = true
	report()
	if err := s.store.Update(func(st *State) error { st.Hosts["node"].LastSeen = time.Now().Add(-time.Hour); return nil }); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "POST", replace+old.Request.ID, "", 409)
	report()
	callAPI(t, s, "POST", replace+"stale-id", "", 409)
	// The controller retains the completed result and ID even if the local agent lost its result.
	status.MOKImport = nil
	report()
	if raw := callAPI(t, s, "GET", "/api/status", "", 200); !strings.Contains(raw, old.Request.ID) || strings.Contains(raw, old.Password) {
		t.Fatal("unsafe or missing controller request metadata")
	}
	callAPI(t, s, "POST", replace+old.Request.ID, "", 200)
	callAPI(t, s, "POST", replace+old.Request.ID, "", 409) // concurrent retry cannot replace new request
	got := currentMOK(s, "node")
	if got.Request.KeyID != "new" || got.Request.ID == old.Request.ID {
		t.Fatal("recovery failed")
	}
	audit, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if err != nil || !strings.Contains(string(audit), "scope=host=node") || !strings.Contains(string(audit), old.Request.ID) || strings.Contains(string(audit), old.Password) {
		t.Fatal("missing or unsafe recovery audit", err)
	}
}

func TestRolloutScopeRejectsInvalidRequests(t *testing.T) {
	s := mokRotationServer(t)
	if err := s.store.Update(func(st *State) error {
		for _, h := range st.Hosts {
			h.Hostname = "duplicate"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"hosts/duplicate/rollout-cert", "", 409}, {"hosts/missing/rollout-cert", "", 404},
		{"rollout-cert?host=node", "", 400}, {"rollout-cert", `{"host":"node"}`, 400}, {"rollout-cert?replace_request=foo", "", 400},
		{"hosts/node/rollout-cert?replace_request=", "", 400}, {"hosts/node/rollout-cert?replace_request=a&replace_request=b", "", 400},
	} {
		callAPI(t, s, "POST", "/api/signing/new/"+tc.path, tc.body, tc.code)
	}
	if currentMOK(s, "node").Request.ID != "" || currentMOK(s, "other").Request.ID != "" {
		t.Fatal("invalid selector scheduled a request")
	}
	callAPI(t, s, "POST", "/api/signing/new/hosts/node/rollout-cert", "", 200)
	old := currentMOK(s, "node")
	if old.Request.ID == "" || currentMOK(s, "other").Request.ID != "" {
		t.Fatal("host scope violated")
	}
	callAPI(t, s, "POST", "/api/signing/new/rollout-cert", "{}", 200)
	if currentMOK(s, "node").Request != old.Request || currentMOK(s, "other").Request.ID == "" {
		t.Fatal("fleet or idempotency regression")
	}
}

func TestTerminalSameKeyMOKRetry(t *testing.T) {
	for _, outcome := range []string{"failed", "unsupported"} {
		t.Run(outcome, func(t *testing.T) {
			s := mokRotationServer(t)
			path := "/api/signing/new/hosts/node/rollout-cert"
			callAPI(t, s, "POST", path, "", 200)
			old := currentMOK(s, "node")
			status := signingHost(map[string]string{"new": "not_enrolled"}).Status
			status.MOKImport = &model.MOKImportResult{KeyID: "new", ID: old.Request.ID, Status: outcome}
			status.MOKPending = true
			report := func() {
				agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status, AutoImportCert: true}, 200)
			}
			report()
			callAPI(t, s, "POST", path, "", 409)
			if got := currentMOK(s, "node"); got.Request != old.Request || got.Result == nil {
				t.Fatal("changed pending request")
			}
			status.MOKPending, status.MOKListEmpty = false, true
			report()
			if got := currentMOK(s, "node"); got.Request != old.Request || got.Result == nil {
				t.Fatal("automatically retried terminal result")
			}
			callAPI(t, s, "POST", path, "", 200)
			retry := currentMOK(s, "node")
			if retry.Request.ID == old.Request.ID || retry.Result != nil || retry.Password != old.Password || retry.Request.PasswordHash != old.Request.PasswordHash {
				t.Fatal("request identity or console credential lost")
			}
		})
	}
}

func TestSameKeyUnchangedMOKReportsOnlyNewRequests(t *testing.T) {
	const fleet = "/api/signing/new/rollout-cert"
	const scoped = "/api/signing/new/hosts/node/rollout-cert"
	for _, tc := range []struct {
		outcome                        string
		pending, empty, stale, recover bool
	}{
		{"pending", false, true, false, true}, {"pending_existing", false, true, false, true}, {"pending_uncertain", false, true, false, true}, {"enrolled", false, true, false, true},
		{"pending", true, false, false, false}, {"pending_existing", true, false, false, false}, {"pending", false, false, false, false}, {"pending", false, true, true, false}, {"", false, true, false, false},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			s := mokRotationServer(t)
			callAPI(t, s, "POST", scoped, "", 200)
			old := currentMOK(s, "node")
			status := signingHost(map[string]string{"new": "not_enrolled"}).Status
			status.MOKPending, status.MOKListEmpty = tc.pending, tc.empty
			if tc.outcome != "" {
				status.MOKImport = &model.MOKImportResult{ID: old.Request.ID, KeyID: "new", Status: tc.outcome}
			}
			agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, 200)
			if tc.stale {
				if err := s.store.Update(func(st *State) error { st.Hosts["node"].LastSeen = time.Now().Add(-time.Hour); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			hint := "kpctl signing rollout-cert -host node -replace-request " + old.Request.ID + " new"
			for _, want := range []int{1, 0} {
				raw := callAPI(t, s, "POST", fleet, "", 200)
				var result struct {
					Count    int      `json:"scheduled_hosts"`
					Warnings []string `json:"warnings"`
				}
				if err := json.Unmarshal([]byte(raw), &result); err != nil {
					t.Fatal(err)
				}
				msg := strings.Join(result.Warnings, " ")
				if result.Count != want || !strings.Contains(msg, old.Request.ID) || strings.Contains(msg, hint) != tc.recover {
					t.Fatalf("unchanged fleet result: %s", raw)
				}
			}
			raw := callAPI(t, s, "POST", scoped, "", 409)
			if !strings.Contains(raw, old.Request.ID) || strings.Contains(raw, hint) != tc.recover {
				t.Fatal(raw)
			}
			if next := currentMOK(s, "node"); next.Request != old.Request || next.Password != old.Password {
				t.Fatal("unchanged submission replaced credential or request")
			}
			if tc.recover {
				raw = callAPI(t, s, "POST", scoped+"?replace_request="+old.Request.ID, "", 200)
				next := currentMOK(s, "node")
				if !strings.Contains(raw, `"scheduled_hosts":1`) || next.Request.ID == old.Request.ID || next.Request.PasswordHash != old.Request.PasswordHash || next.Password != old.Password || next.Result != nil {
					t.Fatal("same-key recovery did not safely reschedule")
				}
			}
		})
	}
}

func TestConcurrentSameKeyMOKRecoveryCountsOneChange(t *testing.T) {
	s := mokRotationServer(t)
	const scoped = "/api/signing/new/hosts/node/rollout-cert"
	const fleet = "/api/signing/new/rollout-cert"
	callAPI(t, s, "POST", fleet, "", 200)
	old := currentMOK(s, "node")
	status := signingHost(map[string]string{"new": "not_enrolled"}).Status
	status.MOKListEmpty = true
	status.MOKImport = &model.MOKImportResult{ID: old.Request.ID, KeyID: "new", Status: "pending_existing"}
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, 200)
	replace := scoped + "?replace_request=" + old.Request.ID
	handler := s.Handler()
	type reply struct {
		path string
		code int
		body string
	}
	replies := make(chan reply, 3)
	start := make(chan struct{})
	for _, path := range []string{replace, fleet, replace} {
		go func(path string) {
			req := httptest.NewRequest("POST", path, nil)
			req.Header.Set("Authorization", "Bearer "+testAdmin)
			rec := httptest.NewRecorder()
			<-start
			handler.ServeHTTP(rec, req)
			replies <- reply{path, rec.Code, rec.Body.String()}
		}(path)
	}
	close(start)
	successes, conflicts := 0, 0
	for i := 0; i < 3; i++ {
		r := <-replies
		switch {
		case r.path == fleet && r.code == 200 && strings.Contains(r.body, `"scheduled_hosts":0`):
		case r.path == replace && r.code == 200 && strings.Contains(r.body, `"scheduled_hosts":1`):
			successes++
		case r.path == replace && r.code == 409:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent response: %+v", r)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("recovery successes=%d conflicts=%d", successes, conflicts)
	}
	// A delayed report for the old ID cannot complete the newly scheduled request.
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status, AutoImportCert: true}, 200)
	next := currentMOK(s, "node")
	if next.Request.ID == old.Request.ID || next.Password != old.Password || next.Request.PasswordHash != old.Request.PasswordHash || next.Result != nil {
		t.Fatal("lost new request or original credential")
	}
}
