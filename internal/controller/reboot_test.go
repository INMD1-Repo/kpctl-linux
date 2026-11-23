// 이 파일: controller 패키지의 TestRebootApprovalIsExplicitScopedAndOneShot, TestCancelledExpiredChangedAndBusyRebootCannotDispatch, TestWrongKernelBootIsNeverSuccess 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func rebootFixture(t *testing.T) (*Server, model.BootTarget) {
	s := newAutoServer(t, AutoRollout{})
	target := model.BootTarget{Kernel: "6.8.0-86-generic", PackageVersion: "6.8.0-86.86", Entry: "gnulinux-advanced-abc>gnulinux-6.8.0-86-generic-advanced-abc", ImageSHA256: strings.Repeat("a", 64), InitrdSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), GrubSHA256: strings.Repeat("d", 64)}
	target.ID = model.BootTargetID(target)
	target.FallbackEntry = "gnulinux-advanced-abc>gnulinux-6.8.0-85-generic-advanced-abc"
	target.ID = model.BootTargetID(target)
	zero := 0
	_ = s.store.Update(func(st *State) error {
		st.Hosts["node"] = &model.Host{ID: "node", Hostname: "node", Ring: 1, RebootPolicy: model.RebootDrain, Cordoned: true, VMCount: 0, VMCountCheckedAt: time.Now(), LastSeen: time.Now(), TokenHash: hashToken("node-token"), Status: model.HostStatus{Kernel: testKernel, KernelSignature: "Ubuntu 6.8.0-85.85-generic 6.8.12", BootID: "boot-before", BootTarget: &target, LocalVMCount: &zero}}
		return nil
	})
	return s, target
}

func agentRebootAPI(t *testing.T, s *Server, path string, body any, want int) string {
	t.Helper()
	data, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
	r.Header.Set("Authorization", "Bearer node-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s: %d want %d: %s", path, w.Code, want, w.Body)
	}
	return w.Body.String()
}

func approveReboot(t *testing.T, s *Server, target model.BootTarget) {
	t.Helper()
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"target_id":"`+target.ID+`"}`, http.StatusOK)
}

func TestRebootSaveFailuresDoNotChangeLiveApproval(t *testing.T) {
	s, target := rebootFixture(t)
	path := s.store.path
	unwritable := filepath.Join(path, "state.json")
	s.store.path = unwritable
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"target_id":"`+target.ID+`"}`, http.StatusInternalServerError)
	s.store.View(func(st *State) {
		h := st.Hosts["node"]
		if h.RebootApproval != nil || h.RebootRequestID != 0 || st.NextRebootID != 0 {
			t.Fatal("failed write left a live reboot approval")
		}
	})

	s.store.path = path
	approveReboot(t, s, target)
	s.store.path = unwritable
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"cancel":true}`, http.StatusInternalServerError)
	claim := model.RebootClaim{ID: 1, BootID: "boot-before", TargetID: target.ID}
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusInternalServerError)
	s.store.View(func(st *State) {
		h := st.Hosts["node"]
		if h.RebootApproval == nil || h.RebootApproval.DispatchedAt != nil || h.RebootRequestID != 1 || h.RebootResult != nil {
			t.Fatal("failed cancellation or claim changed live approval")
		}
	})
	s.store.path = path
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusOK)
}

func TestRebootApprovalIsExplicitScopedAndOneShot(t *testing.T) {
	s, target := rebootFixture(t)
	// Agent credentials cannot approve their own reboot.
	agentRebootAPI(t, s, "/api/hosts/node/reboot", model.RebootRequest{TargetID: target.ID}, http.StatusUnauthorized)
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{}`, http.StatusConflict)
	approveReboot(t, s, target)
	claim := model.RebootClaim{ID: 1, BootID: "boot-before", TargetID: target.ID}
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusOK)
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusConflict)
	callAPI(t, s, "POST", "/api/hosts/node/cordon", `{"on":false}`, http.StatusConflict)
	var h model.Host
	s.store.View(func(st *State) { h = *st.Hosts["node"] })
	response := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: h.Status, LastRebootID: 1}, http.StatusOK)
	var report model.ReportResponse
	_ = json.Unmarshal([]byte(response), &report)
	if report.RebootID != 0 {
		t.Fatal("legacy agent could execute ID-only reboot")
	}
	s.store.View(func(st *State) {
		if st.Hosts["node"].RebootRequestID == 0 {
			t.Fatal("request ACK falsely treated as a real reboot")
		}
	})
	h.Status.Kernel = target.Kernel
	h.Status.KernelSignature = "Ubuntu 6.8.0-86.86-generic 6.8.12"
	h.Status.BootID = "boot-after"
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: h.Status, LastRebootID: 1}, http.StatusOK)
	s.store.View(func(st *State) {
		h := st.Hosts["node"]
		if h.RebootResult == nil || h.RebootResult.Status != "booted" || h.RebootRequestID != 0 || !h.Cordoned {
			t.Fatalf("unexpected reboot result %+v", h)
		}
	})
}

func TestCancelledExpiredChangedAndBusyRebootCannotDispatch(t *testing.T) {
	for _, kind := range []string{"cancelled", "expired", "kernel changed", "VM appeared", "policy changed", "stale drain", "target changed"} {
		t.Run(kind, func(t *testing.T) {
			s, target := rebootFixture(t)
			approveReboot(t, s, target)
			if kind == "cancelled" {
				callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"cancel":true}`, http.StatusOK)
			} else {
				_ = s.store.Update(func(st *State) error {
					h := st.Hosts["node"]
					switch kind {
					case "expired":
						h.RebootApproval.ExpiresAt = time.Now().Add(-time.Second)
					case "kernel changed":
						h.Status.BootID = "another-boot"
					case "VM appeared":
						h.VMCount = 1
					case "policy changed":
						h.RebootPolicy = model.RebootNever
					case "stale drain":
						h.VMCountCheckedAt = time.Now().Add(-3 * time.Minute)
					case "target changed":
						copy := *h.Status.BootTarget
						copy.ImageSHA256 = strings.Repeat("f", 64)
						h.Status.BootTarget = &copy
					}
					return nil
				})
			}
			agentRebootAPI(t, s, "/api/agent/reboot/claim", model.RebootClaim{ID: 1, BootID: "boot-before", TargetID: target.ID}, http.StatusConflict)
		})
	}
}

func TestWrongKernelBootIsNeverSuccess(t *testing.T) {
	s, target := rebootFixture(t)
	approveReboot(t, s, target)
	agentRebootAPI(t, s, "/api/agent/reboot/claim", model.RebootClaim{ID: 1, BootID: "boot-before", TargetID: target.ID}, http.StatusOK)
	var status model.HostStatus
	s.store.View(func(st *State) { status = st.Hosts["node"].Status })
	status.BootID = "boot-after" // same old ABI
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status, LastRebootID: 1}, http.StatusOK)
	s.store.View(func(st *State) {
		if st.Hosts["node"].RebootResult.Status != "failed" {
			t.Fatal("same old kernel counted as an upgrade")
		}
	})
}
