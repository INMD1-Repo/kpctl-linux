// 이 파일: 서명 설정 호환·키별 배포 자격·제외 호스트와 자격 회복 시험.
package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func signingFixture() (*Server, *model.Job) {
	s := &Server{cfg: &Config{Signing: &SigningConfig{Mode: "always", Keys: []SigningKey{
		{ID: "new", SignCommand: []string{"sign-file", "{module}"}, Active: true},
		{ID: "old", SignCommand: []string{"sign-file", "{module}"}},
	}}}}
	j := &model.Job{ID: 1, Kernel: testKernel, Version: 1, Status: model.JobReleased,
		ModuleName: "kpctl_signed_v1", SHA256: "new-sha", ActiveSigningKey: "new",
		SigningArtifacts: map[string]model.SigningArtifact{
			"new": {KeyID: "new", File: "kpctl_signed_v1.ko", SHA256: "new-sha", Signed: true},
			"old": {KeyID: "old", File: "kpctl_signed_v1.ko", SHA256: "old-sha", Signed: true},
		}}
	return s, j
}

func signingHost(certs map[string]string) *model.Host {
	return &model.Host{ID: "host", Hostname: "host", Ring: 1, LastSeen: time.Now(),
		Status: model.HostStatus{Kernel: testKernel, Firmware: "uefi", SecureBoot: "on",
			Lockdown: "integrity", SigEnforce: "off", EnrolledCerts: certs}}
}

func TestSigningConfigLoaderRejectsUnsafeOrUnknownSettings(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		wantError   bool
	}{
		{"생략", ``, false},
		{"기존 명령", `,"sign_command":["sign-file","{module}"]`, false},
		{"기본 모드", `,"signing":{"keys":[{"id":"new","active":true,"sign_command":["sign-file","{module}"]}]}`, false},
		{"필요한 경우", `,"signing":{"mode":"when_required","keys":[{"id":"new","active":true,"sign_command":["sign-file","{module}"]}]}`, false},
		{"서명 끔", `,"signing":{"mode":"never","keys":[{"id":"new","active":true}]}`, false},
		{"두 설정 동시 사용", `,"sign_command":["sign-file"],"signing":{"keys":[{"id":"new","active":true,"sign_command":["sign-file"]}]}`, true},
		{"활성 키 없음", `,"signing":{"keys":[{"id":"old","sign_command":["sign-file"]}]}`, true},
		{"활성 키 둘", `,"signing":{"keys":[{"id":"new","active":true,"sign_command":["sign-file"]},{"id":"old","active":true,"sign_command":["sign-file"]}]}`, true},
		{"중복 ID", `,"signing":{"keys":[{"id":"new","active":true,"sign_command":["sign-file"]},{"id":"new","sign_command":["sign-file"]}]}`, true},
		{"경로 ID", `,"signing":{"keys":[{"id":"../escape","active":true,"sign_command":["sign-file"]}]}`, true},
		{"서명 명령 없음", `,"signing":{"keys":[{"id":"new","active":true}]}`, true},
		{"알 수 없는 모드", `,"signing":{"mode":"sometimes","keys":[{"id":"new","active":true,"sign_command":["sign-file"]}]}`, true},
		{"알 수 없는 블록 키", `,"signing":{"mdoe":"always","keys":[{"id":"new","active":true,"sign_command":["sign-file"]}]}`, true},
		{"알 수 없는 키 속성", `,"signing":{"keys":[{"id":"new","active":true,"sign_command":["sign-file"],"certt":"key.der"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller.json")
			body := `{"admin_tokens":{"test":"admin-token-0123456789"},"builder_token":"builder-token-0123456789"` + tc.extra + `}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if (err != nil) != tc.wantError {
				t.Fatalf("설정 오류=%v, want 오류=%v", err, tc.wantError)
			}
			if err == nil && cfg.Signing != nil && cfg.Signing.Mode == "" {
				t.Fatal("생략한 signing.mode 기본값이 적용되지 않음")
			}
		})
	}
}

func TestSigningLegacyCommandKeepsAlwaysModeAndDefaultKey(t *testing.T) {
	command := []string{"/usr/src/linux-headers-{kernel}/scripts/sign-file", "sha512", "/private/key.priv", "/public/key.der", "{module}"}
	s := &Server{cfg: &Config{SignCommand: command}}
	got := s.signingConfig()
	if got.Mode != "always" || len(got.Keys) != 1 || got.Keys[0].ID != "default" || !got.Keys[0].Active ||
		got.Keys[0].Cert != "/public/key.der" || !reflect.DeepEqual(got.Keys[0].SignCommand, command) {
		t.Fatalf("기존 서명 설정의 의미가 달라짐: %+v", got)
	}
	s.cfg.SignCommand = []string{"custom-signer", "{module}"}
	got = s.signingConfig()
	if len(got.Keys) != 1 || got.Keys[0].Cert != "" {
		t.Fatalf("기존 custom signer에 없는 인증서 경로를 만들어서는 안 됨: %+v", got)
	}
}

func TestSigningRolloutSelectsEnrolledKeysAndKeepsLegacyFleetEligible(t *testing.T) {
	for _, tc := range []struct {
		name, wantStatus, wantKey string
		certs                     map[string]string
		wantWarning               bool
	}{
		{"활성 키 우선", "eligible", "new", map[string]string{"new": "enrolled", "old": "enrolled"}, false},
		{"옛 키만 등록", "eligible", "old", map[string]string{"new": "not_enrolled", "old": "enrolled"}, false},
		{"옛 에이전트", "eligible", "new", nil, true},
		{"명시적 unknown", "eligible", "new", map[string]string{"new": "unknown", "old": "not_enrolled"}, true},
		{"일부 키 보고 누락", "eligible", "new", map[string]string{"new": "not_enrolled"}, true},
		{"모든 키 미등록", "blocked_mok_missing", "", map[string]string{"new": "not_enrolled", "old": "not_enrolled"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, j := signingFixture()
			got := s.rolloutEligibility(signingHost(tc.certs), j)
			if got.Status != tc.wantStatus || got.KeyID != tc.wantKey || (tc.wantWarning && got.Warning == "") {
				t.Fatalf("배포 자격=%+v, want %s/%s 경고=%v", got, tc.wantStatus, tc.wantKey, tc.wantWarning)
			}
		})
	}
}

func TestSigningMissingMOKReasonDistinguishesPendingApproval(t *testing.T) {
	s, j := signingFixture()
	h := signingHost(map[string]string{"new": "not_enrolled", "old": "not_enrolled"})
	got := s.rolloutEligibility(h, j)
	if got.Status != "blocked_mok_missing" || !strings.Contains(got.Reason, "MOK 등록 필요") {
		t.Fatalf("미등록 사유가 없음: %+v", got)
	}
	h.Status.MOKPending = true
	got = s.rolloutEligibility(h, j)
	if got.Status != "blocked_mok_missing" || !strings.Contains(got.Reason, "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요") {
		t.Fatalf("콘솔 승인 대기 사유가 없음: %+v", got)
	}
}

func TestSigningUnrequiredHostUsesActiveArtifactWithoutMOK(t *testing.T) {
	s, j := signingFixture()
	h := signingHost(map[string]string{"new": "not_enrolled", "old": "not_enrolled"})
	h.Status.Firmware, h.Status.SecureBoot, h.Status.Lockdown = "bios", "off", "none"
	got := s.rolloutEligibility(h, j)
	if got.Status != "eligible" || got.KeyID != "new" {
		t.Fatalf("서명 불필요 호스트는 active 사본을 받아야 함: %+v", got)
	}
}

func TestSigningNeverBlocksRequiredHostsEvenWhenKeyIsEnrolled(t *testing.T) {
	s, j := signingFixture()
	s.cfg.Signing.Mode = "never"
	h := signingHost(map[string]string{"new": "enrolled", "old": "enrolled"})
	got := s.rolloutEligibility(h, j)
	if got.Status != "blocked_signing_disabled" || got.Warning == "" {
		t.Fatalf("never 모드에서 서명 필요 호스트가 제외·경고되지 않음: %+v", got)
	}
	h.Status = model.HostStatus{Kernel: testKernel}
	got = s.rolloutEligibility(h, j)
	if got.Status != "blocked_signing_disabled" || got.Warning == "" {
		t.Fatalf("보안 신호가 없는 이전 호스트도 never 모드에서는 서명 필요: %+v", got)
	}
}

func TestSigningSelectedArtifactMustExist(t *testing.T) {
	s, j := signingFixture()
	delete(j.SigningArtifacts, "old")
	h := signingHost(map[string]string{"new": "not_enrolled", "old": "enrolled"})
	got := s.rolloutEligibility(h, j)
	if got.Status != "blocked_artifact" {
		t.Fatalf("등록된 키의 사본이 없는데 다른 키로 배포함: %+v", got)
	}
}

func TestSigningPreviouslyUnsignedArtifactCannotReachNewlyEnforcedHost(t *testing.T) {
	s, j := signingFixture()
	s.cfg.Signing.Mode = "when_required"
	for key, artifact := range j.SigningArtifacts {
		artifact.Signed = false
		j.SigningArtifacts[key] = artifact
	}
	h := signingHost(map[string]string{"new": "enrolled", "old": "not_enrolled"})
	h.Status.Firmware, h.Status.SecureBoot, h.Status.Lockdown = "bios", "off", "none"
	if got := s.rolloutEligibility(h, j); got.Status != "eligible" {
		t.Fatalf("서명 불필요 호스트에는 기존 미서명 사본이 유효해야 함: %+v", got)
	}
	h.Status.SigEnforce = "on"
	if got := s.rolloutEligibility(h, j); got.Status != "blocked_artifact" {
		t.Fatalf("서명 강제가 켜진 호스트에 기존 미서명 사본을 배포함: %+v", got)
	}
}

func TestSigningBlockedHostDoesNotPreventHealthyHostPromotion(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	fixture, j := signingFixture()
	s.cfg.Signing = fixture.cfg.Signing
	healthy := signingHost(map[string]string{"new": "enrolled", "old": "not_enrolled"})
	healthy.Status.Version = j.Version
	healthy.Status.Loaded = []model.LoadedPatch{{Name: j.ModuleName, Enabled: true}}
	blocked := signingHost(map[string]string{"new": "not_enrolled", "old": "not_enrolled"})
	blocked.ID, blocked.Hostname, blocked.Status.Error = "blocked", "blocked", "서명 검증 실패"
	blocked.LastSeen = time.Now().Add(-24 * time.Hour)
	st := &State{Jobs: []*model.Job{j}, Hosts: map[string]*model.Host{"healthy": healthy, "blocked": blocked}}
	if problems := s.promoteProblems(st, testKernel, 1, j.Version, time.Now().Add(-48*time.Hour), 2); len(problems) != 0 {
		t.Fatalf("서명 자격으로 제외된 호스트가 건강한 호스트의 승급을 막음: %v", problems)
	}
}

func TestSigningEnrollmentRecoveryImmediatelyReceivesCurrentTarget(t *testing.T) {
	s, j := signingFixture()
	h := signingHost(map[string]string{"new": "not_enrolled", "old": "not_enrolled"})
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: j.Version}}}}
	if got := s.desired(st, h); got.Version != 0 || !got.Blocked || got.Warning == "" {
		t.Fatalf("등록 전 호스트는 rollback과 구분되는 배포 제외 응답이 필요함: %+v", got)
	}
	h.Status.EnrolledCerts["old"] = "enrolled"
	got := s.desired(st, h)
	if got.Version != j.Version || got.ModuleName != j.ModuleName || got.SHA256 != "old-sha" || got.URL == "" {
		t.Fatalf("등록 보고 직후 현재 목표 버전/옛 키 사본이 전달되지 않음: %+v", got)
	}
}

func TestSigningLegacyJobWithoutNewFieldsStillDeploys(t *testing.T) {
	s := &Server{cfg: &Config{SignCommand: []string{"legacy-sign", "{module}"}}}
	j := &model.Job{Kernel: testKernel, Version: 3, Status: model.JobReleased,
		ModuleName: "kpctl_legacy_v3", SHA256: "legacy-sha"}
	h := &model.Host{Ring: 1, Status: model.HostStatus{Kernel: testKernel}}
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: 3}}}}
	got := s.desired(st, h)
	if got.Blocked || got.Version != 3 || got.ModuleName != j.ModuleName || got.SHA256 != j.SHA256 || got.Warning == "" {
		t.Fatalf("새 필드가 없는 기존 배포 작업/호스트의 호환성이 깨짐: %+v", got)
	}
}

func TestSigningLegacyHostReportGetsActiveArtifactAndWarning(t *testing.T) {
	s, j := signingFixture()
	h := &model.Host{ID: "legacy", Ring: 1, Status: model.HostStatus{Kernel: testKernel}}
	got := s.rolloutEligibility(h, j)
	if got.Status != "eligible" || got.KeyID != "new" || got.Warning == "" {
		t.Fatalf("이전 에이전트의 보안 필드 누락 때문에 기존 fleet 배포가 막힘: %+v", got)
	}
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: j.Version}}}}
	if desired := s.desired(st, h); desired.Version != j.Version || desired.SHA256 != "new-sha" {
		t.Fatalf("이전 에이전트는 active 사본과 해시를 받아야 함: %+v", desired)
	}
	data, err := json.Marshal(j)
	if err != nil || !strings.Contains(string(data), `"sha256":"new-sha"`) {
		t.Fatalf("기존 API SHA256 필드가 유지되지 않음: %s (%v)", data, err)
	}
}

func TestSigningCopiesPreserveUnsignedOriginalAndExpandKernel(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	root := t.TempDir()
	signer := vmScript(t, root, "sign.sh", `printf '%s' ":$2:$3" >> "$1"`)
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{
		{ID: "new", Active: true, SignCommand: []string{signer, "{module}", "{kernel}", "new"}},
		{ID: "old", SignCommand: []string{signer, "{module}", "{kernel}", "old"}},
		{ID: "unused", SignCommand: []string{signer, "{module}", "{kernel}", "unused"}},
	}}
	addHost(t, s, "old-only", 1)
	if err := s.store.Update(func(st *State) error {
		st.Hosts["old-only"].Status = signingHost(map[string]string{"new": "not_enrolled", "old": "enrolled", "unused": "not_enrolled"}).Status
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id := addBuilt(t, s, "manual")
	var module string
	s.store.View(func(st *State) { module = st.job(id).ModuleName })
	for attempt := 0; attempt < 2; attempt++ {
		artifacts, active, err := s.prepareSigningArtifacts(id, testKernel, module)
		if err != nil {
			t.Fatal(err)
		}
		if active != "new" || len(artifacts) != 2 {
			t.Fatalf("active와 필요한 옛 키의 사본만 생성해야 함: %s %+v", active, artifacts)
		}
		for _, key := range []string{"new", "old"} {
			path := s.signingArtifactFile(testKernel, module, key)
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "module:"+testKernel+":"+key {
				t.Fatalf("시도 %d 키 %s의 서명/치환/원본 재사용 실패: %q (%v)", attempt, key, data, err)
			}
			sum, err := fileSHA256(path)
			if err != nil || artifacts[key].SHA256 != sum || !artifacts[key].Signed {
				t.Fatalf("서명 사본의 해시가 실제 바이트와 다름: %+v %s (%v)", artifacts[key], sum, err)
			}
		}
	}
	data, err := os.ReadFile(s.unsignedArtifactFile(testKernel, module))
	if err != nil || string(data) != "module" {
		t.Fatalf("서명 전 원본이 변경됨: %q (%v)", data, err)
	}
}

func TestSigningUnknownEnrollmentCannotReceiveExplicitUnsignedArtifact(t *testing.T) {
	s, j := signingFixture()
	s.cfg.Signing.Mode = "when_required"
	j.SigningArtifacts["new"] = model.SigningArtifact{KeyID: "new", Signed: false}
	h := signingHost(nil)
	if got := s.rolloutEligibility(h, j); got.Status != "blocked_artifact" {
		t.Fatalf("unsigned active artifact must be blocked: %+v", got)
	}
}
func TestSigningRemovedKeyCannotBeSelectedFromHistoricalJob(t *testing.T) {
	s, j := signingFixture()
	j.ActiveSigningKey = "old"
	s.cfg.Signing.Keys = s.cfg.Signing.Keys[:1]
	h := signingHost(map[string]string{"new": "not_enrolled", "old": "enrolled"})
	if got := s.rolloutEligibility(h, j); got.Status != "blocked_mok_missing" {
		t.Fatalf("removed historical key selected: %+v", got)
	}
}

// 검토 항목 2.3: 서명 도구가 되돌려 준 개인키 경로가 API 오류·감사 로그에 노출되면 안 됩니다.
func TestSigningFailureOutputRedactsCommandArguments(t *testing.T) {
	if got := redactSigningOutput("sign-file: /etc/kpctl/keys/k.priv: No such file (sha512)", []string{"/usr/bin/sign-file", "sha512", "/etc/kpctl/keys/k.priv", "{module}"}); got != "sign-file: <redacted>: No such file (<redacted>)" {
		t.Fatalf("예상과 다른 가림 결과: %q", got)
	}
	s := newAutoServer(t, AutoRollout{})
	root := t.TempDir()
	signer := vmScript(t, root, "sign-fail.sh", `echo "sign-file: $3: No such file or directory"; exit 1`)
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{
		{ID: "new", Active: true, SignCommand: []string{signer, "{module}", "sha512", "/etc/kpctl/keys/private-secret.priv", "{kernel}"}},
	}}
	id := addBuilt(t, s, "manual")
	var module string
	s.store.View(func(st *State) { module = st.job(id).ModuleName })
	_, _, err := s.prepareSigningArtifacts(id, testKernel, module)
	if err == nil {
		t.Fatal("서명 실패를 성공으로 처리함")
	}
	if strings.Contains(err.Error(), "private-secret.priv") {
		t.Fatalf("개인키 경로가 오류에 노출됨: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") || !strings.Contains(err.Error(), "No such file") {
		t.Fatalf("도구 출력은 경로만 가린 채 남아야 함: %v", err)
	}
}
