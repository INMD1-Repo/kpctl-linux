// Package model 은 컨트롤러, 빌드 서버, 에이전트, kpctl 이 함께 쓰는 데이터 구조입니다.
//
// 여기 있는 구조체는 두 곳에 그대로 쓰입니다.
//  1. 컨트롤러의 상태 파일(state.json)
//  2. 각 프로그램 사이의 HTTP API (JSON)
//
// 필드를 추가할 때는 반드시 `json:"..."` 태그를 붙이세요.
// 필드 이름을 바꾸면 기존 state.json 과 호환이 깨지므로, 바꾸지 말고 새 필드를 추가하세요.
package model

import "time"

// ─────────────────────────────────────────────
// 패치
// ─────────────────────────────────────────────

// 패치 상태
const (
	PatchActive   = "active"   // 누적 패치에 포함됨
	PatchRejected = "rejected" // 예전 버전에서 자동 제외된 기록 (kpctl patch enable 로 되살릴 수 있음)
	PatchDisabled = "disabled" // 관리자가 직접 제외함
)

// Patch 는 누적 패치를 구성하는 패치 하나입니다.
// 패치 본문(diff)은 컨트롤러 data_dir/patches/<ID>.patch 파일에 따로 저장됩니다.
type Patch struct {
	Prerelease bool      `json:"prerelease,omitempty"` // 정식 수집·누적본과 분리한 출시 전 입력
	ID         string    `json:"id"`                   // 예: p0007
	Kernel     string    `json:"kernel"`               // 예: 6.8.0-85-generic
	Source     string    `json:"source"`               // "ubuntu" (자동 수집) 또는 "manual" (kpctl submit)
	Commit     string    `json:"commit,omitempty"`     // Ubuntu 커널 git 커밋 해시 (manual 이면 비어 있음)
	CVEs       []string  `json:"cves"`
	Title      string    `json:"title"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"` // rejected/disabled 이유
	AddedBy    string    `json:"added_by"`
	AddedAt    time.Time `json:"added_at"`
}

// Unpatchable은 기존 불가 판정 이력과 미해결 커밋의 관리자 제외를 보관합니다.
// 새 시험 실패는 자동으로 추가하지 않습니다. Decision이 있는 항목은 불가 판정이 아닙니다.
type Unpatchable struct {
	Kernel  string    `json:"kernel"`
	Commit  string    `json:"commit"`
	CVEs    []string  `json:"cves"`
	Title   string    `json:"title"`
	Reason  string    `json:"reason"`
	FoundAt time.Time `json:"found_at"`
	// Decision가 있으면 불가 판정이 아니라, 미해결로 남기는 관리자 제외입니다.
	Decision *CommitDecision `json:"decision,omitempty"`
}

const (
	FailureBusy        = "busy"
	FailureEnvironment = "environment"
	FailureUnsupported = "unsupported"
	FailureArtifact    = "artifact"
	FailureUnknown     = "unknown"
)

// BuildInput은 결정 당시의 입력 기록입니다. 입력 변경 시 자동 무효화하지 않습니다.
type BuildInput struct {
	BaseTag   string `json:"base_tag"`
	BuildTool string `json:"build_tool"`
	Profile   string `json:"profile,omitempty"`
	Image     string `json:"image,omitempty"`
}

type TrialFailure struct {
	Commit string     `json:"commit"`
	CVEs   []string   `json:"cves"`
	Title  string     `json:"title"`
	Input  BuildInput `json:"input"`
}

type CommitDecision struct {
	By    string     `json:"by"`
	At    time.Time  `json:"at"`
	Input BuildInput `json:"input"`
}

type ExcludeCommitRequest struct {
	Reason     string `json:"reason"`
	ProblemRef string `json:"problem_ref"`
}

// ─────────────────────────────────────────────
// 빌드 작업
// ─────────────────────────────────────────────

// 빌드 작업 상태 흐름:
//
//	queued → running → built → released
//	                ↘ failed
//	(새 작업이 생기면 이전의 queued/running/built 작업은 superseded)
const (
	JobQueued     = "queued"     // 빌드 서버가 가져가기를 기다림
	JobRunning    = "running"    // 빌드 서버가 빌드 중
	JobBuilt      = "built"      // 빌드 성공, 관리자 승인 대기
	JobFailed     = "failed"     // 빌드 실패
	JobReleased   = "released"   // 승인되어 배포됨
	JobSuperseded = "superseded" // 더 새로운 작업에 포함되어 폐기됨
)

// Job 은 "커널 하나에 대한 누적 패치 한 버전"을 만드는 작업입니다.
type Job struct {
	Prerelease        bool      `json:"prerelease,omitempty"`
	PrereleaseVersion int       `json:"prerelease_version,omitempty"` // 출시 전 전용 양수 번호; Version은 충돌 없는 음수 전송 식별자
	ID                int       `json:"id"`
	Kernel            string    `json:"kernel"`
	Version           int       `json:"version"`       // 정식은 커널별 양수 순번, 출시 전은 별도 음수 식별자
	PatchIDs          []string  `json:"patch_ids"`     // 이 버전에 포함된 모든 패치
	NewPatchIDs       []string  `json:"new_patch_ids"` // 직전 배포 버전에 없던 패치
	Urgent            bool      `json:"urgent"`
	Status            string    `json:"status"`
	Builder           string    `json:"builder,omitempty"`
	Error             string    `json:"error,omitempty"`
	ModuleName        string    `json:"module_name,omitempty"`     // 커널 모듈 이름 (= .ko 파일 이름)
	SHA256            string    `json:"sha256,omitempty"`          // 배포되는 .ko 파일의 해시
	UnsignedSHA256    string    `json:"unsigned_sha256,omitempty"` // 업로드된 서명 전 원본 바이트 고정
	RequestedBy       string    `json:"requested_by"`
	ApprovedBy        string    `json:"approved_by,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	StartedAt         time.Time `json:"started_at"`
	HeartbeatAt       time.Time `json:"heartbeat_at,omitempty"` // 실행 중인 빌더의 마지막 상태 보고
	FinishedAt        time.Time `json:"finished_at"`
	ReleasedAt        time.Time `json:"released_at"`
	// UpToTag: 이 버전이 반영한 Ubuntu 태그. 예: "Ubuntu-7.0.0-42.42" → 호스트 커널이 28 이어도 42 까지의 수정이 들어 있음
	UpToTag          string                     `json:"up_to_tag,omitempty"`
	VMTest           *VMTestResult              `json:"vm_test,omitempty"`
	SigningArtifacts map[string]SigningArtifact `json:"signing_artifacts,omitempty"`
	ActiveSigningKey string                     `json:"active_signing_key,omitempty"`
}

// Track 은 커널 버전 하나의 배포 상태입니다.
// RingVersions[링 번호] = 그 링에 배포할 패치 버전 (0 = 패치 없음)
type Track struct {
	NextPrereleaseVersion  int               `json:"next_prerelease_version,omitempty"`
	PrereleaseRingVersions map[int]int       `json:"prerelease_ring_versions,omitempty"`
	PrereleaseRingSetAt    map[int]time.Time `json:"prerelease_ring_set_at,omitempty"`
	Kernel                 string            `json:"kernel"`
	NextVersion            int               `json:"next_version"`
	RingVersions           map[int]int       `json:"ring_versions"`
	RingSetAt              map[int]time.Time `json:"ring_set_at"`
	// AutoHold: 비어 있지 않으면 이 커널은 자동 배포를 멈춥니다 (롤백, 호스트 오류 등). 값은 이유입니다.
	AutoHold string `json:"auto_hold,omitempty"`
	// 종류가 없는 예전 멈춤은 수동 멈춤으로 취급합니다. 문구를 해석하지 않습니다.
	AutoHoldKind string    `json:"auto_hold_kind,omitempty"`
	AutoHoldRef  string    `json:"auto_hold_ref,omitempty"`
	AutoHoldAt   time.Time `json:"auto_hold_at,omitempty"`
	// AutoHoldResolved: 자동으로 건 멈춤의 원인이 사라졌으면 그 내용 (멈춤은 사람이 자동 재개로 풉니다).
	AutoHoldResolved string `json:"auto_hold_resolved,omitempty"`
}

// ─────────────────────────────────────────────
// 호스트
// ─────────────────────────────────────────────

// 재부팅 정책
const (
	RebootDrain = "drain" // VM 이 모두 빠진(드레인된) 뒤에만 관리자 승인으로 재부팅
	RebootNever = "never" // 재부팅 요청 자체를 거부
)

// LoadedPatch 는 호스트 커널에 올라가 있는 라이브패치 하나입니다.
// (/sys/kernel/livepatch/<이름>/ 에서 읽음)
type LoadedPatch struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Transition bool   `json:"transition"` // true 면 아직 모든 태스크가 새 코드로 넘어가지 않음
}

// HostStatus 는 에이전트가 주기적으로 보고하는 호스트 상태입니다.
type HostStatus struct {
	ModuleSHA256      string            `json:"module_sha256,omitempty"` // 현재 부팅용 설치 사본의 실제 해시; 동일 버전 키 교체 때 기존 보호 유지
	Kernel            string            `json:"kernel"`                  // uname -r
	Firmware          string            `json:"firmware"`                // uefi, bios, unknown
	SecureBoot        string            `json:"secure_boot"`             // on, off, unknown
	Lockdown          string            `json:"lockdown"`                // none, integrity, confidentiality, unknown
	SigEnforce        string            `json:"sig_enforce"`             // on, off, unknown
	SignatureRequired bool              `json:"signature_required"`      // 정책 활성 또는 보안 신호 미확인이면 true
	SecurityWarning   string            `json:"security_warning,omitempty"`
	EnrolledCerts     map[string]string `json:"enrolled_certs,omitempty"`
	MOKPending        bool              `json:"mok_pending,omitempty"`
	MOKListEmpty      bool              `json:"mok_list_empty,omitempty"` // Successful --list-new, empty, and no per-cert pending.
	MOKImport         *MOKImportResult  `json:"mok_import,omitempty"`
	// KernelSignature: /proc/version_signature. 예: "Ubuntu 6.8.0-85.85-generic 6.8.12"
	// 빌드 서버가 정확한 기준 태그(Ubuntu-6.8.0-85.85)를 고르고 HWE 커널을 가려낼 때 씁니다.
	KernelSignature string               `json:"kernel_signature,omitempty"`
	Version         int                  `json:"version"` // 에이전트가 적용한 패치 버전 (0 = 없음)
	Loaded          []LoadedPatch        `json:"loaded"`
	Tainted         int64                `json:"tainted"` // /proc/sys/kernel/tainted
	Error           string               `json:"error,omitempty"`
	BootID          string               `json:"boot_id,omitempty"`
	BootConfirmedID int                  `json:"boot_confirmed_id,omitempty"` // GRUB 기본값 확정과 준비 기록 정리까지 마친 재부팅 승인 ID
	BootTarget      *BootTarget          `json:"boot_target,omitempty"`
	BootProblem     string               `json:"boot_problem,omitempty"`
	LocalVMCount    *int                 `json:"local_vm_count,omitempty"`
	KernelPrepare   *KernelPrepareStatus `json:"kernel_prepare,omitempty"`
}

// KernelPrepareStatus 는 공식 GA 커널의 디스크 준비 상태입니다. 재부팅 승인이 아닙니다.
type KernelPrepareStatus struct {
	Kernel        string    `json:"kernel"` // 준비를 시작한 실행 커널
	State         string    `json:"state"`  // preparing, failed, prepared
	Error         string    `json:"error,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	// Request: 이 시도를 시작한 관리자 요청 시각. 같은 요청으로는 재시도 대기를 한 번만 건너뜁니다.
	Request time.Time `json:"request,omitempty"`
}

// Host 는 컨트롤러에 등록된 물리 노드입니다.
type Host struct {
	ID               string          `json:"id"`
	Hostname         string          `json:"hostname"`
	Ring             int             `json:"ring"`
	RebootPolicy     string          `json:"reboot_policy"`
	Cordoned         bool            `json:"cordoned"`          // 신규 VM 배치 차단 중
	VMCount          int             `json:"vm_count"`          // -1 = 모름
	RebootRequestID  int             `json:"reboot_request_id"` // 0 이 아니면 재부팅 승인됨
	RebootApproval   *RebootApproval `json:"reboot_approval,omitempty"`
	RebootResult     *RebootResult   `json:"reboot_result,omitempty"`
	AutoKernelJump   *RebootApproval `json:"auto_kernel_jump,omitempty"` // 마지막 자동 점프 시도; 실패·취소 뒤 자동 반복 방지
	VMCountCheckedAt time.Time       `json:"vm_count_checked_at,omitempty"`
	// KernelPrepareRequest: 관리자가 이 호스트에 다음 공식 GA 커널 디스크 설치(점프 1단계)를 요청함.
	// 요청한 커널에서만 유효하며, 준비 기록이 생기거나 커널이 바뀌면 지웁니다. 재부팅은 별도 승인.
	KernelPrepareRequest *KernelPrepareRequest `json:"kernel_prepare_request,omitempty"`
	// UpdateNow*: 관리자가 이 호스트만 링보다 먼저 올린 버전 (그 커널에서만 유효, 롤백하면 풀림)
	UpdateNowKernel    string              `json:"update_now_kernel,omitempty"`
	UpdateNowVersion   int                 `json:"update_now_version,omitempty"`
	TokenHash          string              `json:"token_hash,omitempty"`
	RegisteredAt       time.Time           `json:"registered_at"`
	LastSeen           time.Time           `json:"last_seen"`
	Status             HostStatus          `json:"status"`
	MOKRequest         *MOKImportResult    `json:"mok_request,omitempty"` // 관리자 상태 응답용. 요청 ID·키·결과만 표시.
	RolloutEligibility *RolloutEligibility `json:"rollout_eligibility,omitempty"`
}

// ─────────────────────────────────────────────
// API 요청/응답
// ─────────────────────────────────────────────

// --- 에이전트 ---

// KernelPrepareRequest 는 관리자의 수동 커널 준비 요청 기록입니다.
type KernelPrepareRequest struct {
	Kernel      string    `json:"kernel"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

// PrepareKernelBody 는 POST /api/hosts/{id}/prepare-kernel 본문입니다.
type PrepareKernelBody struct {
	Kernel string `json:"kernel"` // 화면에서 본 현재 커널 (바뀌었으면 거부)
	Cancel bool   `json:"cancel"`
}

// UpdateNowRequest 는 POST /api/hosts/{id}/update-now 본문입니다 (비워도 됨).
type UpdateNowRequest struct {
	Cancel  bool   `json:"cancel"`
	Kernel  string `json:"kernel,omitempty"`  // 확인창에서 검토한 커널 (이전 클라이언트는 생략 가능)
	Version int    `json:"version,omitempty"` // 확인창에서 검토한 최신 승인 버전
}

type RegisterRequest struct {
	EnrollToken string `json:"enroll_token"`
	Hostname    string `json:"hostname"`
	Kernel      string `json:"kernel"`
}

type RegisterResponse struct {
	HostID    string `json:"host_id"`
	HostToken string `json:"host_token"`
}

type ReportRequest struct {
	AutoImportCert bool       `json:"auto_import_cert,omitempty"`
	Status         HostStatus `json:"status"`
	LastRebootID   int        `json:"last_reboot_id"` // 에이전트가 마지막으로 실행한 재부팅 요청 번호
	RebootError    string     `json:"reboot_error,omitempty"`
}

// DesiredPatch 는 컨트롤러가 "이 호스트는 이 버전이어야 한다"고 알려주는 값입니다.
// Version 이 0 이면 우리 패치를 모두 내려야 합니다.
type DesiredPatch struct {
	Blocked    bool   `json:"blocked,omitempty"`
	Warning    string `json:"warning,omitempty"`
	Version    int    `json:"version"`
	ModuleName string `json:"module_name,omitempty"`
	URL        string `json:"url,omitempty"` // 컨트롤러 기준 상대 경로 (/artifacts/...)
	SHA256     string `json:"sha256,omitempty"`
}

type ReportResponse struct {
	SigningCerts          []SigningCert     `json:"signing_certs,omitempty"`
	MOKImport             *MOKImportRequest `json:"mok_import,omitempty"`
	Desired               DesiredPatch      `json:"desired"`
	PrepareKernel         bool              `json:"prepare_kernel,omitempty"`           // 공식 GA 커널 설치만 요청, 재부팅은 별도 승인
	PrepareKernelTargetID string            `json:"prepare_kernel_target_id,omitempty"` // 검증한 기존 준비 기록의 갱신 허용 ID
	PrepareKernelRequest  *time.Time        `json:"prepare_kernel_request,omitempty"`   // 관리자 요청 시각: 원인을 고친 뒤 재시도 대기 없이 바로 다시 시도
	RebootID              int               `json:"reboot_id"`                          // 이전 호환 필드. 항상 0, scoped Reboot 승인만 실행
	Reboot                *RebootApproval   `json:"reboot,omitempty"`
	RebootResult          *RebootResult     `json:"reboot_result,omitempty"`
}

// BootTarget pins prepared on-disk files and a normal GRUB boot entry.
type BootTarget struct {
	ID             string `json:"id"`
	Kernel         string `json:"kernel"`
	PackageVersion string `json:"package_version"`
	Entry          string `json:"entry"`
	ImageSHA256    string `json:"image_sha256"`
	InitrdSHA256   string `json:"initrd_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	GrubSHA256     string `json:"grub_sha256"`
	FallbackEntry  string `json:"fallback_entry"`
}
type RebootApproval struct {
	ID           int        `json:"id"`
	Target       BootTarget `json:"target"`
	FromBootID   string     `json:"from_boot_id"`
	FromKernel   string     `json:"from_kernel"`
	ApprovedBy   string     `json:"approved_by"`
	ApprovedAt   time.Time  `json:"approved_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
}
type RebootResult struct {
	ID                   int       `json:"id"`
	TargetKernel         string    `json:"target_kernel"`
	TargetPackageVersion string    `json:"target_package_version,omitempty"`
	FromBootID           string    `json:"from_boot_id,omitempty"`
	TargetID             string    `json:"target_id,omitempty"`
	Status               string    `json:"status"` // booted, failed, expired, cancelled
	Detail               string    `json:"detail"`
	At                   time.Time `json:"at"`
}
type RebootRequest struct {
	TargetID string `json:"target_id"`
	Cancel   bool   `json:"cancel"`
}
type RebootClaim struct {
	ID       int    `json:"id"`
	BootID   string `json:"boot_id"`
	TargetID string `json:"target_id"`
}

// --- 빌드 서버 ---

type NextJobRequest struct {
	CanPrerelease bool   `json:"can_prerelease,omitempty"` // 음수 버전·출시 전 모듈 이름을 처리하는 빌더만 수신
	Builder       string `json:"builder"`
	// Series: 빌드 서버의 Ubuntu 시리즈 (예: noble). 컨트롤러는 이 시리즈의 커널 작업만 줍니다.
	// 비어 있으면 아무 작업이나 줍니다 (시리즈를 정하지 않은 예전 방식).
	Series string `json:"series,omitempty"`
	// Kernels: 설정에 직접 적은 커널. 시리즈와 달라도 이 커널 작업은 받습니다.
	Kernels []string `json:"kernels,omitempty"`
	// Jobs waiting for this builder's APT cooldown. Applies only to this poll.
	DeferredJobIDs []int `json:"deferred_job_ids,omitempty"`
	// CanRefresh: 이 빌드 서버는 BuildTask.Refresh(바로 수집 요청)를 처리할 수 있음. 예전 빌드 서버에는 주지 않음
	CanRefresh bool `json:"can_refresh,omitempty"`
	// CanPurge: 이 빌드 서버는 BuildTask.Purge(범위 밖 커널의 빌드 서버 자료 삭제)를 처리할 수 있음
	CanPurge bool `json:"can_purge,omitempty"`
	// BinarySHA256: 빌드 서버 실행 파일의 sha256 (컨트롤러가 가진 최신 실행 파일과 비교해 웹에 표시)
	BinarySHA256 string `json:"binary_sha256,omitempty"`
}

// BuilderUpdateRequest / Response: POST /api/builder/update — 빌드 서버 자동 업데이트 확인
type BuilderUpdateRequest struct {
	SHA256 string `json:"sha256"` // 지금 실행 중인 kpctl-builder 의 sha256
}

type BuilderUpdateResponse struct {
	Update bool   `json:"update"`           // true 면 GET /api/builder/binary 로 받아 교체
	SHA256 string `json:"sha256,omitempty"` // 받을 실행 파일의 sha256 (받은 뒤 확인용)
	Size   int64  `json:"size,omitempty"`
}

// HostKernel 은 등록된 호스트들이 지금 쓰는 커널 하나입니다.
type HostKernel struct {
	Kernel    string `json:"kernel"`              // uname -r
	Signature string `json:"signature,omitempty"` // /proc/version_signature (보고한 호스트가 있으면)
	Hosts     int    `json:"hosts"`               // 이 커널을 쓰는 호스트 수
}

type HostKernelsResponse struct {
	Kernels []HostKernel `json:"kernels"`
}

type TaskPatch struct {
	ID       string `json:"id"`
	Content  string `json:"content"`
	Filename string `json:"filename,omitempty"`
	Size     int64  `json:"size,omitempty"` // UTF-8 본문의 바이트 수
	SHA256   string `json:"sha256,omitempty"`
}

// BuildKernelInfo는 작업을 넘길 때 호스트 보고에서 확인한 기준 입력입니다.
// 빌드 서버의 로컬 경로나 도구 설정은 전달하지 않습니다.
type BuildKernelInfo struct {
	Kernel         string `json:"kernel"`
	Signature      string `json:"signature"`
	PackageVersion string `json:"package_version"`
	BaseTag        string `json:"base_tag"`
}

type BuildTask struct {
	Job        Job              `json:"job"`
	Patches    []TaskPatch      `json:"patches"` // 이 순서대로 적용
	KernelInfo *BuildKernelInfo `json:"kernel_info,omitempty"`
	// Refresh: 빌드할 작업은 없지만 관리자가 "빌드"를 눌러 바로 수집을 요청한 커널 (Job.ID 는 0)
	Refresh []string `json:"refresh,omitempty"`
	// Purge: 관리자가 웹에서 빌드 서버 자료 삭제를 요청한 범위 밖 커널
	Purge []string `json:"purge,omitempty"`
}

// BuilderInfo 는 빌드 서버가 작업을 확인하러 올 때마다 남기는 기록입니다 (웹에서 요청이 왜 안 넘어가는지 보이게).
type BuilderInfo struct {
	CanPrerelease bool              `json:"can_prerelease,omitempty"`
	Name          string            `json:"name"`
	Series        string            `json:"series,omitempty"`
	Kernels       []string          `json:"kernels,omitempty"`
	CanRefresh    bool              `json:"can_refresh"` // false 면 예전 빌드 서버 (웹의 "빌드" 요청·최신 태그 보고 못 함)
	SHA256        string            `json:"sha256,omitempty"`
	UpToDate      bool              `json:"up_to_date"` // 컨트롤러가 가진 kpctl-builder 와 같은 실행 파일인지
	Addr          string            `json:"addr,omitempty"`
	LastSeen      time.Time         `json:"last_seen"`
	LastPolledAt  time.Time         `json:"last_polled_at,omitempty"`
	HeartbeatAt   time.Time         `json:"heartbeat_at,omitempty"`
	Activity      *BuilderActivity  `json:"activity,omitempty"`
	Resources     *BuilderResources `json:"resources,omitempty"`
	Cache         *BuildCacheStats  `json:"cache,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	LogTruncated  bool              `json:"log_truncated,omitempty"`
	Maintenance   string            `json:"maintenance,omitempty"`
}

// BuilderLogLimit bounds each live log independently. Completed job logs keep
// their existing, separate storage and are never replaced by a heartbeat.
const BuilderLogLimit = 256 << 10

type BuilderActivity struct {
	Phase        string    `json:"phase"`
	Step         string    `json:"step,omitempty"`
	Kernel       string    `json:"kernel,omitempty"`
	JobID        int       `json:"job_id,omitempty"`
	Version      int       `json:"version,omitempty"`
	JobStartedAt time.Time `json:"job_started_at,omitempty"`
	Commit       string    `json:"commit,omitempty"`
	CVEs         []string  `json:"cves,omitempty"`
	Current      int       `json:"current,omitempty"`
	Total        int       `json:"total,omitempty"`
	Message      string    `json:"message,omitempty"`
	StartedAt    time.Time `json:"started_at"`
}

type BuilderResources struct {
	CPUs            int     `json:"cpus"`
	Jobs            int     `json:"jobs"`
	Load1           float64 `json:"load1"`
	MemoryTotal     uint64  `json:"memory_total"`
	MemoryAvailable uint64  `json:"memory_available"`
	DiskTotal       uint64  `json:"disk_total"`
	DiskAvailable   uint64  `json:"disk_available"`
	DiskMinimum     uint64  `json:"disk_minimum,omitempty"`
}

type BuilderHeartbeatRequest struct {
	Maintenance string `json:"maintenance,omitempty"`
	NextJobRequest
	Activity     BuilderActivity  `json:"activity"`
	Resources    BuilderResources `json:"resources"`
	Cache        *BuildCacheStats `json:"cache,omitempty"`
	Environment  string           `json:"environment"`
	Log          string           `json:"log"`
	JobLog       string           `json:"job_log,omitempty"`
	LogTruncated bool             `json:"log_truncated,omitempty"`
}

type BuildCacheStats struct {
	Enabled             bool     `json:"enabled"`
	Kernel              string   `json:"kernel"`
	Key                 string   `json:"key,omitempty"`
	Hits                int64    `json:"hits"`
	Misses              int64    `json:"misses"`
	HitRate             *float64 `json:"hit_rate"`
	BuildSeconds        float64  `json:"build_seconds"`
	BaselineSeconds     float64  `json:"baseline_seconds,omitempty"`
	VerificationSeconds float64  `json:"verification_seconds,omitempty"`
	Warning             string   `json:"warning,omitempty"`
}

type BuilderDetail struct {
	Builder *BuilderInfo `json:"builder"`
	Log     string       `json:"log"`
}

// Upstream 은 커널 하나의 Ubuntu 최신 상황입니다 (빌드 서버가 알려 줌).
type Upstream struct {
	// LatestTag: 자동 모드는 정식 APT 배포 버전에 대응하는 태그, 직접 지정 모드는 설정한 Git 범위의 최신 태그.
	LatestTag string    `json:"latest_tag,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// CollectedTag: CVE 수정을 이 태그까지 수집했음 (이 태그까지의 라이브패치 가능한 수정은 패치로 들어감)
	CollectedTag string `json:"collected_tag,omitempty"`
	// RefreshRequested*: 관리자가 "빌드"를 눌러 바로 수집을 요청함. 빌드 서버가 가져가면 지움
	RefreshRequestedAt time.Time `json:"refresh_requested_at,omitempty"`
	RefreshRequestedBy string    `json:"refresh_requested_by,omitempty"`
	RefreshTakenBy     string    `json:"refresh_taken_by,omitempty"` // 마지막으로 가져간 빌드 서버
	RefreshTakenAt     time.Time `json:"refresh_taken_at,omitempty"`
	// Problem: 빌드 서버가 이 커널을 수집·빌드할 수 없는 이유 (비어 있으면 문제 없음)
	Problem     string    `json:"problem,omitempty"`
	ProblemAt   time.Time `json:"problem_at,omitempty"`
	ProblemKind string    `json:"problem_kind,omitempty"`
	// 명시적인 복구 보고가 확인한 문제의 ProblemAt (범위 밖 전환은 복구가 아님).
	ProblemResolvedRef string        `json:"problem_resolved_ref,omitempty"`
	ProblemResolution  string        `json:"problem_resolution,omitempty"` // admin_exclusion이면 실제 복구가 아님
	ProblemFailure     *TrialFailure `json:"problem_failure,omitempty"`
	// Outside: 빌드 서버의 최근 커널 범위(max_kernels) 밖이라 자동 수집하지 않음 (비어 있으면 범위 안)
	Outside string `json:"outside,omitempty"`
	// Purge*: 관리자가 범위 밖 커널의 빌드 서버 자료(캐시·디버그 심볼·시험 기록) 삭제를 요청함. 빌드 서버가 가져가면 요청을 지움
	PurgeRequestedAt time.Time `json:"purge_requested_at,omitempty"`
	PurgeRequestedBy string    `json:"purge_requested_by,omitempty"`
	PurgeTakenBy     string    `json:"purge_taken_by,omitempty"`
	PurgedAt         time.Time `json:"purged_at,omitempty"`
	PurgeResult      string    `json:"purge_result,omitempty"`
}

// UpstreamReport 는 POST /api/builder/kernels/{kernel}/upstream 본문입니다. 빈 값은 바꾸지 않습니다.
type UpstreamReport struct {
	LatestTag    string `json:"latest_tag"`
	CollectedTag string `json:"collected_tag"`
	// Problem: nil 이면 그대로, "" 이면 문제 해결, 그 밖에는 수집·빌드할 수 없는 이유
	Problem        *string       `json:"problem,omitempty"`
	ProblemKind    string        `json:"problem_kind,omitempty"`
	ProblemFailure *TrialFailure `json:"problem_failure,omitempty"`
	// Recovered 는 실제 수집 완료·태그 확인·디스크 여유 회복을 확인한 경우에만 보냅니다.
	Recovered bool `json:"recovered,omitempty"`
	// Outside: nil 이면 그대로, "" 이면 범위 안, 그 밖에는 범위 밖 사유
	Outside *string `json:"outside,omitempty"`
	// Purged: 빌드 서버 자료 삭제 결과 (nil 이면 보고 없음)
	Purged *string `json:"purged,omitempty"`
}

type BuildResult struct {
	Success      bool       `json:"success"`
	Deferred     bool       `json:"deferred,omitempty"` // temporary archive, lock or disk failure
	Builder      string     `json:"builder,omitempty"`
	JobStartedAt *time.Time `json:"job_started_at,omitempty"` // start time from the job assignment
	Error        string     `json:"error,omitempty"`
	Log          string     `json:"log"`
	ModuleName   string     `json:"module_name,omitempty"`
	ModuleBase64 string     `json:"module_base64,omitempty"`
}

type KnownCommitsResponse struct {
	Commits       []string          `json:"commits"`
	ActivePatches []DiscoveredPatch `json:"active_patches,omitempty"` // 누적 빌드와 같은 순서의 기존 활성 패치
}

type DiscoveredPatch struct {
	Commit  string   `json:"commit"`
	CVEs    []string `json:"cves"`
	Title   string   `json:"title"`
	Content string   `json:"content"`
}

type DiscoveredRequest struct {
	Prerelease  bool              `json:"prerelease,omitempty"`
	Patches     []DiscoveredPatch `json:"patches"`
	Unpatchable []Unpatchable     `json:"unpatchable"`
	// LatestTag: 이번에 이 태그까지의 CVE 수정을 수집함 (새 빌드 작업이 "어디까지 반영"했는지 기록)
	LatestTag string `json:"latest_tag,omitempty"`
}

type DiscoveredResponse struct {
	AddedPatches int `json:"added_patches"`
	JobID        int `json:"job_id"` // 0 = 작업을 만들지 않음
}

// --- 관리자 (kpctl) ---

type SubmitPatchRequest struct {
	Title   string   `json:"title"`
	CVEs    []string `json:"cves"`
	Content string   `json:"content"`
	Urgent  bool     `json:"urgent"`
}

type SubmitPatchResponse struct {
	PatchID string `json:"patch_id"`
	JobID   int    `json:"job_id"`
	Version int    `json:"version"`
}

type BuildRequest struct {
	Urgent     bool `json:"urgent"`
	Prerelease bool `json:"prerelease,omitempty"`
}

type ApproveRequest struct {
	Prerelease bool `json:"prerelease,omitempty"`
}

type PromoteRequest struct {
	Ring            int  `json:"ring"`
	Force           bool `json:"force"`
	Prerelease      bool `json:"prerelease,omitempty"`
	ExpectedVersion *int `json:"expected_version,omitempty"`
}

type RollbackRequest struct {
	Version    int  `json:"version"`
	Prerelease bool `json:"prerelease,omitempty"`
}

type PatchStateRequest struct {
	State string `json:"state"`
}

type HostUpdateRequest struct {
	Ring         *int    `json:"ring,omitempty"`
	RebootPolicy *string `json:"reboot_policy,omitempty"`
}

type CordonRequest struct {
	On bool `json:"on"`
}

type AutoPauseRequest struct {
	Paused bool `json:"paused"`
}

type AutoHoldRequest struct {
	Hold bool `json:"hold"`
}

// AutoStatus 는 자동 배포(auto_rollout) 현황입니다.
type AutoStatus struct {
	Enabled     bool   `json:"enabled"`      // 설정에서 켰는지
	ApproveOnly bool   `json:"approve_only"` // 첫 번째 링까지만 자동
	SoakMinutes int    `json:"soak_minutes"` // 다음 링으로 넘어가기 전 최소 관찰 시간
	Paused      bool   `json:"paused"`       // 전체 일시 중지
	PausedBy    string `json:"paused_by,omitempty"`
	// Notes[커널] = 그 커널이 지금 자동으로 진행되지 않는 이유
	Notes map[string][]string `json:"notes,omitempty"`
}

type StatusResponse struct {
	Now              time.Time      `json:"now"`
	Who              string         `json:"who,omitempty"` // 이 요청을 보낸 관리자
	Rings            []int          `json:"rings"`
	HostStaleMinutes int            `json:"host_stale_minutes"`
	Auto             *AutoStatus    `json:"auto,omitempty"`
	Tracks           []*Track       `json:"tracks"`
	Jobs             []*Job         `json:"jobs"`
	Hosts            []*Host        `json:"hosts"`
	Unpatchable      []*Unpatchable `json:"unpatchable"`
	// LatestReleased[커널] = 배포(승인)된 가장 높은 버전 (호스트 "즉시 업데이트" 버튼용)
	LatestReleased map[string]int `json:"latest_released"`
	// Upstream[커널] = Ubuntu 최신 태그, 수집 상황 (호스트 "업데이트/빌드" 버튼용)
	Upstream map[string]*Upstream `json:"upstream"`
	// Builders[이름] = 최근에 작업을 확인하러 온 빌드 서버
	Builders map[string]*BuilderInfo `json:"builders"`
	// ReleasedTags[커널][버전] = 그 배포 버전이 반영한 Ubuntu 태그 ("어디까지 올라갔나" 표시용)
	ReleasedTags map[string]map[int]string `json:"released_tags"`
	Validation   *ValidationStatus         `json:"validation,omitempty"`
}

// ValidationStatus is optional evidence from an explicitly configured lab run.
// Its completion is not an assertion that all kernel CVEs are fixed.
type ValidationStatus struct {
	Phase         string             `json:"phase"`
	StartedAt     time.Time          `json:"started_at"`
	EligibleAfter time.Time          `json:"eligible_after"`
	UpdatedAt     time.Time          `json:"updated_at"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	Error         string             `json:"error,omitempty"`
	LastAction    *ValidationAction  `json:"last_action,omitempty"`
	Targets       []ValidationTarget `json:"targets,omitempty"`
}
type ValidationAction struct {
	Path  string `json:"path"`
	State string `json:"state"`
}
type ValidationTarget struct {
	Kernel       string      `json:"kernel"`
	RingVersions map[int]int `json:"ring_versions"`
}
