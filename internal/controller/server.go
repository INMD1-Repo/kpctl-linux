// Package controller 는 kpatch 라이브패치 컨트롤러입니다.
//
// 파일 안내 (무엇을 고치려면 어디를 보면 되는지):
//
//	config.go          설정 파일 구조와 기본값
//	state.go           저장되는 상태(state.json)와 조회 도우미
//	server.go          ← 지금 파일. API 주소 목록(routes)과 인증
//	jobs.go            빌드 작업 만들기 (누적 패치 버전 매기기)
//	handlers_admin.go  kpctl 이 부르는 관리자 API (승인, promote, 롤백, 호스트 관리)
//	handlers_builder.go 빌드 서버가 부르는 API
//	handlers_agent.go  호스트 에이전트가 부르는 API
//	rollout.go         "이 호스트는 어떤 버전이어야 하나", promote 전 건강 검사
//	drain.go           cordon 된 호스트의 VM 수를 주기적으로 확인
//	auto.go            자동 배포: 사람 승인 없이 승인·승급 (기본 꺼짐)
//	web.go, web/       관리자 웹 화면 (컨트롤러에 내장)
//	util.go            공통 도우미
package controller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kpctl/internal/testvm"
)

type Server struct {
	signingWarningMu   sync.Mutex
	signingWarnings    map[string]string
	signingCertSHA256  map[string]string // 시작 때 고정한 인증서 ID별 해시; 이후 읽기 전용
	cfg                *Config
	store              *Store
	mux                *http.ServeMux
	approveMu          sync.Mutex     // 승인(서명)은 한 번에 하나씩
	rolloutSettingsMu  sync.Mutex     // 자동 배포 커밋과 웹 설정 변경을 직렬화
	rebootMu           sync.Mutex     // drain/승인/실행 전달을 직렬화
	background         sync.WaitGroup // 요청 뒤 따로 도는 확인(cordon 직후 VM 수 확인 등). 시험이 끝나기 전에 기다립니다.
	auditMu            sync.Mutex
	coverageMu         sync.Mutex
	coverage           *coverageCache
	kernelInputsMu     sync.Mutex // 큰 입력 패키지의 중복 다운로드와 캐시 쓰기를 직렬화
	kernelInputsClient *http.Client
	testVM             *testvm.Manager
	testVMCtx          context.Context
	testVMCancel       context.CancelFunc

	setMu sync.RWMutex // 웹에서 바꿀 수 있는 설정 (settings.go)
	set   Settings
}

func NewServer(cfg *Config) (*Server, error) {
	if err := cfg.validateSigning(); err != nil {
		return nil, err
	}
	for _, d := range []string{"", "patches", "artifacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(cfg.DataDir, d), 0o750); err != nil {
			return nil, err
		}
	}
	store, err := OpenStore(filepath.Join(cfg.DataDir, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("상태 파일 열기 실패: %w", err)
	}
	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	if err := s.loadSettings(); err != nil {
		return nil, err
	}
	if err := s.reviewUnpatchable(); err != nil {
		return nil, fmt.Errorf("과거 시험 빌드 판정 재검토 실패: %w", err)
	}
	if err := s.initSigning(); err != nil {
		return nil, err
	}
	if err := s.initTestVM(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// routes 는 API 주소 목록입니다. 새 API 를 추가하려면 여기에 한 줄 넣으세요.
func (s *Server) routes() {
	m := s.mux

	// 관리자 (kpctl)
	m.HandleFunc("GET /api/status", s.admin(s.handleStatus))
	m.HandleFunc("GET /api/signing", s.admin(s.handleSigningList))
	m.HandleFunc("POST /api/signing/{id}/rollout-cert", s.admin(s.handleRolloutCert))
	m.HandleFunc("POST /api/signing/{id}/hosts/{host}/rollout-cert", s.admin(s.handleRolloutCert))
	m.HandleFunc("GET /api/hosts/{id}/mok-password", s.admin(s.handleMOKPassword))
	m.HandleFunc("GET /api/builders/{name}", s.admin(s.handleBuilderDetail))
	m.HandleFunc("GET /api/coverage", s.admin(s.handleCoverage))
	m.HandleFunc("GET /api/kernels/{kernel}/patches", s.admin(s.handleListPatches))
	m.HandleFunc("POST /api/kernels/{kernel}/patches", s.admin(s.handleSubmitPatch))
	m.HandleFunc("POST /api/kernels/{kernel}/build", s.admin(s.handleBuild))
	m.HandleFunc("POST /api/kernels/{kernel}/promote", s.admin(s.handlePromote))
	m.HandleFunc("POST /api/kernels/{kernel}/rollback", s.admin(s.handleRollback))
	m.HandleFunc("POST /api/patches/{id}/state", s.admin(s.handlePatchState))
	m.HandleFunc("POST /api/jobs/{id}/approve", s.admin(s.handleApprove))
	m.HandleFunc("GET /api/jobs/{id}/log", s.admin(s.handleJobLog))
	m.HandleFunc("POST /api/hosts/{id}", s.admin(s.handleHostUpdate))
	m.HandleFunc("DELETE /api/hosts/{id}", s.admin(s.handleHostDelete))
	m.HandleFunc("POST /api/hosts/{id}/cordon", s.admin(s.handleHostCordon))
	m.HandleFunc("POST /api/hosts/{id}/reboot", s.admin(s.handleHostReboot))
	m.HandleFunc("POST /api/hosts/{id}/update-now", s.admin(s.handleHostUpdateNow))
	m.HandleFunc("POST /api/hosts/{id}/prepare-kernel", s.admin(s.handleHostPrepareKernel))
	m.HandleFunc("POST /api/kernels/{kernel}/refresh", s.admin(s.handleKernelRefresh))
	m.HandleFunc("POST /api/kernels/{kernel}/purge", s.admin(s.handleKernelPurge))
	m.HandleFunc("GET /api/settings", s.admin(s.handleGetSettings))
	m.HandleFunc("POST /api/settings", s.admin(s.handleSetSettings))
	m.HandleFunc("GET /api/patches/{id}/diff", s.admin(s.handlePatchDiff))
	m.HandleFunc("GET /api/audit", s.admin(s.handleAudit))
	m.HandleFunc("POST /api/auto", s.admin(s.handleAutoPause))
	m.HandleFunc("POST /api/distribution-proofs/base", s.admin(s.handleInstallBaseProof))
	m.HandleFunc("POST /api/kernels/{kernel}/auto", s.admin(s.handleAutoHold))
	m.HandleFunc("POST /api/kernels/{kernel}/commits/{commit}/exclude", s.admin(s.handleExcludeCommit))
	m.HandleFunc("DELETE /api/kernels/{kernel}/commits/{commit}/exclude", s.admin(s.handleCancelExcludeCommit))

	// 관리자 웹 화면 (화면 자체에는 비밀이 없고, 데이터는 위 API 를 토큰으로 부릅니다)
	m.HandleFunc("GET /{$}", s.handleWeb)
	m.HandleFunc("GET /ui/{file}", s.handleWeb)

	// 빌드 서버
	m.HandleFunc("POST /api/builder/next", s.builder(s.handleBuilderNext))
	m.HandleFunc("POST /api/builder/heartbeat", s.builder(s.handleBuilderHeartbeat))
	m.HandleFunc("POST /api/builder/jobs/{id}/result", s.builder(s.handleBuilderResult))
	m.HandleFunc("GET /api/builder/kernels", s.builder(s.handleHostKernels))
	m.HandleFunc("GET /api/builder/kernels/{kernel}/known", s.builder(s.handleKnownCommits))
	m.HandleFunc("POST /api/builder/kernels/{kernel}/discovered", s.builder(s.handleDiscovered))
	m.HandleFunc("POST /api/builder/kernels/{kernel}/upstream", s.builder(s.handleUpstream))
	m.HandleFunc("POST /api/builder/update", s.builder(s.handleBuilderUpdate))
	m.HandleFunc("GET /api/builder/binary", s.builder(s.handleBuilderBinary))
	m.HandleFunc("GET /api/builder/kernel-inputs/{kernel}/{version}/{arch}/{file}", s.builder(s.handleKernelInput))

	// 호스트 에이전트
	m.HandleFunc("POST /api/agent/register", s.handleRegister) // 등록 토큰은 본문으로 받음
	m.HandleFunc("GET /api/bootstrap/agent.tar.gz", s.handleBootstrapBundle)
	m.HandleFunc("POST /api/agent/report", s.agent(s.handleReport))
	m.HandleFunc("POST /api/agent/reboot/claim", s.agent(s.handleRebootClaim))
	m.HandleFunc("GET /artifacts/{kernel}/{file}", s.agentOrAdmin(s.handleArtifact))

	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
}

// ── 인증 ──
// 모든 요청은 "Authorization: Bearer <토큰>" 헤더로 인증합니다.

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// admin 은 관리자 토큰을 확인하고, 관리자 이름(who)을 핸들러에 넘깁니다.
func (s *Server) admin(h func(w http.ResponseWriter, r *http.Request, who string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who := s.adminName(bearer(r))
		if who == "" {
			writeErr(w, fail(http.StatusUnauthorized, "관리자 토큰이 필요합니다"))
			return
		}
		h(w, r, who)
	}
}

func (s *Server) adminName(token string) string {
	if token == "" {
		return ""
	}
	for name, t := range s.cfg.AdminTokens {
		if sameSecret(t, token) {
			return name
		}
	}
	return ""
}

func (s *Server) builder(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameSecret(s.cfg.BuilderToken, bearer(r)) {
			writeErr(w, fail(http.StatusUnauthorized, "빌드 서버 토큰이 필요합니다"))
			return
		}
		h(w, r)
	}
}

// agent 는 호스트 토큰을 확인하고 호스트 ID 를 핸들러에 넘깁니다.
func (s *Server) agent(h func(w http.ResponseWriter, r *http.Request, hostID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := s.hostIDByToken(bearer(r))
		if id == "" {
			writeErr(w, fail(http.StatusUnauthorized, "호스트 토큰이 필요합니다 (등록이 지워졌다면 에이전트 상태 파일을 지우고 다시 등록하세요)"))
			return
		}
		h(w, r, id)
	}
}

func (s *Server) agentOrAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if s.adminName(tok) == "" && s.hostIDByToken(tok) == "" {
			writeErr(w, fail(http.StatusUnauthorized, "인증이 필요합니다"))
			return
		}
		h(w, r)
	}
}

func (s *Server) hostIDByToken(token string) string {
	if token == "" {
		return ""
	}
	want := hashToken(token)
	id := ""
	s.store.View(func(st *State) {
		for _, h := range st.Hosts {
			if sameSecret(h.TokenHash, want) {
				id = h.ID
			}
		}
	})
	return id
}

// ── 파일 경로 ──

func (s *Server) patchFile(id string) string {
	return filepath.Join(s.cfg.DataDir, "patches", id+".patch")
}

func (s *Server) artifactFile(kernel, module string) string {
	return filepath.Join(s.cfg.DataDir, "artifacts", kernel, module+".ko")
}

func (s *Server) logFile(jobID int) string {
	return filepath.Join(s.cfg.DataDir, "logs", fmt.Sprintf("job-%d.log", jobID))
}

// ── 감사 로그 ──

// audit 은 누가 무엇을 했는지 data_dir/audit.log 에 한 줄씩 남깁니다.
func (s *Server) audit(who, format string, args ...any) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	line := fmt.Sprintf("%s\t%s\t%s\n", time.Now().Format(time.RFC3339), who, fmt.Sprintf(format, args...))
	log.Print("[감사] " + strings.TrimSpace(line))
	f, err := os.OpenFile(filepath.Join(s.cfg.DataDir, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("감사 로그 기록 실패: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// ── 실행 ──

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) Run(ctx context.Context) error {
	defer func() {
		s.testVMCancel()
		// ListenAndServe returns before Shutdown has waited for handlers.
		// Let the in-flight approval finish VM log collection and destruction.
		s.approveMu.Lock()
		s.approveMu.Unlock()
	}()
	go s.drainLoop(ctx)
	go s.autoLoop(ctx)

	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		s.testVMCancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	var err error
	if s.cfg.TLSCert != "" {
		log.Printf("컨트롤러 시작 (HTTPS) %s", s.cfg.Listen)
		err = srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	} else {
		log.Printf("경고: TLS 가 설정되지 않았습니다. 테스트 외에는 tls_cert/tls_key 를 설정하세요.")
		log.Printf("컨트롤러 시작 (HTTP) %s", s.cfg.Listen)
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
