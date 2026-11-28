// 이 파일: 웹 화면에서 바꿀 수 있는 운영 설정
//
// controller.json 은 root 소유라 컨트롤러(kpctl 사용자)가 고칠 수 없습니다.
// 그래서 웹에서 바꾼 값은 data_dir/settings.json 에 저장하고, 시작할 때 controller.json 위에 덮어씁니다.
// (settings.json 을 지우고 재시작하면 controller.json 값으로 돌아갑니다)
//
//	GET  /api/settings   지금 값 + controller.json 값
//	POST /api/settings   바꾸기 (바꿀 항목만 보내면 됨)
package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kpctl/internal/model"
)

// Settings 는 실행 중에 바꿀 수 있는 설정입니다.
type Settings struct {
	AutoEnabled       bool        `json:"auto_enabled"`              // 자동 배포
	AutoApproveOnly   bool        `json:"auto_approve_only"`         // 첫 번째 링까지만 자동
	AutoSoakMinutes   int         `json:"auto_soak_minutes"`         // 자동 승급 전 관찰 시간
	NativeAutoPin     bool        `json:"native_auto_pin,omitempty"` // 네이티브 빌더 자동 수집·승인 핀 등록
	MinSoakMinutes    map[int]int `json:"min_soak_minutes"`          // 링별 최소 관찰 시간 (수동 promote 에도 적용)
	HostStaleMinutes  int         `json:"host_stale_minutes"`        // 이 시간 넘게 보고가 없으면 연락 끊김
	JobTimeoutMinutes int         `json:"job_timeout_minutes"`       // 빌드가 이 시간 넘으면 다시 대기열로
}

// SettingsUpdate 는 POST /api/settings 본문입니다. 비운(null) 항목은 바꾸지 않습니다.
type SettingsUpdate struct {
	AutoEnabled       *bool       `json:"auto_enabled"`
	AutoApproveOnly   *bool       `json:"auto_approve_only"`
	AutoSoakMinutes   *int        `json:"auto_soak_minutes"`
	NativeAutoPin     *bool       `json:"native_auto_pin"`
	MinSoakMinutes    map[int]int `json:"min_soak_minutes"`
	HostStaleMinutes  *int        `json:"host_stale_minutes"`
	JobTimeoutMinutes *int        `json:"job_timeout_minutes"`
}

type SettingsResponse struct {
	Signing model.SigningStatus `json:"signing"` // 공개 키 현황만 포함; 파일 경로·서명 명령은 제외
	Current Settings            `json:"current"`
	File    Settings            `json:"file"` // controller.json 값 (웹에서 바꾸기 전)
	Rings   []int               `json:"rings"`
}

func settingsFromConfig(c *Config) Settings {
	m := map[int]int{}
	for k, v := range c.MinSoakMinutes {
		m[k] = v
	}
	out := Settings{
		AutoEnabled: c.AutoRollout.Enabled, AutoApproveOnly: c.AutoRollout.ApproveOnly, AutoSoakMinutes: c.AutoRollout.soak(),
		NativeAutoPin:  c.NativeAutoPin,
		MinSoakMinutes: m, HostStaleMinutes: c.HostStaleMinutes, JobTimeoutMinutes: c.JobTimeoutMinutes,
	}
	// LoadConfig 를 거치지 않은 설정(테스트 등)에도 같은 기본값
	if out.HostStaleMinutes == 0 {
		out.HostStaleMinutes = 10
	}
	if out.JobTimeoutMinutes == 0 {
		out.JobTimeoutMinutes = 180
	}
	return out
}

func (s Settings) clone() Settings {
	m := make(map[int]int, len(s.MinSoakMinutes))
	for k, v := range s.MinSoakMinutes {
		m[k] = v
	}
	s.MinSoakMinutes = m
	return s
}

func (s Settings) validate(rings []int) error {
	if s.AutoSoakMinutes < 0 {
		return fmt.Errorf("자동 승급 관찰 시간은 0 이상이어야 합니다")
	}
	if s.HostStaleMinutes < 1 {
		return fmt.Errorf("연락 끊김 기준은 1분 이상이어야 합니다")
	}
	if s.JobTimeoutMinutes < 10 {
		return fmt.Errorf("빌드 제한 시간은 10분 이상이어야 합니다")
	}
	for r, v := range s.MinSoakMinutes {
		found := false
		for _, x := range rings {
			found = found || x == r
		}
		if !found {
			return fmt.Errorf("링 %d 은 설정(rings)에 없습니다", r)
		}
		if v < 0 {
			return fmt.Errorf("링 %d 관찰 시간은 0 이상이어야 합니다", r)
		}
	}
	return nil
}

func (s *Server) settingsFile() string { return filepath.Join(s.cfg.DataDir, "settings.json") }

// loadSettings 는 controller.json 값에 settings.json 을 덮어씁니다. NewServer 가 부릅니다.
func (s *Server) loadSettings() error {
	cur := settingsFromConfig(s.cfg)
	data, err := os.ReadFile(s.settingsFile())
	if os.IsNotExist(err) {
		s.set = cur
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &cur); err != nil {
		return fmt.Errorf("%s 해석 실패 (지우면 controller.json 값으로 돌아갑니다): %w", s.settingsFile(), err)
	}
	if cur.MinSoakMinutes == nil {
		cur.MinSoakMinutes = map[int]int{}
	}
	if err := cur.validate(s.cfg.Rings); err != nil {
		return fmt.Errorf("%s: %w", s.settingsFile(), err)
	}
	s.set = cur
	return nil
}

// settings 는 지금 설정의 사본입니다. 어디서 불러도 안전합니다 (store 잠금과 별개).
func (s *Server) settings() Settings {
	s.setMu.RLock()
	defer s.setMu.RUnlock()
	return s.set.clone()
}

// GET /api/settings
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, who string) {
	writeJSON(w, http.StatusOK, SettingsResponse{Current: s.settings(), File: settingsFromConfig(s.cfg), Rings: s.cfg.Rings, Signing: s.signingStatus()})
}

// POST /api/settings
func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request, who string) {
	var req SettingsUpdate
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	s.rolloutSettingsMu.Lock()
	s.setMu.Lock()
	unlock := func() {
		s.setMu.Unlock()
		s.rolloutSettingsMu.Unlock()
	}
	next := s.set.clone()
	var changes []string
	note := func(name string, old, now any) {
		if fmt.Sprint(old) != fmt.Sprint(now) {
			changes = append(changes, fmt.Sprintf("%s %v→%v", name, old, now))
		}
	}
	if req.AutoEnabled != nil {
		note("자동배포", next.AutoEnabled, *req.AutoEnabled)
		next.AutoEnabled = *req.AutoEnabled
	}
	if req.AutoApproveOnly != nil {
		note("첫링까지만", next.AutoApproveOnly, *req.AutoApproveOnly)
		next.AutoApproveOnly = *req.AutoApproveOnly
	}
	if req.AutoSoakMinutes != nil {
		note("자동관찰분", next.AutoSoakMinutes, *req.AutoSoakMinutes)
		next.AutoSoakMinutes = *req.AutoSoakMinutes
	}
	if req.NativeAutoPin != nil {
		note("네이티브자동핀", next.NativeAutoPin, *req.NativeAutoPin)
		next.NativeAutoPin = *req.NativeAutoPin
	}
	if req.HostStaleMinutes != nil {
		note("연락끊김분", next.HostStaleMinutes, *req.HostStaleMinutes)
		next.HostStaleMinutes = *req.HostStaleMinutes
	}
	if req.JobTimeoutMinutes != nil {
		note("빌드제한분", next.JobTimeoutMinutes, *req.JobTimeoutMinutes)
		next.JobTimeoutMinutes = *req.JobTimeoutMinutes
	}
	rings := make([]int, 0, len(req.MinSoakMinutes))
	for r := range req.MinSoakMinutes {
		rings = append(rings, r)
	}
	sort.Ints(rings)
	for _, ring := range rings {
		note(fmt.Sprintf("링%d관찰분", ring), next.MinSoakMinutes[ring], req.MinSoakMinutes[ring])
		next.MinSoakMinutes[ring] = req.MinSoakMinutes[ring]
	}
	if err := next.validate(s.cfg.Rings); err != nil {
		unlock()
		writeErr(w, fail(http.StatusBadRequest, "%v", err))
		return
	}
	data, _ := json.MarshalIndent(next, "", "  ")
	tmp := s.settingsFile() + ".tmp"
	err := os.WriteFile(tmp, append(data, '\n'), 0o640)
	if err == nil {
		err = os.Rename(tmp, s.settingsFile())
	}
	if err != nil {
		unlock()
		writeErr(w, fmt.Errorf("설정 저장 실패: %w", err))
		return
	}
	s.set = next
	unlock()

	if len(changes) > 0 {
		s.audit(who, "설정 변경: %s", strings.Join(changes, ", "))
	}
	writeJSON(w, http.StatusOK, SettingsResponse{Current: next.clone(), File: settingsFromConfig(s.cfg), Rings: s.cfg.Rings, Signing: s.signingStatus()})
}
