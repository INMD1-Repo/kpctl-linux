// 이 파일: main 패키지의 newTable, getStatus, cmdStatus 구현·자료형.
package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

// 이 파일: 화면 출력 (status, jobs, hosts)

func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func getStatus(c *client.Client) (*model.StatusResponse, error) {
	var st model.StatusResponse
	if err := c.Do("GET", "/api/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func cmdStatus(c *client.Client, args []string) error {
	for _, w := range bootWarnings("/etc/kpctl", systemctlEnabled) {
		fmt.Fprintln(os.Stderr, "!! "+w)
	}
	st, err := getStatus(c)
	if err != nil {
		return err
	}

	if st.Auto != nil && st.Auto.Enabled {
		printAuto(st)
		fmt.Println()
	}
	fmt.Println("■ 커널별 배포 버전")
	printTracks(st)

	fmt.Println("\n■ 승인 대기 / 진행 중 작업")
	n := 0
	tw := newTable()
	fmt.Fprintln(tw, "작업\t커널\t버전\t상태\t긴급\t새 패치\t")
	for _, j := range st.Jobs {
		if j.Status == model.JobQueued || j.Status == model.JobRunning || j.Status == model.JobBuilt {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t\n", j.ID, j.Kernel, model.VersionLabel(j.Version), statusKo(j.Status), yes(j.Urgent), strings.Join(j.NewPatchIDs, ","))
			n++
		}
	}
	tw.Flush()
	if n == 0 {
		fmt.Println("  (없음)")
	}

	fmt.Println("\n■ 호스트")
	printHosts(st)

	if len(st.Unpatchable) > 0 {
		fmt.Println("\n■ 미해결 CVE (관리자 제외·이전 불가 판정)")
		tw := newTable()
		fmt.Fprintln(tw, "커널\tCVE\t커밋\t상태\t제목")
		for _, u := range st.Unpatchable {
			state := "이전 불가 판정"
			if u.Decision != nil {
				state = "미해결 · 관리자 제외"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Kernel, strings.Join(u.CVEs, ","), u.Commit[:min(12, len(u.Commit))], state, cut(u.Title, 60))
		}
		tw.Flush()
	}
	return nil
}

func printTracks(st *model.StatusResponse) {
	if len(st.Tracks) == 0 {
		fmt.Println("  (아직 없음)")
		return
	}
	tw := newTable()
	header := "커널"
	for _, r := range st.Rings {
		header += fmt.Sprintf("\t링 %d", r)
	}
	fmt.Fprintln(tw, header+"\t")
	for _, t := range st.Tracks {
		line := t.Kernel
		for _, r := range st.Rings {
			v := t.TargetVersion(r)
			if v == 0 {
				line += "\t-"
			} else {
				line += "\t" + model.VersionLabel(v)
			}
		}
		fmt.Fprintln(tw, line+"\t")
	}
	tw.Flush()
}

func cmdJobs(c *client.Client, args []string) error {
	st, err := getStatus(c)
	if err != nil {
		return err
	}
	tw := newTable()
	fmt.Fprintln(tw, "작업\t커널\t버전\t상태\t긴급\t패치수\t요청\t승인\t생성\t오류")
	for _, j := range st.Jobs {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			j.ID, j.Kernel, model.VersionLabel(j.Version), statusKo(j.Status), yes(j.Urgent), len(j.PatchIDs),
			j.RequestedBy, j.ApprovedBy, j.CreatedAt.Local().Format("01-02 15:04"), cut(j.Error, 40))
	}
	return tw.Flush()
}

func cmdHosts(c *client.Client, args []string) error {
	if len(args) > 0 {
		if len(args) == 2 && args[0] == "mok-password" {
			return cmdMOKPassword(c, args[1])
		}
		return fmt.Errorf("사용법: kpctl hosts [mok-password <호스트>]")
	}
	st, err := getStatus(c)
	if err != nil {
		return err
	}
	printHosts(st)
	return nil
}

func printHosts(st *model.StatusResponse) {
	if len(st.Hosts) == 0 {
		fmt.Println("  (등록된 호스트 없음)")
		return
	}
	tracks := map[string]*model.Track{}
	for _, t := range st.Tracks {
		tracks[t.Kernel] = t
	}

	tw := newTable()
	fmt.Fprintln(tw, "호스트\tID\t링\t커널\t적용/목표\t상태\t드레인\t정책\t마지막 보고\t준비된 다음 커널\t서명 필요\t배포 자격·경고")
	excluded := 0
	for _, h := range st.Hosts {
		target := 0
		if t := tracks[h.Status.Kernel]; t != nil && !model.HWEWithGAName(h.Status) {
			target = t.TargetVersion(h.Ring)
		}
		state := hostState(h, target, st.Now)
		if model.HWEWithGAName(h.Status) && state == "정상" {
			state = "HWE 미지원"
		}
		prepared := "준비 필요"
		if h.Status.BootTarget != nil {
			prepared = h.Status.BootTarget.Kernel
		}
		required, warning := model.SignaturePolicy(h.Status.SecureBoot, h.Status.Lockdown, h.Status.SigEnforce)
		if h.Status.SignatureRequired {
			required = true
		}
		if h.Status.SecurityWarning != "" {
			warning = h.Status.SecurityWarning
		}
		eligibility := ""
		if e := h.RolloutEligibility; e != nil {
			eligibility = e.Status
			if e.KeyID != "" {
				eligibility += " (" + e.KeyID + ")"
			}
			if e.Reason != "" {
				eligibility += ": " + e.Reason
			}
			if e.Warning != "" {
				warning = e.Warning
			}
			if strings.HasPrefix(e.Status, "blocked_") {
				excluded++
			}
		}
		if warning != "" {
			eligibility += " / 경고: " + warning
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			h.Hostname, h.ID, h.Ring, h.Status.Kernel, model.VersionLabel(h.Status.Version), model.VersionLabel(target),
			state, drainState(h), h.RebootPolicy, ago(st.Now, h.LastSeen), prepared, yes(required), eligibility)
	}
	tw.Flush()
	if excluded > 0 {
		fmt.Printf("배포 제외: %d대 (사유는 배포 자격·경고 열 참조)\n", excluded)
	}
}

// hostState 는 호스트 상태를 한 단어로 요약합니다.
func hostState(h *model.Host, target int, now time.Time) string {
	switch {
	case now.Sub(h.LastSeen) > 10*time.Minute:
		return "연락끊김"
	case h.Status.Error != "":
		return "오류: " + cut(h.Status.Error, 40)
	case h.Status.Version != target:
		return "적용대기"
	}
	for _, lp := range h.Status.Loaded {
		if lp.Transition {
			return "전환중"
		}
	}
	return "정상"
}

func drainState(h *model.Host) string {
	if !h.Cordoned {
		return "-"
	}
	s := "cordon"
	switch {
	case h.VMCount < 0:
		s += ", VM ?"
	case h.VMCount == 0:
		s += ", VM 0 (재부팅 가능)"
	default:
		s += fmt.Sprintf(", VM %d", h.VMCount)
	}
	if h.RebootRequestID != 0 {
		s += ", 재부팅 승인됨"
	}
	return s
}

// ── 작은 도우미 ──

func statusKo(s string) string {
	switch s {
	case model.JobQueued:
		return "대기"
	case model.JobRunning:
		return "빌드중"
	case model.JobBuilt:
		return "승인대기"
	case model.JobFailed:
		return "실패"
	case model.JobReleased:
		return "배포됨"
	case model.JobSuperseded:
		return "폐기"
	}
	return s
}

func yes(b bool) string {
	if b {
		return "예"
	}
	return ""
}

func cut(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d초 전", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d분 전", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d시간 전", int(d.Hours()))
	}
}
