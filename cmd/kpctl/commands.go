// 이 파일: main 패키지의 cmdLog, cmdApprove, cmdSubmit 구현·자료형.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

// ── 패치·작업 ──

func cmdLog(c *client.Client, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("사용법: kpctl log <작업번호>")
	}
	var text string
	if err := c.Do("GET", "/api/jobs/"+args[0]+"/log", nil, &text); err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

func cmdApprove(c *client.Client, args []string) error {
	var positional []string
	prerelease := false
	for _, arg := range args {
		if arg == "--prerelease" || arg == "-prerelease" {
			prerelease = true
		} else {
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 || strings.HasPrefix(positional[0], "-") {
		return fmt.Errorf("사용법: kpctl approve <작업번호> [--prerelease]")
	}
	var resp struct {
		Kernel  string `json:"kernel"`
		Version int    `json:"version"`
		Ring    int    `json:"ring"`
	}
	if err := c.Do("POST", "/api/jobs/"+positional[0]+"/approve", model.ApproveRequest{Prerelease: prerelease}, &resp); err != nil {
		return err
	}
	fmt.Printf("승인 완료: %s %s → 링 %d 배포 시작\n", resp.Kernel, model.VersionLabel(resp.Version), resp.Ring)
	fmt.Println("에이전트가 다음 보고 주기에 적용합니다. kpctl hosts 로 확인하세요.")
	return nil
}

func cmdSubmit(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "대상 커널 (uname -r)")
	urgent := fs.Bool("urgent", false, "긴급: 대기 중인 다른 빌드보다 먼저")
	cves := fs.String("cve", "", "CVE 번호 (쉼표로 여러 개)")
	title := fs.String("title", "", "설명")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kernel == "" || fs.NArg() != 1 {
		return fmt.Errorf("사용법: kpctl submit -kernel K [-urgent] [-cve CVE-..] [-title ..] <파일.patch>")
	}
	content, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	req := model.SubmitPatchRequest{Title: *title, Content: string(content), Urgent: *urgent}
	if *cves != "" {
		req.CVEs = strings.Split(*cves, ",")
	}
	var resp model.SubmitPatchResponse
	if err := c.Do("POST", "/api/kernels/"+*kernel+"/patches", req, &resp); err != nil {
		return err
	}
	fmt.Printf("제출 완료: 패치 %s → 빌드 작업 %d (v%d)\n", resp.PatchID, resp.JobID, resp.Version)
	fmt.Printf("빌드가 끝나면 kpctl approve %d\n", resp.JobID)
	return nil
}

func cmdBuild(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "대상 커널")
	urgent := fs.Bool("urgent", false, "긴급")
	prerelease := fs.Bool("prerelease", false, "출시 전 후보와 정식 활성 패치의 누적본을 별도 빌드")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kernel == "" {
		return fmt.Errorf("사용법: kpctl build -kernel K [-urgent] [--prerelease]")
	}
	var job model.Job
	if err := c.Do("POST", "/api/kernels/"+*kernel+"/build", model.BuildRequest{Urgent: *urgent, Prerelease: *prerelease}, &job); err != nil {
		return err
	}
	fmt.Printf("빌드 작업 %d (%s) 생성, 패치 %d개\n", job.ID, model.VersionLabel(job.Version), len(job.PatchIDs))
	return nil
}

func cmdPatches(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("patches", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "대상 커널")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kernel == "" {
		return fmt.Errorf("사용법: kpctl patches -kernel K")
	}
	var patches []model.Patch
	if err := c.Do("GET", "/api/kernels/"+*kernel+"/patches", nil, &patches); err != nil {
		return err
	}
	tw := newTable()
	fmt.Fprintln(tw, "ID\t상태\t출처\tCVE\t제목\t비고")
	for _, p := range patches {
		src := p.Source
		if p.Prerelease {
			src += " (출시 전)"
		}
		if p.Commit != "" {
			src += " " + p.Commit[:min(12, len(p.Commit))]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.State, src, strings.Join(p.CVEs, ","), cut(p.Title, 50), p.Reason)
	}
	return tw.Flush()
}

func cmdPatch(c *client.Client, args []string) error {
	if len(args) != 2 || (args[0] != "enable" && args[0] != "disable") {
		return fmt.Errorf("사용법: kpctl patch enable|disable <패치ID>")
	}
	state := model.PatchActive
	if args[0] == "disable" {
		state = model.PatchDisabled
	}
	if err := c.Do("POST", "/api/patches/"+args[1]+"/state", model.PatchStateRequest{State: state}, nil); err != nil {
		return err
	}
	fmt.Printf("패치 %s → %s. 반영하려면 kpctl build -kernel <커널>\n", args[1], state)
	return nil
}

// ── 배포 ──

func cmdPromote(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "대상 커널")
	ring := fs.Int("ring", -1, "배포할 링")
	force := fs.Bool("force", false, "건강 검사를 무시하고 진행")
	prerelease := fs.Bool("prerelease", false, "명시 승인된 출시 전 누적본의 수동 승급")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kernel == "" || *ring < 0 {
		return fmt.Errorf("사용법: kpctl promote -kernel K -ring N [-force]")
	}
	var resp struct {
		Version       int                  `json:"version"`
		ExcludedCount int                  `json:"excluded_count"`
		ExcludedHosts []model.ExcludedHost `json:"excluded_hosts"`
	}
	if err := c.Do("POST", "/api/kernels/"+*kernel+"/promote", model.PromoteRequest{Ring: *ring, Force: *force, Prerelease: *prerelease}, &resp); err != nil {
		return err
	}
	fmt.Printf("링 %d 에 %s 배포 시작\n", *ring, model.VersionLabel(resp.Version))
	if resp.ExcludedCount > 0 || len(resp.ExcludedHosts) > 0 {
		fmt.Printf("배포 제외: %d대\n", max(resp.ExcludedCount, len(resp.ExcludedHosts)))
		for _, host := range resp.ExcludedHosts {
			fmt.Printf("  %s (%s): %s\n", host.Hostname, host.ID, host.Reason)
		}
	}
	return nil
}

func cmdRollback(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "대상 커널")
	version := fs.Int("version", -1, "되돌릴 버전 (0 = 패치 전부 내림)")
	prerelease := fs.Bool("prerelease", false, "출시 전 전용 번호로 롤백 (예: --prerelease -version 2)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kernel == "" || *version < 0 {
		return fmt.Errorf("사용법: kpctl rollback -kernel K -version N [--prerelease]")
	}
	if *prerelease && *version == 0 {
		return fmt.Errorf("출시 전 롤백 번호는 1 이상이어야 합니다")
	}
	target := *version
	if *prerelease {
		target = -target
	}
	if err := c.Do("POST", "/api/kernels/"+*kernel+"/rollback", model.RollbackRequest{Version: target, Prerelease: *prerelease}, nil); err != nil {
		return err
	}
	if *version == 0 {
		fmt.Println("모든 링: 패치를 전부 내리도록 지시했습니다")
	} else {
		fmt.Printf("모든 링: %s 로 되돌리도록 지시했습니다\n", model.VersionLabel(target))
	}
	return nil
}

// ── 호스트 ──

const hostUsage = `사용법:
  kpctl host set <호스트> [-ring N] [-policy drain|never]
  kpctl host cordon <호스트>      신규 VM 배치 차단 (드레인 시작)
  kpctl host uncordon <호스트>    배치 차단 해제
  kpctl host prepare-kernel <호스트> [-cancel]   커널 점프 1단계: 다음 공식 GA 커널 디스크 설치 요청 (재부팅 안 함)
  kpctl host reboot <호스트> -kernel <새-GA-커널>  준비된 커널로 5분 내 1회 재부팅 승인
  kpctl host cancel-reboot <호스트>             실행 전 승인 취소
  kpctl host delete <호스트>      등록 삭제
<호스트> 자리에는 호스트 ID(h-...) 또는 호스트 이름을 쓸 수 있습니다.`

func cmdHost(c *client.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("%s", hostUsage)
	}
	action, target, rest := args[0], args[1], args[2:]
	id, name, err := resolveHost(c, target)
	if err != nil {
		return err
	}

	switch action {
	case "set":
		fs := flag.NewFlagSet("host set", flag.ContinueOnError)
		ring := fs.Int("ring", -1, "링")
		policy := fs.String("policy", "", "재부팅 정책 drain|never")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		var req model.HostUpdateRequest
		if *ring >= 0 {
			req.Ring = ring
		}
		if *policy != "" {
			req.RebootPolicy = policy
		}
		if req.Ring == nil && req.RebootPolicy == nil {
			return fmt.Errorf("-ring 또는 -policy 중 하나는 있어야 합니다")
		}
		if err := c.Do("POST", "/api/hosts/"+id, req, nil); err != nil {
			return err
		}
		fmt.Printf("%s 설정 변경 완료\n", name)

	case "cordon", "uncordon":
		on := action == "cordon"
		if err := c.Do("POST", "/api/hosts/"+id+"/cordon", model.CordonRequest{On: on}, nil); err != nil {
			return err
		}
		if on {
			fmt.Printf("%s: 신규 VM 배치를 막았습니다. VM 이 모두 빠지면 kpctl hosts 에 'VM 0' 으로 보입니다.\n", name)
		} else {
			fmt.Printf("%s: 배치 차단을 풀었습니다.\n", name)
		}

	case "reboot":
		fs := flag.NewFlagSet("host reboot", flag.ContinueOnError)
		kernel := fs.String("kernel", "", "승인할 새 GA 커널 (필수)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *kernel == "" {
			return fmt.Errorf("-kernel 에 승인할 새 GA 커널을 지정하세요 (준비: 호스트에서 sudo kpctl-prepare-kernel)")
		}
		var status model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &status); err != nil {
			return err
		}
		var targetID string
		for _, h := range status.Hosts {
			if h.ID == id && h.Status.BootTarget != nil && h.Status.BootTarget.Kernel == *kernel {
				targetID = h.Status.BootTarget.ID
			}
		}
		if targetID == "" {
			return fmt.Errorf("%s 에 %s 커널의 검증된 준비 기록이 없습니다", name, *kernel)
		}
		var resp struct {
			RebootID int `json:"reboot_id"`
		}
		if err := c.Do("POST", "/api/hosts/"+id+"/reboot", model.RebootRequest{TargetID: targetID}, &resp); err != nil {
			return err
		}
		fmt.Printf("%s → %s 재부팅 승인 (요청 #%d, 유효시간 5분, 1회).\n", name, *kernel, resp.RebootID)
	case "prepare-kernel":
		fs := flag.NewFlagSet("host prepare-kernel", flag.ContinueOnError)
		cancel := fs.Bool("cancel", false, "요청 취소")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		var resp struct {
			Message string `json:"message"`
		}
		if err := c.Do("POST", "/api/hosts/"+id+"/prepare-kernel", model.PrepareKernelBody{Cancel: *cancel}, &resp); err != nil {
			return err
		}
		fmt.Println(resp.Message)
	case "cancel-reboot":
		if err := c.Do("POST", "/api/hosts/"+id+"/reboot", model.RebootRequest{Cancel: true}, nil); err != nil {
			return err
		}
		fmt.Printf("%s 재부팅 승인을 취소했습니다.\n", name)

	case "delete":
		if err := c.Do("DELETE", "/api/hosts/"+id, nil, nil); err != nil {
			return err
		}
		fmt.Printf("%s 등록을 삭제했습니다\n", name)

	default:
		return fmt.Errorf("%s", hostUsage)
	}
	return nil
}

// resolveHost 는 호스트 ID 또는 이름으로 호스트를 찾습니다.
func resolveHost(c *client.Client, target string) (id, name string, err error) {
	var st model.StatusResponse
	if err := c.Do("GET", "/api/status", nil, &st); err != nil {
		return "", "", err
	}
	for _, h := range st.Hosts {
		if h.ID == target || h.Hostname == target {
			return h.ID, h.Hostname, nil
		}
	}
	return "", "", fmt.Errorf("호스트 %q 를 찾지 못했습니다 (kpctl hosts 로 확인)", target)
}

// ── 자동 배포 ──

const autoUsage = `사용법:
  kpctl auto                  자동 배포 현황
  kpctl auto pause            전체 일시 중지
  kpctl auto resume           전체 재개
  kpctl auto hold <커널>       커널 하나 멈춤
  kpctl auto clear <커널>      멈춘 커널 재개 (롤백, 호스트 오류 뒤 원인을 확인했을 때)`

func cmdAuto(c *client.Client, args []string) error {
	action := ""
	if len(args) > 0 {
		action = args[0]
	}
	switch {
	case action == "" && len(args) == 0:
		st, err := getStatus(c)
		if err != nil {
			return err
		}
		printAuto(st)
		return nil
	case (action == "pause" || action == "resume") && len(args) == 1:
		if err := c.Do("POST", "/api/auto", model.AutoPauseRequest{Paused: action == "pause"}, nil); err != nil {
			return err
		}
		fmt.Println("자동 배포:", map[string]string{"pause": "일시 중지", "resume": "재개"}[action])
		return nil
	case (action == "hold" || action == "clear") && len(args) == 2:
		if err := c.Do("POST", "/api/kernels/"+args[1]+"/auto", model.AutoHoldRequest{Hold: action == "hold"}, nil); err != nil {
			return err
		}
		fmt.Printf("%s: 자동 배포 %s\n", args[1], map[string]string{"hold": "멈춤", "clear": "재개"}[action])
		return nil
	}
	return fmt.Errorf("%s", autoUsage)
}

func printAuto(st *model.StatusResponse) {
	a := st.Auto
	switch {
	case a == nil || !a.Enabled:
		fmt.Println("자동 배포: 꺼짐 (controller.json 의 auto_rollout.enabled)")
		return
	case a.Paused:
		fmt.Printf("자동 배포: 일시 중지 (%s)\n", a.PausedBy)
	case a.ApproveOnly:
		fmt.Printf("자동 배포: 켜짐, 첫 번째 링까지만\n")
	default:
		fmt.Printf("자동 배포: 켜짐, 링 사이 관찰 %d분\n", a.SoakMinutes)
	}
	for _, t := range st.Tracks {
		for _, n := range a.Notes[t.Kernel] {
			fmt.Printf("  %s: %s\n", t.Kernel, n)
		}
	}
}
