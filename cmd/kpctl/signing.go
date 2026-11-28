// 이 파일: 공개 서명 키 현황, 인증서 등록 예약, 감사되는 호스트별 MOK 비밀번호 조회.
package main

import (
	"flag"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

const signingUsage = `사용법:
  kpctl signing init-key [-dir 디렉터리] <키ID>   컨트롤러에서 서비스 계정으로 모듈 서명 키 생성
  kpctl signing list                    키·인증서 만료일·등록 호스트 수
  kpctl signing rollout-cert [-host 호스트 [-replace-request 기존요청ID]] <키ID>      호스트별 MOK 등록 예약 (재부팅 없음)
  kpctl hosts mok-status <호스트>        최신 보고의 키별 등록 상태·예약 결과
  kpctl hosts mok-password <호스트>      다음 계획된 재부팅의 콘솔 승인 비밀번호 조회`

func cmdSigning(c *client.Client, args []string) error {
	switch {
	case len(args) > 0 && args[0] == "init-key":
		return initSigningKey(args[1:])
	case len(args) == 1 && args[0] == "list":
		var status model.SigningStatus
		if err := c.Do("GET", "/api/signing", nil, &status); err != nil {
			return err
		}
		fmt.Printf("서명 모드: %s\n", status.Mode)
		tw := newTable()
		fmt.Fprintln(tw, "키 ID\t활성\t인증서 만료일\t등록 호스트 수\t경고")
		for _, key := range status.Keys {
			expires := "미확인"
			if key.ExpiresAt != nil {
				expires = key.ExpiresAt.Local().Format("2006-01-02")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", key.ID, yes(key.Active), expires, key.EnrolledHosts, key.Warning)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		for _, warning := range status.Warnings {
			fmt.Println("경고:", warning)
		}
		return nil
	case len(args) > 0 && args[0] == "rollout-cert":
		return cmdRolloutCert(c, args[1:])
	default:
		return fmt.Errorf("%s", signingUsage)
	}
}

func cmdRolloutCert(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rollout-cert", flag.ContinueOnError)
	host := fs.String("host", "", "등록된 호스트 ID 또는 정확한 이름")
	replace := fs.String("replace-request", "", "빈 MokNew 확인 후 교체할 기존 요청 ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if fs.NArg() != 1 || !model.ValidSigningKeyID(id) {
		return fmt.Errorf("%s", signingUsage)
	}
	var invalid bool
	fs.Visit(func(f *flag.Flag) {
		value := f.Value.String()
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "/\\\r\n\t") || value == "." || value == ".." {
			invalid = true
		}
	})
	if invalid || *replace != "" && *host == "" {
		return fmt.Errorf("%s", signingUsage)
	}
	path := "/api/signing/" + url.PathEscape(id)
	if *host == "" {
		fmt.Println("이 컨트롤러에 등록된 전체 호스트에 적용됩니다. 첫 시험은 -host로 canary 한 대를 지정하세요.")
	} else {
		fmt.Printf("MOK 예약 대상: %s 한 대\n", *host)
		path += "/hosts/" + url.PathEscape(*host)
	}
	path += "/rollout-cert"
	if *replace != "" {
		path += "?replace_request=" + url.QueryEscape(*replace)
	}
	var result struct {
		ScheduledHosts int      `json:"scheduled_hosts"`
		Warnings       []string `json:"warnings"`
	}
	if err := c.Do("POST", path, nil, &result); err != nil {
		return err
	}
	if result.ScheduledHosts > 0 {
		fmt.Printf("MOK 인증서 %s 등록 예약: %d대. 재부팅은 수행하지 않습니다.\n", id, result.ScheduledHosts)
		fmt.Println("새로 예약된 호스트의 에이전트 결과를 확인한 뒤 다음 계획된 재부팅 때 콘솔에서 승인하세요. 비밀번호: kpctl hosts mok-password <호스트>")
	} else {
		fmt.Println("새로 예약된 호스트가 없습니다.")
	}
	for _, warning := range result.Warnings {
		fmt.Println("경고:", warning)
	}
	return nil
}

func cmdMOKStatus(c *client.Client, target string) error {
	st, err := getStatus(c)
	if err != nil {
		return err
	}
	for _, h := range st.Hosts {
		if h.ID != target && h.Hostname != target {
			continue
		}
		fmt.Printf("%s (%s) 마지막 보고 %s\n", h.Hostname, h.ID, h.LastSeen.Format(time.RFC3339))
		pending, empty := "미보고/확인 불가", "미보고/확인 불가"
		if h.Status.MOKPending {
			pending, empty = "true", "false (대기 보고)"
		} else if h.Status.MOKListEmpty {
			pending, empty = "false", "true"
		}
		fmt.Printf("Secure Boot: %s  mok_pending: %s\n", h.Status.SecureBoot, pending)
		ids := make([]string, 0, len(h.Status.EnrolledCerts))
		for id := range h.Status.EnrolledCerts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if len(ids) == 0 {
			fmt.Println("키별 등록 상태 미보고 (unknown)")
		}
		for _, id := range ids {
			fmt.Printf("%s: %s\n", id, h.Status.EnrolledCerts[id])
		}
		if r := h.Status.MOKImport; r != nil {
			fmt.Printf("마지막 예약 결과 (%s): %s %s\n", r.KeyID, r.Status, r.Detail)
		}
		if r := h.MOKRequest; r != nil {
			fmt.Printf("컨트롤러 요청 ID: %s  키: %s  상태: %s\n", r.ID, r.KeyID, r.Status)
		}
		fmt.Printf("MokNew 빈 목록 확인: %s\n", empty)
		if h.Status.SecurityWarning != "" {
			fmt.Println("경고:", h.Status.SecurityWarning)
		}
		return nil
	}
	return fmt.Errorf("호스트 %q 를 찾지 못했습니다 (kpctl hosts 로 확인)", target)
}

func cmdMOKPassword(c *client.Client, target string) error {
	id, name, err := resolveHost(c, target)
	if err != nil {
		return err
	}
	var result struct {
		KeyID             string `json:"key_id"`
		Password          string `json:"password"`
		CandidatePassword string `json:"candidate_password"`
		Status            string `json:"status"`
		Warning           string `json:"warning"`
	}
	if err := c.Do("GET", "/api/hosts/"+url.PathEscape(id)+"/mok-password", nil, &result); err != nil {
		return err
	}
	fmt.Printf("%s (%s), 키 %s\n", name, id, result.KeyID)
	if result.Status != "" {
		fmt.Println("등록 예약 상태:", result.Status)
	}
	if result.Warning != "" {
		fmt.Println("안내:", result.Warning)
	}
	if result.CandidatePassword != "" && (result.Status == "pending_uncertain" || result.Status == "failed") {
		fmt.Println("출처 미확인 MOK 후보 비밀번호:", result.CandidatePassword)
	}
	if result.Password != "" && result.Status == "pending" && !strings.HasPrefix(result.Warning, "기존 MOK 예약 감지") {
		fmt.Println("이 요청에 저장된 MOK 비밀번호:", result.Password)
	}
	fmt.Println("이 조회는 감사 로그에 기록됩니다. 다음 계획된 재부팅의 콘솔 승인에만 사용하세요.")
	return nil
}
