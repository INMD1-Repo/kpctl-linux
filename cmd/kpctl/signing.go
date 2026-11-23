// 이 파일: 공개 서명 키 현황, 인증서 등록 예약, 감사되는 호스트별 MOK 비밀번호 조회.
package main

import (
	"fmt"
	"net/url"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

const signingUsage = `사용법:
  kpctl signing list                    키·인증서 만료일·등록 호스트 수
  kpctl signing rollout-cert <키ID>      호스트별 MOK 등록 예약 (재부팅 없음)
  kpctl hosts mok-password <호스트>      다음 계획된 재부팅의 콘솔 승인 비밀번호 조회`

func cmdSigning(c *client.Client, args []string) error {
	switch {
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
	case len(args) == 2 && args[0] == "rollout-cert":
		var result struct {
			ScheduledHosts int      `json:"scheduled_hosts"`
			Warnings       []string `json:"warnings"`
		}
		if err := c.Do("POST", "/api/signing/"+url.PathEscape(args[1])+"/rollout-cert", nil, &result); err != nil {
			return err
		}
		fmt.Printf("MOK 인증서 %s 등록 예약: %d대. 재부팅은 수행하지 않습니다.\n", args[1], result.ScheduledHosts)
		fmt.Println("다음 계획된 재부팅 때 콘솔에서 승인하세요. 비밀번호: kpctl hosts mok-password <호스트>")
		for _, warning := range result.Warnings {
			fmt.Println("경고:", warning)
		}
		return nil
	default:
		return fmt.Errorf("%s", signingUsage)
	}
}

func cmdMOKPassword(c *client.Client, target string) error {
	id, name, err := resolveHost(c, target)
	if err != nil {
		return err
	}
	var result struct {
		KeyID    string `json:"key_id"`
		Password string `json:"password"`
		Status   string `json:"status"`
		Warning  string `json:"warning"`
	}
	if err := c.Do("GET", "/api/hosts/"+url.PathEscape(id)+"/mok-password", nil, &result); err != nil {
		return err
	}
	fmt.Printf("%s (%s), 키 %s\nMOK 콘솔 승인 비밀번호: %s\n", name, id, result.KeyID, result.Password)
	if result.Status != "" {
		fmt.Println("등록 예약 상태:", result.Status)
	}
	if result.Warning != "" {
		fmt.Println("안내:", result.Warning)
	}
	fmt.Println("이 조회는 감사 로그에 기록됩니다. 다음 계획된 재부팅의 콘솔 승인에만 사용하세요.")
	return nil
}
