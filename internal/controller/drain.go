// 이 파일: controller 패키지의 drainLoop, checkDrain 구현·자료형.
package controller

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

// drainLoop 는 cordon 된 호스트의 VM 수를 주기적으로 스케줄러에 물어봅니다.
// VM 이 0 대가 되면 kpctl status 에 "재부팅 가능"으로 보이고, kpctl host reboot 로 승인할 수 있습니다.
func (s *Server) drainLoop(ctx context.Context) {
	if len(s.cfg.Scheduler.VMCountCommand) == 0 {
		log.Printf("scheduler.vm_count_command 가 비어 있어 드레인 확인을 하지 않습니다")
		return
	}
	ticker := time.NewTicker(time.Duration(s.cfg.DrainCheckSeconds) * time.Second)
	defer ticker.Stop()
	for {
		s.checkDrain()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkDrain 은 cordon 된 호스트마다 vm_count_command 를 실행해 VM 수를 기록합니다.
// 명령 출력은 숫자 하나여야 합니다 (예: "3").
func (s *Server) checkDrain() {
	if len(s.cfg.Scheduler.VMCountCommand) == 0 {
		return
	}
	type target struct{ id, hostname string }
	var targets []target
	s.store.View(func(st *State) {
		for _, h := range st.Hosts {
			if h.Cordoned {
				targets = append(targets, target{h.ID, h.Hostname})
			}
		}
	})

	for _, t := range targets {
		count := -1
		out, err := runCommand(s.cfg.Scheduler.VMCountCommand, map[string]string{"host": t.hostname}, time.Minute)
		if err == nil {
			count, err = strconv.Atoi(strings.TrimSpace(out))
			if err != nil {
				count = -1
			}
		}
		if err != nil {
			log.Printf("%s VM 수 확인 실패: %v (출력: %q)", t.hostname, err, strings.TrimSpace(out))
		}
		_ = s.store.Update(func(st *State) error {
			if h := st.Hosts[t.id]; h != nil && h.Cordoned {
				h.VMCount = count
				h.VMCountCheckedAt = time.Now()
			}
			return nil
		})
	}
}
