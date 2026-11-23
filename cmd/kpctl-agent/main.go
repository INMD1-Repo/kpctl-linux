// kpctl-agent: 호스트 에이전트
//
//	kpctl-agent -config /etc/kpctl/agent.json         계속 실행 (systemd 서비스)
//	kpctl-agent -config /etc/kpctl/agent.json -once   한 주기만 실행하고 종료 (설치 확인용)
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kpctl/internal/agent"
)

func main() {
	configPath := flag.String("config", "/etc/kpctl/agent.json", "설정 파일 경로")
	once := flag.Bool("once", false, "한 주기만 실행하고 종료")
	flag.Parse()

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("설정 오류: %v", err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *once {
		if err := a.RunOnce(); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.Run(ctx)
}
