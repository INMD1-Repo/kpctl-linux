// kpctl-controller: 라이브패치 컨트롤러
//
//	kpctl-controller -config /etc/kpctl/controller.json
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kpctl/internal/controller"
)

func main() {
	configPath := flag.String("config", "/etc/kpctl/controller.json", "설정 파일 경로")
	flag.Parse()

	cfg, err := controller.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("설정 오류: %v", err)
	}
	srv, err := controller.NewServer(cfg)
	if err != nil {
		log.Fatalf("시작 실패: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
