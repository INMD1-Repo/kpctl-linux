// kpctl-builder: 빌드 서버
//
//	kpctl-builder -config /etc/kpctl/builder.json          계속 실행 (systemd 서비스)
//	kpctl-builder -config ... -once                         자동 수집 1회 + 대기 작업 모두 빌드 후 종료
//	kpctl-builder -config ... -discover-only               자동 수집만 1회
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kpctl/internal/builder"
)

func main() {
	configPath := flag.String("config", "/etc/kpctl/builder.json", "설정 파일 경로")
	once := flag.Bool("once", false, "자동 수집 1회 + 대기 작업 모두 빌드하고 종료")
	discoverOnly := flag.Bool("discover-only", false, "자동 수집만 1회 하고 종료")
	buildRequest := flag.String("build-request", "", "격리 컨테이너 내부의 로컬 빌드 요청")
	checkConfig := flag.Bool("check-config", false, "설정·CA 읽기 검사 후 종료 (컨트롤러에 접속하지 않음)")
	flag.Parse()
	if *buildRequest != "" {
		if err := builder.RunBuildRequest(*buildRequest); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := builder.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("설정 오류: %v", err)
	}
	b, err := builder.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *checkConfig {
		log.Print("빌더 설정·CA 검사 통과")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopReporting := b.StartReporting(ctx)
	defer stopReporting()

	switch {
	case *discoverOnly:
		b.DiscoverAll()
		b.DiscoverPrereleases()
	case *once:
		b.DiscoverAll()
		b.DiscoverPrereleases()
		for b.BuildNext() {
		}
	default:
		b.Run(ctx)
		if b.RestartForUpdate {
			stopReporting()
			os.Exit(builder.ExitRestartForUpdate) // systemd 가 다시 시작하며 새 실행 파일 설치
		}
	}
}
