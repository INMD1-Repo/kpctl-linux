// 이 파일: 현재 문서 검사 CLI. 운영 바이너리 묶음에는 포함하지 않습니다.
package main

import (
	"flag"
	"fmt"
	"os"

	"kpctl/internal/docscheck"
)

func main() {
	root := flag.String("root", ".", "검사할 저장소 루트")
	flag.Parse()
	summary, err := docscheck.Check(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("문서 %d개 · 설정 블록 %d개 · 설정 파일 %d개 · CLI 참조 %d개 · 상대 링크 %d개 · 보존 이력 %d개 검증 통과\n", summary.Documents, summary.ConfigExamples, summary.ConfigFiles, summary.CLIReferences, summary.RelativeLinks, summary.Archives)
}
