// 이 파일: 현재 Go 선언으로 Markdown 코드 지도를 출력하는 개발 도구.
package main

import (
	"flag"
	"fmt"
	"os"

	"kpctl/internal/docscheck"
)

func main() {
	root := flag.String("root", ".", "저장소 루트")
	flag.Parse()
	body, err := docscheck.GenerateCodeMap(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(body)
}
