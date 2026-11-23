// 이 파일: builder 패키지의 changeGroupEnds, extendMacroChanges, unbalancedQuotes 구현·자료형.
package builder

import (
	"regexp"
	"strconv"
	"strings"
)

// klp-build 의 줄 번호 보정과 여러 줄 매크로
//
// klp-build 는 패치를 적용하기 전에 scripts/livepatch/fix-patch-lines 로 "변경된 줄 묶음 바로 뒤"에
// `#line N` 을 끼워 넣습니다 (뒤쪽 함수의 __LINE__ 이 바뀌어 불필요하게 달라 보이지 않게 하려는 것).
// 그런데 변경이 `\` 로 이어지는 여러 줄 매크로 한가운데서 끝나면 `#line` 이 매크로 본문 안에 들어가
// 헤더가 깨집니다. 빌드 환경과 상관없이 패치 모양만으로 항상 재현됩니다.
//
//	#define rxrpc_skb_traces \
//		EM(rxrpc_skb_put_response,      "PUT response ") \
//	+	EM(rxrpc_skb_put_response_copy, "PUT resp-cpy ") \
//	+#line 192                                             ← 매크로 안: "stray '#' in program"
//		EM(rxrpc_skb_put_rotate,        "PUT rotate   ") \
//
// 커널 소스는 기준 태그와 한 글자도 달라지면 안 되므로(integrity.go) 도구를 고치지 않고, 도구에 넘기는
// 누적 diff 쪽을 맞춥니다: 변경 묶음이 매크로 중간에서 끝나면 그 매크로의 마지막 줄까지 공백만 바꿔
// 묶음을 늘립니다. 그러면 `#line` 이 매크로가 끝난 다음 줄에 들어갑니다. 바꾸는 것은 줄 끝 `\` 앞의
// 공백과 마지막 줄의 들여쓰기뿐이라 전처리 결과는 같습니다.

var hunkHeaderRe = regexp.MustCompile(`(?m)^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// changeGroupEnds 는 `git diff -U0` 출력에서 변경 묶음마다 "새 파일 기준 마지막 줄 번호"를 돌려줍니다.
// 삭제만 있는 묶음은 삭제 지점 바로 앞 줄입니다. fix-patch-lines 는 이 줄 바로 뒤에 #line 을 넣습니다.
func changeGroupEnds(diffU0 string) []int {
	var ends []int
	for _, m := range hunkHeaderRe.FindAllStringSubmatch(diffU0, -1) {
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		if count == 0 {
			ends = append(ends, start)
		} else {
			ends = append(ends, start+count-1)
		}
	}
	return ends
}

// extendMacroChanges 는 ends(변경 묶음의 마지막 줄, 1부터)가 `\` 로 이어지는 줄이면 그 매크로의 끝까지
// 공백만 바꾼 내용을 돌려줍니다. 바꾼 것이 없으면 changed=false.
// 안전하게 바꿀 수 없는 모양(문자열이 줄을 넘어 이어짐)이면 ok=false 로 원문을 그대로 돌려줍니다.
func extendMacroChanges(content string, ends []int) (out string, changed, ok bool) {
	ls := strings.Split(content, "\n")
	continued := func(i int) bool { // i: 0부터
		return i >= 0 && i < len(ls) && strings.HasSuffix(strings.TrimRight(ls[i], " \t\r"), `\`)
	}
	touched := map[int]bool{}
	for _, end := range ends {
		i := end - 1
		if !continued(i) {
			continue
		}
		// i 다음 줄부터, `\` 로 끝나지 않는 첫 줄(매크로의 마지막 줄)까지
		for j := i + 1; j < len(ls); j++ {
			last := !continued(j)
			if !touched[j] {
				touched[j] = true
				if last {
					switch {
					case strings.HasPrefix(ls[j], "\t"), strings.HasPrefix(ls[j], " "):
						ls[j] = ls[j][:1] + ls[j]
					default:
						ls[j] = " " + ls[j]
					}
				} else {
					if unbalancedQuotes(ls[j]) {
						return content, false, false
					}
					body := strings.TrimRight(ls[j], " \t\r")
					ls[j] = strings.TrimSuffix(body, `\`) + ` \`
					if ls[j] == body { // 이미 같은 모양이면 공백을 하나 더
						ls[j] = strings.TrimSuffix(body, `\`) + `  \`
					}
				}
				changed = true
			}
			if last {
				break
			}
		}
	}
	return strings.Join(ls, "\n"), changed, true
}

// unbalancedQuotes 는 문자열 리터럴이 이 줄에서 닫히지 않는지 봅니다 (줄 끝 공백을 바꾸면 내용이 달라짐).
func unbalancedQuotes(line string) bool {
	in := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if in {
				i++
			}
		case '"':
			in = !in
		case '\'':
			if !in && i+2 < len(line) { // 문자 상수 '"' 는 건너뜀
				if line[i+1] == '\\' && i+3 < len(line) {
					i += 3
				} else {
					i += 2
				}
			}
		}
	}
	return in
}
