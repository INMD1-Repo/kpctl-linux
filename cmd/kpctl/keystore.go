// 이 파일: 관리자가 준 SSH 키 저장소 (kpctl ssh-key add | list | remove)
//
// 호스트에 이미 관리자 키(예: 서버를 만들 때 넣어 둔 키)가 들어 있다면, 그 개인키를 컨트롤러에 저장해 두면
// 컨트롤러 키를 따로 등록하지 않아도 kpctl install 과 자동 등록(autoenroll)이 그 키로 접속해 설치합니다.
//
//	저장 위치: /etc/kpctl/ssh/keys/<이름>      (KPCTL_SSH_KEY_DIR 로 바꿀 수 있음)
//	          /etc/kpctl/ssh/keys/<이름>.pub  (지문 확인용)
//	          /etc/kpctl/ssh/keys/<이름>.user (이 키로 접속할 계정. 없으면 KPCTL_SSH_USER)
//
// 무인으로 쓰므로 암호(passphrase)가 없는 키만 받습니다.
// 접속 순서: 컨트롤러 키(KPCTL_SSH_USER) → 저장한 키(계정별로 묶어 이름 순). 처음 로그인되는 조합으로 설치합니다 (pickLogin).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"kpctl/internal/remote"
)

const keyStoreUsage = `사용법:
  kpctl ssh-key add [-name 이름] [-user 계정] <개인키 파일>...   관리자가 준 키를 컨트롤러에 저장
  kpctl ssh-key add [-user 계정] -home                          내 ~/.ssh 폴더의 개인키를 모두 저장
  kpctl ssh-key list                               저장한 키 목록 (지문)
  kpctl ssh-key remove <이름>...                    저장한 키 삭제

  저장한 키는 kpctl install, kpctl autoenroll 이 컨트롤러 키 다음으로 차례로 시도합니다.
  -user 는 그 키가 들어 있는 호스트 계정입니다 (예: root, ubuntu). 비우면 KPCTL_SSH_USER.
  -role builder 는 빌드 서버 전용 키로 표시합니다. 빌드 서버 키는 install-builder 만 쓰고,
  클라이언트 자동 설치(autoenroll)·에이전트 설치(install)에는 쓰지 않습니다 (빌드 서버에 에이전트가 깔리지 않도록).
  이미 저장한 키의 용도만 바꾸려면 같은 파일로 다시 add -role builder|client 하세요.
  root 가 아닌 계정이면 그 계정에 비밀번호 없는 sudo(NOPASSWD)가 있어야 설치할 수 있습니다.
  이미 저장한 키의 계정만 바꾸려면 같은 파일로 다시 add -user ... 하세요.
  암호가 걸린 키는 무인 설치에 쓸 수 없어 받지 않습니다.

옵션:`

// keyStoreDir 은 관리자 키를 저장하는 디렉터리입니다.
func keyStoreDir() string {
	if d := os.Getenv("KPCTL_SSH_KEY_DIR"); d != "" {
		return d
	}
	return "/etc/kpctl/ssh/keys"
}

// storedKeys 는 저장된 개인키 경로를 이름 순서로 돌려줍니다. 디렉터리가 없거나 읽을 수 없으면 빈 목록입니다.
func storedKeys() []string {
	entries, err := os.ReadDir(keyStoreDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && !strings.HasSuffix(n, ".pub") && !strings.HasSuffix(n, ".user") && !strings.HasSuffix(n, ".role") && !strings.HasPrefix(n, ".") {
			out = append(out, filepath.Join(keyStoreDir(), n))
		}
	}
	sort.Strings(out)
	return out
}

func cmdKeyStore(action string, args []string) error {
	fs := flag.NewFlagSet("ssh-key "+action, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, keyStoreUsage); fs.PrintDefaults() }
	name := fs.String("name", "", "저장할 이름 (파일 하나일 때만. 기본: 파일 이름)")
	loginUser := fs.String("user", "", "이 키로 접속할 호스트 계정 (예: root, ubuntu. 비우면 KPCTL_SSH_USER)")
	role := fs.String("role", "", "키 용도: client (클라이언트 설치용) | builder (빌드 서버 전용). 비우면 바꾸지 않음 (새 키는 client)")
	home := fs.Bool("home", false, "내 ~/.ssh 폴더의 개인키를 모두 저장 (sudo 로 실행하면 sudo 를 부른 사용자의 ~/.ssh)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch action {
	case "list":
		return keyStoreList()
	case "remove":
		return keyStoreRemove(fs.Args())
	}

	files := fs.Args()
	if *home {
		found, dir, err := homeKeys()
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return fmt.Errorf("%s 에 개인키가 없습니다", dir)
		}
		fmt.Printf("%s 에서 개인키 %d개를 찾았습니다\n", dir, len(found))
		files = append(files, found...)
	}
	if len(files) == 0 {
		return fmt.Errorf("저장할 개인키 파일을 주세요 (또는 -home). 자세히: kpctl ssh-key add -h")
	}
	if *loginUser != "" && !userRe.MatchString(*loginUser) {
		return fmt.Errorf("계정 이름이 이상합니다: %q", *loginUser)
	}
	if *role != "" && *role != keyRoleClient && *role != keyRoleBuilder {
		return fmt.Errorf("-role 은 client 또는 builder 입니다: %q", *role)
	}
	if *name != "" && len(files) != 1 {
		return fmt.Errorf("-name 은 파일 하나에만 쓸 수 있습니다")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("root 권한이 필요합니다 (sudo kpctl ssh-key add ...)")
	}
	if err := os.MkdirAll(keyStoreDir(), 0o700); err != nil {
		return err
	}

	failed := 0
	for _, f := range files {
		n := *name
		if n == "" {
			n = filepath.Base(f)
		}
		if err := keyStoreAdd(f, n, *loginUser, *role); err != nil {
			fmt.Printf("[%s] 건너뜀: %v\n", f, err)
			failed++
		}
	}
	if keys := storedKeys(); len(keys) > 4 {
		fmt.Printf("주의: 저장한 키가 %d개입니다. sshd 는 보통 접속 한 번에 키 6개까지만 받으므로 쓰지 않는 키는 지우세요.\n", len(keys))
	}
	if failed > 0 {
		return fmt.Errorf("%d개 중 %d개를 저장하지 못했습니다", len(files), failed)
	}
	return nil
}

var (
	keyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	userRe    = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)
)

// keyUser 는 저장한 키의 접속 계정입니다. 정하지 않았으면 "".
func keyUser(keyPath string) string {
	data, err := os.ReadFile(keyPath + ".user")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// setKeyUser 는 접속 계정을 기록합니다. user 가 "" 이면 바꾸지 않습니다.
func setKeyUser(keyPath, user string) error {
	if user == "" {
		return nil
	}
	return writeFileAtomic(keyPath+".user", []byte(user+"\n"), 0o644)
}

// 저장한 키의 용도 (<키>.role). 파일이 없으면 client.
const (
	keyRoleClient  = "client"
	keyRoleBuilder = "builder"
)

// keyRole 은 저장한 키의 용도입니다 (client | builder).
func keyRole(keyPath string) string {
	data, err := os.ReadFile(keyPath + ".role")
	if err == nil && strings.TrimSpace(string(data)) == keyRoleBuilder {
		return keyRoleBuilder
	}
	return keyRoleClient
}

// setKeyRole 은 용도를 기록합니다. role 이 "" 이면 바꾸지 않습니다.
func setKeyRole(keyPath, role string) error {
	switch role {
	case "":
		return nil
	case keyRoleBuilder:
		return writeFileAtomic(keyPath+".role", []byte(role+"\n"), 0o644)
	default:
		if err := os.Remove(keyPath + ".role"); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
}

// clientKeys 는 저장한 키 중 클라이언트 설치에 쓸 키입니다 (빌드 서버 전용 키 제외).
func clientKeys() []string {
	var out []string
	for _, k := range storedKeys() {
		if keyRole(k) != keyRoleBuilder {
			out = append(out, k)
		}
	}
	return out
}

func roleDesc(keyPath string) string {
	if keyRole(keyPath) == keyRoleBuilder {
		return "빌드 서버"
	}
	return "클라이언트"
}

// keyStoreAdd 는 개인키 하나를 검사해서 저장소에 복사합니다. user 는 접속 계정 ("" 이면 KPCTL_SSH_USER), role 은 용도 ("" 이면 그대로).
func keyStoreAdd(src, name, user, role string) error {
	name = strings.TrimSuffix(name, ".pub")
	if !keyNameRe.MatchString(name) {
		return fmt.Errorf("이름은 영문, 숫자, . _ - 만 됩니다: %q", name)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if !looksLikePrivateKey(data) {
		return fmt.Errorf("개인키 파일이 아닙니다 (공개키 .pub 가 아니라 개인키를 주세요)")
	}
	pub, err := publicKeyOf(src)
	if err != nil {
		return err
	}

	dst := filepath.Join(keyStoreDir(), name)
	if old, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(old, data) {
			if err := setKeyUser(dst, user); err != nil {
				return err
			}
			if err := setKeyRole(dst, role); err != nil {
				return err
			}
			fmt.Printf("[%s] 이미 저장됨: %s  계정 %s  용도 %s\n", src, name, showUser(keyUser(dst)), roleDesc(dst))
			return nil
		}
		return fmt.Errorf("같은 이름(%s)의 다른 키가 이미 있습니다. -name 으로 다른 이름을 주거나 먼저 remove 하세요", name)
	}
	for _, k := range append([]string{os.Getenv("KPCTL_SSH_KEY")}, storedKeys()...) {
		if k == "" {
			continue
		}
		if old, err := os.ReadFile(k); err == nil && bytes.Equal(old, data) {
			if k != os.Getenv("KPCTL_SSH_KEY") {
				if err := setKeyUser(k, user); err != nil {
					return err
				}
				if err := setKeyRole(k, role); err != nil {
					return err
				}
			}
			fmt.Printf("[%s] 이미 저장됨: %s\n", src, k)
			return nil
		}
	}

	if err := writeFileAtomic(dst, data, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(dst+".pub", []byte(pub+"\n"), 0o644); err != nil {
		return err
	}
	if err := setKeyUser(dst, user); err != nil {
		return err
	}
	if err := setKeyRole(dst, role); err != nil {
		return err
	}
	fmt.Printf("[%s] 저장: %s  %s  계정 %s  용도 %s\n", src, dst, fingerprint(dst+".pub"), showUser(user), roleDesc(dst))
	return nil
}

func keyStoreList() error {
	tw := newTable()
	fmt.Fprintln(tw, "이름\t용도\t접속 계정\t지문\t파일")
	if k := os.Getenv("KPCTL_SSH_KEY"); k != "" {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", "(컨트롤러 키)", "클라이언트", showUser(""), fingerprint(k+".pub"), k)
	}
	keys := storedKeys()
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", filepath.Base(k), roleDesc(k), showUser(keyUser(k)), fingerprint(k+".pub"), k)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(keys) == 0 {
		if _, err := os.ReadDir(keyStoreDir()); os.IsPermission(err) {
			return fmt.Errorf("%s 를 읽을 권한이 없습니다 (sudo kpctl ssh-key list)", keyStoreDir())
		}
		fmt.Println("(저장한 관리자 키 없음. kpctl ssh-key add <개인키> 로 저장)")
	}
	return nil
}

func keyStoreRemove(names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("사용법: kpctl ssh-key remove <이름>...  (이름은 kpctl ssh-key list 로 확인)")
	}
	for _, n := range names {
		if !keyNameRe.MatchString(n) {
			return fmt.Errorf("이름이 이상합니다: %q", n)
		}
		p := filepath.Join(keyStoreDir(), n)
		if err := os.Remove(p); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s 라는 저장된 키가 없습니다 (kpctl ssh-key list 로 확인)", n)
			}
			return err
		}
		_ = os.Remove(p + ".pub")
		_ = os.Remove(p + ".user")
		_ = os.Remove(p + ".role")
		fmt.Printf("삭제: %s\n", n)
	}
	return nil
}

// homeKeys 는 ~/.ssh 의 개인키 파일을 찾습니다. sudo 로 실행했으면 sudo 를 부른 사용자의 홈을 봅니다.
func homeKeys() ([]string, string, error) {
	home, err := os.UserHomeDir()
	if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
		if u, e := user.Lookup(su); e == nil {
			home, err = u.HomeDir, nil
		}
	}
	if err != nil {
		return nil, "", err
	}
	dir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, dir, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || strings.HasSuffix(n, ".pub") || strings.HasPrefix(n, "known_hosts") ||
			n == "authorized_keys" || n == "config" {
			continue
		}
		p := filepath.Join(dir, n)
		if data, err := os.ReadFile(p); err == nil && looksLikePrivateKey(data) {
			out = append(out, p)
		}
	}
	return out, dir, nil
}

// looksLikePrivateKey 는 PEM 머리글로 개인키인지 봅니다 (OpenSSH, RSA, EC 등).
func looksLikePrivateKey(data []byte) bool {
	head := string(data)
	if len(head) > 100 {
		head = head[:100]
	}
	return strings.Contains(head, "-----BEGIN ") && strings.Contains(head, "PRIVATE KEY-----")
}

// publicKeyOf 는 개인키에서 공개키를 뽑습니다. 암호가 걸린 키는 빈 암호로 열리지 않아 실패합니다.
func publicKeyOf(path string) (string, error) {
	out, err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", path).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(msg), "passphrase") || strings.Contains(msg, "incorrect") {
			return "", fmt.Errorf("암호(passphrase)가 걸린 키라 무인 설치에 쓸 수 없습니다")
		}
		return "", fmt.Errorf("키를 읽지 못했습니다: %s", msg)
	}
	return strings.TrimSpace(string(out)), nil
}

func fingerprint(pubFile string) string {
	out, err := exec.Command("ssh-keygen", "-l", "-f", pubFile).Output()
	if err != nil {
		return "-"
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return "-"
	}
	return f[1]
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp") // 점으로 시작: storedKeys 가 무시
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// showUser 는 접속 계정을 보여 줄 문자열입니다 ("" → KPCTL_SSH_USER 값).
func showUser(u string) string {
	if u != "" {
		return u
	}
	if d := os.Getenv("KPCTL_SSH_USER"); d != "" {
		return d + " (기본)"
	}
	return "(ssh 기본)"
}

// ── 접속 조합 고르기 ──

// loginCandidates 는 시도할 (계정, 키) 조합입니다.
// 첫째는 base 그대로(컨트롤러 키 + KPCTL_SSH_USER), 다음은 컨트롤러 키 + ssh-key copy 가 기억한 계정,
// 그 다음은 저장한 키를 계정별로 묶은 것입니다.
// 같은 계정의 키는 한 번의 접속에서 ssh 가 차례로 시도하므로 하나로 묶습니다.
func loginCandidates(base *remote.SSH, keys []string) []remote.SSH {
	out := []remote.SSH{*base}
	// ssh-key copy <계정> 으로 컨트롤러 키를 다른 계정에도 넣었으면 그 계정도 시도
	for _, u := range rememberedUsers(base.KeyFile) {
		if u != base.User {
			c := *base
			c.User = u
			out = append(out, c)
		}
	}
	byUser := map[string][]string{}
	var order []string
	for _, k := range keys {
		u := keyUser(k)
		if u == "" {
			u = base.User
		}
		if _, ok := byUser[u]; !ok {
			order = append(order, u)
		}
		byUser[u] = append(byUser[u], k)
	}
	for _, u := range order {
		c := *base
		c.User = u
		c.KeyFile = byUser[u][0]
		c.ExtraKeys = byUser[u][1:]
		out = append(out, c)
	}
	return out
}

// pickLogin 은 host 에 로그인되는 (계정, 키) 조합을 찾습니다.
// 로그인되면 그 설정을 돌려주고, 안 되면 가장 의미 있는 실패(호스트 키 오류 > 키 없음 > 접속 안 됨)를 돌려줍니다.
func pickLogin(base *remote.SSH, host string) (*remote.SSH, keyState, string) {
	return pickLoginWith(base, host, storedKeys())
}

// pickClientLogin 은 클라이언트 키(컨트롤러 키 + 빌드 서버 전용이 아닌 저장 키)로만 로그인해 봅니다.
// 에이전트 자동 설치 조건: "등록한 클라이언트 키로 들어가지는 호스트".
func pickClientLogin(base *remote.SSH, host string) (*remote.SSH, keyState, string) {
	return pickLoginWith(base, host, clientKeys())
}

func pickLoginWith(base *remote.SSH, host string, keys []string) (*remote.SSH, keyState, string) {
	worst, detail := keyUnreachable, ""
	rank := map[keyState]int{keyUnreachable: 0, keyMissing: 1, keyError: 2}
	for i, c := range loginCandidates(base, keys) {
		c := c
		state, d := probeKey(&c, host)
		if state == keyOK {
			return &c, keyOK, ""
		}
		if state == keyUnreachable && i == 0 {
			return nil, state, d // 접속 자체가 안 되면 다른 키를 시도해도 같음
		}
		if detail == "" || rank[state] > rank[worst] {
			worst, detail = state, d
		}
	}
	return nil, worst, detail
}

// loginDesc 는 로그에 남길 "계정 / 키" 설명입니다.
func loginDesc(s *remote.SSH) string {
	u := s.User
	if u == "" {
		u = "(ssh 기본)"
	}
	keys := s.Keys()
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = filepath.Base(k)
	}
	return u + " / " + strings.Join(names, ",")
}
