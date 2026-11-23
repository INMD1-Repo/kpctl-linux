// Package dhcp 는 컨트롤러 관리망 DHCP 서버(dnsmasq)의 파일 두 개를 다룹니다.
//
//	임대 파일   /var/lib/kpctl/dnsmasq.leases   dnsmasq 가 씀, 여기서는 읽기만
//	예약 파일   /etc/kpctl/dhcp-hosts           고정 IP 예약. kpctl dhcp reserve 가 고침
//
// 예약 파일을 고친 뒤 Reload 로 dnsmasq 에 SIGHUP 을 보내면 재시작 없이 다시 읽습니다.
package dhcp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────
// 임대 (dnsmasq 가 IP 를 나눠 준 기록)
// ─────────────────────────────────────────────

// Lease 는 임대 파일의 한 줄입니다.
// dnsmasq 형식: "<만료 유닉스시간> <MAC> <IP> <이름> <client-id>"   (이름을 모르면 "*", 무기한이면 만료 0)
type Lease struct {
	Expires time.Time // 비어 있으면(IsZero) 무기한
	MAC     string
	IP      string
	Name    string // 호스트가 알려준 이름. 모르면 ""
}

// Active 는 아직 만료되지 않은 임대인지 알려줍니다.
func (l Lease) Active(now time.Time) bool {
	return l.Expires.IsZero() || l.Expires.After(now)
}

// ReadLeases 는 임대 파일을 읽습니다. 파일이 아직 없으면(DHCP 를 받은 호스트가 없으면) 빈 목록입니다.
func ReadLeases(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Lease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] == "duid" { // duid 줄은 IPv6 용
			continue
		}
		sec, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		l := Lease{MAC: strings.ToLower(fields[1]), IP: fields[2], Name: fields[3]}
		if sec != 0 {
			l.Expires = time.Unix(sec, 0)
		}
		if l.Name == "*" {
			l.Name = ""
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// ─────────────────────────────────────────────
// 고정 예약 (dnsmasq dhcp-hostsfile)
// ─────────────────────────────────────────────

// Reservation 은 예약 파일의 한 줄입니다. 형식: "MAC,IP,이름,infinite"
//
// 주석·빈 줄이나 사람이 직접 쓴 다른 형식의 줄은 Raw 에 그대로 보관했다가 그대로 다시 씁니다
// (파일을 고쳐 쓸 때 내용을 잃지 않도록).
type Reservation struct {
	MAC       string
	IP        string
	Name      string
	LeaseTime string // 보통 "infinite": 호스트가 갱신을 안 해도 IP 가 계속 유지됨
	Raw       string // 이 프로그램이 이해하지 못한(또는 손대지 않을) 줄 원문
}

const reservationHeader = "# kpctl 관리망 고정 IP 예약 (dnsmasq dhcp-hostsfile)\n" +
	"# 형식: MAC,IP,이름,infinite   — kpctl dhcp reserve / unreserve 로 관리합니다.\n"

var (
	macRe  = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidMAC 는 aa:bb:cc:dd:ee:ff 형식인지 확인합니다 (소문자로 바꾼 뒤).
func ValidMAC(s string) bool { return macRe.MatchString(strings.ToLower(s)) }

// ValidName 은 DNS 이름 한 칸(점 없는 호스트 이름)으로 쓸 수 있는지 확인합니다.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidIPv4 는 IPv4 주소인지 확인합니다.
func ValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// ReadReservations 는 예약 파일을 읽습니다. 파일이 없으면 빈 목록입니다.
func ReadReservations(path string) ([]Reservation, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	isHeader := map[string]bool{}
	for _, h := range strings.Split(reservationHeader, "\n") {
		isHeader[h] = true
	}

	var out []Reservation
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		switch r, ok := parseReservation(line); {
		case ok:
			out = append(out, r)
		case isHeader[line]:
			// 헤더는 쓸 때 다시 붙이므로 건너뜀 (중복 방지)
		default:
			out = append(out, Reservation{Raw: line}) // 주석·직접 쓴 줄은 그대로 보관
		}
	}
	return out, nil
}

// parseReservation 은 "MAC,IP[,이름][,임대시간]" 줄을 읽습니다. 이 형식이 아니면 ok=false.
func parseReservation(line string) (Reservation, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Reservation{}, false
	}
	parts := strings.Split(line, ",")
	if len(parts) < 2 || len(parts) > 4 || !ValidMAC(parts[0]) || !ValidIPv4(parts[1]) {
		return Reservation{}, false
	}
	r := Reservation{MAC: strings.ToLower(parts[0]), IP: parts[1]}
	for _, p := range parts[2:] {
		switch {
		case p == "infinite" || isDuration(p):
			r.LeaseTime = p
		case ValidName(p):
			r.Name = p
		default:
			return Reservation{}, false
		}
	}
	return r, true
}

func isDuration(s string) bool {
	if s == "" {
		return false
	}
	last := s[len(s)-1]
	num := s
	if last == 's' || last == 'm' || last == 'h' || last == 'd' || last == 'w' {
		num = s[:len(s)-1]
	}
	_, err := strconv.Atoi(num)
	return err == nil
}

// Line 은 예약을 파일 한 줄로 만듭니다.
func (r Reservation) Line() string {
	if r.MAC == "" {
		return r.Raw
	}
	fields := []string{r.MAC, r.IP}
	if r.Name != "" {
		fields = append(fields, r.Name)
	}
	if r.LeaseTime != "" {
		fields = append(fields, r.LeaseTime)
	}
	return strings.Join(fields, ",")
}

// WriteReservations 는 예약 파일을 통째로 다시 씁니다 (임시 파일 → 이름 바꾸기).
// dnsmasq 가 권한을 내려놓은 뒤에도 읽어야 하므로 0644 입니다 (비밀 정보 없음).
func WriteReservations(path string, rs []Reservation) error {
	var b strings.Builder
	b.WriteString(reservationHeader)
	for _, r := range rs {
		b.WriteString(r.Line())
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CheckConflict 는 새 예약이 기존 예약과 MAC, IP, 이름이 겹치는지 확인합니다.
func CheckConflict(rs []Reservation, n Reservation) error {
	for _, r := range rs {
		if r.MAC == "" {
			continue
		}
		switch {
		case r.MAC == n.MAC:
			return fmt.Errorf("MAC %s 은 이미 %s 로 예약되어 있습니다 (먼저 unreserve)", n.MAC, r.IP)
		case r.IP == n.IP:
			return fmt.Errorf("IP %s 은 이미 %s(%s) 에 예약되어 있습니다", n.IP, r.MAC, r.Name)
		case n.Name != "" && r.Name == n.Name:
			return fmt.Errorf("이름 %s 은 이미 %s 에 예약되어 있습니다", n.Name, r.IP)
		}
	}
	return nil
}

// Reload 는 dnsmasq 에 SIGHUP 을 보내 예약 파일을 다시 읽게 합니다.
func Reload(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("dnsmasq PID 파일 %s 를 읽지 못했습니다: %w", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("dnsmasq PID 파일 %s 내용이 이상합니다", pidFile)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("dnsmasq(PID %d)에 신호를 보내지 못했습니다: %w", pid, err)
	}
	return nil
}
