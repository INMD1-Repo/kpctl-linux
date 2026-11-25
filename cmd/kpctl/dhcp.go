// 이 파일: kpctl dhcp — 컨트롤러 관리망 DHCP(dnsmasq) 임대 보기, 고정 예약
//
//	kpctl dhcp leases                         임대 목록 + 예약 여부 + 에이전트 등록 여부
//	kpctl dhcp reserve <IP|MAC|이름>...        지금 받은 IP 를 그대로 고정 (무기한)
//	kpctl dhcp reserve -all                   예약 안 된 임대 전부 고정
//	kpctl dhcp unreserve <IP|MAC|이름>...
//	kpctl dhcp restart                        dnsmasq 설정 검사 후 kpctl-dnsmasq 재시작
//
// 파일 위치는 kpctl.env 에서 옵니다 (setup-controller.sh 가 -N 옵션일 때 넣어 줌):
//
//	KPCTL_DHCP_LEASES  /var/lib/kpctl/dnsmasq.leases
//	KPCTL_DHCP_HOSTS   /etc/kpctl/dhcp-hosts
//	KPCTL_DNSMASQ_PID  /run/kpctl-dnsmasq.pid
//
// 실제 파일 처리는 internal/dhcp 패키지에 있습니다.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/dhcp"
	"kpctl/internal/model"
)

const dhcpUsage = `사용법:
  kpctl dhcp leases
  kpctl dhcp reserve [-ip 새IP] [-name 새이름] <IP|MAC|이름>...
  kpctl dhcp reserve -all
  kpctl dhcp unreserve <IP|MAC|이름>...
  kpctl dhcp restart

  restart 는 /etc/kpctl/dnsmasq.conf 를 먼저 검사하고 kpctl-dnsmasq 서비스를 재시작합니다.
  (예약만 바꿨다면 재시작할 필요 없음 — reserve/unreserve 가 알아서 다시 읽게 합니다)

  reserve 는 호스트가 지금 받은 IP 를 그대로 무기한 고정합니다. 고정된 호스트는 IP 갱신이 필요 없어서
  컨트롤러가 멈춰 있어도 관리망 IP 를 잃지 않습니다. 호스트는 모두 고정하는 것을 권장합니다.

옵션:`

type dhcpPaths struct{ leases, hosts, pid, conf string }

func getDHCPPaths() dhcpPaths {
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return dhcpPaths{
		leases: env("KPCTL_DHCP_LEASES", "/var/lib/kpctl/dnsmasq.leases"),
		hosts:  env("KPCTL_DHCP_HOSTS", "/etc/kpctl/dhcp-hosts"),
		pid:    env("KPCTL_DNSMASQ_PID", "/run/kpctl-dnsmasq.pid"),
		conf:   env("KPCTL_DNSMASQ_CONF", "/etc/kpctl/dnsmasq.conf"),
	}
}

func cmdDHCP(c *client.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("kpctl dhcp leases | reserve | unreserve | restart  (자세히: kpctl dhcp reserve -h)")
	}
	p := getDHCPPaths()
	switch args[0] {
	case "leases":
		return dhcpLeases(c, p)
	case "reserve":
		return dhcpReserve(p, args[1:])
	case "unreserve":
		return dhcpUnreserve(p, args[1:])
	case "restart":
		return dhcpRestart(p)
	}
	return fmt.Errorf("모르는 명령: dhcp %s", args[0])
}

// ── 목록 ──

func dhcpLeases(c *client.Client, p dhcpPaths) error {
	leases, err := dhcp.ReadLeases(p.leases)
	if err != nil {
		return err
	}
	rs, err := dhcp.ReadReservations(p.hosts)
	if err != nil {
		return err
	}
	hosts := registeredHosts(c)
	now := time.Now()

	reserved := map[string]bool{}
	for _, r := range rs {
		if r.MAC != "" {
			reserved[r.MAC] = true
		}
	}

	type row struct{ ip, mac, name, lease, res, agent string }
	var rows []row
	seen := map[string]bool{}
	for _, l := range leases {
		if !l.Active(now) {
			continue
		}
		seen[l.MAC] = true
		lease := "고정(무기한)"
		if !l.Expires.IsZero() {
			lease = "남은 " + l.Expires.Sub(now).Round(time.Minute).String()
		}
		rows = append(rows, row{l.IP, l.MAC, l.Name, lease, yes(reserved[l.MAC]), agentState(hosts, l.Name)})
	}
	for _, r := range rs { // 예약은 있지만 지금 임대가 없는 호스트 (꺼져 있거나 아직 안 붙음)
		if r.MAC != "" && !seen[r.MAC] {
			rows = append(rows, row{r.IP, r.MAC, r.Name, "임대 없음", "예", agentState(hosts, r.Name)})
		}
	}
	if len(rows) == 0 {
		fmt.Println("(관리망에서 IP 를 받은 호스트가 없습니다)")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return ipLess(rows[i].ip, rows[j].ip) })

	tw := newTable()
	fmt.Fprintln(tw, "IP\tMAC\t이름\t임대\t예약\t에이전트")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ip, r.mac, dash(r.name), r.lease, r.res, r.agent)
	}
	return tw.Flush()
}

// registeredHosts 는 컨트롤러에 등록된 호스트를 이름(소문자, 도메인 없이)으로 찾을 수 있게 돌려줍니다.
// 컨트롤러에 연결할 수 없으면 빈 맵입니다 (DHCP 목록 자체는 보여줄 수 있도록).
func registeredHosts(c *client.Client) map[string]*model.Host {
	out := map[string]*model.Host{}
	var st model.StatusResponse
	if err := c.Do("GET", "/api/status", nil, &st); err != nil {
		fmt.Fprintf(os.Stderr, "경고: 컨트롤러에서 등록 정보를 가져오지 못했습니다: %v\n", err)
		return out
	}
	for _, h := range st.Hosts {
		out[shortName(h.Hostname)] = h
	}
	return out
}

func agentState(hosts map[string]*model.Host, name string) string {
	if h := hosts[shortName(name)]; name != "" && h != nil {
		return fmt.Sprintf("등록 (링 %d, v%d)", h.Ring, h.Status.Version)
	}
	return "-"
}

func shortName(n string) string {
	n = strings.ToLower(n)
	if i := strings.IndexByte(n, '.'); i >= 0 {
		n = n[:i]
	}
	return n
}

// installLeases 는 설치에 쓸 동적 임대와 명시한 호스트를 모읍니다.
func (p dhcpPaths) installLeases(listed []string, now time.Time) ([]dhcp.Lease, error) {
	leases, err := dhcp.ReadLeases(p.leases)
	if err != nil {
		return nil, err
	}
	if len(leases) == 0 {
		return listedLeases(listed, nil), nil
	}
	reservations, err := dhcp.ReadReservations(p.hosts)
	if err != nil {
		return nil, err
	}
	reservedMAC, reservedIP := map[string]bool{}, map[string]bool{}
	for _, r := range reservations {
		if r.MAC != "" {
			reservedMAC[r.MAC] = true
			reservedIP[r.IP] = true
		}
	}
	// 같은 MAC의 이전 주소로 접속하지 않도록 현재 임대를 먼저 고릅니다.
	newest := map[string]dhcp.Lease{}
	for _, l := range leases {
		if !l.Active(now) {
			continue
		}
		old, seen := newest[l.MAC]
		if !seen || l.Expires.IsZero() || (!old.Expires.IsZero() && l.Expires.After(old.Expires)) {
			newest[l.MAC] = l
		}
	}
	explicit := map[string]bool{}
	for _, host := range listed {
		explicit[host] = true
	}
	var targets []dhcp.Lease
	for _, l := range newest {
		fixed := l.Expires.IsZero() || reservedMAC[l.MAC] || reservedIP[l.IP]
		if !fixed || explicit[l.IP] {
			targets = append(targets, l)
		}
	}
	// 목록 파일에 남은 옛 DHCP 주소가 수동 호스트로 다시 추가되지 않게 합니다.
	return append(targets, listedLeases(listed, leases)...), nil
}

// dhcpInstallTargets 는 동적 임대 중 아직 컨트롤러에 등록되지 않은 호스트의 IP 목록입니다.
// (kpctl install -from-dhcp, kpctl ssh-key copy -from-dhcp 가 사용)
func dhcpInstallTargets(c *client.Client) (targets []string, registered int, err error) {
	leases, err := getDHCPPaths().installLeases(nil, time.Now())
	if err != nil {
		return nil, 0, err
	}
	hosts := registeredHosts(c)
	for _, l := range leases {
		if l.Name != "" && hosts[shortName(l.Name)] != nil {
			registered++
			continue
		}
		targets = append(targets, l.IP)
	}
	sort.Slice(targets, func(i, j int) bool { return ipLess(targets[i], targets[j]) })
	return targets, registered, nil
}

// ── 예약 ──

func dhcpReserve(p dhcpPaths, args []string) error {
	fs := flag.NewFlagSet("dhcp reserve", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, dhcpUsage); fs.PrintDefaults() }
	all := fs.Bool("all", false, "예약 안 된 임대 전부 고정")
	newIP := fs.String("ip", "", "지금 IP 대신 이 IP 로 고정 (호스트 하나일 때만, 다음 갱신 때 바뀜)")
	newName := fs.String("name", "", "호스트가 알려준 이름 대신 이 이름으로 (호스트 하나일 때만)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *all == (fs.NArg() > 0) {
		return fmt.Errorf("대상(IP, MAC, 이름)을 주거나 -all 을 쓰세요 (둘 중 하나만)")
	}
	if (*newIP != "" || *newName != "") && fs.NArg() != 1 {
		return fmt.Errorf("-ip, -name 은 호스트 하나에만 쓸 수 있습니다")
	}
	if *newIP != "" && !dhcp.ValidIPv4(*newIP) {
		return fmt.Errorf("IP 형식이 아닙니다: %s", *newIP)
	}
	if *newName != "" && !dhcp.ValidName(*newName) {
		return fmt.Errorf("이름은 영문 소문자, 숫자, - 만 됩니다 (점 없이): %s", *newName)
	}

	leases, err := dhcp.ReadLeases(p.leases)
	if err != nil {
		return err
	}
	rs, err := dhcp.ReadReservations(p.hosts)
	if err != nil {
		return err
	}
	now := time.Now()

	var picks []dhcp.Lease
	if *all {
		for _, l := range leases {
			if l.Active(now) && findReservation(rs, l.MAC) < 0 {
				picks = append(picks, l)
			}
		}
		if len(picks) == 0 {
			fmt.Println("예약할 임대가 없습니다 (모두 예약됨)")
			return nil
		}
	} else {
		for _, key := range fs.Args() {
			l, err := findLease(leases, key, now)
			if err != nil {
				return err
			}
			picks = append(picks, l)
		}
	}

	var added []dhcp.Reservation
	for _, l := range picks {
		n := dhcp.Reservation{MAC: l.MAC, IP: l.IP, Name: l.Name, LeaseTime: "infinite"}
		if *newIP != "" {
			n.IP = *newIP
		}
		if *newName != "" {
			n.Name = *newName
		}
		if n.Name != "" && !dhcp.ValidName(n.Name) {
			return fmt.Errorf("%s 의 이름 %q 는 DNS 이름으로 쓸 수 없습니다. -name 으로 지정하세요", l.IP, n.Name)
		}
		if err := dhcp.CheckConflict(append(rs, added...), n); err != nil {
			return err
		}
		added = append(added, n)
	}

	if err := dhcp.WriteReservations(p.hosts, append(rs, added...)); err != nil {
		return err
	}
	for _, n := range added {
		fmt.Printf("고정: %s → %s %s\n", n.MAC, n.IP, n.Name)
	}
	return reloadDNSMasq(p)
}

func dhcpUnreserve(p dhcpPaths, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("사용법: kpctl dhcp unreserve <IP|MAC|이름>...")
	}
	rs, err := dhcp.ReadReservations(p.hosts)
	if err != nil {
		return err
	}
	for _, key := range args {
		i := findReservation(rs, key)
		if i < 0 {
			return fmt.Errorf("%s 에 해당하는 예약이 없습니다", key)
		}
		fmt.Printf("예약 해제: %s %s %s\n", rs[i].MAC, rs[i].IP, rs[i].Name)
		rs = append(rs[:i], rs[i+1:]...)
	}
	if err := dhcp.WriteReservations(p.hosts, rs); err != nil {
		return err
	}
	fmt.Println("호스트는 지금 IP 를 임대 만료까지 쓰고, 그 뒤에는 동적 범위에서 새로 받습니다.")
	return reloadDNSMasq(p)
}

// findLease 는 IP, MAC, 이름 중 하나로 활성 임대를 찾습니다.
func findLease(leases []dhcp.Lease, key string, now time.Time) (dhcp.Lease, error) {
	key = strings.ToLower(key)
	for _, l := range leases {
		if l.Active(now) && (l.IP == key || l.MAC == key || (l.Name != "" && strings.ToLower(l.Name) == key)) {
			return l, nil
		}
	}
	return dhcp.Lease{}, fmt.Errorf("%s 에 해당하는 활성 임대가 없습니다 (kpctl dhcp leases 로 확인)", key)
}

// findReservation 은 IP, MAC, 이름 중 하나로 예약을 찾아 위치를 돌려줍니다. 없으면 -1.
func findReservation(rs []dhcp.Reservation, key string) int {
	key = strings.ToLower(key)
	for i, r := range rs {
		if r.MAC != "" && (r.IP == key || r.MAC == key || (r.Name != "" && r.Name == key)) {
			return i
		}
	}
	return -1
}

func reloadDNSMasq(p dhcpPaths) error {
	if err := dhcp.Reload(p.pid); err != nil {
		return fmt.Errorf("예약은 저장했지만 dnsmasq 에 알리지 못했습니다: %w\n  → systemctl reload kpctl-dnsmasq", err)
	}
	fmt.Println("dnsmasq 에 반영했습니다.")
	return nil
}

// ── 재시작 ──

const dnsmasqService = "kpctl-dnsmasq"

// dhcpRestart 는 설정을 검사한 뒤 dnsmasq 서비스를 재시작하고, 다시 떴는지 확인합니다.
// 설정이 틀린 채로 재시작하면 관리망 DHCP/DNS 가 멈추므로 검사를 먼저 합니다.
// (서비스의 ExecStartPre 도 같은 검사를 하지만, 그때는 이미 멈춘 뒤입니다)
func dhcpRestart(p dhcpPaths) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root 권한이 필요합니다 (sudo kpctl dhcp restart)")
	}
	if out, err := exec.Command("dnsmasq", "--test", "--conf-file="+p.conf).CombinedOutput(); err != nil {
		return fmt.Errorf("dnsmasq 설정 오류라 재시작하지 않았습니다 (%s):\n%s", p.conf, strings.TrimSpace(string(out)))
	}
	fmt.Printf("설정 검사 통과: %s\n", p.conf)
	if out, err := exec.Command("systemctl", "restart", dnsmasqService).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s 실패: %v %s\n  → journalctl -u %s -n 50", dnsmasqService, err, strings.TrimSpace(string(out)), dnsmasqService)
	}
	// Restart=on-failure 라 바로 죽어도 잠깐은 activating 으로 보이므로 조금 기다렸다가 봅니다.
	time.Sleep(2 * time.Second)
	out, _ := exec.Command("systemctl", "is-active", dnsmasqService).Output()
	if state := strings.TrimSpace(string(out)); state != "active" {
		return fmt.Errorf("%s 상태가 %q 입니다 → journalctl -u %s -n 50", dnsmasqService, state, dnsmasqService)
	}
	fmt.Printf("%s 재시작 완료. 호스트는 임대를 그대로 쓰고, 갱신 때 다시 받습니다.\n", dnsmasqService)
	return nil
}

// ── 작은 도우미 ──

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ipLess 는 IPv4 주소를 숫자 순서로 비교합니다 (10.0.0.9 < 10.0.0.10).
func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if len(pa[i]) != len(pb[i]) {
			return len(pa[i]) < len(pb[i])
		}
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}
