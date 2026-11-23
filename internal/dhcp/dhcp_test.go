// 이 파일: dhcp 패키지의 TestReadLeases, TestReservationsRoundTrip, TestValidators 회귀 시험.
package dhcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases")
	os.WriteFile(path, []byte(
		"1900000000 AA:BB:CC:00:00:01 10.0.0.101 gpu-01 01:aa:bb:cc:00:00:01\n"+
			"0 aa:bb:cc:00:00:02 10.0.0.20 gpu-02 *\n"+
			"1000 aa:bb:cc:00:00:03 10.0.0.103 * *\n"+
			"duid 00:01:00:01\n"), 0o644)

	ls, err := ReadLeases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 3 {
		t.Fatalf("임대 3건이어야 함: %+v", ls)
	}
	now := time.Unix(1800000000, 0)
	if ls[0].MAC != "aa:bb:cc:00:00:01" || ls[0].Name != "gpu-01" || !ls[0].Active(now) {
		t.Errorf("첫 줄: %+v (MAC 은 소문자로)", ls[0])
	}
	if !ls[1].Expires.IsZero() || !ls[1].Active(now) {
		t.Errorf("만료 0 은 무기한: %+v", ls[1])
	}
	if ls[2].Name != "" || ls[2].Active(now) {
		t.Errorf("이름 * 은 빈 값, 만료 지난 임대는 비활성: %+v", ls[2])
	}

	if ls, err := ReadLeases(filepath.Join(t.TempDir(), "없음")); err != nil || ls != nil {
		t.Errorf("파일이 없으면 빈 목록: %v %v", ls, err)
	}
}

func TestReservationsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp-hosts")
	original := "# 직접 쓴 주석\n" +
		"aa:bb:cc:00:00:01,10.0.0.11,gpu-01,infinite\n" +
		"id:01:02,10.0.0.99\n" // 이 프로그램이 모르는 형식 → 그대로 보관
	os.WriteFile(path, []byte(original), 0o644)

	rs, err := ReadReservations(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 || rs[1].Name != "gpu-01" || rs[1].LeaseTime != "infinite" {
		t.Fatalf("읽기: %+v", rs)
	}

	n := Reservation{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.12", Name: "gpu-02", LeaseTime: "infinite"}
	if err := CheckConflict(rs, n); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Reservation{
		{MAC: "aa:bb:cc:00:00:01", IP: "10.0.0.50"},                 // MAC 중복
		{MAC: "aa:bb:cc:00:00:09", IP: "10.0.0.11"},                 // IP 중복
		{MAC: "aa:bb:cc:00:00:09", IP: "10.0.0.50", Name: "gpu-01"}, // 이름 중복
	} {
		if CheckConflict(rs, bad) == nil {
			t.Errorf("충돌을 못 잡음: %+v", bad)
		}
	}

	if err := WriteReservations(path, append(rs, n)); err != nil {
		t.Fatal(err)
	}
	if err := WriteReservations(path, append(rs, n)); err != nil { // 두 번 써도 헤더가 늘지 않아야 함
		t.Fatal(err)
	}
	rs2, _ := ReadReservations(path)
	data, _ := os.ReadFile(path)
	if len(rs2) != 4 || strings.Count(string(data), "# kpctl 관리망") != 1 {
		t.Fatalf("다시 읽기:\n%s", data)
	}
	for _, keep := range []string{"# 직접 쓴 주석", "id:01:02,10.0.0.99", "aa:bb:cc:00:00:02,10.0.0.12,gpu-02,infinite"} {
		if !strings.Contains(string(data), keep+"\n") {
			t.Errorf("%q 가 파일에 없음:\n%s", keep, data)
		}
	}
}

func TestValidators(t *testing.T) {
	if !ValidMAC("AA:bb:CC:00:00:01") || ValidMAC("aa:bb:cc:00:00") {
		t.Error("ValidMAC")
	}
	if !ValidName("gpu-01") || ValidName("gpu_01") || ValidName("-gpu") || ValidName("gpu.lab") {
		t.Error("ValidName")
	}
	if !ValidIPv4("10.0.0.1") || ValidIPv4("::1") || ValidIPv4("10.0.0") {
		t.Error("ValidIPv4")
	}
}
