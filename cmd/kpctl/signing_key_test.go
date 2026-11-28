// 이 파일: 임시 서명 키 생성·권한·재실행과 실제 sign-file CMS 검증.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/klpcheck/klptest"
)

func privateSigningDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInitSigningKeyPublishesPairOnce(t *testing.T) {
	dir := privateSigningDir(t)
	config := filepath.Join(dir, "controller.json")
	if err := os.WriteFile(config, []byte("existing configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-dir", dir, "test-key"}
	output, err := signingCLIOutput(t, func() error { return initSigningKey(args) })
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "test-key")
	keyPath, certPath := filepath.Join(target, "module.priv"), filepath.Join(target, "module.der")
	for path, mode := range map[string]os.FileMode{target: 0o700, keyPath: 0o600, certPath: 0o600} {
		st, err := os.Lstat(path)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("expected %o at %s: %v", mode, path, err)
		}
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("missing PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) || pub.N.BitLen() != 3072 || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		t.Fatal("invalid RSA signing pair or self-signature")
	}
	if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || len(cert.UnknownExtKeyUsage) != 1 || cert.UnknownExtKeyUsage[0].String() != "1.3.6.1.4.1.2312.16.1.2" || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		t.Fatal("invalid module signing certificate profile")
	}
	if !strings.Contains(output, fmt.Sprintf("%x", sha256.Sum256(der))) || strings.Contains(output, "PRIVATE KEY") || strings.Contains(output, strings.Split(string(keyPEM), "\n")[1]) {
		t.Fatal("unexpected key creation output")
	}
	if err := initSigningKey(args); err == nil {
		t.Fatal("overwrote existing key")
	}
	for path, want := range map[string][]byte{keyPath: keyPEM, certPath: der, config: []byte("existing configuration")} {
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("file changed: %s", path)
		}
	}
	t.Run("real sign-file and CMS verification", func(t *testing.T) {
		verifyModuleSignature(t, dir, keyPath, certPath, der)
	})
}

func verifyModuleSignature(t *testing.T, dir, keyPath, certPath string, der []byte) {
	signers, err := filepath.Glob("/usr/src/linux-headers-*/scripts/sign-file")
	if err != nil {
		t.Fatal(err)
	}
	openssl, err := exec.LookPath("openssl")
	if len(signers) == 0 || err != nil {
		t.Skip("requires kernel headers with sign-file and openssl")
	}
	module := filepath.Join(dir, "fixture.ko")
	data := klptest.Module(klptest.Options{})
	if err := os.WriteFile(module, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(signers[len(signers)-1], "sha256", keyPath, certPath, module).CombinedOutput(); err != nil {
		t.Fatalf("sign-file: %s (%v)", out, err)
	}
	signed, err := os.ReadFile(module)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("~Module signature appended~\n")
	header := len(signed) - len(marker) - 12
	if header <= len(data) || !bytes.HasSuffix(signed, marker) || !bytes.Equal(signed[:len(data)], data) || int(binary.BigEndian.Uint32(signed[header+8:])) != header-len(data) {
		t.Fatal("invalid kernel signature trailer")
	}
	// Verify the detached CMS bytes against exactly the generated certificate.
	for name, value := range map[string][]byte{"cms.der": signed[len(data):header], "unsigned.ko": data, "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		if err := os.WriteFile(filepath.Join(dir, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(openssl, "cms", "-verify", "-inform", "DER", "-in", "cms.der", "-binary", "-content", "unsigned.ko", "-nointern", "-certfile", "cert.pem", "-noverify", "-out", os.DevNull)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CMS signature: %s (%v)", out, err)
	}
}

func TestInitSigningKeyRefusesUnsafeOrPartialDestinations(t *testing.T) {
	dir := privateSigningDir(t)
	if err := os.Mkdir(filepath.Join(dir, "partial"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partial", "module.priv"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "partial"), filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"partial", "linked", "../escape", "."} {
		if err := initSigningKey([]string{"-dir", dir, id}); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := initSigningKey([]string{"-dir", dir, "unsafe"}); err == nil {
		t.Fatal("accepted group-writable parent")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unexpected files in parent: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "partial", "module.priv")); err != nil || string(b) != "keep" {
		t.Fatal("changed pre-existing private file")
	}
}

func TestConcurrentInitSigningKeyOnlyPublishesOnce(t *testing.T) {
	dir := privateSigningDir(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- initSigningKey([]string{"-dir", dir, "race"}) }()
	}
	wg.Wait()
	if (<-results == nil) == (<-results == nil) {
		t.Fatal("expected one success and one refusal")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != "race" {
		t.Fatal("unexpected staging files", err)
	}
}
