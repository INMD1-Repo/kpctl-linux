// 이 파일: 임시 RSA 키와 실제 DER CMS로 서명 후보 검증을 시험합니다.
package controller

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"kpctl/internal/model"
)

func testSigningKey(t *testing.T, id string, active bool) SigningKey {
	t.Helper()
	dir := t.TempDir()
	priv, cert := filepath.Join(dir, "module.priv"), filepath.Join(dir, "module.der")
	cmd := exec.Command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN="+id, "-outform", "DER", "-out", cert, "-keyout", priv)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return SigningKey{ID: id, Active: active, Cert: cert, SignCommand: testSignerCommand(t, cert)}
}

func testSignerCommand(t *testing.T, cert string) []string {
	t.Helper()
	signer, err := filepath.Abs("../../test/fake/sign-file")
	if err != nil {
		t.Fatal(err)
	}
	return []string{signer, "sha256", filepath.Join(filepath.Dir(cert), "module.priv"), cert, "{module}"}
}

// The RSA/CMS fixture omits signingTime, so repeated signatures are deterministic.
func expectedPayload(t *testing.T, s *Server, raw, id string) string {
	t.Helper()
	for _, key := range s.signingConfig().Keys {
		if key.ID != id {
			continue
		}
		path := filepath.Join(t.TempDir(), "test.ko")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		args := testSignerCommand(t, key.Cert)
		args[len(args)-1] = path
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("test signing: %v %s", err, out)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	t.Fatalf("missing key %s", id)
	return ""
}

func TestApproveRejectsInvalidModuleSignatures(t *testing.T) {
	real := testSigningKey(t, "A", true)
	different := testSigningKey(t, "B", true)
	for _, tc := range []struct {
		name string
		cmd  []string
		cert string
	}{
		{"wrong certificate", different.SignCommand, real.Cert},
		{"missing certificate", real.SignCommand, ""},
		{"exit zero", []string{"true", "{module}"}, real.Cert},
		{"garbage", []string{vmScript(t, t.TempDir(), "junk", `echo junk >> "$1"`), "{module}"}, real.Cert},
		{"sign changed payload", append([]string{vmScript(t, t.TempDir(), "edit", `echo changed >> "$5"; exec "$@"`)}, real.SignCommand...), real.Cert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "A", Active: true, Cert: tc.cert, SignCommand: tc.cmd}}}
			id := addBuilt(t, s, "manual")
			if _, _, _, err := s.approveJob(id, "test"); err == nil {
				t.Fatal("invalid candidate approved")
			}
			s.store.View(func(st *State) {
				j := st.job(id)
				if j.Status != model.JobBuilt || len(j.SigningArtifacts) != 0 {
					t.Fatal("invalid candidate released")
				}
			})
		})
	}
}

func TestVerifyModuleSignature(t *testing.T) {
	key := testSigningKey(t, "test", true)
	cert, err := os.ReadFile(key.Cert)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "module.ko")
	raw := []byte("fixture module\x00\r\n")
	sum := signingBytesSHA256(raw)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := testSignerCommand(t, key.Cert)
	args[4] = path
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header := len(original) - len(moduleSignatureMagic) - 12
	for _, tc := range []struct {
		name  string
		index int
	}{
		{"untouched", -1}, {"payload", 2}, {"signature", header - 1}, {"length", header + 8}, {"padding", header + 5}, {"magic", len(original) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := append([]byte(nil), original...)
			if tc.index >= 0 {
				candidate[tc.index] ^= 1
			}
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			actual, err := verifyModuleSignature(path, sum, cert)
			if tc.index < 0 && (err != nil || actual != signingBytesSHA256(original)) || tc.index >= 0 && err == nil {
				t.Fatalf("verify = %s, %v", actual, err)
			}
		})
	}
	t.Run("no verifier", func(t *testing.T) {
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
		if _, err := verifyModuleSignature(path, sum, cert); err == nil {
			t.Fatal("no openssl accepted")
		}
	})
	t.Run("actual kernel sign-file", func(t *testing.T) {
		binaries, err := filepath.Glob("/usr/src/linux-headers-*/scripts/sign-file")
		if err != nil {
			t.Fatal(err)
		}
		if len(binaries) == 0 {
			t.Skip("kernel headers sign-file unavailable")
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		key.SignCommand[0] = binaries[0]
		if _, err := signModule(key, testKernel, path, sum, cert); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("embedded signer cannot override configured certificate", func(t *testing.T) {
		other := testSigningKey(t, "other", true)
		for _, opts := range []struct{ attached, attributes bool }{{}, {attached: true}, {attributes: true}} {
			cmdArgs := []string{"cms", "-sign", "-binary", "-md", "sha256", "-inkey", other.SignCommand[2], "-signer", other.Cert, "-outform", "DER"}
			if !opts.attributes {
				cmdArgs = append(cmdArgs, "-noattr")
			}
			if opts.attached {
				cmdArgs = append(cmdArgs, "-nodetach")
			}
			cmd := exec.Command("openssl", cmdArgs...)
			cmd.Stdin = bytes.NewReader(raw)
			signature, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			trailer := []byte{0, 0, 2, 0, 0, 0, 0, 0}
			trailer = binary.BigEndian.AppendUint32(trailer, uint32(len(signature)))
			candidate := bytes.Join([][]byte{raw, signature, trailer, []byte(moduleSignatureMagic)}, nil)
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyModuleSignature(path, sum, cert); err == nil {
				t.Fatal("foreign embedded signer accepted")
			}
			otherCert, err := os.ReadFile(other.Cert)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyModuleSignature(path, sum, otherCert); (err == nil) == (opts.attached || opts.attributes) {
				t.Fatalf("CMS options %+v: %v", opts, err)
			}
		}
	})
}
