// 이 파일: 컨트롤러 서비스 계정의 모듈 전용 RSA 키와 공개 DER 생성.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
)

func initSigningKey(args []string) error {
	fs := flag.NewFlagSet("signing init-key", flag.ContinueOnError)
	dir := fs.String("dir", "/etc/kpctl/signing", "컨트롤러 서비스 계정이 소유한 키 상위 디렉터리")
	fs.Usage = func() { fmt.Fprintln(fs.Output(), signingUsage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if fs.NArg() != 1 || !model.ValidSigningKeyID(id) {
		return fmt.Errorf("영숫자로 시작하는 키 ID 하나를 지정하세요 (영숫자·밑줄·하이픈, 최대 64자)")
	}
	parent := filepath.Clean(*dir)
	if !filepath.IsAbs(parent) || strings.ContainsAny(parent, "{}") {
		return fmt.Errorf("-dir에는 자리표시자가 없는 절대 경로가 필요합니다")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("키 상위 디렉터리를 서비스 계정용으로 준비하세요: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("키 상위 디렉터리는 실행 계정이 소유하고 그룹·기타 쓰기가 금지된 실제 디렉터리여야 합니다")
	}
	dest := filepath.Join(parent, id)
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("키 경로 %s가 이미 존재합니다. 기존 인증서를 확인하고 교체에는 새 ID를 사용하세요", dest)
	} else if !os.IsNotExist(err) {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	// A positive random serial and a key identifier let the kernel identify the signer.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now().UTC()
	skid := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: id, Organization: []string{"kpctl module signing"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// Ubuntu shim's module-signing-only EKU.
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 2312, 16, 1, 2}},
		SubjectKeyId:       skid[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	// Publish the pair together. Concurrent invocations cannot replace a
	// successfully published (non-empty) directory.
	stage, err := os.MkdirTemp(parent, ".init-key-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writeKeyFile(filepath.Join(stage, "module.priv"), private); err != nil {
		return err
	}
	if err := writeKeyFile(filepath.Join(stage, "module.der"), der); err != nil {
		return err
	}
	if err := syncKeyDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, dest); err != nil {
		return err
	}
	if err := syncKeyDirectory(parent); err != nil {
		return fmt.Errorf("%s에 키를 게시했으나 디렉터리 동기화 실패: %w", dest, err)
	}
	fmt.Printf("모듈 서명 키 %s 생성\n공개 인증서: %s\nDER SHA256: %x\n", id, filepath.Join(dest, "module.der"), sha256.Sum256(der))
	return nil
}

func writeKeyFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncKeyDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
