// 이 파일: Linux 모듈 서명 프레임과 분리된 CMS 서명·서명 인증서 검증.
package controller

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// linux/module_signature.h: unsigned payload, DER signature, 12-byte
// module_signature (PKEY_ID_PKCS7, big-endian length), then the magic.
const moduleSignatureMagic = "~Module signature appended~\n"

func verifyModuleSignature(path, unsignedSum string, certDER []byte) (string, error) {
	if len(certDER) == 0 {
		return "", fmt.Errorf("검증할 공개 DER 인증서를 signing.keys[].cert에 설정하세요")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	header := len(data) - len(moduleSignatureMagic) - 12
	if header <= 0 || !bytes.HasSuffix(data, []byte(moduleSignatureMagic)) ||
		!bytes.Equal(data[header:header+8], []byte{0, 0, 2, 0, 0, 0, 0, 0}) {
		return "", fmt.Errorf("Linux PKCS#7 모듈 서명 trailer가 없거나 형식이 잘못됐습니다")
	}
	size := int64(binary.BigEndian.Uint32(data[header+8:]))
	if size == 0 || size >= int64(header) {
		return "", fmt.Errorf("모듈 서명 길이가 잘못됐습니다")
	}
	offset := header - int(size)
	payload, signature := data[:offset], data[offset:header]
	if unsignedSum != "" && signingBytesSHA256(payload) != unsignedSum {
		return "", fmt.Errorf("모듈 서명 앞의 페이로드가 승인할 원본 SHA256과 다릅니다")
	}
	if !detachedModuleCMS(signature) {
		return "", fmt.Errorf("Linux 모듈 서명에는 서명자 한 명의 분리된 DER SignedData와 signed attributes가 없는 서명이 필요합니다")
	}
	dir, err := os.MkdirTemp("", "kpctl-verify-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "signature.der"), signature, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "signer.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// -nointern forces signer lookup in the exact DER distributed to agents.
	// -noverify skips CA-chain validation only. CMS still checks the signature
	// and content. Kernel trust is decided separately on the target.
	cmd := exec.CommandContext(ctx, "openssl", "cms", "-verify", "-verify_retcode", "-binary", "-inform", "DER",
		"-in", "signature.der", "-content", "/dev/stdin", "-nointern", "-certfile", "signer.pem", "-noverify", "-out", os.DevNull)
	cmd.Dir, cmd.Stdin = dir, bytes.NewReader(payload)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("openssl cms 검증 실패: 도구 사용 가능 여부와 설정 DER·서명자·서명 바이트를 확인하세요: %w", err)
	}
	return signingBytesSHA256(data), nil
}

// Reject encapsulated content before supplying external content to OpenSSL,
// which otherwise allows -content to override the content in a CMS message.
func detachedModuleCMS(signature []byte) bool {
	var content struct {
		Type   asn1.ObjectIdentifier
		Signed struct {
			Version      int
			Digests      asn1.RawValue `asn1:"set"`
			Encapsulated asn1.RawValue `asn1:"sequence"`
			Certificates asn1.RawValue `asn1:"optional,tag:0"`
			Revocations  asn1.RawValue `asn1:"optional,tag:1"`
			// Linux pkcs7_verify(VERIFYING_MODULE_SIGNATURE) rejects signed
			// attributes. The signature algorithm must immediately follow the digest.
			Signers []struct {
				Version   int
				SignerID  asn1.RawValue
				Digest    pkix.AlgorithmIdentifier
				Algorithm pkix.AlgorithmIdentifier
				Signature []byte
			} `asn1:"set"`
		} `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(signature, &content)
	if err != nil || len(rest) != 0 || !content.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) || len(content.Signed.Signers) != 1 {
		return false
	}
	var kind asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(content.Signed.Encapsulated.Bytes, &kind)
	return err == nil && len(rest) == 0 && kind.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
}
