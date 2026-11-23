// 이 파일: 실제 설정 parser를 이용한 문서·배포 예제의 부작용 없는 검사.
package docscheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"kpctl/internal/agent"
	"kpctl/internal/builder"
	"kpctl/internal/controller"
	"kpctl/internal/testvm"
)

func validateConfig(kind string, data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("설정 예제가 올바른 단일 JSON 값이 아닙니다")
	}
	switch kind {
	case "controller":
		_, err := controller.ParseConfig(data)
		return err
	case "builder":
		_, err := builder.ParseConfig(data)
		return err
	case "agent":
		_, err := agent.ParseConfig(data)
		return err
	case "testvm":
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		var config testvm.Config
		if _, wrapped := object["test_vm"]; wrapped {
			var wrapper struct {
				TestVM testvm.Config `json:"test_vm"`
			}
			if err := strictJSON(data, &wrapper); err != nil {
				return err
			}
			config = wrapper.TestVM
		} else if err := strictJSON(data, &config); err != nil {
			return err
		}
		return config.Validate()
	default:
		return fmt.Errorf("알 수 없는 설정 예제 종류 %q", kind)
	}
}

func strictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("JSON 뒤의 추가 값")
	}
	return nil
}

func configKind(filename string) (string, error) {
	for _, kind := range []string{"controller", "builder", "agent", "testvm"} {
		if strings.HasPrefix(filename, kind) {
			return kind, nil
		}
	}
	return "", fmt.Errorf("예제 설정 파일의 loader 종류를 알 수 없습니다: %s", filename)
}
