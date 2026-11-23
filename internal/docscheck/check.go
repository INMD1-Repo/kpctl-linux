// Package docscheck는 현재 문서·CLI·실제 설정 parser와 보존 이력의 일치를 검사합니다.
package docscheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Summary struct{ Documents, ConfigExamples, ConfigFiles, CLIReferences, RelativeLinks, Archives int }
type archiveRecord struct {
	Path       string `json:"path"`
	SourcePath string `json:"source_path"`
	SHA256     string `json:"sha256"`
	Prefix     string `json:"prefix,omitempty"`
}
type archiveManifest struct {
	Version int             `json:"version"`
	Records []archiveRecord `json:"records"`
}

func archivedDocuments(root string) (map[string]string, int, error) {
	path := filepath.Join(root, "docs/history/archive-manifest.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var manifest archiveManifest
	if err := strictJSON(data, &manifest); err != nil {
		return nil, 0, err
	}
	if manifest.Version != 1 || len(manifest.Records) == 0 {
		return nil, 0, fmt.Errorf("보존 이력 manifest가 비었거나 지원하지 않는 형식입니다")
	}
	prefixes := map[string]string{}
	for _, record := range manifest.Records {
		if !strings.HasPrefix(record.Path, "docs/history/") || !strings.HasPrefix(record.SourcePath, "docs/operations/history/") || filepath.ToSlash(filepath.Clean(record.Path)) != record.Path {
			return nil, 0, fmt.Errorf("보존 이력 경로가 잘못됐습니다")
		}
		if _, duplicate := prefixes[record.Path]; duplicate {
			return nil, 0, fmt.Errorf("보존 이력 manifest 중복")
		}
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(record.Path)))
		if err != nil {
			return nil, 0, err
		}
		original := current
		if record.Prefix != "" {
			if !strings.HasPrefix(string(current), record.Prefix) {
				return nil, 0, fmt.Errorf("보존 이력 안내가 바뀌었습니다: %s", record.Path)
			}
			original = current[len(record.Prefix):]
		}
		sum := sha256.Sum256(original)
		if hex.EncodeToString(sum[:]) != record.SHA256 {
			return nil, 0, fmt.Errorf("보존 이력 원문 SHA256 불일치: %s", record.Path)
		}
		prefixes[record.Path] = record.Prefix
	}
	return prefixes, len(manifest.Records), nil
}

var configMarker = regexp.MustCompile(`^<!--\s*config-example:\s*(controller|builder|agent|testvm)\s*-->$`)

func checkConfigExamples(body string) (int, error) {
	lines := strings.Split(body, "\n")
	count := 0
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "<!--") || !strings.Contains(line, "config-example:") {
			continue
		}
		marker := configMarker.FindStringSubmatch(line)
		if marker == nil {
			return count, fmt.Errorf("%d행: 잘못된 config-example 표시", i+1)
		}
		start := i + 1
		for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
			start++
		}
		if start >= len(lines) || strings.TrimSpace(lines[start]) != "```json" {
			return count, fmt.Errorf("%d행: 설정 표시 바로 뒤에 json 블록이 필요합니다", i+1)
		}
		end := start + 1
		for end < len(lines) && strings.TrimSpace(lines[end]) != "```" {
			end++
		}
		if end == len(lines) {
			return count, fmt.Errorf("%d행: 닫히지 않은 설정 JSON 블록", i+1)
		}
		if err := validateConfig(marker[1], []byte(strings.Join(lines[start+1:end], "\n"))); err != nil {
			return count, fmt.Errorf("%d행 %s 예제: %w", i+1, marker[1], err)
		}
		count++
		i = end
	}
	return count, nil
}

func Check(root string) (Summary, error) {
	var summary Summary
	root, err := filepath.Abs(root)
	if err != nil {
		return summary, err
	}
	archives, count, err := archivedDocuments(root)
	if err != nil {
		return summary, err
	}
	summary.Archives = count
	commands, err := loadCommands(root)
	if err != nil {
		return summary, err
	}
	documents := []string{filepath.Join(root, "README.md"), filepath.Join(root, "deploy/kpatch/README.md")}
	if err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			documents = append(documents, path)
		}
		return nil
	}); err != nil {
		return summary, err
	}
	var problems []error
	for _, document := range documents {
		relative, _ := filepath.Rel(root, document)
		relative = filepath.ToSlash(relative)
		data, err := os.ReadFile(document)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		body := string(data)
		if prefix, archived := archives[relative]; archived {
			body = prefix
			if body == "" {
				continue
			}
		}
		summary.Documents++
		configs, configErr := checkConfigExamples(body)
		summary.ConfigExamples += configs
		references, commandErr := checkCommands(body, commands)
		summary.CLIReferences += references
		links, linkErr := checkLinks(root, document, body)
		summary.RelativeLinks += links
		if strings.Contains(body, "<!-- code-map: declarations -->") {
			if symbolErr := checkSourceSymbols(document, body); symbolErr != nil {
				problems = append(problems, fmt.Errorf("%s: %w", relative, symbolErr))
			}
		}
		for _, problem := range []error{configErr, commandErr, linkErr} {
			if problem != nil {
				problems = append(problems, fmt.Errorf("%s: %w", relative, problem))
			}
		}
	}
	samples, err := filepath.Glob(filepath.Join(root, "configs/*.example.json"))
	if err != nil {
		return summary, err
	}
	if len(samples) == 0 {
		problems = append(problems, fmt.Errorf("설정 예제 파일이 없습니다"))
	}
	for _, sample := range samples {
		data, readErr := os.ReadFile(sample)
		kind, kindErr := configKind(filepath.Base(sample))
		if readErr == nil && kindErr == nil {
			readErr = validateConfig(kind, data)
		}
		if readErr != nil || kindErr != nil {
			problems = append(problems, fmt.Errorf("%s: %w", sample, errors.Join(readErr, kindErr)))
		} else {
			summary.ConfigFiles++
		}
	}
	return summary, errors.Join(problems...)
}
