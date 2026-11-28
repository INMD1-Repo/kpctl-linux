# make          → bin/ 에 4개 프로그램 빌드 (정적 바이너리, 다른 서버에 복사만 하면 됨)
# make test     → Go·race·Python·가짜 도구 e2e·문서·셸·웹 통합 검사
# make web      → React 관리자 화면 빌드 (Node.js/npm 필요)
# make dist     → 웹 재빌드 후 배포용 묶음 (Node.js/npm 필요)

GIT_COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
GIT_VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
GIT_BRANCH  ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
VERSION_LDFLAGS := -X kpctl/internal/version.Version=$(GIT_VERSION) -X kpctl/internal/version.Commit=$(GIT_COMMIT) -X kpctl/internal/version.Branch=$(GIT_BRANCH)
GOFLAGS := -trimpath -ldflags="-s -w $(VERSION_LDFLAGS)"
export CGO_ENABLED=0
GO_TEST_FLAGS ?=

.PHONY: docs-check test-race build web web-deps dev-web test test-kpatch test-web test-web-browser test-web-demo vet lint-scripts dist clean

build:
	go build $(GOFLAGS) -o bin/ ./cmd/...

vet:
	gofmt -l . | (! grep .) && go vet ./...

lint-scripts:
	shellcheck -x deploy/testvm/qemu/*.sh deploy/setup-native-builder.sh deploy/kpctl-native-work.sh

test: vet docs-check
	go test $(GO_TEST_FLAGS) ./...
	python3 -B -m unittest discover -s test -p '*_test.py'
	./test/e2e.sh
	$(MAKE) test-race
	$(MAKE) lint-scripts
	$(MAKE) test-web

KPATCH_CDO ?= /usr/local/libexec/kpatch/create-diff-object
test-kpatch:
	python3 -B deploy/kpctl-kpatch-cold-test.py "$(KPATCH_CDO)"

web-deps:
	npm ci --prefix web --ignore-scripts --no-fund

web: web-deps
	npm run build --prefix web

dev-web: web-deps
	npm run dev --prefix web

test-web: web-deps
	npm test --prefix web
	npm run check:build --prefix web

test-web-browser: test-web
	npm run test:browser --prefix web

test-web-demo: test-web
	npm run test:demo --prefix web

dist: web
	$(MAKE) build
	rm -rf dist && mkdir -p dist/agent dist/controller/agent dist/controller/builder dist/builder
	cp bin/kpctl-agent deploy/install-agent.sh deploy/uninstall-agent.sh deploy/kpctl-prepare-kernel.py deploy/mirrors.list deploy/systemd/kpctl-agent.service configs/reboot-hook.example.sh deploy/kpatch/kpatch deploy/kpatch/kpatch.service dist/agent/
	cp dist/agent/* dist/controller/agent/      # kpctl install 이 SSH 로 보낼 설치 묶음
	cp bin/kpctl-controller bin/kpctl deploy/setup-controller.sh deploy/systemd/kpctl-controller.service \
	   deploy/kpctl-cve-inventory.py deploy/systemd/kpctl-cve-inventory.service deploy/systemd/kpctl-cve-inventory.timer \
	   deploy/systemd/kpctl-dnsmasq.service deploy/systemd/kpctl-autoenroll.service deploy/systemd/kpctl-autoenroll.timer \
	   configs/controller.example.json configs/host-mgmt-netplan.example.yaml dist/controller/
	cp -R deploy/testvm dist/controller/
	# 빌더는 배포판별 전용 묶음으로 나눕니다: Ubuntu(setup-builder.sh)와 Debian·Rocky(setup-native-builder.sh).
	# kpctl install-builder 는 호스트 배포판·대상 커널 이름에 맞는 묶음 하나만 보냅니다 (internal/remote/builder.go).
	# 맨 위 kpctl-builder 는 컨트롤러가 빌드 서버 자동 업데이트에 쓰는 사본입니다 (builder_binary 기본값).
	mkdir -p dist/builder/ubuntu dist/builder/debian dist/builder/rocky
	cp bin/kpctl-builder dist/builder/
	cp bin/kpctl-builder bin/kpctl deploy/setup-builder.sh deploy/kpctl-kernel-debug.sh deploy/systemd/kpctl-builder.service configs/builder.example.json \
	   deploy/kpctl-kernel-inputs.py deploy/kpctl-kpatch-fixes.sh deploy/kpctl-kpatch-cold-test.py \
	   deploy/setup-build-environment.sh deploy/kpctl-build-environment.py dist/builder/ubuntu/
	cp -R deploy/kpatch-fixes deploy/build-environment dist/builder/ubuntu/
	for d in debian rocky; do \
	  cp bin/kpctl-builder bin/kpctl deploy/setup-native-builder.sh deploy/kpctl-native-builder.py deploy/native_inputs.py deploy/kpctl-native-work.sh \
	     deploy/systemd/kpctl-native-builder.service deploy/systemd/kpctl-native-builder.timer \
	     deploy/kpctl-kpatch-fixes.sh deploy/kpctl-kpatch-cold-test.py dist/builder/$$d/ && \
	  cp -R deploy/kpatch-fixes dist/builder/$$d/ || exit 1; \
	done
	for d in ubuntu debian rocky; do echo $$d > dist/builder/$$d/builder-flavor; done
	cp -R dist/builder/. dist/controller/builder/  # kpctl install-builder 가 SSH 로 보낼 묶음 + 빌드 서버 자동 업데이트용 kpctl-builder

clean:
	rm -rf bin dist web/coverage web/test-results web/playwright-report
	rm -rf test/__pycache__ test/kernel/__pycache__ deploy/__pycache__

# 현재 설명의 설정·명령·상대 링크와 이동한 과거 증거의 원문 해시 검사.
docs-check:
	go run ./tools/docs-check

# race는 C 컴파일러/CGO가 필요하며 배포 빌드의 CGO=0과 분리합니다.
test-race:
	CGO_ENABLED=1 go test $(GO_TEST_FLAGS) -race ./internal/...
