# make          → bin/ 에 4개 프로그램 빌드 (정적 바이너리, 다른 서버에 복사만 하면 됨)
# make test     → Go·race·Python·가짜 도구 e2e·문서·셸·웹 통합 검사
# make web      → React 관리자 화면 빌드 (Node.js/npm 필요)
# make dist     → 웹 재빌드 후 배포용 묶음 (Node.js/npm 필요)

GOFLAGS := -trimpath -ldflags="-s -w"
export CGO_ENABLED=0
GO_TEST_FLAGS ?=

.PHONY: docs-check test-race build web web-deps dev-web test test-kpatch test-web test-web-browser test-web-demo vet lint-scripts dist clean

build:
	go build $(GOFLAGS) -o bin/ ./cmd/...

vet:
	gofmt -l . | (! grep .) && go vet ./...

lint-scripts:
	shellcheck -x deploy/testvm/qemu/*.sh

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
	cp bin/kpctl-builder deploy/setup-builder.sh deploy/kpctl-kernel-debug.sh deploy/systemd/kpctl-builder.service configs/builder.example.json dist/builder/
	cp deploy/kpctl-kernel-inputs.py deploy/kpctl-native-builder.py deploy/native_inputs.py dist/builder/
	cp deploy/setup-native-builder.sh deploy/kpctl-native-work.sh deploy/systemd/kpctl-native-builder.service deploy/systemd/kpctl-native-builder.timer dist/builder/
	cp deploy/kpctl-kpatch-fixes.sh deploy/kpctl-kpatch-cold-test.py dist/builder/
	cp -R deploy/kpatch-fixes dist/builder/
	cp deploy/setup-build-environment.sh deploy/kpctl-build-environment.py dist/builder/
	cp -R deploy/build-environment dist/builder/
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
