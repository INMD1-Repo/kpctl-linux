# 선택적인 출시 전 수집과 커널 CNA 대조

[기능 목차](README.md)

<a id="f23"></a>
## F23. 출시 전 후보와 별도 수동 배포

출시 전 수집은 `kernels[].prerelease.enabled`를 명시적으로 켠 직접 지정 커널에만 동작합니다. 기본은 꺼짐이며 branch 기본값은 master-next, 주기는 30분입니다. 정식 수집 주기와 독립적으로 실행하지만 빌드 작업·소스 잠금·의존성·실패 검토 규칙을 공유합니다.

`discoverPrerelease`는 신뢰한 APT 배포 버전과 정확한 태그를 먼저 구하고, 기준 커널 → 정식 상한 → 개발 브랜치 tip의 순방향 이력을 확인합니다. 그 정식 상한 이후의 경로·CVE 후보만 선택합니다. 개발 태그를 정식 최신으로 취급하거나 정식 collected_tag를 개발 tip으로 갱신하지 않습니다. 커널별 검토 결과는 빌더 work_dir의 prerelease 기록에 남깁니다.

공식 Ubuntu 커널 저장소는 [jammy](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy), [noble](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble), [resolute](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute)에서 확인할 수 있습니다. 구성한 브랜치가 없거나 이력을 확인할 수 없으면 수집하지 않습니다.

<!-- config-example: builder -->
```json
{
  "controller_url": "https://controller.example:8443",
  "token": "example-builder-token-0123456789",
  "series": "noble",
  "work_dir": "/var/lib/kpctl-builder",
  "kernels": [{
    "kernel": "6.8.0-85-generic",
    "git_dir": "/srv/ubuntu-noble",
    "base_tag": "Ubuntu-6.8.0-85.85",
    "tag_glob": "Ubuntu-6.8.0-*",
    "prerelease": {"enabled": false, "branch": "master-next", "poll_minutes": 30}
  }],
  "cve_feed": {"enabled": false}
}
```

예제는 두 선택 기능을 끈 상태입니다. 실제 수집에는 해당 소스·디버그 자료·빌드 환경과 운영 대상 확인이 필요합니다.

### 번호, 누적 입력과 승인 경계

정식 Patch와 Job에는 출시 전 입력을 섞지 않습니다. 출시 전 누적본은 현재 정식 활성 입력에 아직 정식 경로에 없는 출시 전 입력을 더합니다. 컨트롤러는 별도 카운터의 pre1, pre2를 API에서 -1, -2로 식별하고 `prerelease_version`에 양수 표시 번호를 둡니다. 정식 next_version과 같은 채널의 대기 작업 폐기 범위는 분리합니다. 구 빌더에는 음수 식별자 작업을 주지 않고 `can_prerelease`를 선언한 빌더만 받습니다.

승인은 `kpctl approve`의 `--prerelease` 또는 API의 명시적 동의가 필요하며 test_vm.enabled=true가 필수입니다. 수동 승급·출시 전 롤백에도 동의를 요구합니다. 자동 승인·승급은 이 채널을 처리하지 않으며 출시 전 목표가 남아 있는 정식 자동화도 보류합니다. 호스트 즉시 업데이트로 출시 전 버전을 적용하거나 덮어쓰지 않습니다.

승인 직전과 VM 시험 후에 최신 정식 활성 입력이 빠지지 않았는지 다시 검사합니다. 오래된 후보가 새 정식 보호를 없앨 수 있으면 재빌드를 요구합니다. 실행 호스트에는 링의 출시 전 overlay를 목표로 전달하며 기존 보호 유지·서명 자격·활성 모듈 확인은 정식과 같은 규칙을 적용합니다.

같은 Ubuntu commit SHA가 나중에 정식 배포로 수집되면 별도 정식 Patch를 생성하고 원래 출시 전 기록은 보존합니다. 출시 전 known 조회는 두 경로를 합집합으로 다루며 정식 기록에 들어간 SHA를 출시 전 활성 입력에 다시 추가하지 않습니다. 정식 경로의 관리자 제외를 출시 전 수집으로 우회하지 않습니다.

구현: [builder/prerelease.go](../../internal/builder/prerelease.go)의 `DiscoverPrereleases`, `discoverPrerelease`; [discover.go](../../internal/builder/discover.go)의 `discoverRange`; [controller/prerelease.go](../../internal/controller/prerelease.go)의 `activePrereleasePatches`, `prereleaseApprovalProblem`, `setRingTarget`; [jobs.go](../../internal/controller/jobs.go)의 `createJobChannel`; [model/prerelease.go](../../internal/model/prerelease.go)의 `TargetVersion`, `VersionLabel`.

검증: [builder/prerelease_test.go](../../internal/builder/prerelease_test.go), [prerelease_integration_test.go](../../internal/controller/prerelease_integration_test.go).

<a id="f24"></a>
## F24. 커널 CNA의 수정 커밋 매핑

`cve_feed.enabled`는 기본 false입니다. 켜면 URL별 bare Git 캐시에서 원격 HEAD를 갱신하고 정확한 commit ID를 고정해 공개 데이터만 읽습니다. 같은 URL·commit이면 메모리의 해석 결과를 재사용하지만, 갱신이 실패한 경우 이전 cache로 성공 처리하지 않습니다. HTTPS 또는 로컬 저장소의 절대 경로/file URL을 허용합니다.

기본 원본은 Linux의 [vulns 저장소](https://git.kernel.org/pub/scm/linux/security/vulns.git/)입니다. 실제 clone의 [schema](https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/schema)에 맞춰 published 연도 아래 .sha1의 fixing IDs와 .dyad의 네 번째 fixed ID만 읽습니다. introduced 열, .vulnerable, reserved/rejected/testing 자료는 후보 매핑에 쓰지 않습니다. .dyad의 fixed version/ID가 0:0인 행은 아직 수정이 없다는 정상 sentinel로 건너뜁니다.

CVE 표기가 없는 Ubuntu 커밋도 전체 40자리 SHA를 명시한 cherry picked/backported from commit, 대괄호 Upstream commit 또는 commit … upstream trailer가 매핑되면 후보가 됩니다. 본문의 단순 SHA 인용, 짧은 SHA와 Fixes 도입 ID는 대조하지 않습니다. 메시지의 기존 CVE와 매핑 CVE는 중복 제거해 합칩니다. 기존 소스 경로 필터·정식 상한·선행 수정·시험 빌드는 그대로 적용합니다.

공개 매핑의 형식·경로·연도·정규 파일 여부와 파일/전체 크기를 검사합니다. symlink, 잘못된 SHA, 형식 변화, clone/fetch/해석 실패는 후보 일부를 등록하기 전에 검토 오류로 중단합니다. 이 기능을 끄면 feed용 파일 접근·Git 호출과 후보 확장을 하지 않습니다.

후보 발견의 보조 자료이며 CVE 영향 범위나 실제 차단 검증은 아닙니다. [독립 OSV 대조](coverage-and-console.md#f13)와 데이터·목적을 분리합니다. 이미 처리한 커밋은 known 정책을 따르므로 feed를 켰다고 기존 모든 Patch의 CVE metadata를 전면 재작성하지 않습니다.

구현: [cve_feed.go](../../internal/builder/cve_feed.go)의 `loadCVEFeed`, `readCVEFeedIndex`, `parseCVEFeedArchive`, `mappedCVEs`; [config.go](../../internal/builder/config.go)의 `CVEFeed` 설정 연결; [discover.go](../../internal/builder/discover.go)의 `discoverRange`. 검증: [cve_feed_test.go](../../internal/builder/cve_feed_test.go), [cve_feed_integration_test.go](../../internal/builder/cve_feed_integration_test.go).
