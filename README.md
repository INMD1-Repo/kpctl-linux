# kpctl-linux

Ubuntu GA 커널의 선택한 CVE 수정을 누적 라이브패치 모듈로 만들어 관리자가 승인한 호스트에 적용합니다. 실행 커널을 교체해야 하는 작업은 디스크 커널 준비와 별도의 재부팅 승인 절차로 처리합니다.

| 구성 요소 | 역할 |
|---|---|
| `kpctl-controller` | 패치·버전·호스트 상태 저장, 서명, VM 시험, 링 배포와 승인 |
| `kpctl-builder` | Ubuntu 소스 수집, 의존 패치 확인, 누적 모듈 빌드·ABI 검사 |
| `kpctl-agent` | 호스트 상태 보고, 받은 파일의 해시 확인, 모듈 적용·부팅용 설치 |
| `kpctl` | 운영자가 사용하는 관리자 CLI |

Go 서버는 표준 라이브러리와 JSON 상태 파일을 사용합니다. 관리자 웹의 React 번들은 컨트롤러 실행 파일에 들어갑니다.

## 처리 흐름

1. 자동 모드의 빌더가 APT에서 확인한 정식 배포 버전의 정확한 Ubuntu Git 태그까지 후보를 수집합니다. 경로 필터와 시험 빌드로 확인한 입력을 컨트롤러에 올립니다.
2. 컨트롤러가 커널별 활성 패치를 묶어 새 누적 작업에 버전을 부여합니다.
3. 승인 과정에서 필요한 키별 사본을 서명합니다. VM 검사가 켜져 있으면 실제 배포할 바이트로 시험한 뒤 첫 링을 갱신합니다.
4. 에이전트가 목표 모듈의 SHA256과 ELF를 검사하고 전환 완료를 확인합니다. 다음 링은 이전 링의 적용 상태와 관찰 시간을 확인한 뒤 승급합니다.

라이브패치는 누적 모듈 하나가 이전 모듈을 교체하는 방식입니다. 다른 공급자의 활성 라이브패치가 있으면 적용을 거부합니다. [배포 규칙](docs/overview/rules.md)과 [구현 구조](docs/overview/architecture.md)에 판단 위치를 정리했습니다.

## 기본 커널 식별표

현재 코드의 지원 표는 다음과 같습니다. HWE는 `version_signature`로 구별해 같은 이름의 GA 모듈을 배포하지 않습니다.

| Ubuntu 시리즈 | GA generic 계열 |
|---|---|
| 22.04 `jammy` | `5.15.0-*-generic` |
| 24.04 `noble` | `6.8.0-*-generic` |
| 26.04 `resolute` | `7.0.0-*-generic` |

식별 근거는 [지원 모델](internal/model/lts.go)입니다. 직접 커널을 지정하는 빌더 설정은 기본 지원 범위를 확대하는 보증이 아닙니다.

## 설치와 운영

[설치 순서](docs/install/README.md)는 컨트롤러, 해당 LTS의 빌더, 대상 에이전트 순입니다. 운영 전에 [Secure Boot와 키 교체](docs/operations/secure-boot.md), [기능별 명세](docs/features/README.md), [제약](docs/reference/limitations.md)을 확인하세요.

추가 기능은 설정으로 선택합니다.

- Secure Boot 대상은 컨트롤러 서비스 계정으로 `kpctl signing init-key`를 실행해 공통 모듈 서명 키를 준비할 수 있습니다. 각 호스트에는 공개 인증서를 예약하고 계획된 재부팅 때 콘솔에서 승인합니다. [키 생성·컨트롤러 설정](docs/install/controller.md#module-signing-key) · [첫 패치 적용 확인](docs/operations/secure-boot.md#verify-signed-module)
- 고정 VM 또는 일회용 VM에서 부팅·미서명 거부·교체·롤백·로그·smoke 검사.
- 자동 배포와 분리한 출시 전 수집. 관리자의 명시 승인과 VM 시험이 필요합니다.
- 커널 CNA 저장소의 upstream 수정 커밋 대조. 공식 OSV 재고와의 비교는 별도 기능입니다.

## 개발 확인

```sh
make test
make docs-check
make test-web
make build
make dist
```

`make build`는 포함된 웹 번들을 사용합니다. `make dist`는 Node.js/npm으로 웹을 다시 빌드한 뒤 설치 묶음을 만듭니다. 시험 범위는 [개발 시험](docs/development/testing.md)에 있습니다. 가짜 도구 시험과 실제 커널·펌웨어 검증은 구분합니다.

전체 문서는 [목차](docs/README.md)에 있고, 구현 위치는 [코드 지도](docs/development/code-map.md)에서 찾을 수 있습니다.

# 라이센스
라이센스는 요즘 AI의 무분별한 사용과 상업적 사용을 막기위해 `PolyForm Noncommercial License`을 채택을 합니다. 비상업적이나 개인의 사용은 허용됨니다.
