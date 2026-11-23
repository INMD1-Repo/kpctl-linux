# 배포 묶음의 kpatch 관리 스크립트

이 디렉터리의 [kpatch](kpatch)는 저장소에 함께 보관한 모듈 관리 스크립트이며 내부 VERSION은 0.9.11입니다. [kpatch.service](kpatch.service)는 부팅 시 설치된 모듈을 불러오는 systemd oneshot입니다. 원본 저작권·라이선스 고지는 스크립트 상단에 유지합니다. 상위 프로젝트는 [dynup/kpatch](https://github.com/dynup/kpatch)입니다.

이 파일은 컨트롤러나 kpatch-build의 대체 프로그램이 아닙니다. [Makefile](../../Makefile)의 dist와 [에이전트 설치](../install-agent.sh)가 운영 호스트에 배치하며, 에이전트가 승인받은 누적 모듈을 load·install·unload·uninstall하는 데 사용합니다.

## 코드에서 사용하는 계약

스크립트의 usage와 load_module, unload_module, install 분기에서 확인한 동작입니다.

| 호출 | 사용 목적 |
|---|---|
| load 모듈파일 | 런타임 모듈 적용·전환 |
| unload 모듈이름 | 해당 모듈 비활성화와 제거 |
| install 모듈파일 | 부팅용 설치본 준비 |
| uninstall 모듈이름 | 부팅용 설치본 정리 |
| load --all | 설치 디렉터리의 커널별 모듈을 부팅 때 불러오기 |

에이전트는 직접 조작하기 전에 외부 공급자와 전환 상태를 확인하고, 새 모듈의 enabled·transition 상태를 확인한 뒤 부팅용으로 설치합니다. VM 시험은 주어진 시험 모듈 이름만 정리하며 unload --all로 다른 공급자를 제거하지 않습니다. 정책은 [에이전트 적용](../../docs/features/rollout-and-agent.md#f07)과 [VM 검사](../../docs/features/test-vm.md#f22)에 있습니다.

## 부팅 경로의 한계

service는 에이전트의 다운로드·ELF 검사 함수를 다시 실행하지 않습니다. 부팅용 설치 디렉터리에 남은 파일이 다음 부팅에 영향을 주므로 설치·정리 실패를 무시하지 않아야 합니다. 여러 설치본이 남았으면 실제 활성 모듈과 해시를 확인하고 에이전트의 복구 상태를 점검합니다.

`kpatch.enable=0` 커널 인자는 이 systemd 유닛의 부팅 시 실행 조건입니다. 컨트롤러의 배포 목표나 실행 중인 에이전트의 향후 적용까지 끄는 설정으로 해석하지 않습니다. 운영 패치 변경은 [승인·롤백 경로](../../docs/features/rollout-and-agent.md#f08)와 감사 절차를 사용합니다.
