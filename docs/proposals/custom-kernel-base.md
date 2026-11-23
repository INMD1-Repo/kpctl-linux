# 제안: 직접 빌드한 커널을 기준으로 사용하는 경우

[문서 목차](../README.md) · [현재 빌드 경로](../features/build-and-artifact.md#f03)

이 문서는 향후 설계 검토안입니다. 현재 변경에는 custom base 지원이나 TuxMake 실행 경로를 구현하지 않았습니다. 현재 자동 운영은 Ubuntu 공식 GA generic, 시리즈별 빌더와 대상 GCC를 고정한 격리 환경을 기준으로 합니다.

## 바꾸어야 할 계약

| 항목 | 현재 구현의 근거 | custom base 도입 시 필요한 결정 |
|---|---|---|
| 대상 식별 | `SupportedLTS`, Ubuntu 버전 서명, GA/HWE 구분 | 실행 ABI 이름 외에 정확한 소스 commit·config·도구·이미지 해시로 기준을 식별하고 지원 정책을 다시 정의 |
| 배포 상한 | 정식 APT linux 소스 버전과 같은 Ubuntu Git 태그 | 자체 커널의 승인된 기준·보안 수정 범위를 별도로 정하고 정식 Ubuntu 상한과 섞지 않음 |
| GCC·빌드 환경 | 대상 커널의 compiler 기록과 격리 프로파일 일치 | 베이스 커널과 모듈을 만든 정확한 compiler·패키지·컨테이너 입력을 함께 고정 |
| 부팅 이미지 | Ubuntu 공식 패키지와 확인한 GRUB 대상 | 자체 이미지·initrd 설치, 부트 체인 신뢰, 정확한 대상별 승인·실패 복귀 절차 추가 |
| 라이브패치 도구 | 대상 config의 `CONFIG_KLP_BUILD=y` 여부로 auto 선택 | 새 베이스를 만들 때 필요한 config·툴 버전을 결정하고 실제 실행 커널에서 조건 확인 |
| CVE 설명 | Ubuntu 패키지 범위의 OSV 대조와 선택 커밋 | 자체 소스의 포함 관계와 미적용 수정을 새로 추적하고 자료 부족을 unknown으로 유지 |

현재의 LTS별 빌더와 GCC 프로파일은 공식 커널용 모듈을 재현하는 문제를 다룹니다. custom base는 실행 커널 자체의 출처와 지원 책임까지 바꾸므로 컨테이너를 다른 도구로 바꾸는 것만으로 완료되지 않습니다. 근거 코드는 [lts.go](../../internal/model/lts.go), [published.go](../../internal/builder/published.go), [sandbox_profiles.go](../../internal/builder/sandbox_profiles.go), [kernel_inputs.go](../../internal/model/kernel_inputs.go)에 있습니다.

## Secure Boot와 두 종류의 서명

자체 EFI 커널 이미지에는 부트로더가 신뢰하는 이미지 서명과 인증서 경로가 필요합니다. 모듈 서명에 사용하는 sign-file과 EFI 이미지용 sbsign은 대상과 검증 경로가 다릅니다. sbsign의 역할은 [Ubuntu man page](https://manpages.ubuntu.com/manpages/noble/man1/sbsign.1.html), Ubuntu 부트 체인과 MOK의 모듈 전용 제한은 [Ubuntu Secure Boot 문서](https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/)를 근거로 합니다.

현재 등록한 모듈 전용 MOK를 자체 커널 이미지에도 사용할 수 있다고 가정해서는 안 됩니다. 도입한다면 이미지용 인증서가 shim/GRUB의 해당 검증 경로에서 허용되는지 별도로 확인하고, 기존 모듈 배포 키·DER pin·MOK 예약과 실제 배포 바이트 시험은 유지해야 합니다. 콘솔 승인이나 계획된 재부팅을 자동으로 생략하는 설계를 추가하지 않습니다.

## klp-build와 베이스 이월

현재 `buildTool`은 디스크의 대상 config를 읽습니다. 원래 실행 커널이 그 조건으로 만들어지지 않았는데 모듈 빌드용 config만 고쳐 native 도구 사용이 가능해졌다고 판단해서는 안 됩니다. 자체 베이스라면 먼저 그 커널을 올바른 config·도구로 생성·설치·검증한 뒤 동일 기준에서 모듈을 만들어야 합니다. ELF·전체 vermagic·심볼 CRC 검사를 그대로 유지합니다.

새 베이스로 옮길 때는 이전 누적본의 각 수정이 새 소스에 실제로 포함됐는지 확인해야 합니다. 포함된 수정은 새 베이스의 보호로 설명하고, 아직 포함되지 않은 수정은 새 베이스에 맞는 누적본으로 다시 빌드·검토합니다. 이전 ABI의 .ko를 그대로 재사용하거나 기준 이름이 같다는 이유로 버전만 이어붙이는 방식은 허용하지 않는 설계가 필요합니다.

기준 변경과 라이브패치 교체는 별개입니다. 실행 베이스 교체에는 정확한 이미지·부팅 ID·일회성 재부팅 승인과 복구 경로가 필요합니다. 새 누적본은 이전 보호를 의도치 않게 제거하지 않도록 구성해야 합니다. 누적 교체와 callback/상태 이월의 한계는 [커널 atomic replace 문서](https://docs.kernel.org/livepatch/cumulative-patches.html)를 참고합니다.

## TuxMake의 역할과 비용

[TuxMake 공식 문서](https://tuxmake.org/)는 여러 아키텍처·도구·config의 커널 빌드를 일정한 인터페이스와 컨테이너 환경으로 실행하는 도구를 설명합니다. 자체 커널을 여러 조합으로 검증하거나 빌드 입력과 결과 metadata를 통일하려는 경우 검토할 수 있습니다. 고정한 이미지·툴체인과 정확한 커널 입력은 별도로 관리해야 합니다.

도입 이점은 빌드 조합과 실행 절차의 표준화입니다. 추가 비용은 도구·컨테이너 유지, 자체 커널 보안 추적, 부트 서명과 설치·복구, 지원 범위 확대에 따른 실제 시험입니다. 도구 도입만으로 Ubuntu 패키지의 provenance, 함수 변경의 라이브패치 가능성, Secure Boot 신뢰 또는 운영 무중단이 확보되지는 않습니다.

공식 GA 커널에서 선택 CVE를 안전하게 누적하고 GCC·config·의존성 변화를 통제하는 목적이면 현재 격리 빌드 구조로 처리할 수 있습니다. 공식 커널에 없는 config·아키텍처·실험 기능을 실행 베이스 자체에 요구하거나 자체 커널의 전체 수명주기를 맡기로 결정했을 때 custom base 검토가 필요합니다.

채택한다면 별도 지원 정책과 기준 식별, 이미지 서명·설치·복귀, 베이스별 CVE 이월, 실제 커널·VM·펌웨어 검증을 먼저 정의해야 합니다. 이 문서에 해당 검증을 이미 수행했다는 주장은 없습니다.
