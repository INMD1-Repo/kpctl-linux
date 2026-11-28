#!/bin/bash
# kpctl-native-builder.service 가 1분마다 빌드 계정으로 실행합니다 (kpctl-native-builder.timer).
# /var/lib/kpctl-native/tracks/ 의 대상 커널마다 kpctl-native-builder.py work 를 한 번씩 실행해
# 컨트롤러에서 작업 하나를 받아 빌드·제출합니다. 동시에 두 번 돌지 않도록 flock 으로 직렬화합니다.
set -euo pipefail

ROOT_DIR=${KPCTL_NATIVE_ROOT:-/var/lib/kpctl-native}
DRIVER=${KPCTL_NATIVE_DRIVER:-/opt/kpctl/native-builder/kpctl-native-builder.py}
WORKER=${KPCTL_NATIVE_WORKER:-/etc/kpctl/native-builder/worker.json}

# TODO(codex):
#   - exec 9>"$ROOT_DIR/work.lock"; flock -n 9 || exit 0  (이전 실행이 진행 중이면 조용히 종료)
#   - tracks/*/ 에서 base.json·base-proof.json 이 둘 다 있는 디렉터리만, 이름 순으로
#     python3 -I "$DRIVER" work --plan base.json --proof base-proof.json --cache "$ROOT_DIR/cache"
#       --work-dir "$ROOT_DIR/work" --controller "$WORKER"
#     (-I: 작업 디렉터리의 모듈을 가져오지 않도록. native_inputs.py 는 DRIVER 옆에서 찾게 PYTHONPATH 를 그 디렉터리로 고정)
#   - 한 track 이 실패해도 나머지는 계속, 하나라도 실패하면 마지막에 exit 1 (journal 에 track 과 오류 표시)
#   - 대상이 하나도 없으면 "대상 커널 없음" 출력 후 exit 0
echo "kpctl-native-work.sh: 아직 구현되지 않았습니다" >&2
exit 1
