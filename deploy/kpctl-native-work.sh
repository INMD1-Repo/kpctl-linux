#!/bin/bash
# kpctl-native-builder.service 가 1분마다 빌드 계정으로 실행합니다 (kpctl-native-builder.timer).
# /var/lib/kpctl-native/tracks/ 의 대상 커널마다 kpctl-native-builder.py work 를 한 번씩 실행해
# 컨트롤러에서 작업 하나를 받아 빌드·제출합니다. 동시에 두 번 돌지 않도록 flock 으로 직렬화합니다.
set -euo pipefail

ROOT_DIR=${KPCTL_NATIVE_ROOT:-/var/lib/kpctl-native}
DRIVER=${KPCTL_NATIVE_DRIVER:-/opt/kpctl/native-builder/kpctl-native-builder.py}
WORKER=${KPCTL_NATIVE_WORKER:-/etc/kpctl/native-builder/worker.json}

exec 9>"$ROOT_DIR/work.lock"
flock -n -E 75 9 || { status=$?; [[ $status == 75 ]] && exit 0; exit "$status"; }

export LC_ALL=C
found=0
status=0
for dir in "$ROOT_DIR"/tracks/*; do
  [[ -f "$dir/base.json" && -f "$dir/base-proof.json" ]] || continue
  found=1
  # -I 는 PYTHONPATH 와 스크립트 디렉터리도 제외하므로 설치된 드라이버 옆의 모듈만 추가합니다.
  if ! python3 -I -c '
import os, runpy, sys
sys.argv.pop(0)
sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))
runpy.run_path(sys.argv[0], run_name="__main__")
' "$DRIVER" work --plan "$dir/base.json" --proof "$dir/base-proof.json" \
      --cache "$ROOT_DIR/cache" --work-dir "$ROOT_DIR/work" --controller "$WORKER"; then
    echo "!! ${dir##*/}: 네이티브 빌드 작업 실패" >&2
    status=1
  fi
done
if [[ $found == 0 ]]; then echo "대상 커널 없음"; fi
exit "$status"
