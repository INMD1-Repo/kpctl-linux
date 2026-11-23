#!/bin/bash
# Apply reviewed build-tool fixes without resetting local source changes.
set -euo pipefail
source_dir=${1:?usage: kpctl-kpatch-fixes.sh /path/to/kpatch}
fix_dir=$(cd "$(dirname "$0")/kpatch-fixes" && pwd)
for fix in "$fix_dir"/*.patch; do
  [ -f "$fix" ] || { echo "검토한 kpatch 수정 파일이 없습니다" >&2; exit 1; }
  if git -C "$source_dir" apply --reverse --check "$fix" 2>/dev/null; then
    echo "kpatch 수정 적용됨: $(basename "$fix")"
  elif git -C "$source_dir" apply --check "$fix"; then
    git -C "$source_dir" apply "$fix"
    echo "kpatch 수정 적용: $(basename "$fix")"
  else
    echo "이 kpatch 소스에 검토한 수정을 적용할 수 없습니다. 버전·로컬 변경을 확인하세요." >&2
    exit 1
  fi
done
