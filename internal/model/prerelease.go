// 이 파일: 정식 버전 번호와 분리한 출시 전 번호 표시와 링의 실제 목표 조회.
package model

import (
	"fmt"
	"time"
)

// TargetVersion은 명시 승인한 출시 전 목표를 정식 목표 위에 적용합니다.
// 음수 식별자는 구 에이전트도 0과 구분하여 하나의 누적 모듈로 적용할 수 있습니다.
func (t *Track) TargetVersion(ring int) int {
	if t == nil {
		return 0
	}
	if v := t.PrereleaseRingVersions[ring]; v != 0 {
		return v
	}
	return t.RingVersions[ring]
}

func (t *Track) TargetSetAt(ring int) time.Time {
	if t.PrereleaseRingVersions[ring] != 0 {
		return t.PrereleaseRingSetAt[ring]
	}
	return t.RingSetAt[ring]
}

func (t *Track) HasPrerelease() bool {
	for _, version := range t.PrereleaseRingVersions {
		if version != 0 {
			return true
		}
	}
	return false
}

func VersionLabel(version int) string {
	if version < 0 {
		return fmt.Sprintf("출시 전 pre%d", -version)
	}
	return fmt.Sprintf("v%d", version)
}
