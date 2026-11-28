package main

import (
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestInventoryOnlyHostIsExcludedAtVersionZero(t *testing.T) {
	now := time.Now()
	h := &model.Host{LastSeen: now, RolloutEligibility: &model.RolloutEligibility{Status: "blocked_unsupported", Reason: model.TrixieBlocked}}
	if got := hostState(h, 0, now); got != "배포 제외" {
		t.Fatal(got)
	}
}
