package monitor

import (
	"context"
	"testing"
)

func TestHostProbe_Check(t *testing.T) {
	probe := &HostProbe{}
	ctx := context.Background()

	res, err := probe.Check(ctx, "ignored.test")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Error("Expected success")
	}
	if res.Message != "Host heartbeat" {
		t.Errorf("Expected 'Host heartbeat', got %s", res.Message)
	}
}

func TestHostProbe_SetTargetMode(t *testing.T) {
	probe := &HostProbe{}
	probe.SetTargetMode(TargetModeAll)
	probe.SetTargetMode(TargetModeAny)
}
