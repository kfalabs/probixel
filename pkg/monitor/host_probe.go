package monitor

import (
	"context"
	"strings"
	"time"
)

type HostProbe struct {
}

func (p *HostProbe) Name() string {
	return MonitorTypeHost
}

func (p *HostProbe) SetTargetMode(mode string) {
	// Not used for Host probe, but kept for consistency with other probes
	_ = mode
}

func (p *HostProbe) Check(ctx context.Context, target string) (Result, error) {
	target = strings.TrimSpace(target)
	return Result{
		Success:   true,
		Duration:  time.Millisecond,
		Message:   "Host heartbeat",
		Target:    target,
		Timestamp: time.Now(),
	}, nil
}
