package monitor

import (
	"context"
	"fmt"
	"net"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"
)

type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error { return nil }

func TestTCPProbe_Check(t *testing.T) {
	// Mock success
	mockDialSuccess := func(ctx context.Context, network, address string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	probe := &TCPProbe{
		DialContext: mockDialSuccess,
	}
	ctx := context.Background()

	res, err := probe.Check(ctx, "target.test:80")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestTCPProbe_Check_Failure(t *testing.T) {
	// Mock failure
	mockDialFailure := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	probe := &TCPProbe{
		DialContext: mockDialFailure,
	}
	ctx := context.Background()

	res, err := probe.Check(ctx, "target.test:80")
	if err == nil && res.Success {
		t.Error("Expected error or failure for closed port")
	}
}

func TestTCPProbe_Check_AllMode_Success(t *testing.T) {
	// Mock success for all targets
	mockDialSuccess := func(ctx context.Context, network, address string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	probe := &TCPProbe{
		DialContext: mockDialSuccess,
	}
	probe.SetTargetMode(TargetModeAll)
	ctx := context.Background()

	// Multiple targets, all should succeed
	res, err := probe.Check(ctx, "target1.test:80,target2.test:80")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success when all targets succeed in 'all' mode, got: %s", res.Message)
	}
}

func TestTCPProbe_Check_AllMode_Failure(t *testing.T) {
	// Mock mixed success/failure
	callCount := 0
	mockDialMixed := func(ctx context.Context, network, address string) (net.Conn, error) {
		callCount++
		if callCount == 1 {
			return &mockConn{}, nil // First target succeeds
		}
		return nil, fmt.Errorf("connection refused") // Second target fails
	}

	probe := &TCPProbe{
		DialContext: mockDialMixed,
	}
	probe.SetTargetMode(TargetModeAll)
	ctx := context.Background()

	// Multiple targets, one fails - should fail in 'all' mode
	res, err := probe.Check(ctx, "target1.test:80,target2.test:80")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure when any target fails in 'all' mode")
	}
}

func TestTCPProbe_Check_EdgeCases(t *testing.T) {
	probe := &TCPProbe{}
	probe.SetTargetMode(TargetModeAny)

	ctx := context.Background()
	// Test empty target
	result, _ := probe.Check(ctx, "")
	if result.Success {
		t.Error("Expected failure for empty target")
	}

	// Test real dial (failure)
	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestTCPProbe_Check_AllMode_RealDial(t *testing.T) {
	probe := &TCPProbe{}
	probe.SetTargetMode(TargetModeAll)

	ctx := context.Background()
	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestTCPProbe_Extra_Failures(t *testing.T) {
	t.Run("TCP target failed AllMode", func(t *testing.T) {
		probe := &TCPProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "fail:80" {
					return nil, fmt.Errorf("refused")
				}
				return &mockConn{}, nil
			},
		}
		probe.SetTargetMode(TargetModeAll)
		res, _ := probe.Check(context.Background(), "ok:80, fail:80")
		if res.Success {
			t.Error("expected failure")
		}
	})

	t.Run("TCP all targets failed AnyMode", func(t *testing.T) {
		probe := &TCPProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("refused")
			},
		}
		probe.SetTargetMode(TargetModeAny)
		res, _ := probe.Check(context.Background(), "fail1:80, fail2:80")
		if res.Success {
			t.Error("expected failure")
		}
		if !strings.Contains(res.Message, "all targets failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})
}

func TestTCPProbe_Check_EmptyTargetsFiller(t *testing.T) {
	p := &TCPProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConn{}, nil
		},
	}
	p.SetTargetMode(TargetModeAny)
	_, _ = p.Check(context.Background(), " , target:80 ")

	p.SetTargetMode(TargetModeAll)
	_, _ = p.Check(context.Background(), " , target:80 ")
}
func TestTCPProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &TCPProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "localhost:8080")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestTCPProbe_SetTimeout(t *testing.T) {
	p := &TCPProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
