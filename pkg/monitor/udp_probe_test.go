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

// Mock conn for UDP write
type mockUDPConn struct {
	net.Conn
	writeErr error
}

func (m *mockUDPConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockUDPConn) Close() error { return nil }

func TestUDPProbe_Check(t *testing.T) {
	// Mock success
	mockDialSuccess := func(ctx context.Context, network, address string) (net.Conn, error) {
		return &mockUDPConn{}, nil
	}

	probe := &UDPProbe{
		DialContext: mockDialSuccess,
	}
	ctx := context.Background()

	res, err := probe.Check(ctx, "target.test:53")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestUDPProbe_Check_Failure(t *testing.T) {
	// Mock dial failure
	mockDialFailure := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	probe := &UDPProbe{
		DialContext: mockDialFailure,
	}
	ctx := context.Background()

	res, err := probe.Check(ctx, "target.test:53")
	if err == nil && res.Success {
		t.Error("Expected error or failure for closed port")
	}
	if res.Success {
		t.Error("Expected failure")
	}
}

func TestUDPProbe_Check_WriteFailure(t *testing.T) {
	// Mock dial success but write failure
	mockDialWriteFail := func(ctx context.Context, network, address string) (net.Conn, error) {
		return &mockUDPConn{writeErr: fmt.Errorf("write failed")}, nil
	}

	probe := &UDPProbe{
		DialContext: mockDialWriteFail,
	}
	ctx := context.Background()

	res, err := probe.Check(ctx, "target.test:53")
	if err == nil && res.Success {
		t.Error("Expected error or failure for write failure")
	}
}

func TestUDPProbe_Check_EdgeCases(t *testing.T) {
	probe := &UDPProbe{}
	probe.SetTargetMode(TargetModeAny)

	ctx := context.Background()
	result, _ := probe.Check(ctx, "")
	if result.Success {
		t.Error("Expected failure for empty target")
	}

	// Test real dial (failure)
	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestUDPProbe_Check_AllMode_RealDial(t *testing.T) {
	probe := &UDPProbe{}
	probe.SetTargetMode(TargetModeAll)

	ctx := context.Background()
	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestUDPProbe_Check_AllMode(t *testing.T) {
	// Test UDP probe with "all" target mode
	callCount := 0
	mockDialSuccess := func(ctx context.Context, network, address string) (net.Conn, error) {
		callCount++
		return &mockUDPConn{}, nil
	}

	probe := &UDPProbe{
		DialContext: mockDialSuccess,
	}
	probe.SetTargetMode(TargetModeAll)

	ctx := context.Background()

	// All targets should succeed
	res, err := probe.Check(ctx, "target1.test:1234,target2.test:1234")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Error("Expected success when all targets succeed in 'all' mode")
	}
	if callCount != 2 {
		t.Errorf("Expected 2 dial calls, got %d", callCount)
	}
}

func TestUDPProbe_SetTargetMode(t *testing.T) {
	probe := &UDPProbe{}

	// Test setting to "all" mode
	probe.SetTargetMode(TargetModeAll)

	// Test setting to "any" mode
	probe.SetTargetMode(TargetModeAny)

	// Should not panic
}

func TestUDPProbe_Extra_Failures(t *testing.T) {
	t.Run("UDP target failed AllMode", func(t *testing.T) {
		probe := &UDPProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "fail:53" {
					return nil, fmt.Errorf("refused")
				}
				return &mockUDPConn{}, nil
			},
		}
		probe.SetTargetMode(TargetModeAll)
		res, _ := probe.Check(context.Background(), "ok:53, fail:53")
		if res.Success {
			t.Error("expected failure")
		}
	})

	t.Run("UDP all targets failed AnyMode", func(t *testing.T) {
		probe := &UDPProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("refused")
			},
		}
		probe.SetTargetMode(TargetModeAny)
		res, _ := probe.Check(context.Background(), "fail1:53, fail2:53")
		if res.Success {
			t.Error("expected failure")
		}
		if !strings.Contains(res.Message, "all udp targets failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})
}

func TestUDPProbe_Check_EmptyTargetsFiller(t *testing.T) {
	p := &UDPProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockUDPConn{}, nil
		},
	}
	p.SetTargetMode(TargetModeAll)
	_, _ = p.Check(context.Background(), "target:53")
	_, _ = p.Check(context.Background(), " , target:53 ")
	// Trigger 0 successCount check? If loop skip all.
	_, _ = p.Check(context.Background(), " , ")

	p.SetTargetMode(TargetModeAny)
	_, _ = p.Check(context.Background(), " , target:53 ")
}
func TestUDPProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &UDPProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "localhost:8080")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestUDPProbe_SetTimeout(t *testing.T) {
	p := &UDPProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
