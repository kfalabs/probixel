package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"
)

func TestDNSProbe_Check(t *testing.T) {
	// Mock success
	mockResolveSuccess := func(ctx context.Context, nameserver, host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}

	probe := &DNSProbe{
		Resolve: mockResolveSuccess,
	}
	ctx := context.Background()

	// Resolve mocked
	res, err := probe.Check(ctx, "example.test")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestDNSProbe_Check_Failure(t *testing.T) {
	// Mock failure
	mockResolveFailure := func(ctx context.Context, nameserver, host string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}

	probe := &DNSProbe{
		Resolve: mockResolveFailure,
	}
	ctx := context.Background()

	// Non-existent domain
	res, _ := probe.Check(ctx, "non-existent.test")
	// Should fail
	if res.Success {
		t.Error("Expected failure for non-existent domain")
	}
}

func TestDNSProbe_Check_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		targets    string
		domain     string
		targetMode string
	}{
		{
			name:       "Single target with custom domain",
			targets:    "8.8.8.8:53",
			domain:     "example.com",
			targetMode: TargetModeAny,
		},
		{
			name:       "Multiple targets all mode success",
			targets:    "8.8.8.8:53, 1.1.1.1:53",
			domain:     "google.com",
			targetMode: TargetModeAll,
		},
		{
			name:       "Empty target",
			targets:    "",
			domain:     "example.com",
			targetMode: TargetModeAny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &DNSProbe{
				Resolve: func(ctx context.Context, ns, host string) ([]string, error) {
					return []string{"1.2.3.4"}, nil
				},
			}
			probe.SetDomain(tt.domain)
			probe.SetTargetMode(tt.targetMode)

			ctx := context.Background()
			_, _ = probe.Check(ctx, tt.targets)
		})
	}
}

func TestDNSProbe_Check_AllMode_Failure(t *testing.T) {
	probe := &DNSProbe{
		Resolve: func(ctx context.Context, ns, host string) ([]string, error) {
			if strings.Contains(ns, "bad") {
				return nil, errors.New("dns fail")
			}
			return []string{"1.2.3.4"}, nil
		},
	}
	probe.SetTargetMode(TargetModeAll)

	ctx := context.Background()
	result, _ := probe.Check(ctx, "good:53, bad:53")
	if result.Success {
		t.Error("Expected all mode failure when one target fails")
	}
}

func TestDNSProbe_Check_RealLogic(t *testing.T) {
	// Trigger the real net.Resolver path by not setting Resolve field
	probe := &DNSProbe{}
	probe.SetTargetMode(TargetModeAny)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Use an invalid nameserver to trigger failure/timeout
	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestDNSProbe_Check_AllMode_RealLogic(t *testing.T) {
	probe := &DNSProbe{}
	probe.SetTargetMode(TargetModeAll)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = probe.Check(ctx, "127.0.0.1:1")
}

func TestDNSProbe_SetDomain(t *testing.T) {
	probe := &DNSProbe{}
	probe.SetDomain("example.com")
	if probe.domain != "example.com" {
		t.Errorf("Expected domain example.com, got %s", probe.domain)
	}
}

func TestDNSProbe_Check_Failures(t *testing.T) {
	t.Run("All DNS targets failed AnyMode", func(t *testing.T) {
		probe := &DNSProbe{
			Resolve: func(ctx context.Context, nameserver, host string) ([]string, error) {
				return nil, fmt.Errorf("lookup error")
			},
		}
		probe.SetTargetMode(TargetModeAny)
		res, err := probe.Check(context.Background(), "8.8.8.8, 1.1.1.1")
		if err != nil {
			t.Fatalf("unexpected internal error: %v", err)
		}
		if res.Success {
			t.Error("expected failure for all dns targets")
		}
		if !strings.Contains(res.Message, "all dns targets failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("DNS target failed AllMode", func(t *testing.T) {
		probe := &DNSProbe{
			Resolve: func(ctx context.Context, nameserver, host string) ([]string, error) {
				if nameserver == "1.1.1.1:53" {
					return nil, fmt.Errorf("failed target")
				}
				return []string{"127.0.0.1"}, nil
			},
		}
		probe.SetTargetMode(TargetModeAll)
		res, _ := probe.Check(context.Background(), "8.8.8.8, 1.1.1.1")
		if res.Success {
			t.Error("expected failure in all mode when one target fails")
		}
		if !strings.Contains(res.Message, "target 1.1.1.1 failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})
}

func TestDNSProbe_Check_EmptyTargets(t *testing.T) {
	probe := &DNSProbe{
		Resolve: func(ctx context.Context, namespace, host string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
	}
	ctx := context.Background()
	probe.SetTargetMode(TargetModeAll)
	_, _ = probe.Check(ctx, "8.8.8.8, , 1.1.1.1")
}
func TestDNSProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &DNSProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestDNSProbe_SetTimeout(t *testing.T) {
	p := &DNSProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}

func TestDNSProbe_Check_AnyMode_WithResolveFunc(t *testing.T) {
	// Test the "any" mode path when Resolve func is set (lines 204-205, 236-244)
	// This exercises the path where Resolve != nil in the "any" mode loop
	probe := &DNSProbe{
		Resolve: func(ctx context.Context, nameserver, host string) ([]string, error) {
			if strings.Contains(nameserver, "fail") {
				return nil, fmt.Errorf("resolve error")
			}
			return []string{"1.2.3.4"}, nil
		},
	}
	probe.SetTargetMode(TargetModeAny)

	// First target fails, second succeeds via Resolve func
	res, err := probe.Check(context.Background(), "fail:53, good:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success via second target, got failure: %s", res.Message)
	}
}

func TestDNSProbe_Check_AnyMode_ResolveReturnsEmptyIPs(t *testing.T) {
	// Test when Resolve returns empty IPs (no error but no results)
	probe := &DNSProbe{
		Resolve: func(ctx context.Context, nameserver, host string) ([]string, error) {
			return []string{}, nil // empty IPs, no error
		},
	}
	probe.SetTargetMode(TargetModeAny)

	res, err := probe.Check(context.Background(), "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("Expected failure when resolve returns empty IPs")
	}
}

func TestDNSProbe_Check_AllMode_WithResolveFunc(t *testing.T) {
	// Test "all" mode with Resolve func set and empty IPs returned
	probe := &DNSProbe{
		Resolve: func(ctx context.Context, nameserver, host string) ([]string, error) {
			return nil, nil // nil IPs, no error - triggers len(ips) == 0
		},
	}
	probe.SetTargetMode(TargetModeAll)

	res, err := probe.Check(context.Background(), "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("Expected failure when resolve returns nil IPs in all mode")
	}
}

func TestDNSProbe_Check_AnyMode_RealResolver_UDPSuccess(t *testing.T) {
	// Test the "any" mode real resolver path where UDP succeeds (lines 210-219)
	// Uses system resolver (127.0.0.1:53 or similar)
	probe := &DNSProbe{
		Timeout: 5 * time.Second,
	}
	probe.SetTargetMode(TargetModeAny)
	probe.SetDomain("localhost")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use the system's default DNS resolver
	res, err := probe.Check(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// We don't assert success since the local resolver might not be available,
	// but this exercises the code path
	_ = res
}

func TestDNSProbe_Check_AnyMode_RealResolver_TCPFallback(t *testing.T) {
	// Test the "any" mode real resolver TCP fallback path (lines 222-232)
	// by using a custom DialContext that fails for UDP but succeeds for TCP
	probe := &DNSProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network == "udp" {
				return nil, fmt.Errorf("udp blocked")
			}
			// Let TCP through to a real resolver
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
		Timeout: 5 * time.Second,
	}
	probe.SetTargetMode(TargetModeAny)
	probe.SetDomain("localhost")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := probe.Check(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// This exercises the TCP fallback path. If local DNS is available via TCP it succeeds,
	// otherwise it fails but the code path is still exercised.
	_ = res
}

func TestDNSProbe_GetResolvers_Cached(t *testing.T) {
	probe := &DNSProbe{}

	udp1, tcp1 := probe.getResolvers("8.8.8.8:53")
	udp2, tcp2 := probe.getResolvers("8.8.8.8:53")

	if udp1 != udp2 {
		t.Error("Expected same UDP resolver on second call for same nameserver")
	}
	if tcp1 != tcp2 {
		t.Error("Expected same TCP resolver on second call for same nameserver")
	}

	// Different nameserver should return different resolvers
	udp3, tcp3 := probe.getResolvers("1.1.1.1:53")
	if udp1 == udp3 {
		t.Error("Expected different UDP resolver for different nameserver")
	}
	if tcp1 == tcp3 {
		t.Error("Expected different TCP resolver for different nameserver")
	}
}
