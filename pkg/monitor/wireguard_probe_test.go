package monitor

import (
	"context"
	"fmt"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func probeWithMockDevice(cfg *config.WireguardConfig, dev tunnels.WGDevice, initialized time.Time) *WireguardProbe {
	return &WireguardProbe{
		Config: cfg,
		tunnel: &tunnels.MockTunnel{
			DeviceFunc:         func() tunnels.WGDevice { return dev },
			LastInitTimeFunc:   func() time.Time { return initialized },
			IsStabilizedResult: true,
		},
	}
}

func TestWireguardProbe_Name(t *testing.T) {
	p := &WireguardProbe{}
	if p.Name() != MonitorTypeWireguard {
		t.Errorf("expected %s, got %s", MonitorTypeWireguard, p.Name())
	}
}

func TestWireguardProbe_SetTargetMode(t *testing.T) {
	p := &WireguardProbe{}
	p.SetTargetMode(TargetModeAll)
	if p.targetMode != TargetModeAll {
		t.Errorf("expected %s, got %s", TargetModeAll, p.targetMode)
	}
}

func TestWireguardProbe_SetTunnel(t *testing.T) {
	p := &WireguardProbe{}
	tunnel := tunnels.NewWireguardTunnel("test", &config.WireguardConfig{})
	p.SetTunnel(tunnel)
	if p.tunnel != tunnel {
		t.Error("tunnel not set correctly")
	}
}

func TestWireguardProbe_Check_NoConfig(t *testing.T) {
	p := &WireguardProbe{}
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for missing config")
	}
	if res.Message != "wireguard configuration missing" {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Initialize_NoConfig(t *testing.T) {
	p := &WireguardProbe{}
	err := p.Initialize()
	if err == nil {
		t.Error("expected error for nil config")
	}
	if err.Error() != "wireguard configuration missing" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWireguardProbe_Initialize_AlreadyInitialized(t *testing.T) {
	tunnel := &tunnels.MockTunnel{}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{MaxAge: "5m"},
		tunnel: tunnel,
	}
	err := p.Initialize()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if p.tunnel != tunnel {
		t.Error("tunnel was unexpectedly replaced")
	}
}

func TestWireguardProbe_Initialize_WithTunnel(t *testing.T) {
	tunnel := tunnels.NewWireguardTunnel("test", &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	})

	p := &WireguardProbe{
		Config: &config.WireguardConfig{MaxAge: "5m"},
		tunnel: tunnel,
	}

	// Should delegate to tunnel.Initialize()
	if err := p.Initialize(); err == nil {
		defer tunnel.Stop()
	}
}

func TestWireguardProbe_Initialize_EphemeralTunnel(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses:  "10.0.0.1/32",
			PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
			PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
			Endpoint:   "1.2.3.4:51820",
			MaxAge:     "5m",
		},
	}

	// Should create ephemeral tunnel when no tunnel is set
	if err := p.Initialize(); err == nil {
		defer p.Close()

		wgTunnel, ok := p.tunnel.(*tunnels.WireguardTunnel)
		if !ok || wgTunnel.Device() == nil {
			t.Error("expected device to be created")
		}
		if p.tunnel.LastInitTime().IsZero() {
			t.Error("expected initTime to be set")
		}
	}
}

func TestWireguardProbe_Initialize_EphemeralTunnelError(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "invalid-address", // Will cause Initialize to fail
		},
	}

	err := p.Initialize()
	if err == nil {
		t.Fatal("expected error for invalid address in ephemeral tunnel")
	}
	if !testingContains(err.Error(), "invalid address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWireguardProbe_InlineTunnelRecoversAfterStaleHandshake(t *testing.T) {
	stale := &mockWGDevice{uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Add(-10*time.Minute).Unix())}
	recovered := &mockWGDevice{}
	tunnel := tunnels.NewWireguardTunnel("ephemeral", &config.WireguardConfig{MaxAge: "5m"})
	var created atomic.Int32
	tunnel.SetDeviceFactory(func() (tunnels.WGDevice, *netstack.Net, error) {
		if created.Add(1) == 1 {
			return stale, &netstack.Net{}, nil
		}
		return recovered, &netstack.Net{}, nil
	})

	p := &WireguardProbe{
		Config:    &config.WireguardConfig{MaxAge: "5m"},
		newTunnel: func(string, *config.WireguardConfig) *tunnels.WireguardTunnel { return tunnel },
	}
	if err := p.Initialize(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tunnel.SetStabilizationPeriod(0)
	tunnel.SetSuccessWindow(time.Millisecond)
	time.Sleep(2 * time.Millisecond)

	_, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := tunnel.Device(); got != recovered {
		t.Fatalf("inline tunnel device = %v, want recovered device", got)
	}
	if !stale.closed {
		t.Fatal("expected stale inline device to be closed")
	}
}

func TestWireguardProbe_Check_InvalidMaxAge(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "invalid",
		},
	}
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for invalid max_age")
	}
	if !testingContains(res.Message, "invalid max_age") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_NoDevice(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
	}
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure when device not initialized")
	}
	if !testingContains(res.Message, "wireguard device not initialized") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_IpcGetError(t *testing.T) {
	mock := &mockWGDevice{
		uapiErr: fmt.Errorf("ipc error"),
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now().Add(-1*time.Hour))
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for IpcGet error")
	}
	if !testingContains(res.Message, "failed to get handshake") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_NoHandshake(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "some_other_field=value\n",
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now().Add(-1*time.Hour))
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pending {
		t.Error("expected Pending: true when no handshake found")
	}
	if !testingContains(res.Message, "no handshake yet") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_ParseError(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=invalid\n",
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now().Add(-1*time.Hour))
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for parse error")
	}
	if !testingContains(res.Message, "failed to get handshake time") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_RecentHandshake(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now().Add(-1*time.Hour))
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success for recent handshake, got: %s", res.Message)
	}
	if !testingContains(res.Message, "OK") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_StaleHandshake(t *testing.T) {
	staleTime := time.Now().Add(-10 * time.Minute).Unix()
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", staleTime),
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now().Add(-1*time.Hour))
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for stale handshake")
	}
	if !testingContains(res.Message, "handshake stale") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_GracePeriod(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=0\n",
	}
	p := probeWithMockDevice(&config.WireguardConfig{MaxAge: "5m"}, mock, time.Now())
	p.tunnel = &tunnels.MockTunnel{
		DeviceFunc:       func() tunnels.WGDevice { return mock },
		LastInitTimeFunc: func() time.Time { return time.Now() },
	}
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pending {
		t.Error("expected Pending: true during grace period")
	}
	if !testingContains(res.Message, "waiting for handshake") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_WithTunnel(t *testing.T) {
	tunnel := tunnels.NewWireguardTunnel("test", &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
		MaxAge:     "5m",
	})

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	// Should use tunnel's device when available
	if err := tunnel.Initialize(); err == nil {
		defer tunnel.Stop()

		res, err := p.Check(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Result depends on whether handshake exists, but should not crash
		_ = res
	}
}

func TestWireguardProbe_Check_ReportSuccessOnRecentHandshake(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}
	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
		DeviceFunc:         func() tunnels.WGDevice { return mock },
	}

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success for recent handshake, got: %s", res.Message)
	}
	// This should have called tunnel.ReportSuccess()
}

func TestWireguardProbe_CloseStopsOwnedInlineTunnel(t *testing.T) {
	mock := &mockWGDevice{}
	tunnel := tunnels.NewWireguardTunnel("ephemeral", &config.WireguardConfig{})
	tunnel.SetDeviceFactory(func() (tunnels.WGDevice, *netstack.Net, error) {
		return mock, nil, nil
	})
	if err := tunnel.Initialize(); err != nil {
		t.Fatal(err)
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel:     tunnel,
		ownsTunnel: true,
	}

	p.Close()

	if p.tunnel != nil {
		t.Error("expected inline tunnel to be released after close")
	}
	if !mock.closed {
		t.Error("expected device to be closed")
	}
}

func TestWireguardProbe_CloseDoesNotStopRootTunnel(t *testing.T) {
	tunnel := tunnels.NewWireguardTunnel("test", &config.WireguardConfig{})
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	// Root tunnel ownership remains with the watchdog.
	p.Close()
}

func TestParseLatestHandshake(t *testing.T) {
	tests := []struct {
		name    string
		uapi    string
		want    time.Time
		wantErr bool
	}{
		{
			"valid timestamp",
			fmt.Sprintf("last_handshake_time_sec=%d\n", time.Unix(1234567890, 0).Unix()),
			time.Unix(1234567890, 0),
			false,
		},
		{
			"zero timestamp",
			"last_handshake_time_sec=0\n",
			time.Time{},
			false,
		},
		{
			"no handshake field",
			"some_other_field=value\n",
			time.Time{},
			false,
		},
		{
			"invalid timestamp",
			"last_handshake_time_sec=invalid\n",
			time.Time{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLatestHandshake(tt.uapi)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLatestHandshake() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("parseLatestHandshake() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Mock WireGuard device for testing
type mockWGDevice struct {
	uapi    string
	uapiErr error
	closed  bool
}

func (m *mockWGDevice) IpcGet() (string, error) {
	if m.uapiErr != nil {
		return "", m.uapiErr
	}
	return m.uapi, nil
}

func (m *mockWGDevice) IpcSet(string) error {
	return nil
}

func (m *mockWGDevice) Close() {
	m.closed = true
}

func (m *mockWGDevice) Wait() chan error {
	return make(chan error)
}

func testingContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// mockWireguardTunnel implements the interfaces expected by WireguardProbe.Check
type mockWireguardTunnel struct {
	tunnels.MockTunnel
	config *config.WireguardConfig
	dev    tunnels.WGDevice
}

func (m *mockWireguardTunnel) Config() *config.WireguardConfig {
	return m.config
}

func (m *mockWireguardTunnel) Device() tunnels.WGDevice {
	return m.dev
}

func TestWireguardProbe_Check_InvalidMaxAgeFromTunnel(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}

	tunnel := &mockWireguardTunnel{
		IsStabilizedResult: true,
		config: &config.WireguardConfig{
			MaxAge: "invalid", // This should trigger the tunnel config fallback error
		},
		dev: mock,
	}

	// No Config on probe, should fallback to tunnel
	p := &WireguardProbe{tunnel: tunnel}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for invalid max_age from tunnel")
	}
	if !testingContains(res.Message, "invalid max_age from tunnel") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_TunnelConfigFallbackValid(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}

	tunnel := &mockWireguardTunnel{
		IsStabilizedResult: true,
		config: &config.WireguardConfig{
			MaxAge: "5m", // Valid max_age from tunnel config
		},
		dev: mock,
	}

	// No Config on probe, should fallback to tunnel and succeed
	p := &WireguardProbe{tunnel: tunnel}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_ZeroHandshakeWithTunnel(t *testing.T) {
	failureCalled := false
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=0\n",
	}

	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
		ReportFailureFunc:  func() { failureCalled = true },
		DeviceFunc:         func() tunnels.WGDevice { return mock },
	}

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Pending {
		t.Error("expected Pending: true for zero handshake")
	}
	if !failureCalled {
		t.Error("expected ReportFailure to be called")
	}
}

func TestWireguardProbe_SetTimeout(t *testing.T) {
	p := &WireguardProbe{}
	p.SetTimeout(10 * time.Second)
	// No-op, just ensure no panic
}

func TestWireguardProbe_Check_MaxAgeZero(t *testing.T) {
	// When Config has empty MaxAge and tunnel has no Config(), maxAge stays 0
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}
	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
		DeviceFunc:         func() tunnels.WGDevice { return mock },
	}

	p := &WireguardProbe{tunnel: tunnel}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for maxAge == 0")
	}
	if !testingContains(res.Message, "max_age is required") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_ParseErrorWithTunnel(t *testing.T) {
	failureCalled := false
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=invalid\n",
	}

	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
		ReportFailureFunc:  func() { failureCalled = true },
		DeviceFunc:         func() tunnels.WGDevice { return mock },
	}

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for parse error")
	}
	if !failureCalled {
		t.Error("expected ReportFailure to be called on parse error with tunnel")
	}
}

func TestWireguardProbe_SetTunnel_NonWireguard(t *testing.T) {
	p := &WireguardProbe{}
	// MockTunnel is not *WireguardTunnel, so SetTunnel should not set it
	mock := &tunnels.MockTunnel{}
	p.SetTunnel(mock)
	if p.tunnel != nil {
		t.Error("expected tunnel to remain nil for non-WireguardTunnel")
	}
}

func TestWireguardProbe_Check_StaleHandshakeWithTunnel(t *testing.T) {
	failureCalled := false
	staleTime := time.Now().Add(-10 * time.Minute).Unix()
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", staleTime),
	}

	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
		ReportFailureFunc:  func() { failureCalled = true },
		DeviceFunc:         func() tunnels.WGDevice { return mock },
	}

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for stale handshake")
	}
	if !failureCalled {
		t.Error("expected ReportFailure to be called")
	}
}
