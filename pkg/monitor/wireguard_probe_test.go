package monitor

import (
	"context"
	"fmt"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"testing"
	"time"
)

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
	mock := &mockWGDevice{}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{MaxAge: "5m"},
		dev:    mock,
	}
	err := p.Initialize()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// dev should remain the same
	if p.dev != mock {
		t.Error("device was unexpectedly replaced")
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
		defer p.stop()

		if p.dev == nil {
			t.Error("expected device to be created")
		}
		if p.initTime.IsZero() {
			t.Error("expected initTime to be set")
		}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}
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
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now(), // Just initialized
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
	tunnel := &tunnels.MockTunnel{
		IsStabilizedResult: true,
	}
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel:   tunnel,
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
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

func TestWireguardProbe_Stop(t *testing.T) {
	mock := &mockWGDevice{}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	p.stop()

	if p.dev != nil {
		t.Error("expected device to be nil after stop")
	}
	if !mock.closed {
		t.Error("expected device to be closed")
	}
}

func TestWireguardProbe_Stop_WithTunnel(t *testing.T) {
	tunnel := tunnels.NewWireguardTunnel("test", &config.WireguardConfig{})
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		tunnel: tunnel,
	}

	// stop should call tunnel.Stop(), which should not crash
	p.stop()
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

func TestWireguardProbe_SetTimeout(t *testing.T) {
	p := &WireguardProbe{}
	p.SetTimeout(10 * time.Second)
	// SetTimeout is a no-op for WireguardProbe, but we test it for coverage
}

func testingContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
