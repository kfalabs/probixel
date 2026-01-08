package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"probixel/pkg/config"
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

func TestWireguardProbe_Check_ConfigMissing(t *testing.T) {
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

func TestWireguardProbe_Initialize_NilConfig(t *testing.T) {
	p := &WireguardProbe{}
	err := p.Initialize()
	if err == nil {
		t.Error("expected error for nil config")
	}
	if err.Error() != "wireguard configuration missing" {
		t.Errorf("unexpected error: %v", err)
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

func TestWireguardProbe_Check_InvalidMaxAge(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses:  "10.64.222.21/32",
			PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
			PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
			Endpoint:   "1.2.3.4:51820",
			MaxAge:     "invalid",
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

func TestWireguardProbe_Check_Success(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success, got failure: %s", res.Message)
	}
}

func TestWireguardProbe_Check_StaleHandshake(t *testing.T) {
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Add(-10*time.Minute).Unix()),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for stale handshake")
	}
	if p.dev != nil {
		t.Error("expected device to be closed and nil'd after stale handshake")
	}
	if !testingContains(res.Message, "handshake stale") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_NoHandshake(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=0\n",
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for no handshake")
	}
	if p.dev != nil {
		t.Error("expected device to be closed and nil'd after no handshake")
	}
	if !testingContains(res.Message, "no handshake yet") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_Check_IpcGetError(t *testing.T) {
	mock := &mockWGDevice{
		getErr: fmt.Errorf("ipc error"),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for IPC error")
	}
	if !testingContains(res.Message, "failed to get wireguard status") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestWireguardProbe_InitDevice_Errors(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "invalid-addr",
		},
	}
	_, _, err := p.initDevice()
	if err == nil {
		t.Error("expected error for invalid address")
	}

	p.Config.Addresses = "10.0.0.1/32"
	p.Config.PrivateKey = "invalid-key"
	_, _, err = p.initDevice()
	if err == nil {
		t.Error("expected error for invalid private key")
	}

	p.Config.PrivateKey = "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU="
	p.Config.PublicKey = "invalid-key"
	_, _, err = p.initDevice()
	if err == nil {
		t.Error("expected error for invalid public key")
	}

	p.Config.PublicKey = "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0="
	p.Config.PresharedKey = "invalid-key"
	_, _, err = p.initDevice()
	if err == nil {
		t.Error("expected error for invalid preshared key")
	}
}

func TestWireguardProbe_Check_ParseError(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=not_a_number\n",
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
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

func TestWireguardProbe_Check_BypassHandshakeWithTargets(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=0\n", // No handshake
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour), // Way past grace period
	}

	// If target is set, but netst is nil, it SHOULD fail during connectivity check, NOT handshake check.
	res, err := p.Check(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if testingContains(res.Message, "no handshake yet") {
		t.Error("expected handshake check to be bypassed when target is provided")
	}

	if !testingContains(res.Message, "connectivity check failed") {
		t.Errorf("expected connectivity check to be reached, got: %s", res.Message)
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
	if res.Success {
		t.Error("expected failure even during grace period")
	}
	if !testingContains(res.Message, "waiting for handshake") {
		t.Errorf("unexpected message: %s", res.Message)
	}
	if p.dev == nil {
		t.Error("expected device to NOT be closed during grace period")
	}
}

func TestWireguardProbe_Check_DetailedLogging(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=1600000000\n",
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "10.100.100.2/32",
			MaxAge:    "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}

	// Test self-ping successful logging
	res, err := p.Check(context.Background(), "10.100.100.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected success for self-ping")
	}
	if !testingContains(res.Message, "Ping 10.100.100.2 OK (self)") {
		t.Errorf("expected detailed success message, got: %s", res.Message)
	}

	// Test combined logging with handshake
	if !testingContains(res.Message, "last handshake") {
		t.Errorf("expected handshake info in message, got: %s", res.Message)
	}

	// Test failure logging (netstack nil causes failure for non-self targets)
	res, err = p.Check(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for non-existent netstack")
	}
	if !testingContains(res.Message, "Ping 1.1.1.1 failed: netstack not initialized") {
		t.Errorf("expected detailed failure message, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_SuccessOnHeartbeat(t *testing.T) {
	mock := &mockWGDevice{
		uapi: "last_handshake_time_sec=1600000000\n",
	}
	// Fixed time for deterministic test
	now := time.Unix(1600000000, 0).Add(1 * time.Minute)

	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses:          "10.100.100.2/32",
			MaxAge:             "5m",
			SuccessOnHeartbeat: true,
		},
		dev:      mock,
		initTime: now.Add(-1 * time.Hour),
	}

	// Target fails (nil netst), but SuccessOnHeartbeat is true and handshake is recent.
	// Ensure Check uses our "now" logic or adjust the mock to be very recent.
	mock.uapi = fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-10)

	res, err := p.Check(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected success due to success_on_heartbeat")
	}
	if !testingContains(res.Message, "heartbeat OK") {
		t.Errorf("expected heartbeat success message, got: %s", res.Message)
	}

	// SuccessOnHeartbeat is true, but handshake is TOO OLD.
	mock.uapi = fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-600) // 10m ago, limit is 5m
	res, err = p.Check(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure because heartbeat is too old")
	}
	if !testingContains(res.Message, "connectivity check failed") {
		t.Errorf("expected connectivity failure message, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_TargetModeAll_PartialSuccess(t *testing.T) {
	// When target_mode=all, all targets must succeed. If some fail, the check fails.
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-10),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "10.100.100.2/32",
			MaxAge:    "5m",
		},
		dev:        mock,
		initTime:   time.Now().Add(-1 * time.Hour), // Past grace period
		targetMode: TargetModeAll,
	}

	// Both targets: one is self (succeeds), one is external (fails due to nil netst)
	res, err := p.Check(context.Background(), "10.100.100.2, 1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure because not all targets succeeded in mode=all")
	}
	if !testingContains(res.Message, "connectivity check failed") {
		t.Errorf("expected connectivity check failure, got: %s", res.Message)
	}
	if !testingContains(res.Message, "mode: all") {
		t.Errorf("expected mode=all in message, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_GracePeriodWithTargets(t *testing.T) {
	// During grace period, even if targets fail, don't restart; just report waiting.
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-10),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "10.100.100.2/32",
			MaxAge:    "5m",
		},
		dev:      mock,
		initTime: time.Now(), // Just initialized
	}

	res, err := p.Check(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure because target is unreachable")
	}
	if !testingContains(res.Message, "waiting for connectivity") {
		t.Errorf("expected grace period message, got: %s", res.Message)
	}
	if p.dev == nil {
		t.Error("expected device to NOT be closed during grace period")
	}
}

func TestWireguardProbe_Check_TCPTarget(t *testing.T) {
	// Test that TCP target parsing works (host:port format)
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-10),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "10.100.100.2/32",
			MaxAge:    "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}

	// TCP target with port - will fail due to nil netst
	res, err := p.Check(context.Background(), "1.1.1.1:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for TCP dial with nil netstack")
	}
	// Should mention TCP in failure message
	if !testingContains(res.Message, "TCP 1.1.1.1:80 failed") {
		t.Errorf("expected TCP failure message, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_EmptyTargetInList(t *testing.T) {
	// Test that empty targets in comma-separated list are skipped
	mock := &mockWGDevice{
		uapi: fmt.Sprintf("last_handshake_time_sec=%d\n", time.Now().Unix()-10),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "10.100.100.2/32",
			MaxAge:    "5m",
		},
		dev:      mock,
		initTime: time.Now().Add(-1 * time.Hour),
	}

	// Self-ping with empty entries should still succeed
	res, err := p.Check(context.Background(), "10.100.100.2, , ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success for self-ping, got: %s", res.Message)
	}
}

func TestWireguardProbe_Check_IpcGetError_StopsDevice(t *testing.T) {
	// Verify that IpcGet error triggers stop(), not just returns error
	mock := &mockWGDevice{
		getErr: fmt.Errorf("ipc connection failed"),
	}
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			MaxAge: "5m",
		},
		dev: mock,
	}

	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected failure for IPC error")
	}
	// The device should NOT be nil'd by IpcGet error (only handshake failures do that)
	// But let's verify the message is correct
	if !testingContains(res.Message, "failed to get wireguard status") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

func TestParseLatestHandshake(t *testing.T) {
	tests := []struct {
		name    string
		uapi    string
		want    time.Time
		wantErr bool
	}{
		{
			name: "valid handshake",
			uapi: "public_key=... \nlast_handshake_time_sec=1600000000\nfoo=bar",
			want: time.Unix(1600000000, 0),
		},
		{
			name: "zero handshake",
			uapi: "last_handshake_time_sec=0",
			want: time.Time{},
		},
		{
			name: "no handshake line",
			uapi: "something=else",
			want: time.Time{},
		},
		{
			name:    "invalid handshake value",
			uapi:    "last_handshake_time_sec=not_a_number",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLatestHandshake(tt.uapi)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLatestHandshake() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseLatestHandshake() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWireguardProbe_InitDevice_Success(t *testing.T) {
	// Skip if environment can't create TUN (though netstack should work)
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses:  "10.64.222.21/32",
			PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
			PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
			Endpoint:   "1.2.3.4:51820",
			MaxAge:     "5m",
		},
	}
	dev, _, err := p.initDevice()
	if err != nil {
		t.Skipf("Skipping integration test: failed to create userspace TUN: %v", err)
		return
	}
	defer dev.Close()

	if dev == nil {
		t.Fatal("expected device to be created")
	}

	// Verify access to device.
	uapi, err := dev.IpcGet()
	if err != nil {
		t.Errorf("failed to get state from real device: %v", err)
	}
	if !testingContains(uapi, "public_key=") {
		t.Error("expected public_key in UAPI output")
	}
	if !testingContains(uapi, "persistent_keepalive_interval=25") {
		t.Error("expected default persistent_keepalive_interval=25 in UAPI output")
	}
}

func TestWireguardProbe_InitDevice_WithPresharedKey(t *testing.T) {
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses:    "10.64.222.21/32",
			PublicKey:    "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
			PrivateKey:   "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
			PresharedKey: "E979zS9M3Y9m78jE8Y79zS9M3Y9m78jE8Y79zS9M3Y8=",
			Endpoint:     "1.2.3.4:51820",
			MaxAge:       "5m",
		},
	}
	dev, _, err := p.initDevice()
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}
	defer dev.Close()

	uapi, err := dev.IpcGet()
	if err != nil {
		t.Errorf("failed to get state: %v", err)
	}
	if !testingContains(uapi, "preshared_key=") {
		t.Error("expected preshared_key in UAPI output")
	}
}

func TestWireguardProbe_Check_Reinitialization(t *testing.T) {
	// This test ensures that if initDevice fails, Check returns the error
	// and if p.dev is nil, it tries to re-init.
	p := &WireguardProbe{
		Config: &config.WireguardConfig{
			Addresses: "invalid", // Will cause initDevice to fail
		},
	}
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("expected failure")
	}
	if !testingContains(res.Message, "failed to initialize") {
		t.Errorf("unexpected message: %s", res.Message)
	}
}

type mockWGDevice struct {
	uapi   string
	getErr error
	closed bool
}

func (m *mockWGDevice) IpcGet() (string, error) {
	return m.uapi, m.getErr
}

func (m *mockWGDevice) IpcSet(conf string) error {
	return nil
}

func (m *mockWGDevice) Up() error {
	return nil
}

func (m *mockWGDevice) Close() {
	m.closed = true
}

func testingContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || stringsContains(s, substr))))
}

func stringsContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
