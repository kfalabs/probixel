package tunnels

import (
	"context"
	"probixel/pkg/config"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestWireguardTunnel_Basic(t *testing.T) {
	cfg := &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	}
	name := "wg-t1"

	w := NewWireguardTunnel(name, cfg)

	if w.Name() != name {
		t.Errorf("expected %s, got %s", name, w.Name())
	}
	if w.Type() != "wireguard" {
		t.Errorf("expected wireguard, got %s", w.Type())
	}
	if w.Config() != cfg {
		t.Error("config mismatch")
	}

	// Test getters before initialization
	if w.Device() != nil {
		t.Error("expected nil device before init")
	}
	if w.Netstack() != nil {
		t.Error("expected nil netstack before init")
	}
	if !w.LastInitTime().IsZero() {
		t.Error("expected zero init time before init")
	}

	// Integration test (userspace netstack should work)
	if err := w.Initialize(); err != nil {
		t.Skipf("Skipping integration test: %v", err)
	} else {
		defer w.Stop()
		if w.Device() == nil {
			t.Error("expected device after init")
		}
		if w.Netstack() == nil {
			t.Error("expected netstack after init")
		}
		if w.LastInitTime().IsZero() {
			t.Error("expected non-zero init time after init")
		}

		w.Stop()
		if w.Device() != nil {
			t.Error("expected nil device after stop")
		}
	}
}

func TestWireguardTunnel_DialContext(t *testing.T) {
	w := NewWireguardTunnel("test", &config.WireguardConfig{})
	// Should fail before initialization
	_, err := w.DialContext(context.Background(), "tcp", "1.2.3.4:80")
	if err == nil {
		t.Error("expected error dialing uninitialized tunnel")
	}
}

func TestWireguardTunnel_InitializeErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.WireguardConfig
		wantErr string
	}{
		{
			"invalid address",
			&config.WireguardConfig{Addresses: "invalid"},
			"invalid address",
		},
		{
			"invalid private key",
			&config.WireguardConfig{Addresses: "10.0.0.1/32", PrivateKey: "invalid"},
			"invalid private key",
		},
		{
			"invalid public key",
			&config.WireguardConfig{Addresses: "10.0.0.1/32", PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=", PublicKey: "invalid"},
			"invalid public key",
		},
		{
			"invalid preshared key",
			&config.WireguardConfig{Addresses: "10.0.0.1/32", PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=", PublicKey: "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=", PresharedKey: "invalid"},
			"invalid preshared key",
		},
		{
			"unresolvable endpoint",
			&config.WireguardConfig{Addresses: "10.0.0.1/32", PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=", PublicKey: "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=", Endpoint: "invalid-host:51820"},
			"failed to resolve wireguard endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWireguardTunnel("test", tt.cfg)
			err := w.Initialize()
			if err == nil {
				t.Error("expected error, got nil")
			} else if !stringsContains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func stringsContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestWireguardTunnel_InitializeIdempotency(t *testing.T) {
	cfg := &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	}
	w := NewWireguardTunnel("idempotency-test", cfg)

	if err := w.Initialize(); err != nil {
		t.Skipf("Skipping integration test: %v", err)
		return
	}
	defer w.Stop()

	// Call Initialize again
	if err := w.Initialize(); err != nil {
		t.Errorf("Initialize is not idempotent: %v", err)
	}

	// Test DialContext (success path, but will timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _ = w.DialContext(ctx, "tcp", "8.8.8.8:53")
}

func TestWireguardTunnel_ReportFailure(t *testing.T) {
	threshold := 2
	cfg := &config.WireguardConfig{
		Addresses:        "10.0.0.1/32",
		PrivateKey:       "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:        "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:         "1.2.3.4:51820",
		RestartThreshold: &threshold,
	}
	w := NewWireguardTunnel("test", cfg)

	// Report failure when not initialized should not crash
	w.ReportFailure()

	// If integration test works, test threshold logic
	if err := w.Initialize(); err == nil {
		defer w.Stop()
		if w.Device() == nil {
			t.Fatal("expected device")
		}

		// Set initTime to past to simulate time passage
		w.mu.Lock()
		w.initTime = time.Now().Add(-2 * time.Minute)
		w.mu.Unlock()

		// Set successWindow to a large value
		w.SetSuccessWindow(5 * time.Minute)
		w.ReportFailure()
		if w.Device() == nil {
			t.Error("should not have stopped yet (within successWindow)")
		}

		// Set successWindow to a small value
		w.SetSuccessWindow(1 * time.Minute)
		w.ReportFailure()
		if w.Device() != nil {
			t.Error("should have stopped after exceeding successWindow")
		}
	}
}

func TestWireguardTunnel_IsStabilized(t *testing.T) {
	cfg := &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	}
	w := NewWireguardTunnel("test", cfg)

	// 1. Not stabilized before initialization
	if w.IsStabilized() {
		t.Error("expected not stabilized before init")
	}

	// 2. Test with device factory to control initialization
	if err := w.Initialize(); err == nil {
		defer w.Stop()

		// Should not be stabilized immediately after init (within 20s window)
		if w.IsStabilized() {
			t.Error("expected not stabilized immediately after init")
		}

		// Simulate time passage by setting initTime to past
		w.mu.Lock()
		w.initTime = time.Now().Add(-25 * time.Second)
		w.mu.Unlock()

		// Now should be stabilized
		if !w.IsStabilized() {
			t.Error("expected stabilized after 25 seconds")
		}
	}
}

func TestWireguardTunnel_ReportSuccess(t *testing.T) {
	cfg := &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	}
	w := NewWireguardTunnel("test-success", cfg)

	// Should be no-op or log
	w.ReportSuccess()
}

func TestWireguardTunnel_GetLastHandshakeTime(t *testing.T) {
	cfg := &config.WireguardConfig{
		Addresses:  "10.0.0.1/32",
		PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
		PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
		Endpoint:   "1.2.3.4:51820",
	}
	w := NewWireguardTunnel("test", cfg)

	// Should return zero time when device is nil
	w.mu.Lock()
	handshake := w.getLastHandshakeTime()
	w.mu.Unlock()

	if !handshake.IsZero() {
		t.Error("expected zero time when device is nil")
	}

	// If integration test works, test with actual device
	if err := w.Initialize(); err == nil {
		defer w.Stop()

		w.mu.Lock()
		handshake = w.getLastHandshakeTime()
		w.mu.Unlock()

		// Handshake is not guaranteed, so just verify it doesn't crash
		_ = handshake
	}
}

func TestWireguardTunnel_SetDeviceFactory(t *testing.T) {
	w := NewWireguardTunnel("test", &config.WireguardConfig{})
	w.SetDeviceFactory(func() (WGDevice, *netstack.Net, error) {
		return nil, nil, nil // Mock factory
	})
	// Just verify it doesn't panic. Function is for dependency injection.
}
