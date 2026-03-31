package tunnels

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"probixel/pkg/config"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDevice is an interface for WireGuard device interactions.
type WGDevice interface {
	IpcGet() (string, error)
	IpcSet(conf string) error
	Close()
}

type WireguardTunnel struct {
	name            string
	cfg             *config.WireguardConfig
	dev             WGDevice
	netst           *netstack.Net
	mu              sync.RWMutex
	initTime        time.Time
	lastSuccessTime time.Time
	successWindow   time.Duration // Maximum interval of services + 1 minute grace
	deviceFactory   func() (WGDevice, *netstack.Net, error)
}

func NewWireguardTunnel(name string, cfg *config.WireguardConfig) *WireguardTunnel {
	return &WireguardTunnel{
		name:          name,
		cfg:           cfg,
		successWindow: 90 * time.Second, // Default: 30s max interval + 60s grace
	}
}

func (t *WireguardTunnel) SetDeviceFactory(f func() (WGDevice, *netstack.Net, error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deviceFactory = f
}

func (t *WireguardTunnel) Name() string { return t.name }
func (t *WireguardTunnel) Type() string { return "wireguard" }

func (t *WireguardTunnel) Initialize() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.dev != nil {
		return nil
	}

	return t.initializeLocked()
}

// initializeLocked performs tunnel setup. Caller MUST hold t.mu.
func (t *WireguardTunnel) initializeLocked() error {
	var tunDev tun.Device
	var netst *netstack.Net

	if t.deviceFactory != nil {
		var err error
		t.dev, t.netst, err = t.deviceFactory()
		if err != nil {
			return err
		}
		t.initTime = time.Now()
		return nil
	} else {
		localAddr, err := netip.ParseAddr(strings.Split(t.cfg.Addresses, "/")[0])
		if err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}

		var err2 error
		tunDev, netst, err2 = netstack.CreateNetTUN(
			[]netip.Addr{localAddr},
			[]netip.Addr{}, // DNS
			1420,           // MTU
		)
		if err2 != nil {
			return fmt.Errorf("failed to create netstack TUN: %w", err2)
		}
	}

	logger := device.NewLogger(device.LogLevelSilent, fmt.Sprintf("[wg-tunnel:%s] ", t.name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	privKey, err := wgtypes.ParseKey(t.cfg.PrivateKey)
	if err != nil {
		dev.Close()
		return fmt.Errorf("invalid private key: %w", err)
	}
	pubKey, err := wgtypes.ParseKey(t.cfg.PublicKey)
	if err != nil {
		dev.Close()
		return fmt.Errorf("invalid public key: %w", err)
	}

	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privKey[:]))
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pubKey[:]))
	if t.cfg.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(t.cfg.PresharedKey)
		if err != nil {
			dev.Close()
			return fmt.Errorf("invalid preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(psk[:]))
	}

	resolvedAddr, err := net.ResolveUDPAddr("udp", t.cfg.Endpoint)
	if err != nil {
		dev.Close()
		return fmt.Errorf("failed to resolve wireguard endpoint %q: %w", t.cfg.Endpoint, err)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", resolvedAddr.String())

	allowedIPs := t.cfg.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
		}
	}

	keepalive := t.cfg.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)

	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return fmt.Errorf("failed to configure wireguard device: %w", err)
	}

	t.dev = dev
	t.netst = netst
	t.initTime = time.Now()
	return nil
}

func (t *WireguardTunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	t.netst = nil
	t.initTime = time.Time{} // Reset initTime on stop
}

func (t *WireguardTunnel) LastInitTime() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.initTime
}

// ReportFailure checks tunnel health and restarts if both handshake and success
// indicators are stale. IpcGet is called outside the lock to avoid deadlocks.
func (t *WireguardTunnel) ReportFailure() {
	// Phase 1: Capture state under lock
	t.mu.Lock()
	if t.dev == nil {
		t.mu.Unlock()
		return
	}
	dev := t.dev
	lastCheckTime := t.lastSuccessTime
	threshold := t.successWindow

	if lastCheckTime.IsZero() {
		lastCheckTime = t.initTime
	}
	t.mu.Unlock()

	// Phase 2: Blocking IPC call outside the lock
	lastHandshake := getHandshakeFromDevice(dev)

	// Determine if tunnel is healthy based on EITHER:
	// 1. Recent handshake (< 5 minutes), OR
	// 2. Recent success within threshold
	handshakeHealthy := !lastHandshake.IsZero() && time.Since(lastHandshake) < 5*time.Minute
	successHealthy := !lastCheckTime.IsZero() && time.Since(lastCheckTime) < threshold

	if handshakeHealthy || successHealthy {
		// Tunnel is healthy, don't restart
		if handshakeHealthy && successHealthy {
			log.Printf("[Tunnel:%s] Failure reported but tunnel healthy: handshake %v ago, last success %v ago",
				t.name, time.Since(lastHandshake).Round(time.Second), time.Since(lastCheckTime).Round(time.Second))
		} else if handshakeHealthy {
			log.Printf("[Tunnel:%s] Failure reported but tunnel healthy: recent handshake %v ago (threshold: 5m0s)",
				t.name, time.Since(lastHandshake).Round(time.Second))
		} else {
			log.Printf("[Tunnel:%s] Failure reported but tunnel healthy: last success %v ago (threshold: %v)",
				t.name, time.Since(lastCheckTime).Round(time.Second), threshold)
		}
		return
	}

	// Phase 3: Re-acquire lock for mutation
	t.mu.Lock()
	defer t.mu.Unlock()

	// Re-check dev hasn't changed while we were unlocked
	if t.dev == nil || t.dev != dev {
		return
	}

	// Neither handshake nor success are recent, restart the tunnel
	log.Printf("[Tunnel:%s] Restarting tunnel: no recent handshake or success (handshake: %v ago, success: %v ago, thresholds: 5m0s / %v)",
		t.name,
		func() string {
			if lastHandshake.IsZero() {
				return "never"
			}
			return time.Since(lastHandshake).Round(time.Second).String()
		}(),
		time.Since(lastCheckTime).Round(time.Second),
		threshold)

	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	t.netst = nil
	t.initTime = time.Time{}

	// Attempt immediate re-initialization
	log.Printf("[Tunnel:%s] Attempting re-initialization...", t.name)
	if err := t.initializeLocked(); err != nil {
		log.Printf("[Tunnel:%s] Re-init failed: %v (will retry on next dial)", t.name, err)
	} else {
		log.Printf("[Tunnel:%s] Re-initialized successfully", t.name)
	}
}

// getHandshakeFromDevice retrieves the most recent handshake timestamp from a WireGuard device.
// This is a standalone function that doesn't require any lock.
func getHandshakeFromDevice(dev WGDevice) time.Time {
	if dev == nil {
		return time.Time{}
	}

	uapi, err := dev.IpcGet()
	if err != nil {
		return time.Time{}
	}

	lines := strings.Split(uapi, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			secStr := strings.TrimPrefix(line, "last_handshake_time_sec=")
			var sec int64
			if _, err := fmt.Sscanf(secStr, "%d", &sec); err == nil && sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}

	return time.Time{}
}

// getLastHandshakeTime retrieves the most recent handshake timestamp from the WireGuard device.
// This method must be called with the mutex already locked.
func (t *WireguardTunnel) getLastHandshakeTime() time.Time {
	return getHandshakeFromDevice(t.dev)
}

func (t *WireguardTunnel) ReportSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastSuccessTime = time.Now()
}

func (t *WireguardTunnel) SetSuccessWindow(window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.successWindow = window
}

// DialContext dials through the WireGuard tunnel. If the tunnel has been destroyed
// (e.g. by ReportFailure), it attempts to re-initialize automatically.
func (t *WireguardTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.RLock()
	netst := t.netst
	t.mu.RUnlock()

	if netst == nil {
		// Attempt re-initialization
		if err := t.Initialize(); err != nil {
			return nil, fmt.Errorf("wireguard tunnel %q re-init failed: %w", t.name, err)
		}
		t.mu.RLock()
		netst = t.netst
		t.mu.RUnlock()
		if netst == nil {
			return nil, fmt.Errorf("wireguard tunnel %q not initialized", t.name)
		}
	}
	return netst.DialContext(ctx, network, address)
}

func (t *WireguardTunnel) Device() WGDevice {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dev
}

func (t *WireguardTunnel) Netstack() *netstack.Net {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.netst
}

func (t *WireguardTunnel) Config() *config.WireguardConfig { return t.cfg }

func (t *WireguardTunnel) IsStabilized() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// If never initialized, explicitly stopped, or backends not ready, not stabilized
	if t.initTime.IsZero() || t.dev == nil || t.netst == nil {
		return false
	}

	// Use a 20-second stabilization window after tunnel initialization or restart.
	gracePeriod := 20 * time.Second

	return time.Since(t.initTime) >= gracePeriod
}
