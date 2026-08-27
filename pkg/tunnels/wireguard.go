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

	endpointResolver     func(context.Context, string) (*net.UDPAddr, error)
	lastResolvedEndpoint *net.UDPAddr

	stabilizationPeriod      time.Duration
	supervisorInterval       time.Duration
	supervisorInitialBackoff time.Duration
	supervisorMaxBackoff     time.Duration
	supervisorMu             sync.Mutex
	supervisorCancel         context.CancelFunc
	supervisorDone           chan struct{}
	supervisorState          string
}

func NewWireguardTunnel(name string, cfg *config.WireguardConfig) *WireguardTunnel {
	return &WireguardTunnel{
		name:                     name,
		cfg:                      cfg,
		successWindow:            90 * time.Second, // Default: 30s max interval + 60s grace
		endpointResolver:         resolveWireguardEndpoint,
		stabilizationPeriod:      20 * time.Second,
		supervisorInterval:       30 * time.Second,
		supervisorInitialBackoff: 5 * time.Second,
		supervisorMaxBackoff:     time.Minute,
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
	t.mu.RLock()
	if t.dev != nil {
		t.mu.RUnlock()
		return nil
	}
	usesFactory := t.deviceFactory != nil
	t.mu.RUnlock()

	var resolvedEndpoint *net.UDPAddr
	if !usesFactory {
		if err := t.validateStaticConfig(); err != nil {
			return err
		}
		var err error
		resolvedEndpoint, err = t.resolveEndpoint()
		if err != nil {
			return err
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev != nil {
		return nil
	}
	if resolvedEndpoint != nil {
		t.lastResolvedEndpoint = cloneUDPAddr(resolvedEndpoint)
	}

	return t.initializeLocked(resolvedEndpoint)
}

// validateStaticConfig keeps malformed local configuration from being masked by
// an unavailable DNS resolver. It intentionally performs no network I/O.
func (t *WireguardTunnel) validateStaticConfig() error {
	if _, err := netip.ParseAddr(strings.Split(t.cfg.Addresses, "/")[0]); err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	if _, err := wgtypes.ParseKey(t.cfg.PrivateKey); err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	if _, err := wgtypes.ParseKey(t.cfg.PublicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if t.cfg.PresharedKey != "" {
		if _, err := wgtypes.ParseKey(t.cfg.PresharedKey); err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
	}
	return nil
}

// initializeLocked performs tunnel setup. Caller MUST hold t.mu.
func (t *WireguardTunnel) initializeLocked(resolvedEndpoint *net.UDPAddr) error {
	var tunDev tun.Device
	var netst *netstack.Net

	if t.deviceFactory != nil {
		dev, factoryNetst, err := t.deviceFactory()
		if err != nil {
			return err
		}
		t.dev, t.netst = dev, factoryNetst
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
			t.cfg.MTU,
		)
		if err2 != nil {
			return fmt.Errorf("failed to create netstack TUN: %w", err2)
		}
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[wg-tunnel:%s] ", t.name))
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

	if resolvedEndpoint == nil {
		dev.Close()
		return fmt.Errorf("wireguard endpoint %q was not resolved", t.cfg.Endpoint)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", resolvedEndpoint.String())

	allowedIPs := t.cfg.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}
	for cidr := range strings.SplitSeq(allowedIPs, ",") {
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

func resolveWireguardEndpoint(ctx context.Context, endpoint string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid wireguard endpoint %q: %w", endpoint, err)
	}

	portNumber, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, fmt.Errorf("invalid wireguard endpoint port %q: %w", port, err)
	}

	hosts, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve wireguard endpoint %q: %w", endpoint, err)
	}
	for _, resolvedHost := range hosts {
		if ip := net.ParseIP(resolvedHost); ip != nil {
			return &net.UDPAddr{IP: ip, Port: portNumber}, nil
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("failed to resolve wireguard endpoint %q: no addresses found", endpoint)
	}
	return nil, fmt.Errorf("failed to resolve wireguard endpoint %q: resolver returned invalid addresses", endpoint)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

// resolveEndpoint bounds DNS resolution and retains the last good result so a
// temporary DNS outage cannot turn a restart into a permanently dead tunnel.
func (t *WireguardTunnel) resolveEndpoint() (*net.UDPAddr, error) {
	t.mu.RLock()
	resolver := t.endpointResolver
	endpoint := t.cfg.Endpoint
	cached := cloneUDPAddr(t.lastResolvedEndpoint)
	t.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := resolver(ctx, endpoint)
	if err == nil {
		t.mu.Lock()
		t.lastResolvedEndpoint = cloneUDPAddr(resolved)
		t.mu.Unlock()
		return resolved, nil
	}
	if cached != nil {
		log.Printf("[Tunnel:%s] DNS resolution for %q failed: %v; reusing cached endpoint %s", t.name, endpoint, err, cached)
		return cached, nil
	}
	return nil, err
}

func (t *WireguardTunnel) Stop() {
	t.stopSupervisor()
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

type wireguardHealthSnapshot struct {
	dev       WGDevice
	lastCheck time.Time
	threshold time.Duration
}

func (t *WireguardTunnel) healthSnapshot() wireguardHealthSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	lastCheck := t.lastSuccessTime
	if lastCheck.IsZero() {
		lastCheck = t.initTime
	}
	return wireguardHealthSnapshot{dev: t.dev, lastCheck: lastCheck, threshold: t.successWindow}
}

func tunnelHealthy(lastHandshake, lastCheck time.Time, threshold time.Duration) bool {
	handshakeHealthy := !lastHandshake.IsZero() && time.Since(lastHandshake) < 5*time.Minute
	successHealthy := !lastCheck.IsZero() && time.Since(lastCheck) < threshold
	return handshakeHealthy || successHealthy
}

// restartIfUnhealthy applies the common restart decision after a handshake read.
// It returns true only when it closed the same device that was inspected.
func (t *WireguardTunnel) restartIfUnhealthy(snapshot wireguardHealthSnapshot, lastHandshake time.Time) bool {
	if snapshot.dev == nil || tunnelHealthy(lastHandshake, snapshot.lastCheck, snapshot.threshold) {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev == nil || t.dev != snapshot.dev {
		return false
	}
	t.dev.Close()
	t.dev = nil
	t.netst = nil
	t.initTime = time.Time{}
	return true
}

// ReportFailure checks tunnel health and restarts if both handshake and success
// indicators are stale. IpcGet is called outside the lock to avoid deadlocks.
func (t *WireguardTunnel) ReportFailure() {
	snapshot := t.healthSnapshot()
	if snapshot.dev == nil {
		return
	}
	lastHandshake := getHandshakeFromDevice(snapshot.dev)
	if !t.restartIfUnhealthy(snapshot, lastHandshake) {
		return
	}

	t.logSupervisorState("restarting", "[Tunnel:%s] Restarting tunnel after reported failure", t.name)
	if err := t.Initialize(); err != nil {
		t.logSupervisorState("retrying", "[Tunnel:%s] Re-initialization failed: %v; supervisor will retry", t.name, err)
		return
	}
	t.logSupervisorState("active", "[Tunnel:%s] Re-initialized successfully", t.name)
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

	lines := strings.SplitSeq(uapi, "\n")
	for line := range lines {
		if after, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			secStr := after
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

func (t *WireguardTunnel) SuccessWindow() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.successWindow
}

// SetStabilizationPeriod controls how long a newly created tunnel reports
// Pending. It is primarily useful for deterministic lifecycle tests.
func (t *WireguardTunnel) SetStabilizationPeriod(period time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stabilizationPeriod = period
}

// StartSupervisor starts the tunnel's independent recovery loop. It is safe to
// call more than once; only one loop may run for a tunnel.
func (t *WireguardTunnel) StartSupervisor(parent context.Context) {
	t.supervisorMu.Lock()
	if t.supervisorDone != nil {
		t.supervisorMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	t.supervisorCancel = cancel
	t.supervisorDone = done
	t.supervisorMu.Unlock()

	go func() {
		defer close(done)
		defer func() {
			t.supervisorMu.Lock()
			if t.supervisorDone == done {
				t.supervisorDone = nil
				t.supervisorCancel = nil
				t.supervisorState = ""
			}
			t.supervisorMu.Unlock()
		}()
		t.runSupervisor(ctx)
	}()
}

func (t *WireguardTunnel) stopSupervisor() {
	t.supervisorMu.Lock()
	cancel := t.supervisorCancel
	done := t.supervisorDone
	t.supervisorMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (t *WireguardTunnel) runSupervisor(ctx context.Context) {
	backoff := t.supervisorInitialBackoff
	delay := time.Duration(0)
	for {
		if !waitForSupervisor(ctx, delay) {
			return
		}

		if t.superviseOnce() {
			backoff = t.supervisorInitialBackoff
			delay = t.supervisorInterval
			continue
		}

		delay = backoff
		backoff *= 2
		if backoff > t.supervisorMaxBackoff {
			backoff = t.supervisorMaxBackoff
		}
	}
}

func waitForSupervisor(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// superviseOnce attempts an unavailable tunnel, or restarts one whose
// handshake and service-success signals are both stale.
func (t *WireguardTunnel) superviseOnce() bool {
	snapshot := t.healthSnapshot()
	if snapshot.dev == nil {
		if err := t.Initialize(); err != nil {
			t.logSupervisorState("retrying", "[Tunnel:%s] Supervisor initialization failed: %v; retrying with backoff", t.name, err)
			return false
		}
		t.logSupervisorState("active", "[Tunnel:%s] Supervisor initialized tunnel", t.name)
		return true
	}

	lastHandshake := getHandshakeFromDevice(snapshot.dev)
	if !t.restartIfUnhealthy(snapshot, lastHandshake) {
		t.logSupervisorState("active", "[Tunnel:%s] Supervisor sees healthy tunnel", t.name)
		return true
	}

	t.logSupervisorState("restarting", "[Tunnel:%s] Supervisor restarting stale tunnel", t.name)
	if err := t.Initialize(); err != nil {
		t.logSupervisorState("retrying", "[Tunnel:%s] Supervisor restart failed: %v; retrying with backoff", t.name, err)
		return false
	}
	t.logSupervisorState("active", "[Tunnel:%s] Supervisor restarted tunnel", t.name)
	return true
}

func (t *WireguardTunnel) logSupervisorState(state, format string, args ...any) {
	t.supervisorMu.Lock()
	changed := t.supervisorState != state
	if changed {
		t.supervisorState = state
	}
	t.supervisorMu.Unlock()
	if changed {
		log.Printf(format, args...)
	}
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

	return time.Since(t.initTime) >= t.stabilizationPeriod
}
