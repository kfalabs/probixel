package monitor

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"probixel/pkg/config"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDevice is an interface for WireGuard device interactions, allowing for mocking in tests.
type WGDevice interface {
	IpcGet() (string, error)
	IpcSet(conf string) error
	Up() error
	Close()
}

type WireguardProbe struct {
	Config     *config.WireguardConfig
	targetMode string
	dev        WGDevice
	netst      *netstack.Net
	initTime   time.Time
}

func (p *WireguardProbe) Name() string {
	return MonitorTypeWireguard
}

func (p *WireguardProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *WireguardProbe) Initialize() error {
	if p.Config == nil {
		return fmt.Errorf("wireguard configuration missing")
	}
	if p.dev != nil {
		return nil
	}
	dev, netst, err := p.initDevice()
	if err != nil {
		return err
	}
	p.dev = dev
	p.netst = netst
	p.initTime = time.Now()
	return nil
}

func (p *WireguardProbe) stop() {
	if p.dev != nil {
		p.dev.Close()
		p.dev = nil
	}
	p.netst = nil // device.Close() should have closed the underlying TUN/netstack
}

func (p *WireguardProbe) ping(ctx context.Context, target string) error {
	if p.netst == nil {
		return fmt.Errorf("netstack not initialized")
	}

	// Use the same approach as the official wireguard-go ping_client.go example
	socket, err := p.netst.Dial("ping4", target)
	if err != nil {
		return fmt.Errorf("dial ping4 failed: %w", err)
	}
	defer func() { _ = socket.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = socket.SetReadDeadline(deadline)
	}

	// Write the full ICMP message (header + body) - this is what the official example does
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PROBIXEL"),
		},
	}

	icmpBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	if _, err := socket.Write(icmpBytes); err != nil {
		return fmt.Errorf("ping write: %w", err)
	}

	reply := make([]byte, 1500)
	n, err := socket.Read(reply)
	if err != nil {
		return fmt.Errorf("ping read: %w", err)
	}

	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return fmt.Errorf("parse failed (n=%d): %v", n, err)
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return nil
	default:
		return fmt.Errorf("unexpected ICMP type: %v", rm.Type)
	}
}

func (p *WireguardProbe) Check(ctx context.Context, target string) (Result, error) {
	start := time.Now()
	_ = target // WireGuard probe is single-target per service

	if p.Config == nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   "wireguard configuration missing",
			Timestamp: start,
		}, nil
	}

	// Initialize device if not already done
	if err := p.Initialize(); err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to initialize wireguard device: %v", err),
			Timestamp: start,
		}, nil
	}

	var maxAge time.Duration
	if p.Config.MaxAge != "" {
		var err error
		maxAge, err = config.ParseDuration(p.Config.MaxAge)
		if err != nil {
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   fmt.Sprintf("invalid max_age: %v", err),
				Timestamp: start,
			}, nil
		}
	}

	uapi, err := p.dev.IpcGet()
	if err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to get wireguard status: %v", err),
			Timestamp: start,
		}, nil
	}

	lastHandshake, err := parseLatestHandshake(uapi)
	if err != nil {
		p.stop()
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to get handshake time: %v", err),
			Timestamp: start,
		}, nil
	}

	// If no targets, handshake check is required.
	if target == "" {
		if maxAge == 0 {
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   "no targets and no max_age provided - nothing to monitor",
				Timestamp: start,
			}, nil
		}

		if lastHandshake.IsZero() {
			if time.Since(p.initTime) < 20*time.Second {
				return Result{
					Success:   false,
					Duration:  time.Since(start),
					Message:   fmt.Sprintf("waiting for handshake (%s passed)", time.Since(p.initTime).Round(time.Second)),
					Timestamp: start,
				}, nil
			}
			p.stop()
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   "no handshake yet -> restarting interface",
				Timestamp: start,
			}, nil
		}

		age := time.Since(lastHandshake)
		if age > maxAge {
			p.stop()
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   fmt.Sprintf("handshake stale: %s (limit: %s) -> restarting interface", age.Round(time.Second), maxAge),
				Timestamp: start,
			}, nil
		}

		return Result{
			Success:   true,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("OK (last handshake %s ago)", age.Round(time.Second)),
			Timestamp: start,
		}, nil
	}

	// target != "": Check connectivity
	targets := strings.Split(target, ",")
	var successes int
	var details []string

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// Check if target is the local interface address
		localIP := strings.Split(p.Config.Addresses, "/")[0]
		if t == localIP {
			// Pinging ourselves. This check succeeds if the stack is initialized.
			successes++
			details = append(details, fmt.Sprintf("Ping %s OK (self)", t))
			if p.targetMode == TargetModeAny {
				break
			}
			continue
		}

		// Check if target has a port
		host, port, splitErr := net.SplitHostPort(t)
		isTCP := splitErr == nil && port != ""

		var checkErr error
		typeStr := "Ping"
		if isTCP {
			typeStr = "TCP"
			if p.netst == nil {
				checkErr = fmt.Errorf("netstack not initialized")
			} else {
				dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
				conn, err := p.netst.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
				dialCancel()
				if err == nil {
					_ = conn.Close()
				} else {
					checkErr = err
				}
			}
		} else {
			// Shorter timeout for ICMP since it's userspace and often targets self/local
			dialCtx, dialCancel := context.WithTimeout(ctx, 1*time.Second)
			checkErr = p.ping(dialCtx, t)
			dialCancel()
		}

		if checkErr == nil {
			successes++
			details = append(details, fmt.Sprintf("%s %s OK", typeStr, t))
			if p.targetMode == TargetModeAny {
				break
			}
		} else {
			details = append(details, fmt.Sprintf("%s %s failed: %v", typeStr, t, checkErr))
		}
	}

	success := false
	if p.targetMode == TargetModeAll {
		success = successes == len(targets)
	} else {
		success = successes > 0
	}

	if !success {
		if p.Config.SuccessOnHeartbeat && !lastHandshake.IsZero() && maxAge > 0 {
			age := time.Since(lastHandshake)
			if age <= maxAge {
				success = true
				details = append(details, fmt.Sprintf("heartbeat OK (%s ago)", age.Round(time.Second)))
			}
		}
	}

	if !success {
		// Even if connectivity fails, wait for the grace period before restarting.
		if time.Since(p.initTime) < 20*time.Second {
			message := strings.Join(details, "; ")
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   fmt.Sprintf("%s (waiting for connectivity, %s passed)", message, time.Since(p.initTime).Round(time.Second)),
				Timestamp: start,
			}, nil
		}

		p.stop()
		msg := fmt.Sprintf("connectivity check failed (mode: %s): %s -> restarting interface", p.targetMode, strings.Join(details, "; "))
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   msg,
			Timestamp: start,
		}, nil
	}

	msg := strings.Join(details, "; ")
	if !lastHandshake.IsZero() {
		msg = fmt.Sprintf("%s (last handshake %s ago)", msg, time.Since(lastHandshake).Round(time.Second))
	} else {
		msg = fmt.Sprintf("%s (no handshake yet)", msg)
	}
	return Result{
		Success:   true,
		Duration:  time.Since(start),
		Message:   msg,
		Timestamp: start,
	}, nil
}

func (p *WireguardProbe) initDevice() (WGDevice, *netstack.Net, error) {
	// Create TUN
	localAddr, err := netip.ParseAddr(strings.Split(p.Config.Addresses, "/")[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address: %w", err)
	}

	tunDev, netst, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{}, // DNS
		1420,           // MTU
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create netstack TUN: %w", err)
	}

	logger := device.NewLogger(device.LogLevelSilent, "[wireguard-probe] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	privKey, err := wgtypes.ParseKey(p.Config.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}
	pubKey, err := wgtypes.ParseKey(p.Config.PublicKey)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	uapiConf := "replace_peers=true\n"
	uapiConf += fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privKey[:]))
	uapiConf += fmt.Sprintf("public_key=%s\n", hex.EncodeToString(pubKey[:]))
	if p.Config.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.Config.PresharedKey)
		if err != nil {
			dev.Close()
			return nil, nil, fmt.Errorf("invalid preshared key: %w", err)
		}
		uapiConf += fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(psk[:]))
	}
	// Resolve endpoint hostname to IP (WireGuard UAPI requires numeric IP)
	resolvedAddr, err := net.ResolveUDPAddr("udp", p.Config.Endpoint)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to resolve wireguard endpoint %q: %w", p.Config.Endpoint, err)
	}
	uapiConf += fmt.Sprintf("endpoint=%s\n", resolvedAddr.String())

	allowedIPs := p.Config.AllowedIPs
	if allowedIPs == "" {
		// Default: route all IPv4 traffic to the peer
		allowedIPs = "0.0.0.0/0"
	}
	// UAPI requires separate allowed_ip= lines for each CIDR
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			uapiConf += fmt.Sprintf("allowed_ip=%s\n", cidr)
		}
	}

	keepalive := p.Config.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}
	uapiConf += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive)

	if err := dev.IpcSet(uapiConf); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to configure wireguard device: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to bring up wireguard device: %w", err)
	}

	return dev, netst, nil
}

func parseLatestHandshake(uapi string) (time.Time, error) {
	lines := strings.Split(uapi, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			secStr := strings.TrimPrefix(line, "last_handshake_time_sec=")
			var sec int64
			if _, err := fmt.Sscanf(secStr, "%d", &sec); err != nil {
				return time.Time{}, err
			}
			if sec == 0 {
				return time.Time{}, nil
			}
			// Check for nsec if available (usually next line)
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, nil
}
