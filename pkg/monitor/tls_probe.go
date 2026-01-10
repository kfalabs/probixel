package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"probixel/pkg/tunnels"
)

type TLSProbe struct {
	targetMode         string
	ExpiryThreshold    time.Duration
	InsecureSkipVerify bool
	Timeout            time.Duration
	DialContext        func(ctx context.Context, network, address string) (net.Conn, error)
	tunnel             tunnels.Tunnel
}

func (p *TLSProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *TLSProbe) Name() string {
	return MonitorTypeTLS
}

func (p *TLSProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *TLSProbe) Check(ctx context.Context, target string) (Result, error) {
	var lastErr error
	startTotal := time.Now()

	// Strict stabilization adherence: always return Pending if tunnel not stabilized
	if p.tunnel != nil && !p.tunnel.IsStabilized() {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(startTotal),
			Message:   fmt.Sprintf("waiting for tunnel %q to stabilize", p.tunnel.Name()),
			Timestamp: startTotal,
		}, nil
	}

	// Use threshold from config
	threshold := p.ExpiryThreshold

	targets := strings.Split(target, ",")
	// Handle tls:// scheme if present
	for i, t := range targets {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, "tls://") {
			targets[i] = strings.TrimPrefix(t, "tls://")
		} else {
			targets[i] = t
		}
	}

	if p.targetMode == TargetModeAll {
		successCount := 0
		var totalDuration time.Duration

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			res, err := p.checkTarget(ctx, t, threshold)
			if err != nil || !res.Success {
				errMsg := fmt.Sprintf("target %s failed", t)
				if err != nil {
					errMsg = fmt.Sprintf("%s: %v", errMsg, err)
				} else {
					errMsg = fmt.Sprintf("%s: %s", errMsg, res.Message)
				}
				return Result{
					Success:   false,
					Message:   errMsg,
					Timestamp: startTotal,
				}, nil
			}
			totalDuration += res.Duration
			successCount++
		}

		if successCount > 0 {
			return Result{
				Success:   true,
				Duration:  totalDuration / time.Duration(successCount),
				Message:   fmt.Sprintf("all %d certs OK", successCount),
				Timestamp: startTotal,
			}, nil
		}
	}

	// Default "any" mode
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		res, err := p.checkTarget(ctx, t, threshold)
		if err == nil && res.Success {
			return res, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s", res.Message)
		}
	}

	return Result{
		Success:   false,
		Message:   fmt.Sprintf("all targets failed, last error: %v", lastErr),
		Timestamp: startTotal,
	}, nil
}

func (p *TLSProbe) checkTarget(ctx context.Context, target string, threshold time.Duration) (Result, error) {
	start := time.Now()

	// Ensure target has a port
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// Try adding default HTTPS port if missing
		host = target
		target = net.JoinHostPort(host, "443")
	}

	dialer := p.DialContext
	if dialer == nil {
		timeout := p.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		d := net.Dialer{Timeout: timeout}
		dialer = d.DialContext
	}

	rawConn, err := dialer(ctx, "tcp", target)
	if err != nil {
		return Result{}, err
	}

	conn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: p.InsecureSkipVerify, // nolint:gosec // deliberate feature
		ServerName:         host,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return Result{}, err
	}
	defer func() { _ = conn.Close() }()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return Result{
			Success:   false,
			Message:   "no certificates found",
			Timestamp: start,
		}, nil
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	expiry := cert.NotAfter
	remaining := time.Until(expiry)

	if remaining < 0 {
		return Result{
			Success:   false,
			Message:   fmt.Sprintf("certificate EXPIRED on %s", expiry.Format("2006-01-02")),
			Timestamp: start,
		}, nil
	}

	if remaining < threshold {
		remainingDays := int(remaining.Hours() / 24)
		return Result{
			Success:   false,
			Message:   fmt.Sprintf("certificate expires soon: %d days remaining (threshold: %v)", remainingDays, threshold),
			Timestamp: start,
		}, nil
	}

	daysRemaining := int(remaining.Hours() / 24)
	return Result{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("OK (expires in %d days)", daysRemaining),
		Target:    target,
		Timestamp: start,
	}, nil
}
func (p *TLSProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
