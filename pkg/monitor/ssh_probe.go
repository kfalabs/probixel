package monitor

import (
	"context"
	"fmt"
	"net"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHProbe struct {
	Config      *config.SSHConfig
	targetMode  string
	Timeout     time.Duration
	tunnel      tunnels.Tunnel
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	signer      ssh.Signer // cached parsed private key
	signerOnce  sync.Once
	signerErr   error
}

func (p *SSHProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *SSHProbe) Name() string {
	return MonitorTypeSSH
}

func (p *SSHProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *SSHProbe) Check(ctx context.Context, target string) (Result, error) {
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

	// If tunnel is provided, use its target unless overridden
	if p.tunnel != nil && target == "" {
		if st, ok := p.tunnel.(*tunnels.SSHTunnel); ok {
			target = st.Target()
		}
	}

	// SSH is restricted to a single target
	res := p.checkOne(ctx, target)
	res.Timestamp = startTotal
	return res, nil
}

func (p *SSHProbe) checkOne(ctx context.Context, target string) Result {
	target = strings.TrimSpace(target)
	if target == "" {
		return Result{Success: false, Message: "empty target"}
	}

	cfg := p.Config
	if p.tunnel != nil && cfg == nil {
		if st, ok := p.tunnel.(*tunnels.SSHTunnel); ok {
			cfg = st.Config()
		}
	}

	port := 22
	if cfg != nil && cfg.Port != 0 {
		port = cfg.Port
	}

	host := target
	if !strings.Contains(target, ":") {
		host = fmt.Sprintf("%s:%d", target, port)
	}

	start := time.Now()

	authRequired := true
	if cfg != nil && cfg.AuthRequired != nil {
		authRequired = *cfg.AuthRequired
	}

	if !authRequired {
		// Just check TCP connection
		conn, err := p.dialSSH(ctx, host)
		if err != nil {
			return Result{Success: false, Message: err.Error()}
		}
		_ = conn.Close()
		return Result{Success: true, Duration: time.Since(start), Message: "TCP OK", Target: target}
	}

	// Auth required
	if cfg == nil {
		return Result{Success: false, Message: "missing ssh config for authenticated check"}
	}

	var authMethods []ssh.AuthMethod
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if cfg.PrivateKey != "" {
		p.signerOnce.Do(func() {
			p.signer, p.signerErr = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		})
		if p.signerErr != nil {
			return Result{Success: false, Message: fmt.Sprintf("invalid private key: %v", p.signerErr)}
		}
		authMethods = append(authMethods, ssh.PublicKeys(p.signer))
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // G106: monitoring targets do not require a pre-managed known_hosts file.
		Timeout:         timeout,
	}

	conn, err := p.dialSSH(ctx, host)
	if err != nil {
		return Result{Success: false, Message: err.Error()}
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, host, sshConfig)
	if err != nil {
		_ = conn.Close()
		return Result{Success: false, Message: err.Error()}
	}

	client := ssh.NewClient(ncc, chans, reqs)
	_ = client.Close()

	return Result{Success: true, Duration: time.Since(start), Message: "Login OK", Target: target}
}

func (p *SSHProbe) dialSSH(ctx context.Context, host string) (net.Conn, error) {
	if p.DialContext != nil {
		return p.DialContext(ctx, "tcp", host)
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", host)
}

func (p *SSHProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
