package tunnels

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"probixel/pkg/config"

	"golang.org/x/crypto/ssh"
)

type SSHTunnel struct {
	name   string
	cfg    *config.SSHConfig
	target string

	mu       sync.Mutex
	client   *ssh.Client
	initTime time.Time
}

func NewSSHTunnel(name string, target string, cfg *config.SSHConfig) *SSHTunnel {
	return &SSHTunnel{
		name:   name,
		target: target,
		cfg:    cfg,
	}
}

func (t *SSHTunnel) Name() string { return t.name }
func (t *SSHTunnel) Type() string { return "ssh" }

func (t *SSHTunnel) Initialize() error {
	if t.cfg == nil {
		return fmt.Errorf("ssh configuration missing for tunnel %q", t.name)
	}
	return nil
}

func (t *SSHTunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
}

func (t *SSHTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	client, err := t.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.Dial(network, address)
}

func (t *SSHTunnel) GetClient(ctx context.Context) (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		// Basic check if client is still alive (this isn't perfect but helps)
		_, _, err := t.client.SendRequest("keepalive@probixel", true, nil)
		if err == nil {
			return t.client, nil
		}
		_ = t.client.Close()
		t.client = nil
	}

	// Create new client
	sshConfig := &ssh.ClientConfig{
		User:            t.cfg.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         10 * time.Second,
	}

	if t.cfg.Password != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(t.cfg.Password))
	}
	if t.cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(t.cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
	}

	target := t.target
	if !strings.Contains(target, ":") {
		port := t.cfg.Port
		if port == 0 {
			port = 22
		}
		target = fmt.Sprintf("%s:%d", target, port)
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("ssh dial failed: %w", err)
	}

	c, channel, req, err := ssh.NewClientConn(conn, target, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake failed: %w", err)
	}

	t.client = ssh.NewClient(c, channel, req)
	t.initTime = time.Now()
	return t.client, nil
}

func (t *SSHTunnel) LastInitTime() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.initTime
}

func (t *SSHTunnel) ReportFailure() {
	// For SSH, close the client to force a reconnect next time.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
}

func (t *SSHTunnel) ReportSuccess() {
	// SSH tunnels don't need restart prevention logic
}

func (t *SSHTunnel) Config() *config.SSHConfig { return t.cfg }
func (t *SSHTunnel) Target() string            { return t.target }

func (t *SSHTunnel) IsStabilized() bool {
	return true // SSH currently has no stabilization window
}
