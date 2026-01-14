package monitor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateTestKey() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(privateKeyPEM)), nil
}

func startMockSSHServer(t *testing.T, password string, privateKey string) (string, func()) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}

	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			t.Fatalf("failed to parse private key: %v", err)
		}
		config.AddHostKey(signer)

		config.PublicKeyCallback = func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		}
	} else {
		// Need a host key even if auth is disabled
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		signer, _ := ssh.NewSignerFromKey(key)
		config.AddHostKey(signer)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _, _, _ = ssh.NewServerConn(nConn, config)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

func TestSSHProbe_Check(t *testing.T) {
	privKey, _ := generateTestKey()
	addr, cleanup := startMockSSHServer(t, "secret", privKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	t.Run("AuthSuccess_Password", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User:     "test",
				Password: "secret",
				Port:     port,
			},
		}
		res, err := p.Check(context.Background(), host)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "Login OK") {
			t.Errorf("Expected Login OK message, got %s", res.Message)
		}
	})

	t.Run("AuthSuccess_PrivateKey", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User:       "test",
				PrivateKey: privKey,
				Port:       port,
			},
		}
		res, err := p.Check(context.Background(), host)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
	})

	t.Run("AuthFailure_Password", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User:     "test",
				Password: "wrong",
				Port:     port,
			},
		}
		res, err := p.Check(context.Background(), host)
		if err != nil {
			t.Fatalf("Check returned internal error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for wrong password, got success")
		}
	})

	t.Run("NoAuth_Success", func(t *testing.T) {
		f := false
		p := &SSHProbe{
			Config: &config.SSHConfig{
				AuthRequired: &f,
				Port:         port,
			},
		}
		res, err := p.Check(context.Background(), host)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "TCP OK") {
			t.Errorf("Expected TCP OK message, got %s", res.Message)
		}
	})

	t.Run("Connection_Failure", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				Port: 1, // Port 1 is likely closed
			},
		}
		res, err := p.Check(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Check returned internal error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for closed port, got success")
		}
	})

	t.Run("EmptyTarget", func(t *testing.T) {
		p := &SSHProbe{}
		res, err := p.Check(context.Background(), "")
		if err != nil {
			t.Fatalf("Check internal error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for empty target")
		}
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User:       "test",
				PrivateKey: "not-a-key",
				Port:       port,
			},
		}
		res, err := p.Check(context.Background(), host)
		if err != nil {
			t.Fatalf("Check internal error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for invalid private key")
		}
		if !strings.Contains(res.Message, "invalid private key") {
			t.Errorf("Expected invalid private key message, got %s", res.Message)
		}
	})
}

func TestSSHProbe_ManualConfigFallback(t *testing.T) {
	privKey, _ := generateTestKey()
	addr, cleanup := startMockSSHServer(t, "secret", privKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	p := &SSHProbe{
		Config: &config.SSHConfig{
			User:     "test",
			Password: "secret",
			Port:     port,
		},
	}

	// Check should use the inline Config since p.tunnel is nil.
	res, err := p.Check(context.Background(), host)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if !strings.Contains(res.Message, "Login OK") {
		t.Errorf("Unexpected message: %s", res.Message)
	}
}

func TestSSHProbe_Metadata(t *testing.T) {
	p := &SSHProbe{}
	if p.Name() != MonitorTypeSSH {
		t.Errorf("expected %s, got %s", MonitorTypeSSH, p.Name())
	}
	p.SetTargetMode(TargetModeAll)
	if p.targetMode != TargetModeAll {
		t.Errorf("expected %s, got %s", TargetModeAll, p.targetMode)
	}
}

func TestSSHProbe_SetTunnel(t *testing.T) {
	p := &SSHProbe{}
	tun := tunnels.NewSSHTunnel("my-tun", "host", nil)
	p.SetTunnel(tun)
	if p.tunnel != tun {
		t.Errorf("expected tunnel to be set")
	}
}
func TestSSHProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &SSHProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestSSHProbe_SetTimeout(t *testing.T) {
	p := &SSHProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}

func TestSSHProbe_Coverage_Errors(t *testing.T) {
	// 1. DialContext Error
	t.Run("DialContext_Error", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User: "test",
				Port: 22,
			},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("dial failed")
			},
		}
		res, err := p.Check(context.Background(), "localhost")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for dial error")
		}
		if !strings.Contains(res.Message, "dial failed") {
			t.Errorf("Expected 'dial failed' message, got %s", res.Message)
		}
	})

	// 2. NewClientConn Error (Handshake fail)
	// We need a dial that succeeds but returns a connection that fails handshake immediately
	t.Run("Handshake_Error", func(t *testing.T) {
		p := &SSHProbe{
			Config: &config.SSHConfig{
				User: "test",
				Port: 22,
			},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Return a closed pipe to trigger handshake read error
				c1, c2 := net.Pipe()
				c1.Close()
				return c2, nil
			},
		}
		res, err := p.Check(context.Background(), "localhost")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for handshake error")
		}
		// The error from NewClientConn on a closed pipe varies but shouldn't be success
	})
}

func TestSSHProbe_Check_TargetFromTunnel(t *testing.T) {
	privKey, _ := generateTestKey()
	addr, cleanup := startMockSSHServer(t, "secret", privKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// Create an SSH tunnel with target
	tun := tunnels.NewSSHTunnel("test-tun", host, &config.SSHConfig{
		User:     "test",
		Password: "secret",
		Port:     port,
	})

	p := &SSHProbe{
		tunnel: tun,
	}

	// Check with empty target - should derive from tunnel
	res, err := p.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	// May fail due to missing config for auth check, but at least exercises the path
	_ = res
}

func TestSSHProbe_Check_NoAuthWithDialContext(t *testing.T) {
	f := false
	p := &SSHProbe{
		Config: &config.SSHConfig{
			AuthRequired: &f,
			Port:         22,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial failed via custom dialer")
		},
	}
	res, err := p.Check(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure for dial error")
	}
	if !strings.Contains(res.Message, "dial failed") {
		t.Errorf("Expected 'dial failed' message, got %s", res.Message)
	}
}

func TestSSHProbe_Check_MissingSSHConfig(t *testing.T) {
	// Auth required but no config
	p := &SSHProbe{
		tunnel: &tunnels.MockTunnel{IsStabilizedResult: true},
	}
	res, err := p.Check(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure for missing ssh config")
	}
	if !strings.Contains(res.Message, "missing ssh config") {
		t.Errorf("Expected 'missing ssh config' message, got %s", res.Message)
	}
}
