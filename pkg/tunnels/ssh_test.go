package tunnels

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"probixel/pkg/config"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHTunnel(t *testing.T) {
	cfg := &config.SSHConfig{User: "testuser"}
	target := "1.2.3.4"
	name := "ssh-t1"

	s := NewSSHTunnel(name, target, cfg)

	if s.Name() != name {
		t.Errorf("expected %s, got %s", name, s.Name())
	}
	if s.Type() != "ssh" {
		t.Errorf("expected ssh, got %s", s.Type())
	}
	if s.Target() != target {
		t.Errorf("expected %s, got %s", target, s.Target())
	}
	if s.Config() != cfg {
		t.Error("config mismatch")
	}

	if err := s.Initialize(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	s.Stop() // Should not crash

	s2 := NewSSHTunnel("s2", "target", nil)
	if err := s2.Initialize(); err == nil {
		t.Error("expected error for nil config")
	}
}

func TestSSHTunnel_Integration(t *testing.T) {
	// 1. Setup mock SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	sshAddr := listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(sshAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil // Accept any for mock
		},
	}
	// Need a host key
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := ssh.NewSignerFromKey(key)
	serverConfig.AddHostKey(signer)

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				sConn, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				defer sConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "direct-tcpip" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					// Just accept and close for test
					ch, _, _ := newChan.Accept()
					ch.Close()
				}
			}()
		}
	}()

	// 2. Test Tunnel
	cfg := &config.SSHConfig{
		User:     "test",
		Password: "secret",
		Port:     port,
	}
	tun := NewSSHTunnel("test-tun", host, cfg)

	t.Run("Initialize", func(t *testing.T) {
		if err := tun.Initialize(); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
	})

	t.Run("DialContext Success", func(t *testing.T) {
		// Mock a target to dial to (the SSH server itself works as a dummy target)
		conn, err := tun.DialContext(context.Background(), "tcp", "127.0.0.1:22")
		if err != nil {
			t.Fatalf("DialContext failed: %v", err)
		}
		if conn == nil {
			t.Fatal("expected conn, got nil")
		}
		conn.Close()
	})

	t.Run("Caching", func(t *testing.T) {
		client1, err := tun.GetClient(context.Background())
		if err != nil {
			t.Fatalf("getClient 1 failed: %v", err)
		}
		client2, err := tun.GetClient(context.Background())
		if err != nil {
			t.Fatalf("getClient 2 failed: %v", err)
		}
		if client1 != client2 {
			t.Error("expected cached client to be returned")
		}
	})

	t.Run("Stop and Restart", func(t *testing.T) {
		tun.Stop()
		if tun.client != nil {
			t.Error("client should be nil after stop")
		}
		// Should reconnect
		conn, err := tun.DialContext(context.Background(), "tcp", "127.0.0.1:22")
		if err != nil {
			t.Fatalf("DialContext failed after stop: %v", err)
		}
		conn.Close()
	})

	t.Run("Private Key Auth", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		privKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		tun2 := NewSSHTunnel("pk-tun", host, &config.SSHConfig{
			User:       "pk-user",
			PrivateKey: string(privKeyPEM),
			Port:       port,
		})
		conn, err := tun2.DialContext(context.Background(), "tcp", "127.0.0.1:22")
		if err != nil {
			t.Fatalf("Private key dial failed: %v", err)
		}
		conn.Close()
	})
}

func TestSSHTunnel_HandshakeError(t *testing.T) {
	// Start a non-SSH TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Write garbage and close
			conn.Write([]byte("NOT SSH\n"))
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	tun := NewSSHTunnel("fail-tun", host, &config.SSHConfig{
		User:     "user",
		Password: "password",
		Port:     port,
	})

	_, err = tun.DialContext(context.Background(), "tcp", "google.com:80")
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
}

func TestSSHTunnel_ReconnectOnFailure(t *testing.T) {
	// 1. Start a flaky server that can be stopped and started
	startServer := func() (net.Listener, int) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(l.Addr().String())
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		serverConfig := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return nil, nil
			},
		}
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		signer, _ := ssh.NewSignerFromKey(key)
		serverConfig.AddHostKey(signer)

		go func() {
			for {
				nConn, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					_, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
					if err != nil {
						nConn.Close()
						return
					}
					go ssh.DiscardRequests(reqs)
					for newChan := range chans {
						newChan.Reject(ssh.Prohibited, "no channels")
					}
				}()
			}
		}()
		return l, port
	}

	// 2. Start initial server
	l1, port := startServer()
	defer l1.Close()

	// 3. Connect
	tun := NewSSHTunnel("reconnect-tun", "127.0.0.1", &config.SSHConfig{
		User:     "user",
		Password: "pwd",
		Port:     port,
	})

	// Initial connection
	if _, err := tun.GetClient(context.Background()); err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}

	conns := make(chan net.Conn, 1)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen 2: %v", err)
	}
	defer l2.Close()
	_, portStr, _ := net.SplitHostPort(l2.Addr().String())
	var p2 int
	fmt.Sscanf(portStr, "%d", &p2)

	// Server loop
	go func() {
		for {
			c, err := l2.Accept()
			if err != nil {
				return
			}

			// Store connection to be closed later.
			conns <- c

			// Handle SSH handshake
			go func(c net.Conn) {
				serverConfig := &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				}
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				signer, _ := ssh.NewSignerFromKey(key)
				serverConfig.AddHostKey(signer)

				ssh.NewServerConn(c, serverConfig)
				// Ignore result, just keeping it open until it closes.
			}(c)
		}
	}()

	tun2 := NewSSHTunnel("rec-tun-2", "127.0.0.1", &config.SSHConfig{
		User: "u", Password: "p", Port: p2,
	})

	// 1. Get Client (Connects)
	if _, err := tun2.GetClient(context.Background()); err != nil {
		t.Fatalf("connect 1 failed: %v", err)
	}

	// 2. Kill the server-side connection
	serverConn := <-conns
	serverConn.Close()

	// 3. Get Client again. Should detect failure and reconnect.
	// Note: Verify the server is ready to accept again. The loop is still running.
	// There is a small race where the client might not have detected the close yet
	// (keepalive is active check, so strictly calling getClient sends a packet).
	// If SendRequest returns error, it reconnects.

	if _, err := tun2.GetClient(context.Background()); err != nil {
		t.Fatalf("reconnect failed: %v", err)
	}
}

func TestSSHTunnel_StatusMethods(t *testing.T) {
	tun := NewSSHTunnel("status-tun", "127.0.0.1", &config.SSHConfig{
		User: "u",
	})

	// Check initial state
	if !tun.LastInitTime().IsZero() {
		t.Error("expected zero init time initially")
	}

	// Report methods (should not panic)
	tun.ReportSuccess()
	tun.ReportFailure()

	_ = tun.IsStabilized()
}

func TestSSHTunnel_ReportFailure_WithClient(t *testing.T) {
	// 1. Start a mock SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := ssh.NewSignerFromKey(key)
	serverConfig.AddHostKey(signer)

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
			}()
		}
	}()

	// 2. Create and connect tunnel
	tun := NewSSHTunnel("failure-test", host, &config.SSHConfig{
		User:     "test",
		Password: "test",
		Port:     port,
	})

	// Connect first
	_, err = tun.GetClient(context.Background())
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	// 3. Verify client exists before
	if tun.client == nil {
		t.Fatal("expected client to be non-nil")
	}

	// 4. Call ReportFailure
	tun.ReportFailure()

	// 5. Verify client is now nil
	if tun.client != nil {
		t.Error("expected client to be nil after ReportFailure")
	}
}
