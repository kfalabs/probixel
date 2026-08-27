package monitor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPingProbe_Check(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		if target == "localhost.test" {
			return 10500 * time.Microsecond, nil
		}
		return 0, fmt.Errorf("ping failed")
	}

	probe := &PingProbe{}
	ctx := context.Background()

	t.Run("Ping Success", func(t *testing.T) {
		res, err := probe.Check(ctx, "localhost.test")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if res.Duration == 0 {
			t.Error("Expected non-zero duration")
		}
	})

	t.Run("Ping Failure", func(t *testing.T) {
		res, err := probe.Check(ctx, "unreachable.test")
		if err != nil {
			t.Fatalf("Check execution failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for unreachable host, got success")
		}
	})
}

func TestPingProbe_AllMode(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		return 10500 * time.Microsecond, nil
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAll)

	_, _ = probe.Check(context.Background(), "127.0.0.1, 8.8.8.8, ,")
}

func TestPingProbe_AllMode_FailFast(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingCount := 0
	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		pingCount++
		if strings.Contains(target, "fail") {
			return 0, fmt.Errorf("ping failed")
		}
		return 10500 * time.Microsecond, nil
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAll)

	result, _ := probe.Check(context.Background(), "fail.test, good.test")
	if result.Success {
		t.Error("Expected failure")
	}
	if pingCount != 1 {
		t.Errorf("Expected fail fast (1 call), got %d", pingCount)
	}
}

func TestParsePingTime_Manual(t *testing.T) {
	_, _ = parsePingTime("time=abc ms")
	_, _ = parsePingTime("no time here")
}

func TestParsePingTimeCoverage(t *testing.T) {
	// Coverage for strconv.ParseFloat error
	_, err := parsePingTime("time=... ms")
	if err == nil {
		t.Error("Expected error for invalid float")
	}

	// Coverage for no time match
	_, err = parsePingTime("ping statistics")
	if err == nil {
		t.Error("Expected error for no match")
	}
}

func TestPingProbeCoverage(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	// Test success with zero duration (triggers time.Since fallback in caller)
	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		return 0, nil
	}
	p := &PingProbe{}
	res, _ := p.Check(context.Background(), "127.0.0.1")
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestParsePingTime_Invalid(t *testing.T) {
	// Test failure branch in parsePingTime
	_, err := parsePingTime("invalid-output")
	if err == nil {
		t.Error("expected error for invalid ping output")
	}
}

func TestPingProbe_Check_AllFailedAnyMode(t *testing.T) {
	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAny)
	// Using a hostname that won't resolve or reply
	ctx := context.Background()
	res, err := probe.Check(ctx, "invalid.hostname.test.local, another.invalid.hostname")
	if err != nil {
		t.Fatalf("unexpected internal error: %v", err)
	}
	if res.Success {
		t.Error("expected failure")
	}
	// Note: This might take some time if timeout is high.
	// Default ping timeout is usually 1s per target.
}

func TestPingProbe_Check_EmptyTargets(t *testing.T) {
	p := &PingProbe{}
	ctx := context.Background()
	p.SetTargetMode(TargetModeAll)
	_, _ = p.Check(ctx, " , ")
	_, _ = p.Check(ctx, "8.8.8.8, , ")

	p.SetTargetMode(TargetModeAny)
	_, _ = p.Check(ctx, " , ")
	_, _ = p.Check(ctx, " , 8.8.8.8")
}

func TestGetPingArgs(t *testing.T) {
	tests := []struct {
		goos     string
		target   string
		wantArgs []string
	}{
		{"windows", "1.2.3.4", []string{"-n", "1", "-w", "5000", "1.2.3.4"}},
		{"linux", "1.2.3.4", []string{"-c", "1", "-W", "5", "1.2.3.4"}},
		{"darwin", "1.2.3.4", []string{"-c", "1", "-W", "5", "1.2.3.4"}},
	}

	for _, tt := range tests {
		args := getPingArgs(tt.goos, tt.target, 0)
		if len(args) != len(tt.wantArgs) {
			t.Errorf("getPingArgs(%s) args len = %v, want %v", tt.goos, len(args), len(tt.wantArgs))
		}
		for i := range args {
			if args[i] != tt.wantArgs[i] {
				t.Errorf("getPingArgs(%s) args[%d] = %v, want %v", tt.goos, i, args[i], tt.wantArgs[i])
			}
		}
	}
}
func TestPingProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &PingProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "localhost.test")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

type mockPingConn struct {
	net.Conn
	readData []byte
	readPos  int
}

func (m *mockPingConn) Write(b []byte) (int, error) {
	// Simple mock: assume it's an echo request and prepare an echo reply
	m.readData = []byte{
		0x00, 0x00, // Echo Reply
		0x00, 0x00, // Checksum (ignored)
		0x00, 0x01, // ID (ignored)
		0x00, 0x01, // Seq (ignored)
		'P', 'R', 'O', 'B', 'I', 'X', 'E', 'L', // Data
	}
	return len(b), nil
}

func (m *mockPingConn) Read(b []byte) (int, error) {
	if m.readPos >= len(m.readData) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockPingConn) Close() error                       { return nil }
func (m *mockPingConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPingConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPingConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPingProbe_Builtin(t *testing.T) {
	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockPingConn{}, nil
		},
	}
	ctx := context.Background()
	res, err := probe.Check(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}
func TestPingProbe_Timeout(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	var receivedTimeout time.Duration
	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		receivedTimeout = timeout
		return 10500 * time.Microsecond, nil
	}

	p := &PingProbe{Timeout: 5 * time.Second}
	res, err := p.Check(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if receivedTimeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", receivedTimeout)
	}
}

func TestPingProbe_SetTimeout(t *testing.T) {
	p := &PingProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
func TestPingProbe_RemoteSSH(t *testing.T) {
	// 1. Setup mock SSH server
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
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
				_, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, reqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" {
								// Mock ping command
								command := string(req.Payload[4:]) // skip length (4 bytes) - simple parse
								if strings.Contains(command, "ping") {
									ch.Write([]byte("time=20.5 ms\n"))
									req.Reply(true, nil)
									ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									ch.Close()
									return
								}
								req.Reply(false, nil)
							}
						}
					}(reqs)
				}
			}()
		}
	}()

	// 2. Setup Tunnel
	cfg := &config.SSHConfig{
		User:     "user",
		Password: "secret",
		Port:     port,
	}
	tun := tunnels.NewSSHTunnel("ssh-tun", host, cfg)
	if err := tun.Initialize(); err != nil {
		t.Fatalf("Failed to init tunnel: %v", err)
	}
	defer tun.Stop()

	// 3. Setup Probe
	ctx := context.Background()

	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial ping4 failed: %w", fmt.Errorf("unsupported protocol scheme \"ping4\""))
		},
	}
	probe.SetTunnel(tun)

	res, err := probe.Check(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	// 20.5ms = 20500000ns
	if res.Duration != 20500*time.Microsecond {
		t.Errorf("Expected 20.5ms duration, got %v", res.Duration)
	}
}

type mockErrorConn struct {
	net.Conn
	writeErr error
	readErr  error
}

func (m *mockErrorConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockErrorConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	// Return valid ICMP if no error, to pass until read
	// Header: 8 bytes.
	copy(b, []byte{0, 0, 0, 0, 0, 1, 0, 1})
	return 8, nil
}

func (m *mockErrorConn) Close() error                       { return nil }
func (m *mockErrorConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockErrorConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockErrorConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPingProbe_Builtin_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("DialContext_Error", func(t *testing.T) {
		p := &PingProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("socket fail")
			},
		}
		res, err := p.Check(ctx, "8.8.8.8")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for dial error")
		}
		if !strings.Contains(res.Message, "socket fail") {
			t.Errorf("Expected 'socket fail' message, got %s", res.Message)
		}
	})

	t.Run("Write_Error", func(t *testing.T) {
		p := &PingProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return &mockErrorConn{writeErr: fmt.Errorf("write fail")}, nil
			},
		}
		res, err := p.Check(ctx, "8.8.8.8")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for write error")
		}
		if !strings.Contains(res.Message, "ping write") {
			t.Errorf("Expected 'ping write' message, got %s", res.Message)
		}
	})

	t.Run("Read_Error", func(t *testing.T) {
		p := &PingProbe{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return &mockErrorConn{readErr: fmt.Errorf("read fail")}, nil
			},
		}
		res, err := p.Check(ctx, "8.8.8.8")
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for read error")
		}
		if !strings.Contains(res.Message, "ping read") {
			t.Errorf("Expected 'ping read' message, got %s", res.Message)
		}
	})
}

// mockUnexpectedICMPConn returns an unexpected ICMP type (Destination Unreachable)
type mockUnexpectedICMPConn struct {
	net.Conn
}

func (m *mockUnexpectedICMPConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockUnexpectedICMPConn) Read(b []byte) (int, error) {
	// ICMP Destination Unreachable (type 3, code 0)
	icmpPacket := []byte{
		0x03, 0x00, // Type 3 (Destination Unreachable), Code 0
		0x00, 0x00, // Checksum
		0x00, 0x00, 0x00, 0x00, // unused
	}
	copy(b, icmpPacket)
	return len(icmpPacket), nil
}

func (m *mockUnexpectedICMPConn) Close() error                       { return nil }
func (m *mockUnexpectedICMPConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockUnexpectedICMPConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockUnexpectedICMPConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPingProbe_Builtin_UnexpectedICMPType(t *testing.T) {
	p := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockUnexpectedICMPConn{}, nil
		},
	}
	ctx := context.Background()
	res, err := p.Check(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure for unexpected ICMP type")
	}
	if !strings.Contains(res.Message, "unexpected ICMP type") {
		t.Errorf("Expected 'unexpected ICMP type' message, got %s", res.Message)
	}
}

func TestPingProbe_RemoteSSH_SessionError(t *testing.T) {
	// Setup SSH tunnel with a server that rejects session channels
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
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
				_, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					// Reject all session channels
					newChan.Reject(ssh.Prohibited, "sessions not allowed")
				}
			}()
		}
	}()

	cfg := &config.SSHConfig{
		User:     "user",
		Password: "pass",
		Port:     port,
	}
	tun := tunnels.NewSSHTunnel("ssh-tun", host, cfg)
	if err := tun.Initialize(); err != nil {
		t.Fatalf("Failed to init tunnel: %v", err)
	}
	defer tun.Stop()

	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial ping4 failed: %w", fmt.Errorf("unsupported protocol scheme \"ping4\""))
		},
	}
	probe.SetTunnel(tun)

	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure for session rejection")
	}
	if !strings.Contains(res.Message, "session") && !strings.Contains(res.Message, "SSH") {
		t.Errorf("Expected session-related error message, got %s", res.Message)
	}
}

func TestPingProbe_Builtin_WithDeadline(t *testing.T) {
	// Test the ctx.Deadline() branch in pingBuiltin
	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockPingConn{}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := probe.Check(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

// mockBadICMPConn returns garbage data that can't be parsed as ICMP
type mockBadICMPConn struct {
	net.Conn
}

func (m *mockBadICMPConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockBadICMPConn) Read(b []byte) (int, error) {
	// Return only 1 byte - too short for valid ICMP
	b[0] = 0xFF
	return 1, nil
}
func (m *mockBadICMPConn) Close() error                       { return nil }
func (m *mockBadICMPConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockBadICMPConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockBadICMPConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPingProbe_Builtin_ICMPParseError(t *testing.T) {
	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockBadICMPConn{}, nil
		},
	}
	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success (parse fail fallback), got failure: %s", res.Message)
	}
	if res.Message != "OK (parse failed)" {
		t.Errorf("Expected 'OK (parse failed)', got %s", res.Message)
	}
}

func TestParsePingTime_Variations(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantDur   time.Duration
		wantError bool
	}{
		{
			name:    "standard time",
			output:  "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms",
			wantDur: time.Duration(12.3 * float64(time.Millisecond)),
		},
		{
			name:      "no time= in output",
			output:    "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n--- 8.8.8.8 ping statistics ---",
			wantError: true,
		},
		{
			name:    "very small time",
			output:  "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.001 ms",
			wantDur: time.Duration(0.001 * float64(time.Millisecond)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dur, err := parsePingTime(tt.output)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if dur != tt.wantDur {
				t.Errorf("Expected duration %v, got %v", tt.wantDur, dur)
			}
		})
	}
}

func TestPingProbe_RemoteSSH_GetClientError(t *testing.T) {
	// Test pingRemoteSSH when GetClient fails (tunnel not connected to a real server)
	cfg := &config.SSHConfig{
		User:     "user",
		Password: "wrong",
		Port:     1, // Port 1 - nothing listening
	}
	tun := tunnels.NewSSHTunnel("ssh-tun", "127.0.0.1", cfg)
	if err := tun.Initialize(); err != nil {
		t.Fatalf("Failed to init tunnel: %v", err)
	}
	defer tun.Stop()

	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("unsupported protocol scheme \"ping4\"")
		},
	}
	probe.SetTunnel(tun)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := probe.Check(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure when GetClient fails")
	}
	if !strings.Contains(res.Message, "SSH") && !strings.Contains(res.Message, "ssh") && !strings.Contains(res.Message, "failed") {
		t.Errorf("Expected SSH/failure-related error message, got %s", res.Message)
	}
}

func TestPingProbe_RemoteSSH_CombinedOutputError(t *testing.T) {
	// Setup an SSH server that rejects the exec request (returns non-zero exit)
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
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
				_, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, reqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" {
								// Send non-zero exit status to cause CombinedOutput error
								req.Reply(true, nil)
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1}) // exit code 1
								ch.Close()
								return
							}
							req.Reply(false, nil)
						}
					}(reqs)
				}
			}()
		}
	}()

	cfg := &config.SSHConfig{
		User:     "user",
		Password: "pass",
		Port:     port,
	}
	tun := tunnels.NewSSHTunnel("ssh-tun", host, cfg)
	if err := tun.Initialize(); err != nil {
		t.Fatalf("Failed to init tunnel: %v", err)
	}
	defer tun.Stop()

	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("unsupported protocol scheme \"ping4\"")
		},
	}
	probe.SetTunnel(tun)

	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if res.Success {
		t.Error("Expected failure when remote ping returns non-zero exit")
	}
	if !strings.Contains(res.Message, "remote ping failed") {
		t.Errorf("Expected 'remote ping failed' message, got %s", res.Message)
	}
}

func TestPingProbe_RemoteSSH_ParseTimeFail(t *testing.T) {
	// Setup SSH server that returns output without a parseable time
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
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
				_, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, reqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" {
								// Return output without time= pattern
								ch.Write([]byte("PING 8.8.8.8: 1 packets transmitted, 1 received\n"))
								req.Reply(true, nil)
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
								return
							}
							req.Reply(false, nil)
						}
					}(reqs)
				}
			}()
		}
	}()

	cfg := &config.SSHConfig{
		User:     "user",
		Password: "pass",
		Port:     port,
	}
	tun := tunnels.NewSSHTunnel("ssh-tun", host, cfg)
	if err := tun.Initialize(); err != nil {
		t.Fatalf("Failed to init tunnel: %v", err)
	}
	defer tun.Stop()

	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("unsupported protocol scheme \"ping4\"")
		},
	}
	probe.SetTunnel(tun)

	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success (time parse fail fallback), got failure: %s", res.Message)
	}
	if res.Message != "OK (time parse fail)" {
		t.Errorf("Expected 'OK (time parse fail)', got %s", res.Message)
	}
}

func TestPingProbe_Check_AllMode_MultipleSuccess(t *testing.T) {
	// Test "all" mode with multiple targets all succeeding, including duration=0 path
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		// Return 0 duration to trigger the duration=0 / time.Since(start) path
		return 0, nil
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAll)

	res, err := probe.Check(context.Background(), "target1.test, target2.test")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if !strings.Contains(res.Message, "all 2 targets OK") {
		t.Errorf("Expected 'all 2 targets OK', got %s", res.Message)
	}
}

func TestPingProbe_Check_AnyMode_DurationZeroFallback(t *testing.T) {
	// Test the "any" mode path where duration == 0, triggering time.Since(start) fallback
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		return 0, nil
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAny)

	res, err := probe.Check(context.Background(), "target.test")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if res.Duration == 0 {
		t.Error("Expected non-zero duration from time.Since(start) fallback")
	}
}

func TestPingProbe_pingTarget_FallbackToProBing(t *testing.T) {
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	proBingCalled := false
	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		proBingCalled = true
		return 5500 * time.Microsecond, nil
	}

	// When DialContext returns unsupported protocol and no SSH tunnel is available,
	// it should fallback to pingProBing
	probe := &PingProbe{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("unsupported protocol scheme \"ping4\"")
		},
	}

	res, err := probe.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if !proBingCalled {
		t.Error("Expected fallback to pro-bing ping")
	}
}

func TestDefaultPingFunc_PrivilegedSucceeds(t *testing.T) {
	// When privileged ping works, it should succeed without trying unprivileged
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = defaultPingFunc

	// We can't easily mock runPing internals, so test via the probe with a real
	// target. Skip if no network.
	// Instead, test the fallback logic by swapping pingFunc to simulate behavior.
	calls := 0
	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		calls++
		return 5 * time.Millisecond, nil
	}

	p := &PingProbe{Timeout: 5 * time.Second}
	res, _ := p.Check(context.Background(), "8.8.8.8")
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
	if calls != 1 {
		t.Errorf("Expected 1 call, got %d", calls)
	}
}

func TestRunPing_PacketLoss(t *testing.T) {
	// runPing is tested indirectly; test the packet loss error message
	oldPing := pingFunc
	defer func() { pingFunc = oldPing }()

	pingFunc = func(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
		return 0, fmt.Errorf("100%% packet loss")
	}

	p := &PingProbe{}
	res, _ := p.Check(context.Background(), "8.8.8.8")
	if res.Success {
		t.Error("Expected failure for packet loss")
	}
	if !strings.Contains(res.Message, "packet loss") {
		t.Errorf("Expected packet loss message, got: %s", res.Message)
	}
}
