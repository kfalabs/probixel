package monitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"
)

// Helper to mock exec.CommandContext
func fakeExecCommand(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...) //nolint:gosec // G204: Helper process requiring variable path
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess isn't a real test. It's used as a mock process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	// Check arguments to decide exit code and output
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	cmd, cmdArgs := args[0], args[1:]

	if cmd != "ping" {
		fmt.Fprintf(os.Stderr, "Unknown command %q\n", cmd)
		os.Exit(2)
	}

	// Simple argument check
	target := cmdArgs[len(cmdArgs)-1]

	switch target {
	case "localhost.test":
		// Success
		fmt.Printf("time=10.5 ms\n")
		os.Exit(0)
	case "unreachable.test":
		// Failure (timeout or unreachable)
		// Simulate delay?
		// time.Sleep(100 * time.Millisecond) // Fast failure for test speed
		os.Exit(1)
	default:
		// Unknown
		os.Exit(1)
	}
}

func TestPingProbe_Check(t *testing.T) {
	// Swap execCommand
	oldExec := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = oldExec }()

	probe := &PingProbe{}
	ctx := context.Background()

	// Test 1: Ping mocked success
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

	// Test 2: Ping mocked failure
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
	oldExec := execCommand
	defer func() { execCommand = oldExec }()

	execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "time=10.5 ms")
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAll)

	_, _ = probe.Check(context.Background(), "127.0.0.1, 8.8.8.8, ,")
}

func TestPingProbe_AllMode_FailFast(t *testing.T) {
	oldExec := execCommand
	defer func() { execCommand = oldExec }()

	execCount := 0
	execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		execCount++
		if strings.Contains(arg[len(arg)-1], "fail") {
			return exec.Command("ls", "/non-existent")
		}
		return exec.Command("echo", "time=10.5 ms")
	}

	probe := &PingProbe{}
	probe.SetTargetMode(TargetModeAll)

	result, _ := probe.Check(context.Background(), "fail.test, good.test")
	if result.Success {
		t.Error("Expected failure")
	}
	if execCount != 1 {
		t.Errorf("Expected fail fast (1 call), got %d", execCount)
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
	oldExec := execCommand
	defer func() { execCommand = oldExec }()

	// Trigger "OK (time parse fail)" path
	execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "success but no time info")
	}
	p := &PingProbe{}
	res, _ := p.Check(context.Background(), "127.0.0.1")
	if !res.Success || res.Message != "OK (time parse fail)" {
		t.Errorf("Expected OK (time parse fail), got %s", res.Message)
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
		wantName string
		wantArgs []string
	}{
		{"windows", "1.2.3.4", "ping", []string{"-n", "1", "-w", "5000", "1.2.3.4"}},
		{"linux", "1.2.3.4", "ping", []string{"-c", "1", "-W", "5", "1.2.3.4"}},
		{"darwin", "1.2.3.4", "ping", []string{"-c", "1", "-W", "5", "1.2.3.4"}},
	}

	for _, tt := range tests {
		name, args := getPingArgs(tt.goos, tt.target, 0)
		if name != tt.wantName {
			t.Errorf("getPingArgs(%s) name = %v, want %v", tt.goos, name, tt.wantName)
		}
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
	oldExec := execCommand
	defer func() { execCommand = oldExec }()

	execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		// Verify -W flag in ping command
		cmdStr := strings.Join(arg, " ")
		if !strings.Contains(cmdStr, "-W 5") {
			return exec.Command("false")
		}
		return exec.Command("echo", "time=10.5 ms")
	}

	p := &PingProbe{Timeout: 5 * time.Second}
	res, err := p.Check(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestPingProbe_SetTimeout(t *testing.T) {
	p := &PingProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
