package monitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"probixel/pkg/tunnels"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// execCommand is a variable to allow mocking in tests
var execCommand = exec.CommandContext

type PingProbe struct {
	targetMode  string
	Timeout     time.Duration
	tunnel      tunnels.Tunnel
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

func (p *PingProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *PingProbe) Name() string {
	return MonitorTypePing
}

func (p *PingProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *PingProbe) Check(ctx context.Context, target string) (Result, error) {
	targets := strings.Split(target, ",")
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

	// For "all" mode, track successes
	if p.targetMode == TargetModeAll {
		var totalDuration time.Duration
		successCount := 0

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			start := time.Now()
			duration, _, err := p.pingTarget(ctx, t)

			if err != nil {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			totalDuration += duration
			if duration == 0 {
				totalDuration += time.Since(start)
			}
			successCount++
		}

		if successCount > 0 {
			return Result{
				Success:   true,
				Duration:  totalDuration / time.Duration(successCount),
				Message:   fmt.Sprintf("all %d targets OK", successCount),
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

		start := time.Now()
		duration, msg, err := p.pingTarget(ctx, t)

		if err == nil {
			if duration == 0 {
				duration = time.Since(start)
			}
			return Result{
				Success:   true,
				Duration:  duration,
				Message:   msg,
				Target:    t,
				Timestamp: startTotal,
			}, nil
		}
		lastErr = err
	}

	return Result{
		Success:   false,
		Duration:  0,
		Message:   fmt.Sprintf("all ping targets failed, last error: %v", lastErr),
		Timestamp: startTotal,
	}, nil
}

func (p *PingProbe) pingTarget(ctx context.Context, target string) (time.Duration, string, error) {
	if p.DialContext != nil {
		duration, msg, err := p.pingBuiltin(ctx, target)
		if err != nil && strings.Contains(err.Error(), "unsupported protocol") {
			// SSH tunnels don't support ICMP - try remote ping execution
			if p.tunnel != nil {
				if sshTunnel, ok := p.tunnel.(*tunnels.SSHTunnel); ok {
					return p.pingRemoteSSH(ctx, sshTunnel, target)
				}
			}
			// Fallback to local executable ping
			return p.pingExecutable(ctx, target)
		}
		return duration, msg, err
	}
	return p.pingExecutable(ctx, target)
}

func (p *PingProbe) pingExecutable(ctx context.Context, target string) (time.Duration, string, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctxCmd, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, args := getPingArgs(runtime.GOOS, target, timeout)
	cmd := execCommand(ctxCmd, name, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, "", err
	}

	rtt, parseErr := parsePingTime(string(output))
	if parseErr != nil {
		return 1 * time.Millisecond, "OK (time parse fail)", nil
	}
	return rtt, "OK", nil
}

func (p *PingProbe) pingRemoteSSH(ctx context.Context, sshTunnel *tunnels.SSHTunnel, target string) (time.Duration, string, error) {
	start := time.Now()

	// Get SSH client from tunnel
	client, err := sshTunnel.GetClient(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get SSH client: %w", err)
	}

	// Create SSH session
	session, err := client.NewSession()
	if err != nil {
		return 0, "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Build ping command
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	name, args := getPingArgs("linux", target, timeout) // SSH usually targets Linux/Unix
	cmd := fmt.Sprintf("%s %s", name, strings.Join(args, " "))

	// Execute remote ping
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return 0, "", fmt.Errorf("remote ping failed: %w", err)
	}

	duration := time.Since(start)

	// Parse output for RTT
	rtt, parseErr := parsePingTime(string(output))
	if parseErr != nil {
		return duration, "OK (time parse fail)", nil
	}
	return rtt, "OK", nil
}

func (p *PingProbe) pingBuiltin(ctx context.Context, target string) (time.Duration, string, error) {
	if p.DialContext == nil {
		return 0, "", fmt.Errorf("DialContext not initialized")
	}

	start := time.Now()
	socket, err := p.DialContext(ctx, "ping4", target)
	if err != nil {
		return 0, "", fmt.Errorf("dial ping4 failed: %w", err)
	}
	defer func() { _ = socket.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = socket.SetReadDeadline(deadline)
	} else {
		timeout := p.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		_ = socket.SetReadDeadline(time.Now().Add(timeout))
	}

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
		return 0, "", fmt.Errorf("marshal failed: %w", err)
	}

	if _, err := socket.Write(icmpBytes); err != nil {
		return 0, "", fmt.Errorf("ping write: %w", err)
	}

	reply := make([]byte, 1500)
	n, err := socket.Read(reply)
	if err != nil {
		return 0, "", fmt.Errorf("ping read: %w", err)
	}

	duration := time.Since(start)

	rm, err := icmp.ParseMessage(1, reply[:n]) // 1 for ICMPv4
	if err != nil {
		return duration, "OK (parse failed)", nil
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return duration, "OK", nil
	default:
		return 0, "", fmt.Errorf("unexpected ICMP type: %v", rm.Type)
	}
}

func getPingArgs(goos, target string, timeout time.Duration) (string, []string) {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec == 0 {
		timeoutSec = 5
	}

	if goos == "windows" {
		return "ping", []string{"-n", "1", "-w", strconv.Itoa(timeoutSec * 1000), target}
	}
	return "ping", []string{"-c", "1", "-W", strconv.Itoa(timeoutSec), target}
}

func parsePingTime(output string) (time.Duration, error) {
	// standard ping output: time=12.3 ms
	re := regexp.MustCompile(`time=([0-9.]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		msStr := matches[1]
		ms, err := strconv.ParseFloat(msStr, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(ms * float64(time.Millisecond)), nil
	}
	return 0, fmt.Errorf("could not find time= in output")
}

func (p *PingProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
