package monitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"probixel/pkg/tunnels"

	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// pingFunc is the default non-tunnel ping implementation, swappable for tests
var pingFunc = defaultPingFunc

var pingTimeRegex = regexp.MustCompile(`time=([0-9.]+)`)

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
	if p.DialContext == nil {
		return p.pingProBing(ctx, target)
	}

	duration, msg, err := p.pingBuiltin(ctx, target)
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		return duration, msg, err
	}

	// SSH tunnels don't support ICMP - try remote ping execution
	if p.tunnel != nil {
		if sshTunnel, ok := p.tunnel.(*tunnels.SSHTunnel); ok {
			return p.pingRemoteSSH(ctx, sshTunnel, target)
		}
	}

	// Fallback to local executable ping
	return p.pingProBing(ctx, target)
}

func runPing(ctx context.Context, target string, timeout time.Duration, privileged bool) (time.Duration, error) {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		return 0, fmt.Errorf("failed to create pinger: %w", err)
	}
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(privileged)

	done := make(chan error, 1)
	go func() {
		done <- pinger.Run()
	}()

	select {
	case <-ctx.Done():
		pinger.Stop()
		return 0, ctx.Err()
	case err := <-done:
		if err != nil {
			return 0, err
		}
	}

	stats := pinger.Statistics()
	if stats.PacketLoss == 100 {
		return 0, fmt.Errorf("100%% packet loss")
	}
	return stats.MaxRtt, nil
}

func defaultPingFunc(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
	// Try privileged (raw ICMP) first — works when running as root or with CAP_NET_RAW
	duration, err := runPing(ctx, target, timeout, true)
	if err == nil {
		return duration, nil
	}

	// Fall back to unprivileged (UDP ICMP) — works when net.ipv4.ping_group_range allows our GID
	duration, unprivErr := runPing(ctx, target, timeout, false)
	if unprivErr == nil {
		return duration, nil
	}

	// Both failed — return the unprivileged error with guidance
	log.Printf("WARNING: Ping probe failed. If using Docker, add --sysctl net.ipv4.ping_group_range=\"0 2147483647\" to your run command")
	return 0, unprivErr
}

func (p *PingProbe) pingProBing(ctx context.Context, target string) (time.Duration, string, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	duration, err := pingFunc(ctx, target, timeout)
	if err != nil {
		return 0, "", err
	}
	return duration, "OK", nil
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

	start := time.Now() // Measure RTT from after dial, not including tunnel setup

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
	matches := pingTimeRegex.FindStringSubmatch(output)
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
