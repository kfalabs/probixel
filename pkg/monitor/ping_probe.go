package monitor

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// execCommand is a variable to allow mocking in tests
var execCommand = exec.CommandContext

type PingProbe struct {
	targetMode string
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

	// For "all" mode, track successes
	if p.targetMode == TargetModeAll {
		var totalDuration time.Duration
		successCount := 0

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			ctxCmd, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			name, args := getPingArgs(runtime.GOOS, t)
			cmd := execCommand(ctxCmd, name, args...)

			output, err := cmd.CombinedOutput()
			if err != nil {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			rtt, parseErr := parsePingTime(string(output))
			if parseErr != nil {
				rtt = 1 * time.Millisecond // Fallback
			}
			totalDuration += rtt
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

		ctxCmd, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		name, args := getPingArgs(runtime.GOOS, t)
		cmd := execCommand(ctxCmd, name, args...)

		output, err := cmd.CombinedOutput()
		if err == nil {
			rtt, parseErr := parsePingTime(string(output))
			if parseErr == nil {
				return Result{
					Success:   true,
					Duration:  rtt,
					Message:   "OK",
					Target:    t,
					Timestamp: startTotal,
				}, nil
			}
			return Result{
				Success:   true,
				Duration:  1 * time.Millisecond,
				Message:   "OK (time parse fail)",
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

func getPingArgs(goos, target string) (string, []string) {
	if goos == "windows" {
		return "ping", []string{"-n", "1", target}
	}
	return "ping", []string{"-c", "1", target}
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
