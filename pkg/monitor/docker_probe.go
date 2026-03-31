package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/tunnels"
)

type DockerProbe struct {
	Sockets     map[string]config.DockerSocketConfig
	SocketName  string
	Healthy     bool
	targetMode  string
	Timeout     time.Duration
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	tunnel      tunnels.Tunnel

	// Cached HTTP client to avoid creating new transports per check
	cachedClient *http.Client
	cachedAPIURL string
	clientOnce   sync.Once
	clientErr    error
}

func (p *DockerProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *DockerProbe) Name() string {
	return MonitorTypeDocker
}

func (p *DockerProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *DockerProbe) Check(ctx context.Context, target string) (Result, error) {
	start := time.Now()
	targets := strings.Split(target, ",")

	// Strict stabilization adherence: always return Pending if tunnel not stabilized
	if p.tunnel != nil && !p.tunnel.IsStabilized() {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("waiting for tunnel %q to stabilize", p.tunnel.Name()),
			Timestamp: start,
		}, nil
	}

	cfg, ok := p.Sockets[p.SocketName]
	if !ok {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("docker socket %q not found in global config", p.SocketName),
			Timestamp: start,
		}, nil
	}

	p.clientOnce.Do(func() {
		p.cachedClient, p.cachedAPIURL, p.clientErr = p.buildClient(cfg)
	})
	if p.clientErr != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to initialize docker client: %v", p.clientErr),
			Timestamp: start,
		}, nil
	}
	client, apiURL := p.cachedClient, p.cachedAPIURL

	if p.targetMode == TargetModeAll {
		var totalDuration time.Duration
		successCount := 0
		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			res := p.checkOne(ctx, client, apiURL, cfg, t)
			if !res.Success {
				res.Duration = time.Since(start)
				res.Timestamp = start
				return res, nil
			}
			totalDuration += res.Duration
			successCount++
		}
		avgDuration := time.Duration(0)
		if successCount > 0 {
			avgDuration = totalDuration / time.Duration(successCount)
		}
		return Result{
			Success:   true,
			Duration:  avgDuration,
			Message:   fmt.Sprintf("all %d containers OK", successCount),
			Timestamp: start,
		}, nil
	}

	// Default "any" mode
	var lastRes Result
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		res := p.checkOne(ctx, client, apiURL, cfg, t)
		if res.Success {
			res.Duration = time.Since(start)
			res.Timestamp = start
			return res, nil
		}
		lastRes = res
	}

	lastRes.Duration = time.Since(start)
	lastRes.Timestamp = start
	if len(targets) > 1 && !lastRes.Success {
		lastRes.Message = fmt.Sprintf("all %d docker targets failed, last error: %s", len(targets), lastRes.Message)
	}
	return lastRes, nil
}

func (p *DockerProbe) checkOne(ctx context.Context, client *http.Client, apiURL string, cfg config.DockerSocketConfig, target string) Result {
	start := time.Now()
	parsedURL, err := url.JoinPath(apiURL, "containers", target, "json")
	if err != nil {
		return Result{Success: false, Message: fmt.Sprintf("failed to build URL: %v", err)}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL, nil)
	if err != nil {
		return Result{Success: false, Message: fmt.Sprintf("failed to create request: %v", err)}
	}

	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req) //nolint:gosec // G704: URL is constructed from validated config, not arbitrary user input
	if err != nil {
		return Result{Success: false, Message: fmt.Sprintf("docker api request failed: %v", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return Result{Success: false, Message: fmt.Sprintf("container %q not found", target), Target: target}
	}

	if resp.StatusCode != http.StatusOK {
		return Result{Success: false, Message: fmt.Sprintf("docker api returned status %d", resp.StatusCode), Target: target}
	}

	var containerInfo struct {
		State struct {
			Status string `json:"Status"`
			Health struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&containerInfo); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("failed to decode docker api response: %v", err), Target: target}
	}

	status := containerInfo.State.Status
	healthStatus := containerInfo.State.Health.Status

	if status != "running" {
		return Result{Success: false, Message: fmt.Sprintf("container is %s", status), Target: target}
	}

	if p.Healthy && healthStatus != "" && healthStatus != "healthy" {
		return Result{Success: false, Message: fmt.Sprintf("container is running but health is %s", healthStatus), Target: target}
	}

	msg := "OK"
	if healthStatus != "" {
		msg = fmt.Sprintf("running (%s)", healthStatus)
	}

	return Result{
		Success:  true,
		Duration: time.Since(start),
		Message:  msg,
		Target:   target,
	}
}

func (p *DockerProbe) Close() {
	if p.cachedClient != nil {
		p.cachedClient.CloseIdleConnections()
	}
}

func (p *DockerProbe) buildClient(cfg config.DockerSocketConfig) (*http.Client, string, error) {
	if cfg.Socket != "" {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "unix", cfg.Socket)
			},
		}
		// When using unix socket, the host in the URL is ignored but must be present
		timeout := p.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		return &http.Client{Transport: tr, Timeout: timeout}, "http://localhost", nil
	}

	if cfg.Host != "" && cfg.Port != 0 {
		protocol := cfg.Protocol
		if protocol == "" {
			protocol = "http"
		}
		apiURL := fmt.Sprintf("%s://%s:%d", protocol, cfg.Host, cfg.Port)

		tr := &http.Transport{}
		if p.DialContext != nil {
			tr.DialContext = p.DialContext
		}

		timeout := p.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		return &http.Client{Transport: tr, Timeout: timeout}, apiURL, nil
	}

	return nil, "", fmt.Errorf("invalid docker socket configuration: must provide either socket path or host/port")
}
func (p *DockerProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
