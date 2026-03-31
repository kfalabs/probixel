package notifier

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Pusher struct {
	Client         *http.Client
	insecureClient *http.Client
	mu             sync.Mutex
	lastPush       map[string]time.Time // per-service rate limit tracking
	rateLimit      time.Duration
}

func NewPusher() *Pusher {
	return &Pusher{
		Client: &http.Client{Timeout: 10 * time.Second},
		insecureClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
			Timeout: 10 * time.Second,
		},
		lastPush:  make(map[string]time.Time),
		rateLimit: 100 * time.Millisecond,
	}
}

// Cleanup removes entries from the lastPush map for services that are no longer active.
func (p *Pusher) Cleanup(activeServices map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name := range p.lastPush {
		if !activeServices[name] {
			delete(p.lastPush, name)
		}
	}
}

func (p *Pusher) SetRateLimit(interval *string) {
	if interval == nil || *interval == "" {
		return
	}
	d, err := config.ParseDuration(*interval)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rateLimit = d
}

// replaceTemplateVars replaces template variables in the URL with actual values
func replaceTemplateVars(urlStr string, result monitor.Result) string {
	// Replace duration (in milliseconds, rounded to nearest)
	durationMs := int64(math.Round(float64(result.Duration) / float64(time.Millisecond)))
	urlStr = strings.ReplaceAll(urlStr, "{%duration%}", strconv.FormatInt(durationMs, 10))

	// Replace error/message
	errorMsg := ""
	if !result.Success {
		errorMsg = url.QueryEscape(result.Message)
	}
	urlStr = strings.ReplaceAll(urlStr, "{%error%}", errorMsg)

	// Replace message (always available)
	urlStr = strings.ReplaceAll(urlStr, "{%message%}", url.QueryEscape(result.Message))

	// Replace target
	urlStr = strings.ReplaceAll(urlStr, "{%target%}", url.QueryEscape(result.Target))

	// Replace timestamp (Unix timestamp)
	timestamp := strconv.FormatInt(result.Timestamp.Unix(), 10)
	urlStr = strings.ReplaceAll(urlStr, "{%timestamp%}", timestamp)

	// Replace success ("true" or "false")
	successStr := "false"
	if result.Success {
		successStr = "true"
	}
	urlStr = strings.ReplaceAll(urlStr, "{%success%}", successStr)

	return urlStr
}

func (p *Pusher) Push(ctx context.Context, serviceName string, result monitor.Result, endpointCfg config.MonitorEndpointConfig, globalEndpointCfg config.GlobalMonitorEndpointConfig) error {
	if result.SkipNotification || result.Pending {
		return nil
	}
	// Enforce per-service rate limit (release lock before sleeping)
	p.mu.Lock()
	var sleepDuration time.Duration
	if p.rateLimit > 0 {
		if last, ok := p.lastPush[serviceName]; ok {
			elapsed := time.Since(last)
			if elapsed < p.rateLimit {
				sleepDuration = p.rateLimit - elapsed
			}
		}
	}
	// Record push time immediately (with projected future time) to block concurrent callers
	p.lastPush[serviceName] = time.Now().Add(sleepDuration)
	p.mu.Unlock()

	if sleepDuration > 0 {
		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	var endpoint *config.EndpointConfig

	// Determine which endpoint definition to use
	if result.Success {
		// Success is required (value in struct)
		endpoint = &endpointCfg.Success
	} else {
		// Failure is optional (pointer in struct)
		endpoint = endpointCfg.Failure
	}

	if endpoint == nil || endpoint.URL == "" {
		return nil // No endpoint configured or optional failure omitted
	}

	targetURL := endpoint.URL

	// Replace template variables in URL
	finalURL := replaceTemplateVars(targetURL, result)

	method := endpoint.Method
	if method == "" {
		method = "GET"
	}

	parsedURL, err := url.Parse(finalURL)
	if err != nil {
		return fmt.Errorf("invalid notification URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
	if err != nil {
		return err
	}

	// Set Global Common Headers
	for k, v := range globalEndpointCfg.Headers {
		req.Header.Set(k, v)
	}

	// Set Service Common Headers (override global)
	for k, v := range endpointCfg.Headers {
		req.Header.Set(k, v)
	}

	// Handle Specific Headers
	for k, v := range endpoint.Headers {
		req.Header.Set(k, v)
	}

	// Resolve timeout hierarchy: endpoint > service-shared > global > default (5s)
	timeoutStr := endpoint.Timeout
	if timeoutStr == "" {
		timeoutStr = endpointCfg.Timeout
	}
	if timeoutStr == "" {
		timeoutStr = globalEndpointCfg.Timeout
	}

	timeout := 5 * time.Second // Default
	if timeoutStr != "" {
		if d, err := config.ParseDuration(timeoutStr); err == nil && d > 0 {
			timeout = d
		}
	}

	// Determine effective retries: service-level > global > default (3)
	retries := 3 // default
	if globalEndpointCfg.Retries != nil {
		retries = *globalEndpointCfg.Retries
	}
	if endpointCfg.Retries != nil {
		retries = *endpointCfg.Retries
	}

	maskedURL := finalURL
	if u, err := url.Parse(finalURL); err == nil && u.RawQuery != "" {
		u.RawQuery = "***"
		maskedURL = u.String()
	}
	sanitizedName := strings.NewReplacer("\n", "", "\r", "").Replace(serviceName)
	sanitizedURL := strings.NewReplacer("\n", "", "\r", "").Replace(maskedURL)
	log.Printf("[%s] Sending notifications to -> %s", sanitizedName, sanitizedURL) //nolint:gosec // G706: values sanitized by stripping newlines/CR

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if attempt > 0 {
			log.Printf("[%s] Retrying alert push (attempt %d/%d)...", serviceName, attempt, retries)
		}

		if attempt > 0 {
			shift := min(attempt-1, 62)                                         //nolint:gosec // G115: shift is bounded [0,62] by min()
			backoff := time.Duration(1<<uint(shift)) * 500 * time.Millisecond //nolint:gosec // G115: shift is bounded [0,62] by min()
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		startPush := time.Now()
		lastErr = p.doPush(req, endpoint, timeout)
		pushDur := time.Since(startPush)

		if lastErr == nil {
			log.Printf("[%s] Alert push successful (%v)", serviceName, pushDur)
			return nil
		}

		log.Printf("[%s] Alert push failed: %v", serviceName, lastErr)

		if attempt < retries {
			// Check context before sleeping or continuing
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
	}

	return lastErr
}

func (p *Pusher) doPush(req *http.Request, endpoint *config.EndpointConfig, timeout time.Duration) error {
	client := p.Client
	if endpoint.InsecureSkipVerify {
		client = p.insecureClient
	}
	if timeout != client.Timeout {
		newClient := *client
		newClient.Timeout = timeout
		client = &newClient
	}

	resp, err := client.Do(req) //nolint:gosec // G704: URL is validated via url.Parse, comes from config
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("bad status code from alert endpoint: %d", resp.StatusCode)
	}

	return nil
}
