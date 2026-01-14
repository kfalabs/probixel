package notifier

import (
	"context"
	"crypto/tls"
	"fmt"
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
	Client    *http.Client
	mu        sync.Mutex
	lastPush  time.Time
	rateLimit time.Duration
}

func NewPusher() *Pusher {
	return &Pusher{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		rateLimit: 100 * time.Millisecond,
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
	// Enforce rate limit
	p.mu.Lock()
	if p.rateLimit > 0 {
		elapsed := time.Since(p.lastPush)
		if elapsed < p.rateLimit {
			time.Sleep(p.rateLimit - elapsed)
		}
	}
	p.lastPush = time.Now()
	p.mu.Unlock()

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

	req, err := http.NewRequestWithContext(ctx, method, finalURL, nil) // Empty body as per bash script (uses query params)
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

	log.Printf("[%s] Sending notifications to -> %s", serviceName, finalURL)

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if attempt > 0 {
			log.Printf("[%s] Retrying alert push (attempt %d/%d)...", serviceName, attempt, retries)
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
		// Create a temporary client with insecure TLS skip
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: User-requested skip
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}
	} else if timeout != p.Client.Timeout {
		// Copy client and set specific timeout
		newClient := *p.Client
		newClient.Timeout = timeout
		client = &newClient
	}

	// We need to be careful with req.Body if it were present, but NewRequest used nil.
	// However, client.Do can modify the request (headers, etc).
	// Actually, req.Header is modified by p.Push before the loop.
	// If we were sending a body, we'd need to reset it.

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("bad status code from alert endpoint: %d", resp.StatusCode)
	}

	return nil
}
