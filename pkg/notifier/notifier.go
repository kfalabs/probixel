package notifier

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"strconv"
	"strings"
	"time"
)

type Pusher struct {
	Client *http.Client
}

func NewPusher() *Pusher {
	return &Pusher{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// replaceTemplateVars replaces template variables in the URL with actual values
func replaceTemplateVars(urlStr string, result monitor.Result) string {
	// Replace duration (in milliseconds)
	durationMs := result.Duration.Milliseconds()
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

func (p *Pusher) Push(result monitor.Result, endpointCfg config.MonitorEndpointConfig, globalEndpointCfg config.GlobalMonitorEndpointConfig) error {
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

	req, err := http.NewRequest(method, finalURL, nil) // Empty body as per bash script (uses query params)
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

	client := p.Client
	if endpoint.InsecureSkipVerify {
		// Create a temporary client with insecure TLS skip
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: User-requested skip
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}
	}

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
