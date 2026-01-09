package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"probixel/pkg/config"

	"github.com/tidwall/gjson"
)

type HTTPProbe struct {
	AcceptedStatusCodes string // Configured range/list, e.g. "200-299, 404"
	InsecureSkipVerify  bool   // Skip TLS verification
	MatchData           *config.MatchDataConfig
	Method              string            // HTTP method
	Headers             map[string]string // HTTP headers for the probe itself
	ExpiryThreshold     time.Duration     // Threshold for TLS expiry check
}

func (p *HTTPProbe) Name() string {
	return MonitorTypeHTTP
}

func (p *HTTPProbe) SetTargetMode(mode string) {
	// Not used for HTTP probe, but kept for consistency with other probes
	_ = mode
}

func (p *HTTPProbe) Check(ctx context.Context, target string) (Result, error) {
	target = strings.TrimSpace(target)
	start := time.Now()

	// Create a custom client to handle timeouts and insecure skip verify if needed
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.InsecureSkipVerify}, //nolint:gosec // G402: Optional skip for untrusted endpoints
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // Global timeout for the request
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects by default
		},
	}

	method := p.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to create request: %v", err),
			Timestamp: start,
		}, nil
	}

	// Add headers
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("request failed: %v", err),
			Timestamp: start,
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(start)

	// Check status code against configuration
	success := p.checkStatusCode(resp.StatusCode)
	msg := fmt.Sprintf("HTTP %d", resp.StatusCode)

	// If status code check passed and there are expectations, check them,
	if success && p.MatchData != nil && len(p.MatchData.Expectations) > 0 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return Result{
				Success:   false,
				Duration:  duration,
				Message:   fmt.Sprintf("failed to read response body: %v", err),
				Target:    target,
				Timestamp: start,
			}, nil
		}

		success, msg = p.evaluateExpectations(body, resp.Header)
	}

	// Check TLS expiry if HTTPS and threshold is set
	if success && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 && p.ExpiryThreshold > 0 {
		cert := resp.TLS.PeerCertificates[0]
		remaining := time.Until(cert.NotAfter)

		threshold := p.ExpiryThreshold
		daysRemaining := int(remaining.Hours() / 24)
		tlsMsg := fmt.Sprintf(" (TLS expires in %d days)", daysRemaining)
		if remaining < 0 {
			success = false
			msg += fmt.Sprintf(" (TLS EXPIRED on %s)", cert.NotAfter.Format("2006-01-02"))
		} else if remaining < threshold {
			success = false
			msg += fmt.Sprintf(" (TLS expires soon: %d days remaining)", daysRemaining)
		} else {
			msg += tlsMsg
		}
	}

	if !success {
		if !strings.Contains(msg, "(fail)") {
			msg = fmt.Sprintf("%s (fail)", msg)
		}
	}

	return Result{
		Success:   success,
		Duration:  duration,
		Message:   msg,
		Target:    target,
		Timestamp: start,
	}, nil
}

func (p *HTTPProbe) evaluateExpectations(body []byte, headers http.Header) (bool, string) {
	for _, exp := range p.MatchData.Expectations {
		var actualValue string
		var found bool

		switch exp.Type {
		case "header":
			actualValue = headers.Get(exp.Header)
			found = actualValue != ""
		case "body":
			actualValue = string(body)
			found = true
		case "json":
			jsonStr := string(body)
			res := gjson.Get(jsonStr, exp.JSONPath)
			results := res.Array()
			if len(results) > 0 {
				// Wildcard query, result set, or literal array: pass if ANY element matches
				anyPassed := false
				var lastErr error
				for _, item := range results {
					passed, err := p.evaluateOperator(exp.Operator, item.String(), exp.Value)
					if err == nil && passed {
						anyPassed = true
						break
					}
					if err != nil {
						lastErr = err
					}
				}
				if !anyPassed {
					if lastErr != nil {
						return false, fmt.Sprintf("expectation failed: %v", lastErr)
					}
					return false, fmt.Sprintf("expectation failed: no element in %s %s %s", exp.JSONPath, exp.Operator, exp.Value)
				}
				continue // This expectation passed
			}

			if res.Type == gjson.Null {
				return false, fmt.Sprintf("field not found: %s", exp.JSONPath)
			}

			actualValue = res.String()
			found = true
		default:
			return false, fmt.Sprintf("unknown expectation type: %s", exp.Type)
		}

		if !found {
			return false, fmt.Sprintf("field not found: %s", exp.JSONPath+exp.Header)
		}

		passed, err := p.evaluateOperator(exp.Operator, actualValue, exp.Value)
		if err != nil {
			return false, fmt.Sprintf("expectation failed: %v", err)
		}
		if !passed {
			return false, fmt.Sprintf("expectation failed: %s %s %s (actual: %s)",
				exp.JSONPath+exp.Header, exp.Operator, exp.Value, actualValue)
		}
	}
	return true, "Expectations met"
}

func (p *HTTPProbe) evaluateOperator(op, actual, target string) (bool, error) {
	switch op {
	case "==":
		return actual == target, nil
	case "contains":
		return strings.Contains(actual, target), nil
	case "matches":
		matched, err := regexp.MatchString(target, actual)
		return matched, err
	case ">":
		return p.compare(actual, target, true)
	case "<":
		return p.compare(actual, target, false)
	default:
		return false, fmt.Errorf("unknown operator: %s", op)
	}
}

func (p *HTTPProbe) compare(actual, target string, isGreater bool) (bool, error) {
	// 1. Try duration check (relative time)
	// If target is "10m", assume actual is a timestamp and check time.Since(actual)
	if dur, err := config.ParseDuration(target); err == nil && dur > 0 {
		actualTime, err := p.parseTimestamp(actual)
		if err != nil {
			return false, fmt.Errorf("failed to parse timestamp for age check: %v", err)
		}
		age := time.Since(actualTime)
		if isGreater {
			return age > dur, nil
		}
		return age < dur, nil
	}

	// 2. Try numeric comparison
	if actNum, err1 := strconv.ParseFloat(actual, 64); err1 == nil {
		if tarNum, err2 := strconv.ParseFloat(target, 64); err2 == nil {
			if isGreater {
				return actNum > tarNum, nil
			}
			return actNum < tarNum, nil
		}
	}

	// 3. Try absolute time comparison
	if actTime, err1 := p.parseTimestamp(actual); err1 == nil {
		if tarTime, err2 := p.parseTimestamp(target); err2 == nil {
			if isGreater {
				return actTime.After(tarTime), nil
			}
			return actTime.Before(tarTime), nil
		}
	}

	return false, fmt.Errorf("unsupported comparison between %q and %q", actual, target)
}

func (p *HTTPProbe) parseTimestamp(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format")
}

func (p *HTTPProbe) checkStatusCode(code int) bool {
	if p.AcceptedStatusCodes == "" {
		// Default behavior: 200-399 is considered success (including redirects if not followed, but usually 2xx)
		return code >= 200 && code < 400
	}

	parts := strings.Split(p.AcceptedStatusCodes, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range: "200-299"
			ranges := strings.Split(part, "-")
			if len(ranges) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(ranges[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(ranges[1]))
				if err1 == nil && err2 == nil {
					if code >= start && code <= end {
						return true
					}
				}
			}
		} else {
			// Single value: "200"
			val, err := strconv.Atoi(part)
			if err == nil {
				if code == val {
					return true
				}
			}
		}
	}

	return false
}
