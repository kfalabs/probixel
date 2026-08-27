package notifier

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"strings"
	"testing"
	"time"
)

//go:fix inline
func ptr(s string) *string {
	return new(s)
}

//go:fix inline
func ptrInt(i int) *int {
	return new(i)
}

func TestPusher_Push(t *testing.T) {
	// Create a test server to mock the alert endpoint
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		// Verify headers (no default headers are set)
		if r.Header.Get("Global-Key") != "GlobalVal" {
			t.Errorf("Expected Global-Key header, got %s", r.Header.Get("Global-Key"))
		}
		if r.Header.Get("Service-Key") != "ServiceVal" {
			t.Errorf("Expected Service-Key header, got %s", r.Header.Get("Service-Key"))
		}

		// Verify query params
		duration := r.URL.Query().Get("duration")
		if duration == "" {
			t.Error("Expected duration query param")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{
			URL:    testServer.URL + "?duration={%duration%}",
			Method: "POST",
		},
		Failure: &config.EndpointConfig{
			URL:    testServer.URL + "?duration={%duration%}",
			Method: "POST",
		},
	}

	res := monitor.Result{
		Success:  true,
		Duration: 100 * time.Millisecond,
		Message:  "OK",
	}

	globalEndpointCfg := config.GlobalMonitorEndpointConfig{
		Headers: map[string]string{"Global-Key": "GlobalVal"},
	}
	alertCfg.Headers = map[string]string{"Service-Key": "ServiceVal"}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalEndpointCfg)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
}

func TestPusher_Push_Failure(t *testing.T) {
	// Mock server that returns 500
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	pusher := NewPusher()

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL + "?duration={%duration%}"},
	}
	res := monitor.Result{Success: true}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{Retries: new(0)})
	if err == nil {
		t.Error("Expected error from 500 response, got nil")
	}
}

func TestPusher_TemplateVariables(t *testing.T) {
	// Test that template variables are correctly replaced
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify template variables were replaced
		duration := r.URL.Query().Get("d")
		if duration == "" {
			t.Error("Expected duration query param 'd'")
		}
		if duration != "150" { // 150ms
			t.Errorf("Expected duration 150ms, got %s", duration)
		}

		msg := r.URL.Query().Get("msg")
		if msg == "" {
			t.Error("Expected message query param 'msg'")
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			t.Error("Expected target query param")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()

	// URL with template variables
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{
			URL: testServer.URL + "?d={%duration%}&msg={%message%}&target={%target%}&success={%success%}",
		},
	}

	res := monitor.Result{
		Success:   true,
		Duration:  150 * time.Millisecond,
		Message:   "Test OK",
		Target:    "test.example.com",
		Timestamp: time.Now(),
	}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
}

func TestPusher_TemplateVariables_Error(t *testing.T) {
	// Test that error template variable is populated on failure
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errVal := r.URL.Query().Get("error")
		if errVal == "" {
			t.Error("Expected error query param")
		}
		if !strings.Contains(errVal, "failed") {
			t.Errorf("Expected error message to contain 'failed', got: %s", errVal)
		}

		success := r.URL.Query().Get("success")
		if success != "false" {
			t.Errorf("Expected success=false, got %s", success)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()

	alertCfg := config.MonitorEndpointConfig{
		Failure: &config.EndpointConfig{
			URL: testServer.URL + "?error={%error%}&success={%success%}",
		},
	}

	res := monitor.Result{
		Success:  false,
		Duration: 50 * time.Millisecond,
		Message:  "Connection failed",
	}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
}

func TestPusher_Push_EmptyEndpoint(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{Success: true}
	err := pusher.Push(context.Background(), "test-service", res, config.MonitorEndpointConfig{}, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Errorf("Push should return nil if no endpoint is configured, got %v", err)
	}
}

func TestPusher_Push_HeaderOverride(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "specific" {
			t.Errorf("Expected X-Test: specific, got %s", r.Header.Get("X-Test"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	res := monitor.Result{Success: true}

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{
			URL:     testServer.URL,
			Headers: map[string]string{"X-Test": "specific"},
		},
		Headers: map[string]string{"X-Test": "common"},
	}
	globalCfg := config.GlobalMonitorEndpointConfig{
		Headers: map[string]string{"X-Test": "global"},
	}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalCfg)
	if err != nil {
		t.Errorf("Push failed: %v", err)
	}
}

func TestPusher_Push_NewRequestError(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{Success: true}

	// Control character in URL should cause NewRequest to fail
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: "http://example.com/\x7f"},
	}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err == nil {
		t.Error("Expected error from invalid URL in NewRequest, got nil")
	}
}

func TestPusher_Push_DoError(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{Success: true}

	// This URL should fail Do() because it's a non-existent local port
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: "http://127.0.0.1:1"},
	}

	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{Retries: new(0)})
	if err == nil {
		t.Error("Expected error from failing Do(), got nil")
	}
}

func TestPushInsecure(t *testing.T) {
	// Create a TLS server with a self-signed certificate
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pusher := NewPusher()
	result := monitor.Result{
		Success:   true,
		Message:   "OK",
		Duration:  10 * time.Millisecond,
		Timestamp: time.Now(),
	}

	globalCfg := config.GlobalMonitorEndpointConfig{Retries: new(0)}

	t.Run("Fail with default client (TLS verification on)", func(t *testing.T) {
		endpointCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{
				URL:                server.URL,
				InsecureSkipVerify: false,
			},
		}

		err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
		if err == nil {
			t.Error("Expected error for self-signed certificate with InsecureSkipVerify: false, but got none")
		}
	})

	t.Run("Succeed with InsecureSkipVerify: true", func(t *testing.T) {
		endpointCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{
				URL:                server.URL,
				InsecureSkipVerify: true,
			},
		}

		err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
		if err != nil {
			t.Errorf("Expected no error with InsecureSkipVerify: true, but got: %v", err)
		}
	})
}

func TestPushOptionalFailure(t *testing.T) {
	pusher := NewPusher()
	result := monitor.Result{
		Success: false,
		Message: "Failed",
	}

	t.Run("Skip alert when failure endpoint is nil", func(t *testing.T) {
		endpointCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{URL: "http://success.test"},
			Failure: nil,
		}
		globalCfg := config.GlobalMonitorEndpointConfig{}

		err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
		if err != nil {
			t.Errorf("Expected nil error when failure endpoint is nil, got: %v", err)
		}
	})

	t.Run("Skip alert when failure URL is empty", func(t *testing.T) {
		endpointCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{URL: "http://success.test"},
			Failure: &config.EndpointConfig{URL: ""},
		}
		globalCfg := config.GlobalMonitorEndpointConfig{}

		err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
		if err != nil {
			t.Errorf("Expected nil error when failure URL is empty, got: %v", err)
		}
	})
}

func TestPusher_RateLimit(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	pusher.SetRateLimit(new("100ms"))

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	res := monitor.Result{Success: true}

	start := time.Now()
	// Push 3 times
	for range 3 {
		_ = pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	}
	duration := time.Since(start)

	// 3 pushes with 100ms interval should take at least 200ms
	// Call 1: immediate
	// Call 2: sleeps ~100ms
	// Call 3: sleeps ~100ms
	if duration < 200*time.Millisecond {
		t.Errorf("Expected duration to be at least 200ms, got %v", duration)
	}
}

func TestPusher_SetRateLimit_Invalid(t *testing.T) {
	pusher := NewPusher()
	pusher.SetRateLimit(new("100ms"))

	// Set to invalid duration should not change existing rate limit
	pusher.SetRateLimit(new("invalid"))

	p := pusher
	p.mu.Lock()
	limit := p.rateLimit
	p.mu.Unlock()

	if limit != 100*time.Millisecond {
		t.Errorf("Expected rate limit to remain 100ms, got %v", limit)
	}
}

func TestPusher_DefaultRateLimit(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	// New pusher should have 100ms default
	pusher := NewPusher()

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	res := monitor.Result{Success: true}

	start := time.Now()
	// Push 2 times
	for range 2 {
		_ = pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	}
	duration := time.Since(start)

	// 2 pushes with 100ms interval should take at least 100ms
	if duration < 100*time.Millisecond {
		t.Errorf("Expected duration to be at least 100ms (default), got %v", duration)
	}
}

func TestPusher_SetRateLimit_Empty(t *testing.T) {
	pusher := NewPusher()
	pusher.SetRateLimit(new("200ms"))

	// Empty string should not change the rate limit
	pusher.SetRateLimit(new(""))

	p := pusher
	p.mu.Lock()
	limit := p.rateLimit
	p.mu.Unlock()

	if limit != 200*time.Millisecond {
		t.Errorf("Expected rate limit to remain 200ms, got %v", limit)
	}
}

func TestPusher_SetRateLimit_Zero(t *testing.T) {
	pusher := NewPusher()

	// "0" should disable the default 100ms rate limit
	pusher.SetRateLimit(new("0"))

	p := pusher
	p.mu.Lock()
	limit := p.rateLimit
	p.mu.Unlock()

	if limit != 0 {
		t.Errorf("Expected rate limit to be 0, got %v", limit)
	}
}

func TestPusher_Push_SetRateLimit_Nil(t *testing.T) {
	pusher := NewPusher() // Default 100ms

	// SetRateLimit(nil) should not change the default
	pusher.SetRateLimit(nil)

	p := pusher
	p.mu.Lock()
	limit := p.rateLimit
	p.mu.Unlock()

	if limit != 100*time.Millisecond {
		t.Errorf("Expected rate limit to remain 100ms, got %v", limit)
	}
}

func TestPusher_Push_TimeoutHierarchy(t *testing.T) {
	// Create a slow test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	res := monitor.Result{Success: true}

	t.Run("Endpoint timeout (shortest)", func(t *testing.T) {
		alertCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{
				URL:     testServer.URL,
				Timeout: "50ms",
			},
			Timeout: "500ms",
		}
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "1s", Retries: new(0)}

		err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalCfg)
		if err == nil {
			t.Error("Expected timeout error (50ms), got nil")
		} else if !strings.Contains(err.Error(), "Client.Timeout exceeded") && !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
	})

	t.Run("Service-shared timeout", func(t *testing.T) {
		alertCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{URL: testServer.URL},
			Timeout: "50ms",
		}
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "1s", Retries: new(0)}

		err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalCfg)
		if err == nil {
			t.Error("Expected timeout error (50ms service-shared), got nil")
		} else if !strings.Contains(err.Error(), "Client.Timeout exceeded") && !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
	})

	t.Run("Global timeout", func(t *testing.T) {
		alertCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{URL: testServer.URL},
		}
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "50ms", Retries: new(0)}

		err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalCfg)
		if err == nil {
			t.Error("Expected timeout error (50ms global), got nil")
		} else if !strings.Contains(err.Error(), "Client.Timeout exceeded") && !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
	})

	t.Run("Default timeout (succeeds with 5s)", func(t *testing.T) {
		alertCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{URL: testServer.URL},
		}
		globalCfg := config.GlobalMonitorEndpointConfig{}

		err := pusher.Push(context.Background(), "test-service", res, alertCfg, globalCfg)
		if err != nil {
			t.Errorf("Expected success with default 5s timeout, got: %v", err)
		}
	})
}

func TestPusher_Push_Retries(t *testing.T) {
	attempts := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	pusher.SetRateLimit(new("0")) // Disable rate limit for testing retries

	result := monitor.Result{Success: true}
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	globalCfg := config.GlobalMonitorEndpointConfig{
		Retries: new(3),
	}

	err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
	if err != nil {
		t.Errorf("Expected success after retries, got error: %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestPusher_Push_Retries_Exhausted(t *testing.T) {
	attempts := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	pusher.SetRateLimit(new("0"))

	result := monitor.Result{Success: true}
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	globalCfg := config.GlobalMonitorEndpointConfig{
		Retries: new(2),
	}

	err := pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)
	if err == nil {
		t.Error("Expected error after exhausting retries, got nil")
	}

	if attempts != 3 { // Initial + 2 retries
		t.Errorf("Expected 3 attempts (1+2), got %d", attempts)
	}
}

func TestPusher_Push_Retries_ServiceOverride(t *testing.T) {
	attempts := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	pusher.SetRateLimit(new("0"))

	result := monitor.Result{Success: true}
	retriesOverride := 1
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
		Retries: &retriesOverride,
	}
	globalCfg := config.GlobalMonitorEndpointConfig{
		Retries: new(5), // Should be ignored
	}

	_ = pusher.Push(context.Background(), "test-service", result, endpointCfg, globalCfg)

	if attempts != 2 { // Initial + 1 retry
		t.Errorf("Expected 2 attempts with service override, got %d", attempts)
	}
}

func TestPusher_Push_ContextCancellation(t *testing.T) {
	// Create a slow test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	res := monitor.Result{Success: true}
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := pusher.Push(ctx, "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	} else if !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "canceled") {
		t.Errorf("Expected context error, got: %v", err)
	}
}

func TestPusher_Push_SkipNotification(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{
		Success:          true,
		SkipNotification: true,
	}
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: "http://should-not-be-called.test"},
	}
	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Errorf("Expected nil error for SkipNotification, got: %v", err)
	}
}

func TestPusher_Push_Pending(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{
		Pending: true,
	}
	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: "http://should-not-be-called.test"},
	}
	err := pusher.Push(context.Background(), "test-service", res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Errorf("Expected nil error for Pending result, got: %v", err)
	}
}

func TestPusher_Push_ContextCancelledBetweenRetries(t *testing.T) {
	var cancel context.CancelFunc
	attempts := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// Cancel context during first request so the between-retries check catches it
			cancel()
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	pusher.SetRateLimit(new("0"))

	var ctx context.Context
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	result := monitor.Result{Success: true}
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	globalCfg := config.GlobalMonitorEndpointConfig{
		Retries: new(10),
	}

	err := pusher.Push(ctx, "test-service", result, endpointCfg, globalCfg)
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
	// Should have stopped well before all 10 retries
	if attempts > 3 {
		t.Errorf("Expected at most 3 attempts due to cancellation, got %d", attempts)
	}
}

func TestPusher_Push_PreCancelledContext(t *testing.T) {
	pusher := NewPusher()
	pusher.SetRateLimit(new("0"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := monitor.Result{Success: true}
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: "http://127.0.0.1:1"},
	}

	err := pusher.Push(ctx, "test-service", result, endpointCfg, config.GlobalMonitorEndpointConfig{})
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

func TestPusher_Cleanup(t *testing.T) {
	t.Run("removes inactive services", func(t *testing.T) {
		pusher := NewPusher()
		pusher.lastPush["active-svc"] = time.Now()
		pusher.lastPush["inactive-svc"] = time.Now()

		activeServices := map[string]bool{
			"active-svc": true,
		}
		pusher.Cleanup(activeServices)

		if _, ok := pusher.lastPush["inactive-svc"]; ok {
			t.Error("Expected inactive-svc to be removed from lastPush")
		}
		if _, ok := pusher.lastPush["active-svc"]; !ok {
			t.Error("Expected active-svc to remain in lastPush")
		}
	})

	t.Run("keeps all active services", func(t *testing.T) {
		pusher := NewPusher()
		pusher.lastPush["svc1"] = time.Now()
		pusher.lastPush["svc2"] = time.Now()

		activeServices := map[string]bool{
			"svc1": true,
			"svc2": true,
		}
		pusher.Cleanup(activeServices)

		if len(pusher.lastPush) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(pusher.lastPush))
		}
	})

	t.Run("empty map clears all", func(t *testing.T) {
		pusher := NewPusher()
		pusher.lastPush["svc1"] = time.Now()
		pusher.lastPush["svc2"] = time.Now()

		pusher.Cleanup(map[string]bool{})

		if len(pusher.lastPush) != 0 {
			t.Errorf("Expected 0 entries after cleanup with empty active map, got %d", len(pusher.lastPush))
		}
	})

	t.Run("no-op on empty lastPush", func(t *testing.T) {
		pusher := NewPusher()
		pusher.Cleanup(map[string]bool{"svc1": true})

		if len(pusher.lastPush) != 0 {
			t.Errorf("Expected 0 entries, got %d", len(pusher.lastPush))
		}
	})
}

func TestPusher_Push_LogVerification(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // Restore

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	pusher := NewPusher()
	res := monitor.Result{Success: true, Duration: 100 * time.Millisecond}

	// Create a URL with variables to verify full URL logging
	endpointCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{
			URL: testServer.URL + "?d={%duration%}",
		},
	}

	svcName := "TestLogger"
	err := pusher.Push(context.Background(), svcName, res, endpointCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	logs := buf.String()

	// URL query params are masked in logs for security
	maskedURL := testServer.URL + "?***"

	// Verify "Sending notifications to ->" format with masked query params
	expectedLog := fmt.Sprintf("[%s] Sending notifications to -> %s", svcName, maskedURL)
	if !strings.Contains(logs, expectedLog) {
		t.Errorf("Expected log to contain %q, got:\n%s", expectedLog, logs)
	}

	// Verify success log
	if !strings.Contains(logs, fmt.Sprintf("[%s] Alert push successful", svcName)) {
		t.Errorf("Expected success log, got:\n%s", logs)
	}
}
