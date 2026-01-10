package notifier

import (
	"net/http"
	"net/http/httptest"
	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"strings"
	"testing"
	"time"
)

func ptr(s string) *string {
	return &s
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

	err := pusher.Push(res, alertCfg, globalEndpointCfg)
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

	err := pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
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

	err := pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
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

	err := pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
}

func TestPusher_Push_EmptyEndpoint(t *testing.T) {
	pusher := NewPusher()
	res := monitor.Result{Success: true}
	err := pusher.Push(res, config.MonitorEndpointConfig{}, config.GlobalMonitorEndpointConfig{})
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

	err := pusher.Push(res, alertCfg, globalCfg)
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

	err := pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
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

	err := pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
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

	globalCfg := config.GlobalMonitorEndpointConfig{}

	t.Run("Fail with default client (TLS verification on)", func(t *testing.T) {
		endpointCfg := config.MonitorEndpointConfig{
			Success: config.EndpointConfig{
				URL:                server.URL,
				InsecureSkipVerify: false,
			},
		}

		err := pusher.Push(result, endpointCfg, globalCfg)
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

		err := pusher.Push(result, endpointCfg, globalCfg)
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

		err := pusher.Push(result, endpointCfg, globalCfg)
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

		err := pusher.Push(result, endpointCfg, globalCfg)
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
	pusher.SetRateLimit(ptr("100ms"))

	alertCfg := config.MonitorEndpointConfig{
		Success: config.EndpointConfig{URL: testServer.URL},
	}
	res := monitor.Result{Success: true}

	start := time.Now()
	// Push 3 times
	for i := 0; i < 3; i++ {
		_ = pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
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
	pusher.SetRateLimit(ptr("100ms"))

	// Set to invalid duration should not change existing rate limit
	pusher.SetRateLimit(ptr("invalid"))

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
	for i := 0; i < 2; i++ {
		_ = pusher.Push(res, alertCfg, config.GlobalMonitorEndpointConfig{})
	}
	duration := time.Since(start)

	// 2 pushes with 100ms interval should take at least 100ms
	if duration < 100*time.Millisecond {
		t.Errorf("Expected duration to be at least 100ms (default), got %v", duration)
	}
}

func TestPusher_SetRateLimit_Empty(t *testing.T) {
	pusher := NewPusher()
	pusher.SetRateLimit(ptr("200ms"))

	// Empty string should not change the rate limit
	pusher.SetRateLimit(ptr(""))

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
	pusher.SetRateLimit(ptr("0"))

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
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "1s"}

		err := pusher.Push(res, alertCfg, globalCfg)
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
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "1s"}

		err := pusher.Push(res, alertCfg, globalCfg)
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
		globalCfg := config.GlobalMonitorEndpointConfig{Timeout: "50ms"}

		err := pusher.Push(res, alertCfg, globalCfg)
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

		err := pusher.Push(res, alertCfg, globalCfg)
		if err != nil {
			t.Errorf("Expected success with default 5s timeout, got: %v", err)
		}
	})
}
