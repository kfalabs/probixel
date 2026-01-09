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
