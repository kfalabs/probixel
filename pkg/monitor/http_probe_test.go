package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/tunnels"
)

func TestHTTPProbe_Check(t *testing.T) {
	// Mock Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	probe := &HTTPProbe{}

	ctx := context.Background()
	res, err := probe.Check(ctx, ts.URL)

	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestHTTPProbe_Check_Failure(t *testing.T) {
	// Closed port / invalid URL
	probe := &HTTPProbe{}
	ctx := context.Background()
	res, err := probe.Check(ctx, "http://non-existing.test")

	// Error might be returned or Success=false
	if err == nil && res.Success {
		t.Error("Expected error or failure for closed port")
	}
}

func TestHTTPProbe_AcceptedStatusCodes(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		serverCode    int
		expectSuccess bool
	}{
		{"Default (200)", "", 200, true},
		{"Default (404)", "", 404, false},
		{"Single (200)", "200", 200, true},
		{"Single (404 accepted)", "404", 404, true},
		{"Single mismatch (200 set, 201 got)", "200", 201, false},
		{"Comma list (200, 201)", "200, 201", 201, true},
		{"Range (200-202)", "200-202", 202, true},
		{"Range mismatch", "200-202", 203, false},
		{"Mixed (200-202, 404)", "200-202, 404", 404, true},
		{"Mixed mismatch", "200-202, 404", 500, false},
		{"Multiple ranges", "200-299, 400-499", 404, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverCode)
			}))
			defer ts.Close()

			probe := &HTTPProbe{AcceptedStatusCodes: tt.config}
			ctx := context.Background()
			res, err := probe.Check(ctx, ts.URL)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			if res.Success != tt.expectSuccess {
				t.Errorf("Expected success=%v, got %v (Code %d, Config %q)", tt.expectSuccess, res.Success, tt.serverCode, tt.config)
			}
		})
	}
}

func TestHTTPProbe_Check_EdgeCases(t *testing.T) {
	probe := &HTTPProbe{
		AcceptedStatusCodes: "200",
	}

	// Test invalid URL (causes request failed)
	result, _ := probe.Check(context.Background(), "http://this.should.fail.invalid")
	if result.Success {
		t.Error("Expected failure for invalid URL")
	}

	// Test malformed URL (causes NewRequest error)
	// URL with control character
	result, _ = probe.Check(context.Background(), "http://example.com/\x7f")
	if result.Success {
		t.Error("Expected failure for malformed URL")
	}

	// No-op SetTargetMode
	probe.SetTargetMode(TargetModeAll)
}

func TestHTTPProbe_CheckStatusCode_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		acceptedCodes string
		actualStatus  int
		shouldSucceed bool
	}{
		{"Empty accepted codes with 200", "", 200, true},
		{"Single code mismatch", "201", 200, false},
		{"Range outside", "200-299", 300, false},
		{"Invalid range (start > end)", "300-200", 250, false},
		{"Malformed codes (text)", "abc, 200", 200, true},
		{"Non-integer input", "200-abc", 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &HTTPProbe{
				AcceptedStatusCodes: tt.acceptedCodes,
			}
			if probe.checkStatusCode(tt.actualStatus) != tt.shouldSucceed {
				t.Errorf("%s failed", tt.name)
			}
		})
	}
}

func TestHTTPProbe_InsecureSkipVerify(t *testing.T) {
	// Start a TLS server with a self-signed certificate
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx := context.Background()

	t.Run("Probe with InsecureSkipVerify=false (default)", func(t *testing.T) {
		probe := &HTTPProbe{InsecureSkipVerify: false}
		res, err := probe.Check(ctx, ts.URL)
		if err != nil {
			t.Fatalf("Check returned internal error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure for self-signed cert with InsecureSkipVerify=false")
		}
	})

	t.Run("Probe with InsecureSkipVerify=true", func(t *testing.T) {
		probe := &HTTPProbe{InsecureSkipVerify: true}
		res, err := probe.Check(ctx, ts.URL)
		if err != nil {
			t.Fatalf("Check returned internal error: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success for self-signed cert with InsecureSkipVerify=true, got failure: %s", res.Message)
		}
	})

	t.Run("TLS expiry check - disabled by default", func(t *testing.T) {
		probe := &HTTPProbe{InsecureSkipVerify: true}
		res, err := probe.Check(ctx, ts.URL)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if strings.Contains(res.Message, "TLS expires in") {
			t.Errorf("Result should not contain TLS expiry info when disabled: %s", res.Message)
		}
	})

	t.Run("TLS expiry check - enabled when threshold set", func(t *testing.T) {
		probe := &HTTPProbe{InsecureSkipVerify: true, ExpiryThreshold: 24 * time.Hour}
		res, err := probe.Check(ctx, ts.URL)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		// httptest certs are usually valid for 10 years, so this should pass
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "TLS expires in") {
			t.Errorf("Message missing TLS expiry info: %s", res.Message)
		}
	})

	t.Run("TLS expiry threshold fail", func(t *testing.T) {
		// Set a very high threshold to trigger failure
		probe := &HTTPProbe{InsecureSkipVerify: true, ExpiryThreshold: 365 * 100 * 24 * time.Hour}
		res, err := probe.Check(ctx, ts.URL)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if res.Success {
			t.Error("Expected failure due to high threshold, got success")
		}
		if !strings.Contains(res.Message, "TLS expires soon") {
			t.Errorf("Unexpected message: %s", res.Message)
		}
	})
}

func TestHTTPProbe_AdvancedOptions(t *testing.T) {
	expectedMethod := "POST"
	expectedHeaderKey := "X-Test-Probe"
	expectedHeaderVal := "Probixel-Check"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("Expected method %s, got %s", expectedMethod, r.Method)
		}
		if val := r.Header.Get(expectedHeaderKey); val != expectedHeaderVal {
			t.Errorf("Expected header %s: %s, got %s", expectedHeaderKey, expectedHeaderVal, val)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	probe := &HTTPProbe{
		Method: expectedMethod,
		Headers: map[string]string{
			expectedHeaderKey: expectedHeaderVal,
		},
	}

	res, err := probe.Check(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Success {
		t.Errorf("Expected success, got failure: %s", res.Message)
	}
}

func TestHTTPProbe_Expectations(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
		headers      map[string]string
		matchData    *config.MatchDataConfig
		wantSuccess  bool
		wantMsgPart  string
	}{
		{
			name:         "JSON equals success",
			responseBody: `{"status": "ok", "version": 1.2}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "status", Operator: "==", Value: "ok"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON equals fail",
			responseBody: `{"status": "error"}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "status", Operator: "==", Value: "ok"},
				},
			},
			wantSuccess: false,
			wantMsgPart: "expectation failed",
		},
		{
			name:         "JSON greater_than success",
			responseBody: `{"count": 10}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "count", Operator: ">", Value: "5"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON less_than success",
			responseBody: `{"count": 10}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "count", Operator: "<", Value: "20"},
				},
			},
			wantSuccess: true,
		},
		{
			name:    "Header equals success",
			headers: map[string]string{"X-Status": "Active"},
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "header", Header: "X-Status", Operator: "==", Value: "Active"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "Body contains success",
			responseBody: "Welcome to the dashboard",
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "body", Operator: "contains", Value: "dashboard"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "Syncthing less_than duration success (recent)",
			responseBody: fmt.Sprintf(`{"device1": {"lastSeen": "%s"}}`, time.Now().Format(time.RFC3339)),
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "device1.lastSeen", Operator: "<", Value: "10m"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "Syncthing less_than duration fail (too old)",
			responseBody: `{"device1": {"lastSeen": "2020-01-01T00:00:00Z"}}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "device1.lastSeen", Operator: "<", Value: "10m"},
				},
			},
			wantSuccess: false,
			wantMsgPart: "expectation failed",
		},
		{
			name:         "Syncthing greater_than duration success (old)",
			responseBody: `{"device1": {"lastSeen": "2020-01-01T00:00:00Z"}}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "device1.lastSeen", Operator: ">", Value: "10m"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "Absolute time comparison success",
			responseBody: `{"time": "2024-01-01T12:00:00Z"}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "time", Operator: "<", Value: "2024-01-02T12:00:00Z"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON array index success",
			responseBody: `{"items": [{"name": "one"}, {"name": "two"}]}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.1.name", Operator: "==", Value: "two"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON array length success",
			responseBody: `{"items": [1, 2, 3]}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#", Operator: ">", Value: "2"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON array length fail",
			responseBody: `{"items": [1, 2, 3]}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#", Operator: "==", Value: "5"},
				},
			},
			wantSuccess: false,
			wantMsgPart: "expectation failed",
		},
		{
			name:         "JSON wildcard any-match success",
			responseBody: `{"items": [{"name": "one"}, {"name": "two"}, {"name": "three"}]}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#.name", Operator: "==", Value: "two"},
				},
			},
			wantSuccess: true,
		},
		{
			name:         "JSON wildcard any-match fail",
			responseBody: `{"items": [{"name": "one"}, {"name": "two"}]}`,
			matchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#.name", Operator: "==", Value: "four"},
				},
			},
			wantSuccess: false,
			wantMsgPart: "expectation failed: no element in items.#.name == four",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			probe := &HTTPProbe{
				MatchData: tt.matchData,
			}

			result, err := probe.Check(context.Background(), server.URL)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}

			if result.Success != tt.wantSuccess {
				t.Errorf("Success = %v, want %v. Message: %s", result.Success, tt.wantSuccess, result.Message)
			}
			if tt.wantMsgPart != "" && !strings.Contains(result.Message, tt.wantMsgPart) {
				t.Errorf("Message %q does not contain %q", result.Message, tt.wantMsgPart)
			}
		})
	}
}

func TestHTTPProbe_EdgeCases_Extended(t *testing.T) {
	t.Run("Unknown expectation type", func(t *testing.T) {
		probe := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "invalid-type", Operator: "=="},
				},
			},
		}
		passed, msg := probe.evaluateExpectations([]byte(`{}`), http.Header{})
		if passed {
			t.Error("expected failure for unknown type")
		}
		if !strings.Contains(msg, "unknown expectation type") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Unknown operator", func(t *testing.T) {
		probe := &HTTPProbe{}
		passed, err := probe.evaluateOperator("invalid-op", "val", "target")
		if err == nil || passed {
			t.Error("expected error for unknown operator")
		}
	})

	t.Run("JSON field not found", func(t *testing.T) {
		probe := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "missing", Operator: "==", Value: "val"},
				},
			},
		}
		passed, msg := probe.evaluateExpectations([]byte(`{"other": 1}`), http.Header{})
		if passed {
			t.Error("expected failure for missing field")
		}
		if !strings.Contains(msg, "field not found") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Compare unsupported", func(t *testing.T) {
		probe := &HTTPProbe{}
		passed, err := probe.compare("abc", "def", true)
		if err == nil || passed {
			t.Error("expected error for unsupported comparison")
		}
	})

	t.Run("Age check - invalid timestamp", func(t *testing.T) {
		probe := &HTTPProbe{}
		// Target "10m" triggers age check
		passed, err := probe.compare("not-a-date", "10m", true)
		if err == nil || passed {
			t.Error("expected error for invalid timestamp in age check")
		}
	})

	t.Run("Parse timestamp - invalid format", func(t *testing.T) {
		probe := &HTTPProbe{}
		_, err := probe.parseTimestamp("invalid-format")
		if err == nil {
			t.Error("expected error for invalid timestamp format")
		}
	})

	t.Run("Failed to read response body", func(t *testing.T) {
		// Use a body that returns an error on read
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		probe := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{{Type: "body", Operator: "=="}},
			},
		}
		res, _ := probe.Check(context.Background(), server.URL)
		if res.Success {
			t.Error("expected failure when body reading fails")
		}
	})

	t.Run("Wildcard JSON - invalid operator in array", func(t *testing.T) {
		probe := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#", Operator: "invalid", Value: "val"},
				},
			},
		}
		passed, msg := probe.evaluateExpectations([]byte(`{"items": [1, 2]}`), http.Header{})
		if passed {
			t.Error("expected failure for invalid operator in wildcard loop")
		}
		if !strings.Contains(msg, "unknown operator") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Header not found", func(t *testing.T) {
		probe := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "header", Header: "X-Missing", Operator: "==", Value: "val"},
				},
			},
		}
		passed, msg := probe.evaluateExpectations([]byte(`{}`), http.Header{})
		if passed {
			t.Error("expected failure for missing header")
		}
		if !strings.Contains(msg, "field not found") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Invalid regex", func(t *testing.T) {
		probe := &HTTPProbe{}
		passed, err := probe.evaluateOperator("matches", "val", "[invalid regex")
		if err == nil || passed {
			t.Error("expected error for invalid regex")
		}
	})

	t.Run("evaluateOperator failure in evaluateExpectations", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "body", Operator: "invalid", Value: "val"},
				},
			},
		}
		passed, msg := p.evaluateExpectations([]byte(`body`), http.Header{})
		if passed {
			t.Error("expected failure")
		}
		if !strings.Contains(msg, "expectation failed") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Expectation not met in evaluateExpectations", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "body", Operator: "==", Value: "wrong"},
				},
			},
		}
		passed, _ := p.evaluateExpectations([]byte(`correct`), http.Header{})
		if passed {
			t.Error("expected failure")
		}
	})

	t.Run("Absolute time comparison", func(t *testing.T) {
		p := &HTTPProbe{}
		t1 := time.Now().Format(time.RFC3339)
		t2 := time.Now().Add(time.Hour).Format(time.RFC3339)
		// t1 < t2, so isGreater=false should be true
		passed, err := p.compare(t1, t2, false)
		if err != nil || !passed {
			t.Errorf("expected true, got %v, err: %v", passed, err)
		}

		// t2 > t1, so isGreater=true should be true
		passed, err = p.compare(t2, t1, true)
		if err != nil || !passed {
			t.Errorf("expected true, got %v, err: %v", passed, err)
		}
	})

	t.Run("Status codes with spaces", func(t *testing.T) {
		p := &HTTPProbe{AcceptedStatusCodes: "200, , 201"}
		if !p.checkStatusCode(201) {
			t.Error("expected 201 to be accepted")
		}
	})

	t.Run("Redirect check", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, "/ok", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		probe := &HTTPProbe{}
		// This should trigger CheckRedirect
		_, _ = probe.Check(context.Background(), server.URL+"/redirect")
	})

	t.Run("Unknown expectation type", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "unknown", Operator: "=="},
				},
			},
		}
		passed, msg := p.evaluateExpectations([]byte(`{}`), http.Header{})
		if passed {
			t.Error("expected failure")
		}
		if !strings.Contains(msg, "unknown expectation type") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Wildcard JSON - invalid operator in array", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "json", JSONPath: "items.#.val", Operator: "invalid", Value: "foo"},
				},
			},
		}
		passed, msg := p.evaluateExpectations([]byte(`{"items":[{"val":"a"},{"val":"b"}]}`), http.Header{})
		if passed {
			t.Error("expected failure")
		}
		if !strings.Contains(msg, "expectation failed") || !strings.Contains(msg, "unknown operator") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("evaluateOperator failure in evaluateExpectations", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "body", Operator: "invalid", Value: "foo"},
				},
			},
		}
		passed, msg := p.evaluateExpectations([]byte(`body`), http.Header{})
		if passed {
			t.Error("expected failure")
		}
		if !strings.Contains(msg, "expectation failed") || !strings.Contains(msg, "unknown operator") {
			t.Errorf("unexpected message: %s", msg)
		}
	})

	t.Run("Header success", func(t *testing.T) {
		p := &HTTPProbe{
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "header", Header: "X-Custom", Operator: "==", Value: "test-value"},
				},
			},
		}
		headers := http.Header{}
		headers.Set("X-Custom", "test-value")
		passed, msg := p.evaluateExpectations([]byte(``), headers)
		if !passed {
			t.Errorf("expected success for header match, got: %s", msg)
		}
	})

	t.Run("Matches operator success", func(t *testing.T) {
		p := &HTTPProbe{}
		passed, err := p.evaluateOperator("matches", "hello-world-123", "^hello.*\\d+$")
		if err != nil || !passed {
			t.Errorf("expected success for matches operator, err=%v, passed=%v", err, passed)
		}
	})

	t.Run("Matches operator failure", func(t *testing.T) {
		p := &HTTPProbe{}
		passed, err := p.evaluateOperator("matches", "no-match-here", "^definitely-not$")
		if err != nil {
			t.Errorf("expected no error for valid regex non-match, got: %v", err)
		}
		if passed {
			t.Error("expected failure for non-matching regex")
		}
	})
}
func TestHTTPProbe_Stabilization(t *testing.T) {
	// Mock Tunnel that is NOT stabilized
	mt := &tunnels.MockTunnel{
		IsStabilizedResult: false,
	}

	probe := &HTTPProbe{}
	probe.SetTunnel(mt)

	ctx := context.Background()
	res, err := probe.Check(ctx, "http://localhost:8080")

	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true when tunnel is not stabilized")
	}
	if res.Success {
		t.Error("Expected Success: false when tunnel is not stabilized")
	}
}

func TestHTTPProbe_SetTimeout(t *testing.T) {
	p := &HTTPProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
