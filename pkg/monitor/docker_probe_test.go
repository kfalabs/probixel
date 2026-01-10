package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"
)

func TestDockerProbe_Check_Proxy(t *testing.T) {
	// Mock Docker API Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/test-container/json" {
			t.Errorf("expected path /containers/test-container/json, got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("expected GET method, got %s", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "Basic dGVzdC1jcmVkcw==" {
			t.Errorf("expected Authorization header Basic dGVzdC1jcmVkcw==, got %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"State": map[string]interface{}{
				"Status": "running",
				"Health": map[string]interface{}{
					"Status": "healthy",
				},
			},
		})
	}))
	defer server.Close()

	// Parse host and port from httptest server
	serverAddr := strings.TrimPrefix(server.URL, "http://")
	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	probe := &DockerProbe{
		Sockets: map[string]config.DockerSocketConfig{
			"proxy": {
				Host:     host,
				Port:     port,
				Protocol: "http",
				Headers: map[string]string{
					"Authorization": "Basic dGVzdC1jcmVkcw==",
				},
			},
		},
		SocketName: "proxy",
		Healthy:    true,
	}

	result, err := probe.Check(context.Background(), "test-container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}
	if !strings.Contains(result.Message, "running (healthy)") {
		t.Errorf("expected message to contain 'running (healthy)', got %s", result.Message)
	}
}

func TestDockerProbe_Check_UnixSocket(t *testing.T) {
	// Create a temporary unix socket file
	socketFile := "/tmp/probixel-docker-test.sock"
	_ = os.Remove(socketFile)
	defer os.Remove(socketFile)

	l, err := net.Listen("unix", socketFile)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer l.Close()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"State": map[string]interface{}{
				"Status": "running",
			},
		})
	}))
	server.Listener = l
	server.Start()
	defer server.Close()

	probe := &DockerProbe{
		Sockets: map[string]config.DockerSocketConfig{
			"local": {
				Socket: socketFile,
			},
		},
		SocketName: "local",
		Healthy:    false,
	}

	result, err := probe.Check(context.Background(), "local-container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}
	if result.Message != "OK" {
		t.Errorf("expected message 'OK', got %s", result.Message)
	}
}

func TestDockerProbe_Check_ContainerStatuses(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		healthStatus string
		waitHealthy  bool
		wantSuccess  bool
		wantMsg      string
	}{
		{"running and healthy", "running", "healthy", true, true, "running (healthy)"},
		{"running but unhealthy", "running", "unhealthy", true, false, "container is running but health is unhealthy"},
		{"running no healthcheck", "running", "", true, true, "OK"},
		{"stopped", "exited", "", false, false, "container is exited"},
		{"starting", "running", "starting", true, false, "container is running but health is starting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"State": map[string]interface{}{
						"Status": tt.status,
						"Health": map[string]interface{}{
							"Status": tt.healthStatus,
						},
					},
				})
			}))
			defer server.Close()

			serverAddr := strings.TrimPrefix(server.URL, "http://")
			host, portStr, _ := net.SplitHostPort(serverAddr)
			port := 0
			fmt.Sscanf(portStr, "%d", &port)

			probe := &DockerProbe{
				Sockets: map[string]config.DockerSocketConfig{
					"test": {
						Host: host,
						Port: port,
					},
				},
				SocketName: "test",
				Healthy:    tt.waitHealthy,
			}

			result, err := probe.Check(context.Background(), "test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Errorf("expected success %v, got %v (message: %s)", tt.wantSuccess, result.Success, result.Message)
			}
			if !strings.Contains(result.Message, tt.wantMsg) {
				t.Errorf("expected message to contain %q, got %q", tt.wantMsg, result.Message)
			}
		})
	}
}

func TestDockerProbe_Check_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")
	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	probe := &DockerProbe{
		Sockets: map[string]config.DockerSocketConfig{
			"test": {Host: host, Port: port},
		},
		SocketName: "test",
	}

	result, err := probe.Check(context.Background(), "non-existent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure, got success")
	}
	if !strings.Contains(result.Message, "container \"non-existent\" not found") {
		t.Errorf("expected message to contain 'container \"non-existent\" not found', got %s", result.Message)
	}
}

func TestDockerProbe_Check_SocketNotFound(t *testing.T) {
	probe := &DockerProbe{
		Sockets:    map[string]config.DockerSocketConfig{},
		SocketName: "missing",
	}

	result, err := probe.Check(context.Background(), "any")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure, got success")
	}
	if !strings.Contains(result.Message, "docker socket \"missing\" not found") {
		t.Errorf("expected message to contain 'docker socket \"missing\" not found', got %s", result.Message)
	}
}

func TestDockerProbe_Metadata(t *testing.T) {
	probe := &DockerProbe{}
	if probe.Name() != MonitorTypeDocker {
		t.Errorf("expected name %s, got %s", MonitorTypeDocker, probe.Name())
	}
	// SetTargetMode is no-op
	probe.SetTargetMode(TargetModeAll)
}

func TestDockerProbe_Check_Errors(t *testing.T) {
	t.Run("invalid client config", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets: map[string]config.DockerSocketConfig{
				"bad": {}, // Empty config
			},
			SocketName: "bad",
		}
		res, err := probe.Check(context.Background(), "any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure for invalid config")
		}
		if !strings.Contains(res.Message, "invalid docker socket configuration") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("api server 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		serverAddr := strings.TrimPrefix(server.URL, "http://")
		host, portStr, _ := net.SplitHostPort(serverAddr)
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		probe := &DockerProbe{
			Sockets: map[string]config.DockerSocketConfig{
				"test": {Host: host, Port: port},
			},
			SocketName: "test",
		}

		res, err := probe.Check(context.Background(), "any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure for 500 response")
		}
		if !strings.Contains(res.Message, "docker api returned status 500") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("malformed json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		serverAddr := strings.TrimPrefix(server.URL, "http://")
		host, portStr, _ := net.SplitHostPort(serverAddr)
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		probe := &DockerProbe{
			Sockets: map[string]config.DockerSocketConfig{
				"test": {Host: host, Port: port},
			},
			SocketName: "test",
		}

		res, err := probe.Check(context.Background(), "any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure for malformed json")
		}
		if !strings.Contains(res.Message, "failed to decode docker api response") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("network error", func(t *testing.T) {
		// Using a port that is likely closed
		probe := &DockerProbe{
			Sockets: map[string]config.DockerSocketConfig{
				"test": {Host: "127.0.0.1", Port: 1},
			},
			SocketName: "test",
		}

		res, err := probe.Check(context.Background(), "any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure for network error")
		}
		if !strings.Contains(res.Message, "docker api request failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("protocol defaults and types", func(t *testing.T) {
		probe := &DockerProbe{}

		// Empty protocol should default to http
		client, url, err := probe.getClient(config.DockerSocketConfig{Host: "localhost", Port: 80})
		if err != nil || url != "http://localhost:80" || client == nil {
			t.Errorf("failed empty protocol: %v, %s", err, url)
		}

		// HTTPS protocol
		client, url, err = probe.getClient(config.DockerSocketConfig{Host: "localhost", Port: 443, Protocol: "https"})
		if err != nil || url != "https://localhost:443" || client == nil {
			t.Errorf("failed https protocol: %v, %s", err, url)
		}
	})

	t.Run("malformed url error", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets: map[string]config.DockerSocketConfig{
				"test": {Host: "localhost", Port: 80, Protocol: "http\x7f"},
			},
			SocketName: "test",
		}
		res, _ := probe.Check(context.Background(), "any")
		if res.Success || !strings.Contains(res.Message, "failed to create request") {
			t.Errorf("expected request creation failure, got: %s", res.Message)
		}
	})
}

func TestDockerProbe_Check_MultiTarget(t *testing.T) {
	// Mock Docker API Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Map container names to statuses
		statuses := map[string]string{
			"db1": "running",
			"db2": "running",
			"db3": "exited",
		}

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		name := parts[2]

		status, ok := statuses[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"State": map[string]interface{}{
				"Status": status,
			},
		})
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")
	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	sockets := map[string]config.DockerSocketConfig{
		"test": {Host: host, Port: port},
	}

	t.Run("Any mode - partial success", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets:    sockets,
			SocketName: "test",
		}
		probe.SetTargetMode(TargetModeAny)

		// db1 is running, db3 is exited. Any should succeed.
		res, err := probe.Check(context.Background(), "db1, db3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Success {
			t.Errorf("expected success in 'any' mode with db1 up, got failure: %s", res.Message)
		}
		if res.Target != "db1" {
			t.Errorf("expected target db1, got %s", res.Target)
		}
	})

	t.Run("All mode - partial success (fails)", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets:    sockets,
			SocketName: "test",
		}
		probe.SetTargetMode(TargetModeAll)

		// db1 is running, db3 is exited. All should fail.
		res, err := probe.Check(context.Background(), "db1, db3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure in 'all' mode with db3 down")
		}
		if !strings.Contains(res.Message, "container is exited") {
			t.Errorf("unexpected message: %s", res.Message)
		}
		if res.Target != "db3" {
			t.Errorf("expected failed target db3, got %s", res.Target)
		}
	})

	t.Run("All mode - full success", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets:    sockets,
			SocketName: "test",
		}
		probe.SetTargetMode(TargetModeAll)

		res, err := probe.Check(context.Background(), "db1, db2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Success {
			t.Errorf("expected success in 'all' mode with db1 and db2 up, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "all 2 containers OK") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})

	t.Run("Any mode - full failure", func(t *testing.T) {
		probe := &DockerProbe{
			Sockets:    sockets,
			SocketName: "test",
		}
		probe.SetTargetMode(TargetModeAny)

		res, err := probe.Check(context.Background(), "db3, missing")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Success {
			t.Error("expected failure in 'any' mode with all targets down")
		}
		if !strings.Contains(res.Message, "all 2 docker targets failed") {
			t.Errorf("unexpected message: %s", res.Message)
		}
	})
}
func TestDockerProbe_Check_EmptyTargets(t *testing.T) {
	probe := &DockerProbe{
		Sockets: map[string]config.DockerSocketConfig{
			"test": {Host: "localhost", Port: 80},
		},
		SocketName: "test",
	}
	ctx := context.Background()

	t.Run("empty part in list any mode", func(t *testing.T) {
		probe.SetTargetMode(TargetModeAny)
		_, _ = probe.Check(ctx, "mysql,  , redis")
	})

	t.Run("empty targets all mode", func(t *testing.T) {
		probe.SetTargetMode(TargetModeAll)
		// Should skip empty and return because successCount is 0
		_, _ = probe.Check(ctx, " , ")
		// Mixed empty
		_, _ = probe.Check(ctx, "mysql, , ")
	})
}

func TestDockerProbe_DialContext(t *testing.T) {
	dialCalled := false
	probe := &DockerProbe{
		Sockets: map[string]config.DockerSocketConfig{
			"proxy": {Host: "localhost", Port: 80},
		},
		SocketName: "proxy",
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCalled = true
			return nil, fmt.Errorf("mock dial error")
		},
	}

	_, _ = probe.Check(context.Background(), "test")
	if !dialCalled {
		t.Error("expected DialContext to be called")
	}
}
func TestDockerProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &DockerProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "test-container")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestDockerProbe_SetTimeout(t *testing.T) {
	p := &DockerProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
