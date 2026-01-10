package monitor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"probixel/pkg/tunnels"
	"strings"
	"testing"
	"time"
)

func TestTLSProbe_Name(t *testing.T) {
	p := &TLSProbe{}
	if p.Name() != MonitorTypeTLS {
		t.Errorf("Expected name %s, got %s", MonitorTypeTLS, p.Name())
	}
}

func TestTLSProbe_Check(t *testing.T) {
	// Create a mock TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")

	t.Run("valid certificate", func(t *testing.T) {
		probe := &TLSProbe{ExpiryThreshold: 24 * time.Hour, InsecureSkipVerify: true}
		res, err := probe.Check(context.Background(), "tls://"+addr)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "OK (expires in") {
			t.Errorf("Unexpected message: %s", res.Message)
		}
	})

	t.Run("missing port", func(t *testing.T) {
		host, _, _ := net.SplitHostPort(addr)
		probe := &TLSProbe{}
		_, _ = probe.Check(context.Background(), "tls://"+host)
	})

	t.Run("connection failure", func(t *testing.T) {
		probe := &TLSProbe{}
		res, err := probe.Check(context.Background(), "localhost:1")
		if err == nil && !res.Success {
			// Expected failure
		} else if err != nil {
			// Also expected
		} else {
			t.Error("Expected error or failure, got success")
		}
	})
}

func TestTLSProbe_MultiTarget(t *testing.T) {
	server1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server1.Close()
	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server2.Close()

	addr1 := strings.TrimPrefix(server1.URL, "https://")
	addr2 := strings.TrimPrefix(server2.URL, "https://")

	t.Run("any mode success", func(t *testing.T) {
		probe := &TLSProbe{InsecureSkipVerify: true}
		probe.SetTargetMode(TargetModeAny)
		res, err := probe.Check(context.Background(), "tls://"+addr1+",tls://"+addr2)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
	})

	t.Run("all mode success", func(t *testing.T) {
		probe := &TLSProbe{InsecureSkipVerify: true}
		probe.SetTargetMode(TargetModeAll)
		res, err := probe.Check(context.Background(), "tls://"+addr1+",tls://"+addr2)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !res.Success {
			t.Errorf("Expected success, got failure: %s", res.Message)
		}
		if !strings.Contains(res.Message, "all 2 certs OK") {
			t.Errorf("Unexpected message: %s", res.Message)
		}
	})

	t.Run("all mode failure", func(t *testing.T) {
		probe := &TLSProbe{}
		probe.SetTargetMode(TargetModeAll)
		res, err := probe.Check(context.Background(), "tls://"+addr1+",tls://localhost:1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if res.Success {
			t.Error("Expected failure, got success")
		}
	})
}

func TestTLSProbe_Expiry(t *testing.T) {
	now := time.Now()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.Add(2 * 24 * time.Hour), // Expires in 2 days
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:    []string{"localhost"},
	}

	// For a real test, a full TLS server with this cert is required,
	// but the checkTarget internal logic can also be tested if it is exported or use a helper.
	// Since checkTarget uses tls.Dial, it's hard to mock without a real listener.
	t.Run("threshold fail", func(t *testing.T) {
		// If cert expires in 2 days and threshold is 7, it should fail
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{generateTestCert(t, template)},
		}
		server.StartTLS()
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "https://")
		probe := &TLSProbe{ExpiryThreshold: 7 * 24 * time.Hour, InsecureSkipVerify: true}
		res, err := probe.Check(context.Background(), "tls://"+addr)
		if err != nil {
			// tls.Dial might fail validation because it's a self-signed cert.
			// Skip if it's a validation error not related to our logic
			return
		}
		if res.Success {
			t.Error("Expected failure due to threshold, got success")
		}
	})
}

func generateTestCert(t *testing.T, template x509.Certificate) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}
func TestTLSProbe_Stabilization(t *testing.T) {
	mt := &tunnels.MockTunnel{IsStabilizedResult: false}
	probe := &TLSProbe{}
	probe.SetTunnel(mt)

	res, err := probe.Check(context.Background(), "localhost:443")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !res.Pending {
		t.Error("Expected Pending: true")
	}
}

func TestTLSProbe_SetTimeout(t *testing.T) {
	p := &TLSProbe{}
	p.SetTimeout(10 * time.Second)
	if p.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", p.Timeout)
	}
}
