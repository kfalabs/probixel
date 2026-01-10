package tunnels

import (
	"context"
	"net"
	"time"
)

// MockTunnel is a mock implementation of the Tunnel interface for testing
type MockTunnel struct {
	NameFunc           func() string
	TypeFunc           func() string
	InitializeFunc     func() error
	StopFunc           func()
	DialContextFunc    func(ctx context.Context, network, address string) (net.Conn, error)
	LastInitTimeFunc   func() time.Time
	ReportFailureFunc  func()
	IsStabilizedResult bool
}

func (m *MockTunnel) Name() string {
	if m.NameFunc != nil {
		return m.NameFunc()
	}
	return "mock"
}

func (m *MockTunnel) Type() string {
	if m.TypeFunc != nil {
		return m.TypeFunc()
	}
	return "mock"
}

func (m *MockTunnel) Initialize() error {
	if m.InitializeFunc != nil {
		return m.InitializeFunc()
	}
	return nil
}

func (m *MockTunnel) Stop() {
	if m.StopFunc != nil {
		m.StopFunc()
	}
}

func (m *MockTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if m.DialContextFunc != nil {
		return m.DialContextFunc(ctx, network, address)
	}
	return nil, nil
}

func (m *MockTunnel) LastInitTime() time.Time {
	if m.LastInitTimeFunc != nil {
		return m.LastInitTimeFunc()
	}
	return time.Time{}
}

func (m *MockTunnel) ReportFailure() {
	if m.ReportFailureFunc != nil {
		m.ReportFailureFunc()
	}
}

func (m *MockTunnel) ReportSuccess() {
	// No-op for mock
}

func (m *MockTunnel) IsStabilized() bool {
	return m.IsStabilizedResult
}
