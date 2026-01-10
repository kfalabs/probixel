package tunnels

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type Tunnel interface {
	Name() string
	Type() string
	Initialize() error
	Stop()
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	LastInitTime() time.Time
	ReportFailure()
	ReportSuccess()
	IsStabilized() bool
}

type Registry struct {
	mu      sync.RWMutex
	tunnels map[string]Tunnel
}

func NewRegistry() *Registry {
	return &Registry{
		tunnels: make(map[string]Tunnel),
	}
}

func (r *Registry) Register(t Tunnel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tunnels[t.Name()]; ok {
		return fmt.Errorf("tunnel %q already registered", t.Name())
	}
	r.tunnels[t.Name()] = t
	return nil
}

func (r *Registry) Get(name string) (Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[name]
	return t, ok
}

func (r *Registry) StopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tunnels {
		t.Stop()
	}
	r.tunnels = make(map[string]Tunnel)
}
