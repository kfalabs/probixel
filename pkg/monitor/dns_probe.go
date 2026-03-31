package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"probixel/pkg/tunnels"
)

const DEFAULT_DOMAIN = "google.com"

type resolverPair struct {
	udp *net.Resolver
	tcp *net.Resolver
}

type DNSProbe struct {
	Resolve     func(ctx context.Context, nameserver, host string) ([]string, error)
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Timeout     time.Duration
	targetMode  string
	domain      string
	tunnel      tunnels.Tunnel
	resolverMu  sync.Mutex
	resolvers   map[string]*resolverPair
}

func (p *DNSProbe) getResolvers(nameserver string) (*net.Resolver, *net.Resolver) {
	p.resolverMu.Lock()
	defer p.resolverMu.Unlock()

	if p.resolvers == nil {
		p.resolvers = make(map[string]*resolverPair)
	}

	if pair, ok := p.resolvers[nameserver]; ok {
		return pair.udp, pair.tcp
	}

	dialer := p.DialContext
	if dialer == nil {
		timeout := p.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		d := net.Dialer{Timeout: timeout}
		dialer = d.DialContext
	}

	pair := &resolverPair{
		udp: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer(ctx, "udp", nameserver)
			},
		},
		tcp: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer(ctx, "tcp", nameserver)
			},
		},
	}
	p.resolvers[nameserver] = pair
	return pair.udp, pair.tcp
}

func (p *DNSProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *DNSProbe) Name() string {
	return MonitorTypeDNS
}

func (p *DNSProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *DNSProbe) SetDomain(domain string) {
	p.domain = domain
}

func (p *DNSProbe) Check(ctx context.Context, target string) (Result, error) {
	// Target might start with "dns:"
	target = strings.TrimPrefix(target, "dns:")
	targets := strings.Split(target, ",")
	var lastErr error

	startTotal := time.Now()

	// Strict stabilization adherence: always return Pending if tunnel not stabilized
	if p.tunnel != nil && !p.tunnel.IsStabilized() {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(startTotal),
			Message:   fmt.Sprintf("waiting for tunnel %q to stabilize", p.tunnel.Name()),
			Timestamp: startTotal,
		}, nil
	}

	// For "all" mode, track successes
	if p.targetMode == TargetModeAll {
		var totalDuration time.Duration
		successCount := 0

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			duration, err := p.resolveTarget(ctx, t)
			if err != nil {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			totalDuration += duration
			successCount++
		}

		if successCount > 0 {
			return Result{
				Success:   true,
				Duration:  totalDuration / time.Duration(successCount),
				Message:   fmt.Sprintf("all %d targets OK", successCount),
				Timestamp: startTotal,
			}, nil
		}
	}

	// Default "any" mode
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// Handle host:port
		host, port, err := net.SplitHostPort(t)
		if err != nil {
			host = t
			port = "53"
		}
		nameserver := net.JoinHostPort(host, port)
		start := time.Now()

		domainToResolve := p.domain
		if domainToResolve == "" {
			domainToResolve = DEFAULT_DOMAIN
		}

		// Enforce timeout on DNS lookups
		lookupTimeout := p.Timeout
		if lookupTimeout == 0 {
			lookupTimeout = 5 * time.Second
		}
		lookupCtx, lookupCancel := context.WithTimeout(ctx, lookupTimeout)

		var ips []string
		if p.Resolve != nil {
			ips, err = p.Resolve(lookupCtx, nameserver, domainToResolve)
		} else {
			udpResolver, tcpResolver := p.getResolvers(nameserver)
			ips, err = udpResolver.LookupHost(lookupCtx, domainToResolve)

			if err == nil && len(ips) > 0 {
				lookupCancel()
				return Result{
					Success:   true,
					Duration:  time.Since(start),
					Message:   "OK",
					Target:    nameserver,
					Timestamp: startTotal,
				}, nil
			}

			// Retry DNS resolution with TCP using the same timeout context
			ips, err = tcpResolver.LookupHost(lookupCtx, domainToResolve)
			if err == nil && len(ips) > 0 {
				lookupCancel()
				return Result{
					Success:   true,
					Duration:  time.Since(start),
					Message:   "OK (TCP)",
					Target:    nameserver,
					Timestamp: startTotal,
				}, nil
			}
		}
		lookupCancel()

		if err == nil && len(ips) > 0 {
			return Result{
				Success:   true,
				Duration:  time.Since(start),
				Message:   "OK",
				Target:    nameserver,
				Timestamp: startTotal,
			}, nil
		}

		lastErr = err
	}

	return Result{
		Success:   false,
		Duration:  0,
		Message:   fmt.Sprintf("all dns targets failed, last error: %v", lastErr),
		Timestamp: startTotal,
	}, nil
}
func (p *DNSProbe) resolveTarget(ctx context.Context, target string) (time.Duration, error) {
	// Handle host:port
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "53"
	}
	nameserver := net.JoinHostPort(host, port)
	start := time.Now()

	domainToResolve := p.domain
	if domainToResolve == "" {
		domainToResolve = DEFAULT_DOMAIN
	}

	// Enforce timeout on DNS lookups
	lookupTimeout := p.Timeout
	if lookupTimeout == 0 {
		lookupTimeout = 5 * time.Second
	}
	lookupCtx, lookupCancel := context.WithTimeout(ctx, lookupTimeout)
	defer lookupCancel()

	var ips []string
	if p.Resolve != nil {
		ips, err = p.Resolve(lookupCtx, nameserver, domainToResolve)
	} else {
		udpResolver, tcpResolver := p.getResolvers(nameserver)
		ips, err = udpResolver.LookupHost(lookupCtx, domainToResolve)
		if err != nil {
			// Retry with TCP
			ips, err = tcpResolver.LookupHost(lookupCtx, domainToResolve)
		}
	}

	if err != nil || len(ips) == 0 {
		return 0, fmt.Errorf("%v", err)
	}

	return time.Since(start), nil
}

func (p *DNSProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
