package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"probixel/pkg/tunnels"
)

const DEFAULT_DOMAIN = "google.com"

type DNSProbe struct {
	Resolve     func(ctx context.Context, nameserver, host string) ([]string, error)
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Timeout     time.Duration
	targetMode  string
	domain      string
	tunnel      tunnels.Tunnel
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

			var ips []string
			if p.Resolve != nil {
				ips, err = p.Resolve(ctx, nameserver, domainToResolve)
			} else {
				dialer := p.DialContext
				if dialer == nil {
					timeout := p.Timeout
					if timeout == 0 {
						timeout = 5 * time.Second
					}
					d := net.Dialer{Timeout: timeout}
					dialer = d.DialContext
				}

				r := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						return dialer(ctx, "udp", nameserver)
					},
				}
				ips, err = r.LookupHost(ctx, domainToResolve)
				if err != nil {
					// Retry with TCP
					rTCP := &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							return dialer(ctx, "tcp", nameserver)
						},
					}
					ips, err = rTCP.LookupHost(ctx, domainToResolve)
				}
			}

			if err != nil || len(ips) == 0 {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			totalDuration += time.Since(start)
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

		var ips []string
		if p.Resolve != nil {
			ips, err = p.Resolve(ctx, nameserver, domainToResolve)
		} else {
			dialer := p.DialContext
			if dialer == nil {
				timeout := p.Timeout
				if timeout == 0 {
					timeout = 5 * time.Second
				}
				d := net.Dialer{Timeout: timeout}
				dialer = d.DialContext
			}

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer(ctx, "udp", nameserver)
				},
			}
			ips, err = r.LookupHost(ctx, domainToResolve)
		}

		if err == nil && len(ips) > 0 {
			return Result{
				Success:   true,
				Duration:  time.Since(start),
				Message:   "OK",
				Target:    nameserver,
				Timestamp: startTotal,
			}, nil
		}

		// Retry DNS resolution with TCP if UDP failed
		if p.Resolve == nil {
			dialer := p.DialContext
			if dialer == nil {
				timeout := p.Timeout
				if timeout == 0 {
					timeout = 5 * time.Second
				}
				d := net.Dialer{Timeout: timeout}
				dialer = d.DialContext
			}

			rTCP := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer(ctx, "tcp", nameserver)
				},
			}
			ips, err = rTCP.LookupHost(ctx, domainToResolve)
			if err == nil && len(ips) > 0 {
				return Result{
					Success:   true,
					Duration:  time.Since(start),
					Message:   "OK (TCP)",
					Target:    nameserver,
					Timestamp: startTotal,
				}, nil
			}
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
func (p *DNSProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
