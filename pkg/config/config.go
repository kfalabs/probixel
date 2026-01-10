package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Global        GlobalConfig                  `yaml:"global"`
	DockerSockets map[string]DockerSocketConfig `yaml:"docker-sockets,omitempty"`
	Tunnels       map[string]TunnelConfig       `yaml:"tunnels,omitempty"`
	Services      []Service                     `yaml:"services"`
}

type TunnelConfig struct {
	Type      string           `yaml:"type"` // ssh, wireguard
	Target    string           `yaml:"target,omitempty"`
	SSH       *SSHConfig       `yaml:"ssh,omitempty"`
	Wireguard *WireguardConfig `yaml:"wireguard,omitempty"`
}

func (c *Config) Validate() error {
	if c.Global.DefaultInterval != "" {
		if _, err := ParseDuration(c.Global.DefaultInterval); err != nil {
			return fmt.Errorf("invalid global default_interval: %w", err)
		}
	}

	if c.Global.Notifier.RateLimit != nil {
		if *c.Global.Notifier.RateLimit == "" {
			return fmt.Errorf("global notifier.rate_limit cannot be an empty string")
		}
		if _, err := ParseDuration(*c.Global.Notifier.RateLimit); err != nil {
			return fmt.Errorf("invalid global notifier.rate_limit: %w", err)
		}
	}

	for name, socketCfg := range c.DockerSockets {
		if socketCfg.Socket == "" && (socketCfg.Host == "" || socketCfg.Port == 0) {
			return fmt.Errorf("docker socket %q is invalid: must provide either socket path or host/port", name)
		}
	}

	for name, tunnelCfg := range c.Tunnels {
		if tunnelCfg.Type == "" {
			return fmt.Errorf("tunnel %q type is mandatory", name)
		}
		switch tunnelCfg.Type {
		case "ssh":
			if tunnelCfg.SSH == nil {
				return fmt.Errorf("tunnel %q of type ssh requires ssh section", name)
			}
			if tunnelCfg.Target == "" {
				return fmt.Errorf("tunnel %q of type ssh requires a target", name)
			}
			// Basic SSH validation (user/auth)
			if tunnelCfg.SSH.User == "" {
				return fmt.Errorf("tunnel %q ssh user is mandatory", name)
			}
			// ... other auth checks ...
		case "wireguard":
			if tunnelCfg.Wireguard == nil {
				return fmt.Errorf("tunnel %q of type wireguard requires wireguard section", name)
			}
			if tunnelCfg.Wireguard.Endpoint == "" || tunnelCfg.Wireguard.PublicKey == "" || tunnelCfg.Wireguard.PrivateKey == "" || tunnelCfg.Wireguard.Addresses == "" {
				return fmt.Errorf("tunnel %q wireguard requires endpoint, public_key, private_key, and addresses", name)
			}
			if err := tunnelCfg.Wireguard.validateAndSetDefaults(); err != nil {
				return fmt.Errorf("tunnel %q wireguard: %w", name, err)
			}
		default:
			return fmt.Errorf("unknown tunnel type %q for tunnel %q", tunnelCfg.Type, name)
		}
	}

	for i, svc := range c.Services {
		if svc.Name == "" {
			return fmt.Errorf("service[%d] name is mandatory", i)
		}

		if svc.Tunnel != "" {
			if _, ok := c.Tunnels[svc.Tunnel]; !ok {
				return fmt.Errorf("service %q references unknown tunnel %q", svc.Name, svc.Tunnel)
			}
		}

		if svc.Interval == "" && c.Global.DefaultInterval == "" {
			return fmt.Errorf("service %q interval is mandatory (no global default_interval set)", svc.Name)
		}
		if svc.Interval != "" {
			if _, err := ParseDuration(svc.Interval); err != nil {
				return fmt.Errorf("service %q has invalid interval %q: %w", svc.Name, svc.Interval, err)
			}
		}

		if svc.MonitorEndpoint.Success.URL == "" {
			return fmt.Errorf("service %q monitor_endpoint.success.url is mandatory", svc.Name)
		}

		switch svc.Type {
		case "http":
			if svc.URL == "" {
				return fmt.Errorf("service %q url is mandatory", svc.Name)
			}
		case "tls":
			if svc.TLS == nil {
				return fmt.Errorf("service %q of type %q requires tls section", svc.Name, svc.Type)
			}
			if svc.URL == "" {
				return fmt.Errorf("service %q url is mandatory", svc.Name)
			}
			if svc.TLS.CertificateExpiry == "" {
				return fmt.Errorf("service %q tls.certificate_expiry is mandatory", svc.Name)
			}
		case "tcp":
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory", svc.Name)
			}
		case "dns":
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory", svc.Name)
			}
		case "ping":
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory", svc.Name)
			}
		case "host":
			// host type just uses name and type, targets optional
			continue
		case "docker":
			if svc.Docker == nil {
				return fmt.Errorf("service %q of type %q requires docker section", svc.Name, svc.Type)
			}
			if svc.Docker.Socket == "" {
				return fmt.Errorf("service %q docker.socket is mandatory", svc.Name)
			}
			socketCfg, ok := c.DockerSockets[svc.Docker.Socket]
			if !ok {
				return fmt.Errorf("service %q references unknown docker socket %q", svc.Name, svc.Docker.Socket)
			}

			// Tunnel requires a proxied docker socket (TCP)
			if svc.Tunnel != "" && socketCfg.Socket != "" {
				return fmt.Errorf("service %q: docker monitor over tunnel %q requires a proxied docker socket (use host/port instead of unix socket path)", svc.Name, svc.Tunnel)
			}

			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory (container name)", svc.Name)
			}
		case "wireguard":
			hasTunnel := svc.Tunnel != ""

			if hasTunnel {
				tunCfg, ok := c.Tunnels[svc.Tunnel]
				if !ok {
					return fmt.Errorf("service %q references unknown tunnel %q", svc.Name, svc.Tunnel)
				}
				if tunCfg.Type != "wireguard" {
					return fmt.Errorf("service %q: WireGuard monitor cannot use a non-WireGuard tunnel %q (type: %q)", svc.Name, svc.Tunnel, tunCfg.Type)
				}
				// Users must provide max_age in the service config, not reliance on validity of tunnel config for checks.
				if svc.Wireguard == nil || svc.Wireguard.MaxAge == "" {
					return fmt.Errorf("service %q: WireGuard monitor using tunnel %q must specify 'wireguard.max_age'", svc.Name, svc.Tunnel)
				}
				if err := svc.Wireguard.validateAndSetDefaults(); err != nil {
					return fmt.Errorf("service %q wireguard: %w", svc.Name, err)
				}
			} else {
				// Inline only
				if svc.Wireguard == nil {
					return fmt.Errorf("service %q: must have either a root 'tunnel' OR an inline 'wireguard' configuration", svc.Name)
				}
				if svc.Wireguard.MaxAge == "" {
					return fmt.Errorf("service %q wireguard.max_age is mandatory (heartbeat check)", svc.Name)
				}
				if err := svc.Wireguard.validateAndSetDefaults(); err != nil {
					return fmt.Errorf("service %q wireguard: %w", svc.Name, err)
				}
			}
		case "udp":
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory", svc.Name)
			}
		case "ssh":
			if len(svc.Targets) > 0 {
				return fmt.Errorf("service %q ssh must use 'target' (string) instead of 'targets' (list)", svc.Name)
			}
			if svc.Target == "" && svc.Tunnel == "" {
				return fmt.Errorf("service %q ssh requires at least a 'target' OR a root 'tunnel'", svc.Name)
			}
			if svc.SSH != nil {
				authRequired := true
				if svc.SSH.AuthRequired != nil {
					authRequired = *svc.SSH.AuthRequired
				}
				if authRequired {
					if svc.SSH.User == "" {
						return fmt.Errorf("service %q ssh user is mandatory when auth_required is true", svc.Name)
					}
					if svc.SSH.Password == "" && svc.SSH.PrivateKey == "" {
						return fmt.Errorf("service %q ssh password or private_key is mandatory when auth_required is true", svc.Name)
					}
					if svc.SSH.PrivateKey != "" {
						_, err := ssh.ParsePrivateKey([]byte(svc.SSH.PrivateKey))
						if err != nil {
							return fmt.Errorf("service %q ssh private_key is invalid: %w", svc.Name, err)
						}
					}
				}
			}
		default:
			return fmt.Errorf("service %q has unknown type %q", svc.Name, svc.Type)
		}

		// Validate service-level timeout against service interval
		intervalStr := svc.Interval
		if intervalStr == "" {
			intervalStr = c.Global.DefaultInterval
		}
		interval, _ := ParseDuration(intervalStr)

		timeoutStr := svc.Timeout
		if timeoutStr == "" {
			timeoutStr = "5s"
		}
		timeout, err := ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("service %q timeout is invalid: %w", svc.Name, err)
		}
		if timeout >= interval {
			return fmt.Errorf("service %q timeout (%v) must be less than interval (%v)", svc.Name, timeout, interval)
		}

		// Validate monitor endpoint timeouts
		if svc.MonitorEndpoint.Timeout != "" {
			if _, err := ParseDuration(svc.MonitorEndpoint.Timeout); err != nil {
				return fmt.Errorf("service %q monitor_endpoint.timeout is invalid: %w", svc.Name, err)
			}
		}
		if svc.MonitorEndpoint.Success.Timeout != "" {
			if _, err := ParseDuration(svc.MonitorEndpoint.Success.Timeout); err != nil {
				return fmt.Errorf("service %q monitor_endpoint.success.timeout is invalid: %w", svc.Name, err)
			}
		}
		if svc.MonitorEndpoint.Failure != nil && svc.MonitorEndpoint.Failure.Timeout != "" {
			if _, err := ParseDuration(svc.MonitorEndpoint.Failure.Timeout); err != nil {
				return fmt.Errorf("service %q monitor_endpoint.failure.timeout is invalid: %w", svc.Name, err)
			}
		}
	}

	// Validate global monitor endpoint timeout
	if c.Global.MonitorEndpoint.Timeout != "" {
		if _, err := ParseDuration(c.Global.MonitorEndpoint.Timeout); err != nil {
			return fmt.Errorf("global monitor_endpoint.timeout is invalid: %w", err)
		}
	}

	return nil
}

type GlobalConfig struct {
	DefaultInterval string                      `yaml:"default_interval,omitempty"`
	MonitorEndpoint GlobalMonitorEndpointConfig `yaml:"monitor_endpoint,omitempty"`
	Notifier        NotifierConfig              `yaml:"notifier,omitempty"`
}

type NotifierConfig struct {
	RateLimit *string `yaml:"rate_limit,omitempty"` // Global rate limit for notifications
}

type DockerSocketConfig struct {
	Socket   string            `yaml:"socket,omitempty"`
	Host     string            `yaml:"host,omitempty"`
	Port     int               `yaml:"port,omitempty"`
	Protocol string            `yaml:"protocol,omitempty"` // http or https
	Headers  map[string]string `yaml:"headers,omitempty"`
}

type GlobalMonitorEndpointConfig struct {
	Headers map[string]string `yaml:"headers,omitempty"`
	Timeout string            `yaml:"timeout,omitempty"`
}

type Service struct {
	Name            string                `yaml:"name"`
	Type            string                `yaml:"type"` // http, tcp, dns, ping, host, docker, wireguard, tls
	URL             string                `yaml:"url,omitempty"`
	Target          string                `yaml:"target,omitempty"`
	Targets         []string              `yaml:"targets,omitempty"`
	TargetMode      string                `yaml:"target_mode,omitempty"` // "any" or "all"
	Tunnel          string                `yaml:"tunnel,omitempty"`
	Interval        string                `yaml:"interval,omitempty"`
	Timeout         string                `yaml:"timeout,omitempty"`
	MonitorEndpoint MonitorEndpointConfig `yaml:"monitor_endpoint"`

	// Type-specific configs
	HTTP      *HTTPConfig      `yaml:"http,omitempty"`
	TCP       *TCPConfig       `yaml:"tcp,omitempty"`
	DNS       *DNSConfig       `yaml:"dns,omitempty"`
	Ping      *PingConfig      `yaml:"ping,omitempty"`
	Host      *HostConfig      `yaml:"host,omitempty"`
	Docker    *DockerConfig    `yaml:"docker,omitempty"`
	Wireguard *WireguardConfig `yaml:"wireguard,omitempty"`
	TLS       *TLSConfig       `yaml:"tls,omitempty"`
	UDP       *UDPConfig       `yaml:"udp,omitempty"`
	SSH       *SSHConfig       `yaml:"ssh,omitempty"`
}

type HTTPConfig struct {
	Method              string            `yaml:"method,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	AcceptedStatusCodes string            `yaml:"accepted_status_codes,omitempty"`
	InsecureSkipVerify  bool              `yaml:"insecure_skip_verify,omitempty"`
	MatchData           *MatchDataConfig  `yaml:"match_data,omitempty"`
	CertificateExpiry   string            `yaml:"certificate_expiry,omitempty"`
}

type TCPConfig struct {
}

type DNSConfig struct {
	Domain string `yaml:"domain,omitempty"`
}

type PingConfig struct {
}

type HostConfig struct {
}

type DockerConfig struct {
	Socket  string `yaml:"socket,omitempty"`
	Healthy bool   `yaml:"healthy,omitempty"`
}

type TLSConfig struct {
	CertificateExpiry  string `yaml:"certificate_expiry"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}

type UDPConfig struct {
}

type SSHConfig struct {
	User         string `yaml:"user,omitempty"`
	Password     string `yaml:"password,omitempty"`
	PrivateKey   string `yaml:"private_key,omitempty"`
	AuthRequired *bool  `yaml:"auth_required,omitempty"` // Default to true
	Port         int    `yaml:"port,omitempty"`          // Default to 22
}

type WireguardConfig struct {
	Endpoint            string `yaml:"endpoint"`
	PublicKey           string `yaml:"public_key"`
	PrivateKey          string `yaml:"private_key"`
	PresharedKey        string `yaml:"preshared_key"`
	Addresses           string `yaml:"addresses"`
	AllowedIPs          string `yaml:"allowed_ips"`
	PersistentKeepalive int    `yaml:"persistent_keepalive"`
	MaxAge              string `yaml:"max_age"`
	RestartThreshold    *int   `yaml:"restart_threshold,omitempty"`
}

func (w *WireguardConfig) validateAndSetDefaults() error {
	if w.RestartThreshold == nil {
		one := 1
		w.RestartThreshold = &one
	} else if *w.RestartThreshold == 0 {
		return fmt.Errorf("restart_threshold cannot be zero")
	} else if *w.RestartThreshold < 0 {
		return fmt.Errorf("restart_threshold must be positive")
	}

	return nil
}

type MatchDataConfig struct {
	Expectations []Expectation `yaml:"expectations"`
}

type Expectation struct {
	Type     string `yaml:"type"`                // json, header, body
	JSONPath string `yaml:"json_path,omitempty"` // Path for JSON extraction
	Header   string `yaml:"header,omitempty"`    // Header name
	Operator string `yaml:"operator"`            // equals, contains, matches, age_less_than, greater_than, less_than
	Value    string `yaml:"value"`               // Target value to compare against
}

type MonitorEndpointConfig struct {
	Success EndpointConfig    `yaml:"success"`
	Failure *EndpointConfig   `yaml:"failure,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"` // Common headers for both
	Timeout string            `yaml:"timeout,omitempty"` // Common timeout for both
}

type EndpointConfig struct {
	URL                string            `yaml:"url"`
	Method             string            `yaml:"method"`
	Headers            map[string]string `yaml:"headers"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify,omitempty"`
	Timeout            string            `yaml:"timeout,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: Config file path from command line flag is expected
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ParseDuration parses a duration string, supporting "d" for days, "h" for hours, "m" for minutes, "s" for seconds.
// "2s", "4m", "5h", "1d"
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	// Check for "0"
	if s == "0" {
		return 0, nil
	}
	// Check for 'd' suffix
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration (days): %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	// Fallback to time.ParseDuration
	return time.ParseDuration(s)
}
