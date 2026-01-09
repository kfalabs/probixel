package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Global        GlobalConfig                  `yaml:"global"`
	DockerSockets map[string]DockerSocketConfig `yaml:"docker-sockets,omitempty"`
	Services      []Service                     `yaml:"services"`
}

func (c *Config) Validate() error {
	if c.Global.DefaultInterval != "" {
		if _, err := ParseDuration(c.Global.DefaultInterval); err != nil {
			return fmt.Errorf("invalid global default_interval: %w", err)
		}
	}

	for name, socketCfg := range c.DockerSockets {
		if socketCfg.Socket == "" && (socketCfg.Host == "" || socketCfg.Port == 0) {
			return fmt.Errorf("docker socket %q is invalid: must provide either socket path or host/port", name)
		}
	}

	for i, svc := range c.Services {
		if svc.Name == "" {
			return fmt.Errorf("service[%d] name is mandatory", i)
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
		case "docker":
			if svc.Docker == nil {
				return fmt.Errorf("service %q of type %q requires docker section", svc.Name, svc.Type)
			}
			if svc.Docker.Socket == "" {
				return fmt.Errorf("service %q docker.socket is mandatory", svc.Name)
			}
			if _, ok := c.DockerSockets[svc.Docker.Socket]; !ok {
				return fmt.Errorf("service %q references unknown docker socket %q", svc.Name, svc.Docker.Socket)
			}
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory (container name)", svc.Name)
			}
		case "wireguard":
			if svc.Wireguard == nil {
				return fmt.Errorf("service %q of type %q requires wireguard section", svc.Name, svc.Type)
			}
			if svc.Wireguard.Endpoint == "" {
				return fmt.Errorf("service %q wireguard.endpoint is mandatory", svc.Name)
			}
			if svc.Wireguard.PublicKey == "" {
				return fmt.Errorf("service %q wireguard.public_key is mandatory", svc.Name)
			}
			if svc.Wireguard.PrivateKey == "" {
				return fmt.Errorf("service %q wireguard.private_key is mandatory", svc.Name)
			}
			if svc.Wireguard.Addresses == "" {
				return fmt.Errorf("service %q wireguard.addresses is mandatory", svc.Name)
			}
			if len(svc.Targets) == 0 && svc.Wireguard.MaxAge == "" {
				return fmt.Errorf("service %q targets or wireguard.max_age is mandatory", svc.Name)
			}
		case "udp":
			if len(svc.Targets) == 0 {
				return fmt.Errorf("service %q targets is mandatory", svc.Name)
			}
		}
	}
	return nil
}

type GlobalConfig struct {
	MonitorEndpoint GlobalMonitorEndpointConfig `yaml:"monitor_endpoint"`
	DefaultInterval string                      `yaml:"default_interval,omitempty"` // Default interval for all services (e.g., "1m")
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
}

type Service struct {
	Name            string                `yaml:"name"`
	Type            string                `yaml:"type"` // http, tcp, dns, ping, host, docker, wireguard, tls
	URL             string                `yaml:"url,omitempty"`
	Targets         []string              `yaml:"targets,omitempty"`
	TargetMode      string                `yaml:"target_mode,omitempty"` // "any" or "all"
	Interval        string                `yaml:"interval,omitempty"`
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

type WireguardConfig struct {
	Endpoint            string `yaml:"endpoint"`
	PublicKey           string `yaml:"public_key"`
	PrivateKey          string `yaml:"private_key"`
	PresharedKey        string `yaml:"preshared_key"`
	Addresses           string `yaml:"addresses"`
	AllowedIPs          string `yaml:"allowed_ips"`
	PersistentKeepalive int    `yaml:"persistent_keepalive"`
	MaxAge              string `yaml:"max_age"`
	SuccessOnHeartbeat  bool   `yaml:"success_on_heartbeat"`
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
}

type EndpointConfig struct {
	URL                string            `yaml:"url"`
	Method             string            `yaml:"method"`
	Headers            map[string]string `yaml:"headers"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify,omitempty"`
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
