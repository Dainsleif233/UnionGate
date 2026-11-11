// Package frps embeds the frp server (frps) in Gate's process as a library:
// no subprocess and no dashboard/admin HTTP endpoint. Gate-facing settings map
// onto frp's server config, frp defaults are applied via Complete, and
// in-process server plugins are queued with RegisterPlugin for the next
// service run.
package frps

import (
	"fmt"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/server"
)

// Config is the Gate-facing configuration for the embedded frp server.
type Config struct {
	// Enabled starts the embedded frp server together with Gate.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// BindAddr is the address frps binds its client listener to.
	BindAddr string `json:"bindAddr,omitempty" yaml:"bindAddr,omitempty"`
	// BindPort is the TCP port frps listens on for frpc clients.
	BindPort int `json:"bindPort,omitempty" yaml:"bindPort,omitempty"`
	// KCPBindPort enables the KCP listener on the given UDP port; 0 disables it.
	KCPBindPort int `json:"kcpBindPort,omitempty" yaml:"kcpBindPort,omitempty"`
	// QUICBindPort enables the QUIC listener on the given UDP port; 0 disables it.
	QUICBindPort int `json:"quicBindPort,omitempty" yaml:"quicBindPort,omitempty"`
	// Token is the shared secret frpc clients must authenticate with.
	// Empty disables token authentication.
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
	// AllowPorts restricts the remote ports frpc clients may bind,
	// e.g. "10000-19999,30000,40000-40010". Empty allows all ports.
	AllowPorts string `json:"allowPorts,omitempty" yaml:"allowPorts,omitempty"`
}

// Validate checks the config: errors for invalid values, warnings for
// risky but working settings.
func (c *Config) Validate() (warns []error, errs []error) {
	e := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	w := func(format string, args ...any) { warns = append(warns, fmt.Errorf(format, args...)) }

	if c.BindPort <= 0 {
		e("frps bindPort %d must be greater than 0", c.BindPort)
	}
	if c.Token == "" {
		w("frps token is empty; any frpc that can reach the frps bind address may open tunnels")
	}
	if c.AllowPorts != "" {
		if _, err := types.NewPortsRangeSliceFromString(c.AllowPorts); err != nil {
			e("frps allowPorts %q: %v", c.AllowPorts, err)
		}
	}
	return warns, errs
}

// ToServerConfig maps the config onto frp's server config and applies frp's
// own defaults via Complete, mirroring what the frps binary does before
// starting. The dashboard webServer and metricsServer stay disabled (port 0),
// so no extra HTTP listener is opened.
func (c *Config) ToServerConfig() (*v1.ServerConfig, error) {
	s := &v1.ServerConfig{
		BindAddr:     c.BindAddr,
		BindPort:     c.BindPort,
		KCPBindPort:  c.KCPBindPort,
		QUICBindPort: c.QUICBindPort,
		Auth: v1.AuthServerConfig{
			Method: v1.AuthMethodToken,
			Token:  c.Token,
		},
	}
	if c.AllowPorts != "" {
		ports, err := types.NewPortsRangeSliceFromString(c.AllowPorts)
		if err != nil {
			return nil, fmt.Errorf("parse frps allowPorts %q: %w", c.AllowPorts, err)
		}
		s.AllowPorts = ports
	}
	if err := s.Complete(); err != nil {
		return nil, fmt.Errorf("complete frps server config: %w", err)
	}
	return s, nil
}

// NewService creates the embedded frp server service. It returns (nil, nil)
// when frps is not enabled. The returned service binds its listeners at
// creation and runs (accepting clients) when Run is called.
func NewService(cfg Config) (*server.Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	scfg, err := cfg.ToServerConfig()
	if err != nil {
		return nil, err
	}
	return server.NewService(scfg)
}

// RegisterPlugin queues an in-process frp server plugin to be registered when
// the frps service starts running (frps drains queued plugins at Run entry).
// It must be called before the frps service starts accepting clients.
func RegisterPlugin(p plugin.Plugin) {
	server.UnionRegisterPlugin(p)
}
