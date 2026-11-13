package config

import (
	"fmt"

	"github.com/fatedier/frp/pkg/config/types"

	jconfig "go.minekube.com/gate/pkg/edition/java/config"
	"go.minekube.com/gate/pkg/internal/api"
	connect "go.minekube.com/gate/pkg/util/connectutil/config"
	"go.minekube.com/gate/pkg/util/validation"
)

// DefaultConfig is a default Config.
var DefaultConfig = Config{
	Config: jconfig.DefaultConfig,
	HealthService: HealthService{
		Enabled: false,
		Bind:    "0.0.0.0:9090",
	},
	Connect: connect.DefaultConfig,
	API: API{
		Enabled: false,
		Config:  api.DefaultConfig,
	},
	Frps: FrpsConfig{
		Enabled:      false,
		BindAddr:     "0.0.0.0",
		BindPort:     7001,
		KCPBindPort:  7002,
		QUICBindPort: 7003,
		AllowPorts:   "10000-19999",
	},
	Union: UnionConfig{
		Mua: MuaConfig{
			Enabled:      false,
			FrpAddress:   "127.0.0.1",
			RestrictPort: false,
			AllowMin:     10000,
			AllowMax:     19999,
		},
		ProxiedProxy: ProxiedProxyConfig{},
		Dimension:    DimensionConfig{Enabled: false},
		MapMod:       MapModConfig{Enabled: false},
	},
}

// Config is the root configuration of Gate.
type Config struct {
	// Config is the Java edition configuration (with embedded Bedrock config).
	Config jconfig.Config `json:"config,omitempty" yaml:"config,omitempty"`
	// See HealthService struct.
	HealthService HealthService `json:"healthService,omitempty" yaml:"healthService,omitempty"`
	// See Connect struct.
	Connect connect.Config `json:"connect,omitempty" yaml:"connect,omitempty"`
	// See API struct.
	API API `json:"api,omitempty" yaml:"api,omitempty"`
	// See FrpsConfig struct.
	Frps FrpsConfig `json:"frps,omitempty" yaml:"frps,omitempty"`
	// See UnionConfig struct.
	Union UnionConfig `json:"union,omitempty" yaml:"union,omitempty"`
	// NoAutoReload disables automatic config file reloading.
	// This is useful in environments where file watching causes issues.
	NoAutoReload bool `json:"noAutoReload,omitempty" yaml:"noAutoReload,omitempty"`
}

// HealthService is a GRPC health probe service for use with Kubernetes pods.
// (https://github.com/grpc-ecosystem/grpc-health-probe)
type HealthService struct {
	Enabled bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Bind    string `json:"bind,omitempty" yaml:"bind,omitempty"`
}

// API is the configuration for the Gate API.
type API struct {
	Enabled bool       `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Config  api.Config `json:",inline" yaml:",inline"`
}

// FrpsConfig is the configuration for the embedded frp server (frps).
// It mirrors pkg/union/frps.Config with the same yaml keys; a separate struct
// keeps this package free of frp server dependencies.
type FrpsConfig struct {
	Enabled      bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	BindAddr     string `json:"bindAddr,omitempty" yaml:"bindAddr,omitempty"`
	BindPort     int    `json:"bindPort,omitempty" yaml:"bindPort,omitempty"`
	KCPBindPort  int    `json:"kcpBindPort,omitempty" yaml:"kcpBindPort,omitempty"`
	QUICBindPort int    `json:"quicBindPort,omitempty" yaml:"quicBindPort,omitempty"`
	Token        string `json:"token,omitempty" yaml:"token,omitempty"`
	// AllowPorts restricts the remote ports frpc clients may bind,
	// e.g. "10000-19999". Empty allows all ports.
	AllowPorts string `json:"allowPorts,omitempty" yaml:"allowPorts,omitempty"`
}

// UnionConfig groups the union plugin set: in-process frp plugins and
// forwarding/dimension integrations wired synchronously into the Java proxy
// during startup (see pkg/union/union.go Wire).
type UnionConfig struct {
	// See MuaConfig struct.
	Mua MuaConfig `json:"mua,omitempty" yaml:"mua,omitempty"`
	// See ProxiedProxyConfig struct.
	ProxiedProxy ProxiedProxyConfig `json:"proxiedProxy,omitempty" yaml:"proxiedProxy,omitempty"`
	// See DimensionConfig struct.
	Dimension DimensionConfig `json:"dimension,omitempty" yaml:"dimension,omitempty"`
	// See MapModConfig struct.
	MapMod MapModConfig `json:"mapMod,omitempty" yaml:"mapMod,omitempty"`
}

// MuaConfig configures the MUA frp control plane, mirroring pkg/union/mua.Config.
type MuaConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// FrpAddress is the address frps advertises to frpc clients for the MUA
	// control plane. Empty falls back to "127.0.0.1".
	FrpAddress string `json:"frpAddress,omitempty" yaml:"frpAddress,omitempty"`
	// RestrictPort limits the remote ports an frpc may bind to the
	// [AllowMin, AllowMax] range; disabled, frps.allowPorts governs.
	RestrictPort bool `json:"restrictPort,omitempty" yaml:"restrictPort,omitempty"`
	AllowMin     int  `json:"allowMin,omitempty" yaml:"allowMin,omitempty"`
	AllowMax     int  `json:"allowMax,omitempty" yaml:"allowMax,omitempty"`
}

// ProxiedProxyConfig configures the proxied-proxy signed forwarding plugin,
// mirroring pkg/union/proxiedproxy.Config.
type ProxiedProxyConfig struct {
	// Role selects the operation mode: "ENTRY", "PROXY",
	// "ENTRY_AND_PROXY" or "DISABLED". Empty or "DISABLED" disables the
	// plugin.
	Role string `json:"role,omitempty" yaml:"role,omitempty"`
	// EntryID uniquely identifies this entry among the PROXY's trusted
	// entries. Required for ENTRY roles.
	EntryID string `json:"entryId,omitempty" yaml:"entryId,omitempty"`
	// ServerCommandAlias exposes the builtin /server command under this name
	// for ENTRY roles. Empty defaults to "hub" (the original ProxiedProxy
	// default); "none" or "off" disables the alias.
	ServerCommandAlias string `json:"serverCommandAlias,omitempty" yaml:"serverCommandAlias,omitempty"`
	// VerificationType selects how packets are authenticated: "RSA" or
	// "KEY". Required for ENTRY roles.
	VerificationType string `json:"verificationType,omitempty" yaml:"verificationType,omitempty"`
	// PrivateKeyPath is the RSA private key PEM file used to sign packets.
	PrivateKeyPath string `json:"privateKeyPath,omitempty" yaml:"privateKeyPath,omitempty"`
	// PublicKeyPath is the RSA public key PEM file of the entry.
	PublicKeyPath string `json:"publicKeyPath,omitempty" yaml:"publicKeyPath,omitempty"`
	// EntryJSONPath is where ENTRY roles write the entry.json record.
	EntryJSONPath string `json:"entryJsonPath,omitempty" yaml:"entryJsonPath,omitempty"`
	// Key is the shared secret used by KEY verification on ENTRY roles.
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
	// TrustedEntriesPath is the TrustedEntries.json file read by PROXY roles.
	TrustedEntriesPath string `json:"trustedEntriesPath,omitempty" yaml:"trustedEntriesPath,omitempty"`
	// AllowClientConnection tolerates direct client connections on PROXY
	// roles instead of refusing them.
	AllowClientConnection bool `json:"allowClientConnection,omitempty" yaml:"allowClientConnection,omitempty"`
}

// DimensionConfig enables the dimension-packet rewriting mapper.
type DimensionConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

// MapModConfig configures the map-mod channel bridge (Xaero's minimap/world
// map, world-info). When enabled with empty Channels the upstream defaults
// (pkg/union/mapmod.DefaultConfig) apply.
type MapModConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Channels to intercept; empty means the default channel set.
	Channels []string `json:"channels,omitempty" yaml:"channels,omitempty"`
	// ForwardToBackend also forwards matched player messages to the backend
	// after tracking world ids.
	ForwardToBackend bool `json:"forwardToBackend,omitempty" yaml:"forwardToBackend,omitempty"`
}

// validate checks the union plugin settings. frpsEnabled reports whether the
// embedded frps server is enabled, which the MUA control plane requires.
// Only values are validated here; no files are read or written.
func (u UnionConfig) validate(frpsEnabled bool) (errs []error) {
	e := func(m string, args ...any) { errs = append(errs, fmt.Errorf(m, args...)) }

	if u.Mua.Enabled {
		if !frpsEnabled {
			e("mua requires the embedded frps server; set frps.enabled to true")
		}
		if u.Mua.RestrictPort {
			if u.Mua.AllowMin < 1 || u.Mua.AllowMin > 65535 {
				e("Invalid mua allowMin %d", u.Mua.AllowMin)
			}
			if u.Mua.AllowMax < 1 || u.Mua.AllowMax > 65535 {
				e("Invalid mua allowMax %d", u.Mua.AllowMax)
			}
			if u.Mua.AllowMin > u.Mua.AllowMax {
				e("Invalid mua allowPorts range %d-%d", u.Mua.AllowMin, u.Mua.AllowMax)
			}
		}
	}

	switch u.ProxiedProxy.Role {
	case "", "DISABLED", "ENTRY", "PROXY", "ENTRY_AND_PROXY":
	default:
		e("Invalid proxiedProxy role %q; allowed: ENTRY, PROXY, ENTRY_AND_PROXY, DISABLED", u.ProxiedProxy.Role)
	}
	if u.ProxiedProxy.Role == "ENTRY" || u.ProxiedProxy.Role == "ENTRY_AND_PROXY" {
		if u.ProxiedProxy.EntryID == "" {
			e("proxiedProxy entryId is required for ENTRY roles")
		}
		switch u.ProxiedProxy.VerificationType {
		case "RSA":
		case "KEY":
			if u.ProxiedProxy.Key == "" {
				e("proxiedProxy key is required for KEY verification")
			}
		default:
			e("Invalid proxiedProxy verificationType %q; allowed: RSA, KEY", u.ProxiedProxy.VerificationType)
		}
	}
	return errs
}

// Validate validates a Config and all enabled configs.
func (c *Config) Validate() (warns []error, errs []error) {
	e := func(m string, args ...any) { errs = append(errs, fmt.Errorf(m, args...)) }
	w := func(m string, args ...any) { warns = append(warns, fmt.Errorf(m, args...)) }
	if c == nil {
		e("config must not be nil")
		return
	}

	if c.HealthService.Enabled {
		if err := validation.ValidHostPort(c.HealthService.Bind); err != nil {
			e("Invalid health probe bind address %q: %v", c.HealthService.Bind, err)
		}
	}

	if c.Frps.Enabled {
		if c.Frps.BindPort <= 0 {
			e("Invalid frps bind port %d", c.Frps.BindPort)
		}
		if c.Frps.Token == "" {
			w("frps token is empty; any frpc that can reach the frps bind address may open tunnels")
		}
		if c.Frps.AllowPorts != "" {
			if _, err := types.NewPortsRangeSliceFromString(c.Frps.AllowPorts); err != nil {
				e("Invalid frps allowPorts %q: %v", c.Frps.AllowPorts, err)
			}
		}
	}

	prefix := func(p string, errs []error) (pErrs []error) {
		for _, err := range errs {
			pErrs = append(pErrs, fmt.Errorf("%s: %w", p, err))
		}
		return
	}

	// Validate Java config (always enabled)
	warns2, errs2 := c.Config.Validate()
	warns = append(warns, prefix("java", warns2)...)
	errs = append(errs, prefix("java", errs2)...)

	// Validate Bedrock config if enabled
	if c.Config.Bedrock.Enabled {
		bedrockConfig := c.Config.Bedrock.ToConfig()
		warns2, errs2 := bedrockConfig.Validate()
		warns = append(warns, prefix("bedrock", warns2)...)
		errs = append(errs, prefix("bedrock", errs2)...)
	}

	if c.API.Enabled {
		warns2, errs2 := c.API.Config.Validate()
		warns = append(warns, prefix("api", warns2)...)
		errs = append(errs, prefix("api", errs2)...)
	}

	// Validate union plugins (always, so garbage roles fail even while
	// disabled).
	errs2 = c.Union.validate(c.Frps.Enabled)
	errs = append(errs, prefix("union", errs2)...)

	// A configured entryId with the plugin disabled is almost always a
	// deployment mistake: downstream PROXYs still send proxied-proxy:login,
	// the core answers Success:false because nobody subscribes, and the
	// member closes the login with the generic legacy-forwarding error.
	if c.Union.ProxiedProxy.EntryID != "" {
		role := c.Union.ProxiedProxy.Role
		if role == "" || role == "DISABLED" {
			w("union.proxiedProxy.entryId is set but role is disabled; " +
				"downstream PROXYs will not receive forwarding data and member logins will fail. " +
				"Set union.proxiedProxy.role to ENTRY on the public entry")
		}
	}

	// Lite mode pipes player connections through unchanged, so the embedded
	// frps server and the union plugins cannot influence how players are
	// routed. Only deliberately enabled settings are reported; defaults stay
	// quiet, matching warnLiteIgnoredSettings in the java config, which cannot
	// see these root-level settings from its package.
	if c.Config.Lite.Enabled {
		if c.Frps.Enabled {
			w("Lite mode ignores frps: the embedded frps server still binds and accepts " +
				"tunnels, but backends registered through it (union.mua) never receive player " +
				"connections because Lite pipes them unchanged to the lite.routes backends. " +
				"Disable frps.enabled unless the tunnels are needed for other purposes. " +
				"See https://gate.minekube.com/guide/lite")
		}
		role := c.Union.ProxiedProxy.Role
		if c.Union.Mua.Enabled || c.Union.Dimension.Enabled || c.Union.MapMod.Enabled ||
			(role != "" && role != "DISABLED") {
			w("Lite mode ignores union plugins (mua, proxiedProxy, dimension, mapMod): " +
				"Lite pipes player connections through unchanged, so none of them can route " +
				"or rewrite anything. Use lite.routes to route connections instead, or " +
				"disable lite.enabled. See https://gate.minekube.com/guide/lite")
		}
	}
	return
}
