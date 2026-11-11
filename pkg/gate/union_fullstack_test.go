package gate

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"go.minekube.com/gate/pkg/configs"
	jproxy "go.minekube.com/gate/pkg/edition/java/proxy"
)

// TestStartupUnionFullStack boots Gate with the whole union stack enabled at
// once - embedded frps with the MUA control plane, the proxied-proxy signed
// forwarding in PROXY role, and the dimension and map-mod plugins - and
// asserts they all wire up and serve on hermetic localhost ports.
//
// Everything here is hermetic: frps binds reserved free ports on 127.0.0.1
// with a test token and an unrestricted port range, the proxied-proxy runs as
// a PROXY with no ENTRY (so no key material is generated) against a
// TrustedEntries.json inside a temp dir, and no frpc client or Minecraft
// client ever connects. Via is NOT started: the managed ViaLite runtime needs
// a network download, so coexistence is verified by config only - Gate boots
// with Via disabled alongside the union stack, and a Via-enabled union config
// is validated without booting it.
func TestStartupUnionFullStack(t *testing.T) {
	cfg := loadTestConfig(t, configs.MinimalConfigBytes)

	// --- hermetic binds -----------------------------------------------------
	cfg.Config.Bind = reserveAddr(t)

	// frps: reserved free ports on loopback with token auth; an empty
	// AllowPorts allows all remote ports, avoiding conflicts with the
	// defaults' 10000-19999 range.
	cfg.Frps.Enabled = true
	cfg.Frps.BindAddr = "127.0.0.1"
	cfg.Frps.BindPort = reservePort(t)
	cfg.Frps.KCPBindPort = reservePort(t)
	cfg.Frps.QUICBindPort = reservePort(t)
	cfg.Frps.Token = "test-token"
	cfg.Frps.AllowPorts = ""

	// --- union plugins ------------------------------------------------------
	// MUA frp control plane (requires frps, enforced by config.Validate).
	cfg.Union.Mua.Enabled = true
	cfg.Union.Mua.FrpAddress = "127.0.0.1"
	cfg.Union.Mua.RestrictPort = false

	// Proxied-proxy as PROXY role: reads (and creates) the trusted entries
	// file from a temp dir and tolerates direct client connections, so no
	// ENTRY key material is generated or written.
	trustedEntries := filepath.Join(t.TempDir(), "TrustedEntries.json")
	cfg.Union.ProxiedProxy.Role = "PROXY"
	cfg.Union.ProxiedProxy.TrustedEntriesPath = trustedEntries
	cfg.Union.ProxiedProxy.AllowClientConnection = true

	// Dimension rewriting and the map-mod bridge; empty Channels means the
	// map-mod default channel set applies.
	cfg.Union.Dimension.Enabled = true
	cfg.Union.MapMod.Enabled = true

	// --- Via coexistence, config-only --------------------------------------
	// The stack above must coexist with the Via configuration without
	// starting the managed ViaLite runtime (it would download artifacts).
	require.False(t, cfg.Config.Via.Enabled,
		"Via must stay disabled here: its runtime needs a network download")
	viaCfg := *cfg
	viaCfg.Config.Via.Enabled = true
	viaCfg.Config.Via.Mode = "subprocess"
	if _, errs := viaCfg.Validate(); len(errs) > 0 {
		t.Fatalf("a Via-enabled union config must validate without booting: %v", errs)
	}

	// --- boot and assert ----------------------------------------------------
	g := bootGate(t, cfg)
	requireDialable(t, cfg.Config.Bind)
	require.NotNil(t, g.Java(), "Java proxy must be created")

	// union.Wire installed the seams for the enabled plugins.
	require.NotNil(t, jproxy.UnionDimensionRewrite,
		"dimension rewrite seam must be installed by union.Wire")
	require.NotNil(t, jproxy.UnionForwardedRemoteAddr,
		"forwarded remote address seam must be installed by union.Wire")

	// MUA subscribed its forced-host routing to the server selection event.
	require.True(t, g.Java().Event().HasSubscriber((*jproxy.PlayerChooseInitialServerEvent)(nil)),
		"MUA forced-host routing must be subscribed to server selection")

	// The proxied-proxy PROXY role materialized its TrustedEntries.json
	// template during the synchronous Init.
	require.FileExists(t, trustedEntries,
		"proxiedproxy PROXY role must create the TrustedEntries.json template")

	// frps binds its client listener at construction (gate.New), so it is
	// dialable once Gate is ready.
	requireDialable(t, net.JoinHostPort(cfg.Frps.BindAddr, strconv.Itoa(cfg.Frps.BindPort)))
}

// reservePort returns a free localhost TCP port number, derived the same way
// as reserveAddr so the reservation pattern stays uniform.
func reservePort(t *testing.T) int {
	t.Helper()
	_, port, err := net.SplitHostPort(reserveAddr(t))
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)
	return p
}
