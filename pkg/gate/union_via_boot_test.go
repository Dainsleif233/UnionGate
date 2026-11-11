package gate

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"github.com/stretchr/testify/require"

	"go.minekube.com/gate/pkg/configs"
	liteconfig "go.minekube.com/gate/pkg/edition/java/lite/config"
	jproxy "go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/gate/config"
)

// Union+Via startup tests: the complement to TestStartupUnionFullStack, which
// boots the union stack with Via disabled because the managed ViaLite runtime
// needs a network download. These tests prove the other half hermetically:
//
//  1. A Via-enabled union config (full union stack + Via.Offline) validates.
//  2. gate.New wires the union seams with Via enabled and never resolves the
//     runtime: jproxy.New only constructs the viaManagedRunner
//     (pkg/edition/java/proxy/vialite.go:60-68); the sole Start site is
//     Proxy.Start's first action (proxy.go:226-231).
//  3. Gate.Start with Via enabled fails fast at runtime-artifact resolution,
//     documenting precisely why Via cannot boot hermetically: the ViaLite
//     runtime artifact must come from BinaryPath/LibraryPath, an
//     embedded build (vialite_embed build tag), $PATH, or a network download
//     (vialite locate.go resolution order); with offline=true the download is
//     refused entirely (config.go Via.Offline, locate.go's ErrNoBinary path),
//     so the resolution fails in milliseconds without any network access.
//  4. The Lite+Via mutual exclusion holds at boot level: with Lite.Enabled,
//     viaManagedRunner.enabled() (vialite.go:70-72:
//     Via.Enabled && !Lite.Enabled) is false, the runtime is never started,
//     and the same Via-enabled union config boots cleanly.
//
// Everything stays hermetic: Via.Offline=true guarantees the managed runtime
// module never downloads (the download branch is only reached with
// offline=false), BinaryPath points at a nonexistent path so resolution fails
// deterministically on every machine before the env/embedded/$PATH lookup,
// and all listener ports are reserved free loopback ports.

// viaEnabledUnionConfig builds the full union stack config from
// TestStartupUnionFullStack (frps+MUA+proxied-proxy PROXY+dimension+map-mod)
// with Via enabled and Offline set, so no Via runtime artifact is ever
// downloaded. It returns the config and the TrustedEntries.json path.
func viaEnabledUnionConfig(t *testing.T) (cfg *config.Config, trustedEntries string) {
	t.Helper()

	cfg = loadTestConfig(t, configs.MinimalConfigBytes)
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

	// Union plugins, same shape as TestStartupUnionFullStack.
	cfg.Union.Mua.Enabled = true
	cfg.Union.Mua.FrpAddress = "127.0.0.1"
	cfg.Union.Mua.RestrictPort = false

	trustedEntries = filepath.Join(t.TempDir(), "TrustedEntries.json")
	cfg.Union.ProxiedProxy.Role = "PROXY"
	cfg.Union.ProxiedProxy.TrustedEntriesPath = trustedEntries
	cfg.Union.ProxiedProxy.AllowClientConnection = true

	cfg.Union.Dimension.Enabled = true
	cfg.Union.MapMod.Enabled = true

	// Via enabled: subprocess mode, offline so the managed runtime module can
	// never attempt a download, and a BinaryPath that does not exist so
	// artifact resolution fails deterministically on every machine (BinaryPath
	// short-circuits before the env, embedded, $PATH and download fallbacks in
	// the vialite module's locateBinary).
	cfg.Config.Via.Enabled = true
	cfg.Config.Via.Mode = "subprocess"
	cfg.Config.Via.Offline = true
	cfg.Config.Via.BinaryPath = filepath.Join(t.TempDir(), "absent-vialite-binary")

	return cfg, trustedEntries
}

// requireUnionWired asserts the union seams and subscriptions a gate.New
// (or booted) Gate must carry with the full union stack enabled.
func requireUnionWired(t *testing.T, g *Gate, trustedEntries string) {
	t.Helper()

	require.NotNil(t, g.Java(), "Java proxy must be created")

	require.NotNil(t, jproxy.UnionDimensionRewrite,
		"dimension rewrite seam must be installed by union.Wire")
	require.NotNil(t, jproxy.UnionForwardedRemoteAddr,
		"forwarded remote address seam must be installed by union.Wire")
	require.True(t, g.Java().Event().HasSubscriber((*jproxy.PlayerChooseInitialServerEvent)(nil)),
		"MUA forced-host routing must be subscribed to server selection")
	require.FileExists(t, trustedEntries,
		"proxiedproxy PROXY role must create the TrustedEntries.json template")
}

// TestStartupUnionViaConfigValidates proves a Via-enabled union config
// (Via.Enabled=true, offline subprocess mode, full union stack on reserved
// loopback ports) passes Validate without any boot or network access. The
// ViaLite config carries no validation-level Lite mutual exclusion, so the
// Lite+Via combination must also validate (the exclusion is behavioral:
// vialite.go:70-72).
func TestStartupUnionViaConfigValidates(t *testing.T) {
	cfg, _ := viaEnabledUnionConfig(t)
	if _, errs := cfg.Validate(); len(errs) > 0 {
		t.Fatalf("a Via-enabled union config must validate without booting: %v", errs)
	}

	// Lite+Via also validates: enabling both is legal at config level and
	// resolves behaviorally at boot (enabled() returns false for Lite mode).
	cfg.Config.Lite.Enabled = true
	cfg.Config.Lite.Routes = []liteconfig.Route{{
		Host:    []string{"union-via.mutual-exclusion.test"},
		Backend: []string{reserveAddr(t)},
	}}
	if _, errs := cfg.Validate(); len(errs) > 0 {
		t.Fatalf("a Via+Lite-enabled union config must still validate (the mutual exclusion is behavioral, not a validation rule): %v", errs)
	}
}

// TestStartupUnionViaNewWiresUnionWithViaEnabled proves gate.New wires the
// union stack correctly with Via enabled, without attempting any Via runtime
// resolution: jproxy.New only constructs the viaManagedRunner, and the sole
// Via Start site is the beginning of Proxy.Start (proxy.go:226-231), which
// only runs at Gate.Start. The frps service created by New binds its client
// listener at construction, so it is dialable without Start.
func TestStartupUnionViaNewWiresUnionWithViaEnabled(t *testing.T) {
	cfg, trustedEntries := viaEnabledUnionConfig(t)

	g, err := New(Options{
		Config:   cfg,
		EventMgr: event.New(event.WithRecoverPanic(false)),
	})
	require.NoError(t, err, "Gate.New must wire up a Via-enabled union config")

	requireUnionWired(t, g, trustedEntries)

	// frps binds its listeners at construction (frps.NewService), so the
	// client listener is already dialable before any Start. Assert with a
	// short bound: this must be immediate, not a background Start artifact.
	frpsAddr := net.JoinHostPort(cfg.Frps.BindAddr, strconv.Itoa(cfg.Frps.BindPort))
	require.Eventually(t, func() bool { return dialable(frpsAddr) },
		3*time.Second, 25*time.Millisecond, "frps must bind its listener at gate.New")
}

// TestStartupUnionViaBootFailsFastAtRuntimeResolution documents precisely why
// a Via-enabled union boot cannot be hermetic: Gate.Start does attempt the
// Via runtime, and the runtime artifact does not exist without a network
// download. With Via.Offline=true the managed runtime module refuses to
// download (vialite locate.go's ErrNoBinary/ErrNoLibrary paths are only
// reached instead of the download branch), and BinaryPath names a nonexistent
// file, so Proxy.Start's first action - via.Start (proxy.go:226-231) - fails
// within milliseconds at artifact resolution, with no network access and no
// hang. The union wiring installed at New survives the failed boot.
func TestStartupUnionViaBootFailsFastAtRuntimeResolution(t *testing.T) {
	cfg, trustedEntries := viaEnabledUnionConfig(t)

	log, logs := testLogger(t)
	g, err := New(Options{
		Config:   cfg,
		EventMgr: event.New(event.WithRecoverPanic(false)),
		Log:      log,
	})
	require.NoError(t, err, "Gate.New must wire up a Via-enabled union config")

	// A short overall deadline: the boot must fail fast, never hang waiting
	// for a runtime that cannot arrive.
	ctx, cancel := context.WithTimeout(
		logr.NewContext(context.Background(), log), 10*time.Second)
	defer cancel()

	started := time.Now()
	startResult := make(chan error, 1)
	go func() { startResult <- g.Start(ctx) }()

	var startErr error
	select {
	case startErr = <-startResult:
	case <-time.After(15 * time.Second):
		t.Fatalf("Gate.Start did not return within 15s: Via runtime resolution must fail fast, not hang\n%s", logs)
	}
	elapsed := time.Since(started)

	// The failure must be the runtime-artifact boundary: Proxy.Start wraps the
	// via.Start error ("error starting vialite", proxy.go), and the vialite
	// module names the BinaryPath resolution step ("vialite: BinaryPath").
	require.Error(t, startErr, "a Via-enabled boot without a runtime artifact must fail")
	require.ErrorContains(t, startErr, "error starting vialite",
		"the failure must surface from the managed ViaLite Start site (proxy.go:226-231)")
	require.ErrorContains(t, startErr, "vialite: BinaryPath",
		"the failure must be runtime-artifact resolution (vialite locate.go), not anything else")
	require.NotContains(t, strings.ToLower(startErr.Error()), "download",
		"offline=true must refuse the download path entirely: no download was attempted")
	require.Less(t, elapsed, 10*time.Second,
		"artifact resolution must fail immediately (measured %s), never stalling on network", elapsed)

	// The union wiring from New is untouched by the failed boot.
	requireUnionWired(t, g, trustedEntries)
}

// TestStartupUnionViaLiteMutualExclusionBootsHermetically proves the
// Lite+Via mutual exclusion at boot level, alongside the union stack: with
// Via.Enabled and Lite.Enabled both set, viaManagedRunner.enabled()
// (vialite.go:70-72: Via.Enabled && !Lite.Enabled) is false, so Proxy.Start
// skips the runtime entirely - the same config that fails in
// TestStartupUnionViaBootFailsFastAtRuntimeResolution boots cleanly, proving
// Via did not attempt artifact resolution. The union wiring is installed
// regardless of Lite mode (union.Wire has no Lite guard).
func TestStartupUnionViaLiteMutualExclusionBootsHermetically(t *testing.T) {
	cfg, trustedEntries := viaEnabledUnionConfig(t)
	cfg.Config.Lite.Enabled = true
	cfg.Config.Lite.Routes = []liteconfig.Route{{
		Host:    []string{"union-via.mutual-exclusion.test"},
		Backend: []string{reserveAddr(t)},
	}}

	g := bootGate(t, cfg)
	requireUnionWired(t, g.Gate, trustedEntries)

	// The boot succeeding where the non-Lite boot failed is the proof of the
	// disabled Via path; assert no ViaLite startup error was logged either.
	require.NotContains(t, g.logs.String(), "error starting vialite",
		"Lite mode must keep the managed ViaLite runtime disabled (vialite.go:70-72)")
}
