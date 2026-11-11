package gate

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/require"

	"go.minekube.com/gate/pkg/configs"
	jproxy "go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/union/mua"
	"go.minekube.com/gate/pkg/util/loopback"
)

// TestStartupUnionFrpcMua is the functional proof for the MUA control plane:
// a REAL frpc client (the vendored third_party/frp client Service with its
// default TCP connector) logs in to Gate's embedded frps server and requests
// a TCP proxy, and the frps plugin seam (Login/NewProxy/CloseProxy
// notifications, no direct Handle() stubs) carries them into the MUA plugin,
// which registers - and later unregisters - a backend server in Gate's Java
// proxy registry.
//
// Everything is hermetic: all listeners are 127.0.0.1 on reserved free ports,
// the frpc connects only to the embedded frps, the proxy's local forward
// target is a dummy listener from Gate's own loopback range that nothing ever
// dials for data, and a failed first login exits fast (LoginFailExit defaults
// to true), so the test cannot hang on retries.
//
// What each phase proves:
//  1. Gate boots with frps+MUA wired (forced-host routing subscribed, frps
//     listener dialable).
//  2. frpc Login (with MUA metas) + NewProxy are accepted end to end: MUA
//     registers the backend under the MUA frp address with the requested
//     remote port in the Gate registry, and frps really binds the remote
//     listener (so the proof cannot be satisfied by MUA accepting a proxy
//     that frps went on to reject).
//  3. GracefulClose stops the client; the CloseProxy round-trip (or the
//     client-exit cleanup, whichever wins) unregisters the backend again.
//
// The only Gate state observed is the public Java proxy registry surface
// (Java()/Server/Servers/Event); the MUA internals stay behind their plugin
// interface on purpose - this test must not reach into them.
func TestStartupUnionFrpcMua(t *testing.T) {
	// frp's ClientTransportConfig.Complete() falls back to the http_proxy
	// environment variable when Transport.ProxyURL is empty, so a shell
	// exporting a proxy would redirect the frpc dial away from 127.0.0.1.
	// An empty value keeps ParseProxyURL proxy-free.
	for _, env := range []string{
		"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
		"all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY",
	} {
		t.Setenv(env, "")
	}

	// --- Gate config: minimal except frps + MUA -----------------------------
	cfg := loadTestConfig(t, configs.MinimalConfigBytes)
	cfg.Config.Bind = reserveAddr(t)

	// frps: reserved free ports on loopback with token auth; an empty
	// AllowPorts allows every remote port, mirroring the fullstack test.
	cfg.Frps.Enabled = true
	cfg.Frps.BindAddr = "127.0.0.1"
	cfg.Frps.BindPort = reservePort(t)
	cfg.Frps.KCPBindPort = reservePort(t)
	cfg.Frps.QUICBindPort = reservePort(t)
	cfg.Frps.Token = "test-token"
	cfg.Frps.AllowPorts = ""

	// MUA control plane (requires frps, enforced by config.Validate).
	cfg.Union.Mua.Enabled = true
	cfg.Union.Mua.FrpAddress = "127.0.0.1"
	cfg.Union.Mua.RestrictPort = false

	// Isolate the MUA path: keep the rest of the union stack and Via out.
	// Via must stay disabled here - its managed runtime needs a download.
	require.False(t, cfg.Config.Via.Enabled,
		"Via must stay disabled here: its runtime needs a network download")
	require.False(t, cfg.Union.Dimension.Enabled)
	require.False(t, cfg.Union.MapMod.Enabled)
	require.Equal(t, "", cfg.Union.ProxiedProxy.Role)

	// --- phase 1: boot Gate -------------------------------------------------
	g := bootGate(t, cfg)
	require.NotNil(t, g.Java(), "Java proxy must be created")
	requireDialable(t, cfg.Config.Bind)

	// union.Wire installed the MUA seams before Gate became ready.
	require.True(t, g.Java().Event().HasSubscriber((*jproxy.PlayerChooseInitialServerEvent)(nil)),
		"MUA forced-host routing must be subscribed to server selection")

	frpcAddr := net.JoinHostPort(cfg.Frps.BindAddr, strconv.Itoa(cfg.Frps.BindPort))
	requireDialable(t, frpcAddr)

	// --- dummy local forward target -----------------------------------------
	// The TCP proxy's local endpoint, allocated from Gate's own loopback
	// range (never the ephemeral range) per the project listener rule. The
	// proof below is control-plane only: no data connection is ever
	// established, so the listener just needs to exist and be owned for the
	// lifetime of the client config.
	localAllocator, err := loopback.Default()
	require.NoError(t, err)
	localLn, err := localAllocator.Listen()
	require.NoError(t, err)
	t.Cleanup(func() { _ = localLn.Close() })
	localAddr := localLn.Addr().String()
	_, localPortStr, err := net.SplitHostPort(localAddr)
	require.NoError(t, err)
	localPort, err := strconv.Atoi(localPortStr)
	require.NoError(t, err)

	// --- phase 2: real frpc client ------------------------------------------
	const proxyName = "func-test-srv"
	remotePort := reservePort(t)
	forcedHostsJSON, err := json.Marshal([]string{"func-test-a.mua.invalid", "func-test-b.mua.invalid"})
	require.NoError(t, err)
	aliasJSON, err := json.Marshal([]string{"func-test-alias.mua.invalid"})
	require.NoError(t, err)

	common := &v1.ClientCommonConfig{
		ServerAddr: "127.0.0.1",
		ServerPort: cfg.Frps.BindPort,
		// MUA metas, verbatim keys of the Kotlin plugin protocol. handleLogin
		// consumes them and stamps mua_generation into the stored login
		// message, which is why the NewProxyContent.User.Metas the register
		// path sees still carries the login metas below.
		Metadatas: map[string]string{
			mua.MetaDomain:      "func-test.mua.invalid",
			mua.MetaForcedHosts: string(forcedHostsJSON),
			mua.MetaDomainAlias: string(aliasJSON),
		},
		Auth: v1.AuthClientConfig{
			Method: v1.AuthMethodToken,
			Token:  cfg.Frps.Token,
		},
		// LoginFailExit keeps its default (true, set by Complete): a failed
		// first login makes Run return an error quickly instead of retrying
		// forever, so a wrong server port or token fails the test fast.
	}
	tcpProxy := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: proxyName,
			Type: string(v1.ProxyTypeTCP),
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   "127.0.0.1",
				LocalPort: localPort,
			},
		},
		RemotePort: remotePort,
	}
	agg := source.NewAggregator(source.NewConfigSource())
	require.NoError(t, agg.ConfigSource().ReplaceAll([]v1.ProxyConfigurer{tcpProxy}, nil))

	frpcService, err := client.NewService(client.ServiceOptions{
		Common:                 common,
		ConfigSourceAggregator: agg,
		// ConnectorCreator nil keeps the DEFAULT frpc connector: a real TCP
		// connection (TCPMux session) to the embedded frps. The client side
		// must not be stubbed - that would repeat unit coverage, not prove
		// the functional path.
	})
	require.NoError(t, err)

	frpcCtx, frpcCancel := context.WithCancel(context.Background())
	defer frpcCancel()
	frpcDone := make(chan error, 1)
	go func() { frpcDone <- frpcService.Run(frpcCtx) }()

	// Login + NewProxy must reach MUA and register the backend in Gate's
	// registry under the MUA frp address and the client-requested remote
	// port (the same mapping handleRegister writes through GateRegistry).
	remoteAddr := net.JoinHostPort(cfg.Union.Mua.FrpAddress, strconv.Itoa(remotePort))
	require.Eventually(t, func() bool {
		rs := g.Java().Server(proxyName)
		if rs == nil {
			return false
		}
		return rs.ServerInfo().Addr().String() == remoteAddr &&
			javaServerPortInUse(g.Java(), remotePort)
	}, 10*time.Second, 50*time.Millisecond,
		"frpc NewProxy must register %q at %s in the Gate registry; java servers: %v",
		proxyName, remoteAddr, javaServerSummaries(g.Java()))

	// frps must have accepted the proxy too: its remote listener only exists
	// after the plugin round-trip AND the server-side proxy registration, so
	// this rules out a proxy that MUA accepted but frps rejected. One
	// transient dial; closing it immediately leaves only harmless
	// work-connection teardown noise on both sides.
	requireDialable(t, net.JoinHostPort(cfg.Frps.BindAddr, strconv.Itoa(remotePort)))

	// --- phase 3: CloseProxy unregisters ------------------------------------
	// GracefulClose sends CloseProxy for live proxies over the session before
	// tearing it down; even if that loses the race against the session close,
	// frps closes every proxy of an exiting client, so MUA's unregister path
	// runs either way. Gate-side cleanup is asynchronous (a plugin goroutine
	// behind the CloseProxy notification), so poll for the removal.
	frpcService.Close()
	select {
	case err := <-frpcDone:
		require.NoError(t, err, "frpc must exit cleanly on graceful close")
	case <-time.After(10 * time.Second):
		frpcCancel()
		t.Fatal("frpc Run did not return after graceful close")
	}
	frpcCancel()

	require.Eventually(t, func() bool {
		return g.Java().Server(proxyName) == nil && !javaServerPortInUse(g.Java(), remotePort)
	}, 10*time.Second, 50*time.Millisecond,
		"frpc CloseProxy must unregister %q from the Gate registry; java servers: %v",
		proxyName, javaServerSummaries(g.Java()))

	// Gate's own shutdown is bootGate cleanup; the bounded waits above are
	// what keep a leaked frpc goroutine from blocking test exit.
}

// javaServerPortInUse mirrors mua.GateRegistry.PortInUse for tests: the
// GateRegistry adapter cannot be constructed from this package (its field is
// unexported), so scan the Java proxy's registered servers directly.
func javaServerPortInUse(p *jproxy.Proxy, port int) bool {
	want := strconv.Itoa(port)
	for _, rs := range p.Servers() {
		_, portStr, err := net.SplitHostPort(rs.ServerInfo().Addr().String())
		if err == nil && portStr == want {
			return true
		}
	}
	return false
}

func javaServerSummaries(p *jproxy.Proxy) []string {
	out := make([]string, 0, len(p.Servers()))
	for _, rs := range p.Servers() {
		info := rs.ServerInfo()
		out = append(out, info.Name()+"="+info.Addr().String())
	}
	return out
}
