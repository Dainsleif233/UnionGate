package mua

import (
	"context"
	"net"
	"strings"

	frpserver "github.com/fatedier/frp/server"
	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"

	"go.minekube.com/gate/pkg/edition/java/lite"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/netutil"
)

// GateRegistry adapts *proxy.Proxy to the Registry interface so the frp
// plugin core stays Gate-free.
type GateRegistry struct{ p *proxy.Proxy }

var _ Registry = GateRegistry{}

// Register implements Registry by registering a backend server with Gate.
func (g GateRegistry) Register(name, addr string) error {
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	_, err = g.p.Register(proxy.NewServerInfo(name, tcp))
	return err
}

// Has implements Registry; Gate looks names up case-insensitively.
func (g GateRegistry) Has(name string) bool {
	return g.p.Server(name) != nil
}

// PortInUse implements Registry by scanning all registered server addresses.
func (g GateRegistry) PortInUse(port int) bool {
	for _, rs := range g.p.Servers() {
		if int(netutil.Port(rs.ServerInfo().Addr())) == port {
			return true
		}
	}
	return false
}

// Unregister implements Registry; it is a no-op when the server is not
// registered (the Kotlin plugin early-returns in that case too).
func (g GateRegistry) Unregister(name string) {
	if rs := g.p.Server(name); rs != nil {
		g.p.Unregister(rs.ServerInfo())
	}
}

// NewCoreForProxy returns the MUA frp server plugin core bound to px's
// backend registry, without installing it anywhere. Use it together with
// SubscribeRouting when the host must queue the plugin itself (via
// frpserver.UnionRegisterPlugin or pkg/union/frps.RegisterPlugin) BEFORE the
// embedded frps service drains the queue - e.g. Gate's union.Wire does both
// during startup, because process.Collection starts runnables concurrently,
// so a queue call inside an Init hook would race the frps service start,
// while queueing in gate.New happens before any runnable is added.
func NewCoreForProxy(px *proxy.Proxy, cfg Config) *Plugin {
	return NewCore(GateRegistry{p: px}, cfg)
}

// NewCoreForProxyWithLogger is NewCoreForProxy with an explicit logger for
// the core's frp control-plane logs. A nil/zero logger (log.GetSink() ==
// nil) falls back to the discard logger, like NewCoreForProxy.
func NewCoreForProxyWithLogger(px *proxy.Proxy, cfg Config, log logr.Logger) *Plugin {
	return NewCoreWithLogger(GateRegistry{p: px}, cfg, log)
}

// SubscribeRouting subscribes core's forced-host routing to px's event bus at
// routeSubscriberPriority - the same wiring NewPlugin's Init performs. It
// must be called at most once per core while the proxy is not serving (a
// second subscription would route each event twice), and nil px is a no-op.
func SubscribeRouting(px *proxy.Proxy, core *Plugin) {
	if px == nil || core == nil {
		return
	}
	// Route players by the dynamic forced hosts map; a lower priority runs
	// after other subscribers so the forced route wins over servers set
	// before it.
	event.Subscribe(px.Event(), routeSubscriberPriority,
		func(e *proxy.PlayerChooseInitialServerEvent) { core.route(e, px) })
}

// NewPlugin returns the Gate plugin that installs the MUA frp control plane.
// Add it to proxy.Plugins with the Config of the deployment.
func NewPlugin(px *proxy.Proxy, cfg Config) proxy.Plugin {
	core := NewCore(GateRegistry{p: px}, cfg)
	return proxy.Plugin{
		Name: PluginName,
		Init: func(ctx context.Context, px *proxy.Proxy) error {
			log := logr.FromContextOrDiscard(ctx).WithName(PluginName)
			core.log = log

			// Queue the in-process frp server plugin; it is registered with
			// the next frp Service run, so this must happen before frps
			// starts (no loopback HTTP and no :8080 listener involved).
			frpserver.UnionRegisterPlugin(core)

			// Route players by the dynamic forced hosts map; a lower
			// priority runs after other subscribers so the forced route
			// wins over servers set before it.
			event.Subscribe(px.Event(), routeSubscriberPriority,
				func(e *proxy.PlayerChooseInitialServerEvent) { core.route(e, px) })

			log.Info("MUA union proxy plugin loaded")
			return nil
		},
	}
}

// routeSubscriberPriority runs the forced-host routing subscriber last.
const routeSubscriberPriority = -1000

// route overrides the player's initial server with the first registered
// server listed for the player's virtual host, mirroring how Velocity's
// config forcedHosts (updated by the Kotlin plugin via reflection) route.
func (p *Plugin) route(e *proxy.PlayerChooseInitialServerEvent, px *proxy.Proxy) {
	player := e.Player()
	if player == nil {
		return
	}
	vhost := player.VirtualHost()
	if vhost == nil {
		return
	}
	// Same processing as Gate's own virtual host handling: clear forge and
	// TCPShield separators, extract the hostname and lowercase it.
	host := strings.ToLower(netutil.HostStr(lite.ClearVirtualHost(vhost.String())))
	for _, name := range p.forcedHostList(host) {
		if s := px.Server(name); s != nil {
			e.SetInitialServer(s)
			return
		}
	}
}
