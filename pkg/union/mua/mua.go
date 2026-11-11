// Package mua ports the control plane of the mua-proxy-plugin
// (https://github.com/MagicalSheep/mua-proxy-plugin) from a Javalin HTTP
// receiver to an in-process frp server plugin.
//
// The Kotlin plugin received frp client lifecycle events (login, new proxy,
// close proxy) over HTTP on :8080 and registered/unregistered Velocity
// backend servers accordingly; frps itself was spawned as a subprocess. Here
// the same logic runs as an frp server.Plugin invoked directly by the embedded
// frps in Gate's process (see github.com/fatedier/frp/server
// UnionRegisterPlugin), and the backend servers are managed through the
// Registry abstraction (implemented by GateRegistry in gate_adapter.go).
package mua

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	frpplugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

// Meta keys carried in frp client metas, verbatim from the Kotlin plugin.
const (
	MetaDomain      = "domain"
	MetaForcedHosts = "forced_hosts"
	MetaDomainAlias = "domain_alias"
	MetaGeneration  = "mua_generation"
)

// PluginName identifies the frp server plugin and the Gate plugin.
const PluginName = "union-mua"

// Registry abstracts the backend server registry so the frp plugin core has
// zero Gate import and is unit-testable with a fake.
type Registry interface {
	// Register registers a backend server under name at addr ("host:port").
	Register(name, addr string) error
	// Has reports whether a server with the given name is registered.
	Has(name string) bool
	// PortInUse reports whether any registered server listens on the given port.
	PortInUse(port int) bool
	// Unregister removes the server with the given name, if registered.
	Unregister(name string)
}

// forcedState tracks the login generation of a domain and whether any of the
// domain's proxies ever attempted to register. Port of the Kotlin
// ForcedHostsState data class.
type forcedState struct {
	generation         string
	hasRegisterAttempt bool
}

// Plugin implements frp server.Plugin for the MUA control plane.
type Plugin struct {
	name     string
	registry Registry
	log      logr.Logger

	// mu protects forcedHosts and states.
	mu          sync.Mutex
	forcedHosts map[string][]string     // lowercased host -> server names
	states      map[string]*forcedState // lowercased domain -> state

	frpAddress   string
	restrictPort bool
	allowMin     int
	allowMax     int
}

// Config mirrors the Kotlin plugin's frp integration settings.
type Config struct {
	// FrpAddress is the host remote players reach the frp entry node on;
	// registered backend servers point at it.
	FrpAddress string
	// RestrictPort limits the remote ports frp proxies may bind to
	// [AllowMin, AllowMax].
	RestrictPort bool
	// AllowMin and AllowMax bound the allowed remote ports.
	AllowMin, AllowMax int
}

// Default returns the Kotlin plugin's default configuration.
func Default() Config {
	return Config{
		FrpAddress:   "127.0.0.1",
		RestrictPort: false,
		AllowMin:     10000,
		AllowMax:     19999,
	}
}

// NewCore creates the frp server plugin with a discard logger. Use
// NewPlugin (gate_adapter.go) to wire it into Gate; use this constructor
// directly in tests.
func NewCore(reg Registry, cfg Config) *Plugin {
	if cfg.FrpAddress == "" {
		cfg.FrpAddress = "127.0.0.1"
	}
	return &Plugin{
		name:         PluginName,
		registry:     reg,
		log:          logr.Discard(),
		forcedHosts:  map[string][]string{},
		states:       map[string]*forcedState{},
		frpAddress:   cfg.FrpAddress,
		restrictPort: cfg.RestrictPort,
		allowMin:     cfg.AllowMin,
		allowMax:     cfg.AllowMax,
	}
}

// NewCoreWithLogger is NewCore with an explicit logger for the plugin's
// frp control-plane logs (forced-host and backend-server registration).
// A nil/zero logger (log.GetSink() == nil) falls back to the discard logger
// NewCore uses, so NewCore's behavior is unchanged.
func NewCoreWithLogger(reg Registry, cfg Config, log logr.Logger) *Plugin {
	p := NewCore(reg, cfg)
	p.SetLogger(log)
	return p
}

// SetLogger replaces the plugin's logger. It is a no-op for a nil/zero
// logger (log.GetSink() == nil), preserving the discard default of NewCore.
// Call it before the frps service starts serving: the frp handlers read the
// logger without synchronization (same contract as the log assignment in
// NewPlugin's Init).
func (p *Plugin) SetLogger(log logr.Logger) {
	if log.GetSink() != nil {
		p.log = log
	}
}

var _ frpplugin.Plugin = (*Plugin)(nil)

// Name implements frp server.Plugin.
func (p *Plugin) Name() string { return p.name }

// IsSupport implements frp server.Plugin; only the ops the Kotlin plugin
// served over HTTP are supported.
func (p *Plugin) IsSupport(op string) bool {
	switch op {
	case frpplugin.OpLogin, frpplugin.OpNewProxy, frpplugin.OpCloseProxy:
		return true
	default:
		return false
	}
}

// Handle implements frp server.Plugin. The frp Manager passes content as a
// value; a non-nil retContent for mutable ops must be a pointer to the same
// type (see handleMutableContent in the frp plugin manager).
func (p *Plugin) Handle(ctx context.Context, op string, content any) (*frpplugin.Response, any, error) {
	switch c := content.(type) {
	case frpplugin.LoginContent:
		return p.handleLogin(ctx, c)
	case frpplugin.NewProxyContent:
		return p.handleRegister(ctx, c)
	case frpplugin.CloseProxyContent:
		return p.handleUnregister(ctx, c)
	default:
		return &frpplugin.Response{Unchange: true}, nil, nil
	}
}

// handleLogin ports the Kotlin login() handler: it consumes the forced hosts
// declared by the frp client, maps the domain and its aliases to those
// server names and stamps the request with a fresh generation.
func (p *Plugin) handleLogin(ctx context.Context, content frpplugin.LoginContent) (*frpplugin.Response, any, error) {
	metas := content.Metas
	if metas == nil {
		return &frpplugin.Response{Unchange: true}, nil, nil
	}
	domain, hasDomain := metas[MetaDomain]
	_, hasHosts := metas[MetaForcedHosts]
	if !hasDomain || !hasHosts {
		return &frpplugin.Response{Unchange: true}, nil, nil
	}

	hosts, err := parseStringList(metas[MetaForcedHosts])
	if err != nil {
		p.log.Error(err, "failed to parse forced hosts meta")
		return &frpplugin.Response{
			Reject: true,
			RejectReason: fmt.Sprintf(
				"There is an error when update forced hosts, please contact administrator. (%s)", err),
		}, nil, nil
	}
	var aliases []string
	if v, ok := metas[MetaDomainAlias]; ok {
		aliases, _ = parseStringList(v) // Kotlin: alias parse errors degrade to an empty list
	}

	key := strings.ToLower(domain)
	tmp := make(map[string][]string, len(aliases)+1)
	tmp[key] = hosts
	for _, a := range aliases {
		tmp[strings.ToLower(a)] = hosts
	}

	generation := uuid.NewString()

	p.mu.Lock()
	// Merge like the Kotlin forcedHosts.putAll; unregister cleanup removes
	// the keys of a domain's metas again.
	for host, list := range tmp {
		p.forcedHosts[host] = list
	}
	p.states[key] = &forcedState{generation: generation}
	p.mu.Unlock()

	p.log.Info("registered forced hosts for domain", "domain", domain, "hosts", hosts)
	if len(aliases) > 0 {
		p.log.Info("registered aliases for domain", "domain", domain, "aliases", aliases)
	}

	// Reply with the whole request content plus the generation, like the
	// Kotlin `metas + (META_GENERATION to generation)`.
	ret := content
	ret.Metas = make(map[string]string, len(metas)+1)
	for k, v := range metas {
		ret.Metas[k] = v
	}
	ret.Metas[MetaGeneration] = generation
	return &frpplugin.Response{Unchange: false}, &ret, nil
}

// handleRegister ports the Kotlin register() handler: first the generation
// gate bookkeeping, then the validations in the same order, then the server
// registration.
func (p *Plugin) handleRegister(ctx context.Context, content frpplugin.NewProxyContent) (*frpplugin.Response, any, error) {
	metas := content.User.Metas
	name := content.ProxyName
	port := content.RemotePort

	if domain, hasDomain := metas[MetaDomain]; hasDomain {
		if generation, hasGeneration := metas[MetaGeneration]; hasGeneration {
			key := strings.ToLower(domain)
			p.mu.Lock()
			if st, ok := p.states[key]; ok && st.generation == generation {
				if hosts, ok := p.forcedHosts[key]; ok && slices.Contains(hosts, name) {
					st.hasRegisterAttempt = true
				}
			}
			p.mu.Unlock()
		}
	}

	if p.restrictPort && (port < p.allowMin || port > p.allowMax) {
		return &frpplugin.Response{
			Reject:       true,
			RejectReason: fmt.Sprintf("You can only use remote ports from %d to %d", p.allowMin, p.allowMax),
		}, nil, nil
	}
	if content.ProxyType != "tcp" {
		return &frpplugin.Response{
			Reject:       true,
			RejectReason: "Proxy type must be TCP",
		}, nil, nil
	}
	if p.registry.Has(name) {
		return &frpplugin.Response{
			Reject:       true,
			RejectReason: fmt.Sprintf("Server name <%s> is already in use", name),
		}, nil, nil
	}
	if p.registry.PortInUse(port) {
		return &frpplugin.Response{
			Reject:       true,
			RejectReason: fmt.Sprintf("Remote port %d is already in use", port),
		}, nil, nil
	}

	addr := net.JoinHostPort(p.frpAddress, strconv.Itoa(port))
	if err := p.registry.Register(name, addr); err != nil {
		p.log.Error(err, "failed to register backend server for frp proxy", "proxy", name, "addr", addr)
		return &frpplugin.Response{
			Reject:       true,
			RejectReason: fmt.Sprintf("Failed to register server <%s>: %v", name, err),
		}, nil, nil
	}
	p.log.Info("registered backend server for frp proxy", "name", name, "addr", addr)

	// Like the Kotlin plugin, a successful register leaves the request unchanged.
	return &frpplugin.Response{Unchange: true}, nil, nil
}

// handleUnregister ports the Kotlin unregister() handler: it replies
// unchanged first (the Kotlin HTTP handler answers before cleanup) and
// performs the cleanup asynchronously.
func (p *Plugin) handleUnregister(ctx context.Context, content frpplugin.CloseProxyContent) (*frpplugin.Response, any, error) {
	c := content
	go p.unregister(c)
	return &frpplugin.Response{Unchange: true}, nil, nil
}

// unregister performs the CloseProxy side effects: it removes the backend
// server of the frp proxy and, if the proxy's metas carry the forced hosts
// metas and no other server of the domain is still up, removes the forced
// hosts routing and the domain's state.
func (p *Plugin) unregister(content frpplugin.CloseProxyContent) {
	p.registry.Unregister(content.ProxyName)

	metas := content.User.Metas
	if metas == nil {
		return
	}
	domain, hasDomain := metas[MetaDomain]
	_, hasHosts := metas[MetaForcedHosts]
	if !hasDomain || !hasHosts {
		return
	}
	var aliases []string
	if v, ok := metas[MetaDomainAlias]; ok {
		aliases, _ = parseStringList(v)
	}

	key := strings.ToLower(domain)
	// Absent generation meta reads as "" like the Kotlin null generation.
	generation := metas[MetaGeneration]

	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.states[key]
	if !ok {
		return
	}
	if st.generation != generation && !st.hasRegisterAttempt {
		return
	}
	hosts, ok := p.forcedHosts[key]
	if !ok {
		return
	}
	for _, h := range hosts {
		if p.registry.Has(h) {
			return // another proxy of this domain is still registered
		}
	}
	delete(p.forcedHosts, key)
	for _, a := range aliases {
		delete(p.forcedHosts, strings.ToLower(a))
	}
	delete(p.states, key)
	p.log.Info("unregistered forced hosts for domain", "domain", domain, "hosts", hosts)
	if len(aliases) > 0 {
		p.log.Info("unregistered aliases for domain", "domain", domain, "aliases", aliases)
	}
}

// forcedHostList returns a snapshot of the server names routed for the given
// (lowercased) virtual host; used by the routing subscriber in
// gate_adapter.go.
func (p *Plugin) forcedHostList(host string) []string {
	host = strings.ToLower(host)
	p.mu.Lock()
	defer p.mu.Unlock()
	hosts, ok := p.forcedHosts[host]
	if !ok {
		return nil
	}
	return slices.Clone(hosts)
}

// parseStringList parses a metas value as a JSON array of strings, tolerating
// a single (quoted) string value.
func parseStringList(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal([]byte(v), &list); err == nil {
		return list, nil
	}
	var single string
	if err := json.Unmarshal([]byte(v), &single); err == nil {
		return []string{single}, nil
	}
	return nil, errors.New("value is not a JSON array of strings")
}
