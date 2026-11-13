package mua

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	frpplugin "github.com/fatedier/frp/pkg/plugin/server"
)

// fakeRegistry is an in-memory Registry for unit tests.
type fakeRegistry struct {
	mu      sync.Mutex
	servers map[string]string // name -> addr

	unregistered chan string // signals each Unregister call
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		servers:      map[string]string{},
		unregistered: make(chan string, 16),
	}
}

func (f *fakeRegistry) Register(name, addr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.servers[name]; ok {
		return errors.New("already registered")
	}
	f.servers[name] = addr
	return nil
}

func (f *fakeRegistry) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.servers[name]
	return ok
}

func (f *fakeRegistry) PortInUse(port int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, addr := range f.servers {
		_, portStr, _ := strings.Cut(addr, ":")
		if p, err := strconv.Atoi(portStr); err == nil && p == port {
			return true
		}
	}
	return false
}

func (f *fakeRegistry) Unregister(name string) {
	f.mu.Lock()
	delete(f.servers, name)
	f.mu.Unlock()
	select {
	case f.unregistered <- name:
	default:
	}
}

func (f *fakeRegistry) addr(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servers[name]
}

func newTestPlugin(t *testing.T, reg Registry, cfg Config) *Plugin {
	t.Helper()
	if cfg == (Config{}) {
		cfg = Default()
	}
	return NewCore(reg, cfg)
}

func loginContent(domain, forcedHosts, domainAlias string) frpplugin.LoginContent {
	metas := map[string]string{}
	if domain != "" {
		metas[MetaDomain] = domain
	}
	if forcedHosts != "" {
		metas[MetaForcedHosts] = forcedHosts
	}
	if domainAlias != "" {
		metas[MetaDomainAlias] = domainAlias
	}
	return frpplugin.LoginContent{Login: msg.Login{Metas: metas}}
}

func newProxyContent(name, proxyType string, remotePort int, metas map[string]string) frpplugin.NewProxyContent {
	return frpplugin.NewProxyContent{
		User:     frpplugin.UserInfo{Metas: metas},
		NewProxy: msg.NewProxy{ProxyName: name, ProxyType: proxyType, RemotePort: remotePort},
	}
}

func closeProxyContent(name string, metas map[string]string) frpplugin.CloseProxyContent {
	return frpplugin.CloseProxyContent{
		User:       frpplugin.UserInfo{Metas: metas},
		CloseProxy: msg.CloseProxy{ProxyName: name},
	}
}

func TestIsSupport(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})
	for _, op := range []string{frpplugin.OpLogin, frpplugin.OpNewProxy, frpplugin.OpCloseProxy} {
		if !p.IsSupport(op) {
			t.Errorf("IsSupport(%q) = false, want true", op)
		}
	}
	for _, op := range []string{frpplugin.OpPing, frpplugin.OpNewWorkConn, frpplugin.OpNewUserConn, ""} {
		if p.IsSupport(op) {
			t.Errorf("IsSupport(%q) = true, want false", op)
		}
	}
}

func TestHandleUnknownOp(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})
	res, ret, err := p.Handle(context.Background(), frpplugin.OpPing, frpplugin.PingContent{})
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if res == nil || !res.Unchange || res.Reject {
		t.Errorf("Handle(ping) response = %+v, want Unchange", res)
	}
	if ret != nil {
		t.Errorf("Handle(ping) retContent = %v, want nil", ret)
	}
}

func TestLoginRequiresDomainAndForcedHostsMetas(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})

	for _, c := range []frpplugin.LoginContent{
		{Login: msg.Login{}},                // no metas
		loginContent("", "", ""),            // empty metas
		loginContent("example.com", "", ""), // missing forced_hosts
		{Login: msg.Login{Metas: map[string]string{MetaForcedHosts: `["srv"]`}}}, // missing domain
	} {
		res, ret, err := p.Handle(context.Background(), frpplugin.OpLogin, c)
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		if res == nil || !res.Unchange || res.Reject {
			t.Errorf("Handle(login %v) response = %+v, want Unchange", c.Metas, res)
		}
		if ret != nil {
			t.Errorf("Handle(login %v) retContent = %v, want nil", c.Metas, ret)
		}
	}
}

func TestLoginSuccess(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})

	res, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("Example.COM", `["srv1","srv2"]`, `["alias.example.com"]`))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	if res == nil || res.Reject || res.Unchange {
		t.Fatalf("Handle(login) response = %+v, want changed", res)
	}
	ret, ok := retContent.(*frpplugin.LoginContent)
	if !ok {
		t.Fatalf("retContent type = %T, want *frpplugin.LoginContent", retContent)
	}

	generation, ok := ret.Metas[MetaGeneration]
	if !ok || generation == "" {
		t.Fatalf("returned metas lack generation: %v", ret.Metas)
	}
	for _, k := range []string{MetaDomain, MetaForcedHosts, MetaDomainAlias} {
		if _, ok := ret.Metas[k]; !ok {
			t.Errorf("returned metas lost meta %q: %v", k, ret.Metas)
		}
	}

	// The domain and its alias route to the declared servers, lowercased.
	if got := p.forcedHostList("example.com"); len(got) != 2 || got[0] != "srv1" || got[1] != "srv2" {
		t.Errorf("forcedHostList(example.com) = %v", got)
	}
	if got := p.forcedHostList("alias.example.com"); len(got) != 2 {
		t.Errorf("forcedHostList(alias.example.com) = %v", got)
	}

	// State records the generation for the domain.
	state, ok := p.states[strings.ToLower("Example.COM")]
	if !ok {
		t.Fatalf("missing state for domain")
	}
	if state.generation != generation {
		t.Errorf("state generation = %q, want %q", state.generation, generation)
	}
	if state.hasRegisterAttempt {
		t.Error("fresh login state must not have a register attempt")
	}
}

func TestLoginToleratesSingleStringList(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})
	res, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `"srv1"`, `"alias.example.com"`))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	if res == nil || res.Reject || res.Unchange {
		t.Fatalf("Handle(login) response = %+v, want changed", res)
	}
	ret := retContent.(*frpplugin.LoginContent)
	if _, ok := ret.Metas[MetaGeneration]; !ok {
		t.Fatalf("returned metas lack generation: %v", ret.Metas)
	}
	if got := p.forcedHostList("example.com"); len(got) != 1 || got[0] != "srv1" {
		t.Errorf("forcedHostList(example.com) = %v, want [srv1]", got)
	}
	if got := p.forcedHostList("alias.example.com"); len(got) != 1 || got[0] != "srv1" {
		t.Errorf("forcedHostList(alias.example.com) = %v, want [srv1]", got)
	}
}

func TestLoginParseErrorRejects(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})
	res, ret, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `[srv1`, ""))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	if ret != nil {
		t.Errorf("retContent = %v, want nil", ret)
	}
	if res == nil || !res.Reject {
		t.Fatalf("Handle(login) response = %+v, want reject", res)
	}
	const wantPrefix = "There is an error when update forced hosts"
	if !strings.HasPrefix(res.RejectReason, wantPrefix) {
		t.Errorf("reject reason = %q, want prefix %q", res.RejectReason, wantPrefix)
	}
	// The malformed login must not have installed any routing or state.
	if got := p.forcedHostList("example.com"); got != nil {
		t.Errorf("forcedHostList after reject = %v, want none", got)
	}
	if len(p.states) != 0 {
		t.Errorf("states after reject = %v, want none", p.states)
	}
}

func TestRegisterValidationsInKotlinOrder(t *testing.T) {
	reg := newFakeRegistry()
	_ = reg.Register("occupied", "127.0.0.1:15000")
	p := newTestPlugin(t, reg, Config{FrpAddress: "127.0.0.1", RestrictPort: true, AllowMin: 10000, AllowMax: 19999})

	tests := []struct {
		name    string
		content frpplugin.NewProxyContent
		want    string
	}{
		{
			name:    "port range comes before type and name checks",
			content: newProxyContent("occupied", "udp", 30000, nil),
			want:    "You can only use remote ports from 10000 to 19999",
		},
		{
			name:    "port below range",
			content: newProxyContent("x", "tcp", 9999, nil),
			want:    "You can only use remote ports from 10000 to 19999",
		},
		{
			name:    "proxy type must be tcp",
			content: newProxyContent("fresh", "udp", 10000, nil),
			want:    "Proxy type must be TCP",
		},
		{
			name:    "server name collision",
			content: newProxyContent("occupied", "tcp", 10001, nil),
			want:    "Server name <occupied> is already in use",
		},
		{
			name:    "remote port already in use by a server address",
			content: newProxyContent("fresh", "tcp", 15000, nil),
			want:    "Remote port 15000 is already in use",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, ret, err := p.Handle(context.Background(), frpplugin.OpNewProxy, tc.content)
			if err != nil {
				t.Fatalf("Handle(newProxy) returned error: %v", err)
			}
			if ret != nil {
				t.Errorf("retContent = %v, want nil", ret)
			}
			if res == nil || !res.Reject || res.RejectReason != tc.want {
				t.Errorf("response = %+v, want reject %q", res, tc.want)
			}
		})
	}
}

func TestRegisterSuccessAndGenerationGate(t *testing.T) {
	reg := newFakeRegistry()
	p := newTestPlugin(t, reg, Config{})

	// Login stamps a generation.
	_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `["srv1"]`, ""))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	generation := retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]

	metas := map[string]string{MetaDomain: "example.com", MetaGeneration: generation}
	res, _, err := p.Handle(context.Background(), frpplugin.OpNewProxy,
		newProxyContent("srv1", "tcp", 10001, metas))
	if err != nil {
		t.Fatalf("Handle(newProxy) returned error: %v", err)
	}
	if res == nil || res.Reject || !res.Unchange {
		t.Fatalf("Handle(newProxy) response = %+v, want unchanged accept", res)
	}
	if addr := reg.addr("srv1"); addr != "127.0.0.1:10001" {
		t.Errorf("registered addr = %q, want 127.0.0.1:10001", addr)
	}

	// The register attempt is recorded on the domain's state.
	state := p.states["example.com"]
	if !state.hasRegisterAttempt {
		t.Error("matching generation register must set hasRegisterAttempt")
	}

	// A register whose generation does not match must not set the attempt.
	p2 := newTestPlugin(t, newFakeRegistry(), Config{})
	_, retContent, err = p2.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `["srv1"]`, ""))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	res, _, err = p2.Handle(context.Background(), frpplugin.OpNewProxy, newProxyContent("srv1", "tcp", 10001,
		map[string]string{MetaDomain: "example.com", MetaGeneration: "stale-generation"}))
	if err != nil {
		t.Fatalf("Handle(newProxy) returned error: %v", err)
	}
	if res == nil || res.Reject || !res.Unchange {
		t.Fatalf("stale generation must not prevent registering: %+v", res)
	}
	if p2.states["example.com"].hasRegisterAttempt {
		t.Error("stale generation must not set hasRegisterAttempt")
	}
}

func TestRegisterRejectsWhenGateRegistrationFails(t *testing.T) {
	reg := newFakeRegistry()
	failing := &failingRegistry{inner: reg}
	p := newTestPlugin(t, failing, Config{})
	res, _, err := p.Handle(context.Background(), frpplugin.OpNewProxy,
		newProxyContent("srv1", "tcp", 10001, nil))
	if err != nil {
		t.Fatalf("Handle(newProxy) returned error: %v", err)
	}
	if res == nil || !res.Reject || res.RejectReason == "" {
		t.Errorf("response = %+v, want reject with reason", res)
	}
}

type failingRegistry struct{ inner Registry }

func (f *failingRegistry) Register(name, addr string) error { return errors.New("boom") }
func (f *failingRegistry) Has(name string) bool             { return f.inner.Has(name) }
func (f *failingRegistry) PortInUse(port int) bool          { return f.inner.PortInUse(port) }
func (f *failingRegistry) Unregister(name string)           { f.inner.Unregister(name) }

// TestUnregisterLifecycle covers the full login -> register -> close proxy
// lifecycle including the forced-host cleanup rule.
func TestUnregisterLifecycle(t *testing.T) {
	t.Run("cleans up domain aliases and state after last server closes", func(t *testing.T) {
		reg := newFakeRegistry()
		p := newTestPlugin(t, reg, Config{})

		_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
			loginContent("example.com", `["srv1"]`, `["alias.example.com"]`))
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		generation := retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]
		res, _, err := p.Handle(context.Background(), frpplugin.OpNewProxy, newProxyContent("srv1", "tcp", 10001,
			map[string]string{MetaDomain: "example.com", MetaGeneration: generation}))
		if err != nil {
			t.Fatalf("Handle(newProxy) returned error: %v", err)
		}
		if res == nil || !res.Unchange {
			t.Fatalf("Handle(newProxy) response = %+v, want unchanged", res)
		}

		// CloseProxy replies unchanged first and cleans up asynchronously.
		res, _, err = p.Handle(context.Background(), frpplugin.OpCloseProxy, closeProxyContent("srv1",
			map[string]string{
				MetaDomain:      "example.com",
				MetaForcedHosts: `["srv1"]`,
				MetaDomainAlias: `["alias.example.com"]`,
				MetaGeneration:  generation,
			}))
		if err != nil {
			t.Fatalf("Handle(closeProxy) returned error: %v", err)
		}
		if res == nil || !res.Unchange || res.Reject {
			t.Fatalf("Handle(closeProxy) response = %+v, want unchanged", res)
		}
		select {
		case <-reg.unregistered:
		case <-time.After(5 * time.Second):
			t.Fatal("cleanup did not unregister the server")
		}
		if got := reg.addr("srv1"); got != "" {
			t.Errorf("server still registered: %q", got)
		}
		if got := p.forcedHostList("example.com"); got != nil {
			t.Errorf("forcedHostList(example.com) = %v, want removed", got)
		}
		if got := p.forcedHostList("alias.example.com"); got != nil {
			t.Errorf("forcedHostList(alias.example.com) = %v, want removed", got)
		}
		if _, ok := p.states["example.com"]; ok {
			t.Error("state not removed")
		}
	})

	t.Run("keeps routing while another server of the domain is registered", func(t *testing.T) {
		reg := newFakeRegistry()
		p := newTestPlugin(t, reg, Config{})

		_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
			loginContent("example.com", `["srv1","srv2"]`, ""))
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		generation := retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]
		if _, _, err = p.Handle(context.Background(), frpplugin.OpNewProxy, newProxyContent("srv2", "tcp", 10002,
			map[string]string{MetaDomain: "example.com", MetaGeneration: generation})); err != nil {
			t.Fatalf("Handle(newProxy) returned error: %v", err)
		}

		// srv1 was never registered but srv2 is still up: keep routing.
		p.unregister(closeProxyContent("srv1", map[string]string{
			MetaDomain:      "example.com",
			MetaForcedHosts: `["srv1","srv2"]`,
			MetaGeneration:  generation,
		}))
		if got := p.forcedHostList("example.com"); got == nil {
			t.Error("routing removed while another server is still registered")
		}
		if _, ok := p.states["example.com"]; !ok {
			t.Error("state removed while another server is still registered")
		}
	})

	t.Run("skips cleanup on generation mismatch without register attempt", func(t *testing.T) {
		reg := newFakeRegistry()
		p := newTestPlugin(t, reg, Config{})
		_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
			loginContent("example.com", `["srv1"]`, ""))
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		_ = retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]

		// No register attempt was made; a CloseProxy with a stale generation
		// (e.g. from a previous frpc run_id) must not clear the routing.
		p.unregister(closeProxyContent("srv1", map[string]string{
			MetaDomain:      "example.com",
			MetaForcedHosts: `["srv1"]`,
			MetaGeneration:  "stale-generation",
		}))
		if got := p.forcedHostList("example.com"); got == nil {
			t.Error("routing cleared on stale generation without register attempt")
		}
		if _, ok := p.states["example.com"]; !ok {
			t.Error("state cleared on stale generation without register attempt")
		}
	})

	t.Run("stale generation still cleans up after a register attempt", func(t *testing.T) {
		reg := newFakeRegistry()
		p := newTestPlugin(t, reg, Config{})
		_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
			loginContent("example.com", `["srv1"]`, ""))
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		generation := retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]
		// A proxy registers once (attempt recorded), then frpc restarts and
		// closes with a different generation it never registered.
		if _, _, err = p.Handle(context.Background(), frpplugin.OpNewProxy, newProxyContent("srv1", "tcp", 10001,
			map[string]string{MetaDomain: "example.com", MetaGeneration: generation})); err != nil {
			t.Fatalf("Handle(newProxy) returned error: %v", err)
		}
		p.unregister(closeProxyContent("srv1", map[string]string{
			MetaDomain:      "example.com",
			MetaForcedHosts: `["srv1"]`,
			MetaGeneration:  "gen-2",
		}))
		if got := p.forcedHostList("example.com"); got != nil {
			t.Errorf("forcedHostList(example.com) = %v, want removed after register attempt", got)
		}
		if _, ok := p.states["example.com"]; ok {
			t.Error("state not removed after register attempt")
		}
	})

	t.Run("ignores close proxy without forced hosts metas", func(t *testing.T) {
		reg := newFakeRegistry()
		p := newTestPlugin(t, reg, Config{})
		_, retContent, err := p.Handle(context.Background(), frpplugin.OpLogin,
			loginContent("example.com", `["srv1"]`, ""))
		if err != nil {
			t.Fatalf("Handle(login) returned error: %v", err)
		}
		generation := retContent.(*frpplugin.LoginContent).Metas[MetaGeneration]
		// srv1 IS registered, but the close proxy carries no domain metas:
		// only the server unregister happens, routing stays.
		if _, _, err = p.Handle(context.Background(), frpplugin.OpNewProxy, newProxyContent("srv1", "tcp", 10001,
			map[string]string{MetaDomain: "example.com", MetaGeneration: generation})); err != nil {
			t.Fatalf("Handle(newProxy) returned error: %v", err)
		}
		p.unregister(closeProxyContent("srv1", nil))
		if got := p.forcedHostList("example.com"); got == nil {
			t.Error("routing cleared without forced hosts metas")
		}
		if _, ok := p.states["example.com"]; !ok {
			t.Error("state cleared without forced hosts metas")
		}
	})
}

func TestLoginReLoginRefreshesGeneration(t *testing.T) {
	p := newTestPlugin(t, newFakeRegistry(), Config{})

	_, ret1, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `["srv1"]`, ""))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	gen1 := ret1.(*frpplugin.LoginContent).Metas[MetaGeneration]
	_, ret2, err := p.Handle(context.Background(), frpplugin.OpLogin,
		loginContent("example.com", `["srv1","srv2"]`, ""))
	if err != nil {
		t.Fatalf("Handle(login) returned error: %v", err)
	}
	gen2 := ret2.(*frpplugin.LoginContent).Metas[MetaGeneration]
	if gen1 == gen2 {
		t.Fatal("re-login must mint a fresh generation")
	}
	if got := p.forcedHostList("example.com"); len(got) != 2 {
		t.Errorf("forcedHostList(example.com) = %v, want re-login to override the list", got)
	}
	if got := p.states["example.com"]; got.generation != gen2 {
		t.Errorf("state generation = %q, want %q", got.generation, gen2)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.FrpAddress != "127.0.0.1" || cfg.RestrictPort ||
		cfg.AllowMin != 10000 || cfg.AllowMax != 19999 {
		t.Errorf("Default() = %+v", cfg)
	}
}

func TestParseStringList(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "", want: nil},
		{in: `[]`, want: []string{}},
		{in: `["a","b"]`, want: []string{"a", "b"}},
		{in: `"a"`, want: []string{"a"}},
		{in: `[a,b]`, wantErr: true},
		{in: `123`, wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseStringList(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseStringList(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseStringList(%q) returned error: %v", tc.in, err)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("parseStringList(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestForcedHostServersCopiesAndLowercases(t *testing.T) {
	p := NewCore(&fakeRegistry{}, Config{})
	p.mu.Lock()
	p.forcedHosts["play.example.com"] = []string{"lobby", "survival"}
	p.mu.Unlock()

	got := p.ForcedHostServers("PLAY.Example.COM")
	if len(got) != 2 || got[0] != "lobby" || got[1] != "survival" {
		t.Fatalf("ForcedHostServers = %v, want [lobby survival]", got)
	}
	got[0] = "mutated"
	again := p.ForcedHostServers("play.example.com")
	if again[0] != "lobby" {
		t.Fatalf("ForcedHostServers returned a shared slice: %v", again)
	}
	if p.ForcedHostServers("missing.example.com") != nil {
		t.Fatal("expected nil for unknown host")
	}
}
