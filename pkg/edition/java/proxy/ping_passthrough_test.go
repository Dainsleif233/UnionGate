package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/go-logr/logr"

	"go.minekube.com/gate/pkg/edition/java/config"
	"go.minekube.com/gate/pkg/edition/java/proto/codec"
	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proto/state"
	"go.minekube.com/gate/pkg/edition/java/proto/version"
	gproto "go.minekube.com/gate/pkg/gate/proto"
)

type pingTestInbound struct {
	vhost net.Addr
	ctx   context.Context
}

func (i pingTestInbound) Protocol() gproto.Protocol { return version.Minecraft_1_20_3.Protocol }
func (i pingTestInbound) VirtualHost() net.Addr     { return i.vhost }
func (i pingTestInbound) HandshakeIntent() packet.HandshakeIntent {
	return packet.StatusHandshakeIntent
}
func (i pingTestInbound) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (i pingTestInbound) Active() bool { return true }
func (i pingTestInbound) Context() context.Context {
	if i.ctx != nil {
		return i.ctx
	}
	return context.Background()
}

func pingTestAddr(t *testing.T, addr string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("resolve %q: %v", addr, err)
	}
	return a
}

// startPingBackend serves exactly one server list ping and returns its address.
func startPingBackend(t *testing.T, status string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		log := logr.Discard()
		dec := codec.NewDecoder(conn, gproto.ServerBound, log)
		dec.SetProtocol(version.Minecraft_1_20_3.Protocol)
		dec.SetState(state.Handshake)
		if _, err = dec.Decode(); err != nil {
			return
		}
		dec.SetState(state.Status)
		if _, err = dec.Decode(); err != nil {
			return
		}

		enc := codec.NewEncoder(conn, gproto.ClientBound, log)
		enc.SetProtocol(version.Minecraft_1_20_3.Protocol)
		enc.SetState(state.Status)
		_, _ = enc.WritePacket(&packet.StatusResponse{Status: status})
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func newPingTestHandler(t *testing.T, mode, backendAddr string) (*statusSessionHandler, *Proxy, *pingTestInbound) {
	t.Helper()
	cfg := config.DefaultConfig
	cfg.Status.PingPassthrough = mode
	cfg.Try = []string{"lobby"}

	p := &Proxy{
		cfg:     &cfg,
		servers: map[string]*registeredServer{},
	}
	if backendAddr != "" {
		p.servers["lobby"] = newRegisteredServer(NewServerInfo("lobby", pingTestAddr(t, backendAddr)))
	}
	inbound := &pingTestInbound{vhost: &testVhostAddr{network: "tcp", addr: "play.example.com:25565"}}
	h := &statusSessionHandler{
		sessionHandlerDeps: &sessionHandlerDeps{
			proxy:          p,
			configProvider: &testConfigProvider{cfg: &cfg},
		},
		inbound: inbound,
		log:     logr.Discard(),
	}
	return h, p, inbound
}

func TestResolveInitialPingDisabledUsesLocal(t *testing.T) {
	h, p, _ := newPingTestHandler(t, "disabled", "")
	local := newInitialPing(p, version.Minecraft_1_20_3.Protocol)
	got := h.resolveInitialPing(version.Minecraft_1_20_3.Protocol)
	if got == nil {
		t.Fatal("expected local status")
	}
	if got.Version.Name != local.Version.Name {
		t.Fatalf("version name = %q, want local %q", got.Version.Name, local.Version.Name)
	}
	if got.Description != local.Description {
		t.Fatal("disabled mode must keep the local description")
	}
}

func TestResolveInitialPingAllUsesBackend(t *testing.T) {
	status := `{"version":{"name":"Backend","protocol":765},"players":{"online":3,"max":20},"description":{"text":"Backend MOTD"}}`
	addr := startPingBackend(t, status)
	h, p, _ := newPingTestHandler(t, "all", addr)
	local := newInitialPing(p, version.Minecraft_1_20_3.Protocol)

	got := h.resolveInitialPing(version.Minecraft_1_20_3.Protocol)
	if got == nil {
		t.Fatal("expected backend status")
	}
	if got.Version.Name != "Backend" {
		t.Fatalf("version name = %q, want Backend", got.Version.Name)
	}
	if got.Players == nil || got.Players.Online != 3 || got.Players.Max != 20 {
		t.Fatalf("players = %+v, want online 3 max 20", got.Players)
	}
	if got.Description == local.Description {
		t.Fatal("all mode must use the backend description, not the local one")
	}
}

func TestResolveInitialPingModsCopiesModInfoOnly(t *testing.T) {
	status := `{"version":{"name":"Backend","protocol":765},"players":{"online":3,"max":20},"description":{"text":"Backend MOTD"},"modinfo":{"type":"FML","modList":[{"modid":"forge","version":"1.0"}]},"forgeData":{"channels":[]}}`
	addr := startPingBackend(t, status)
	h, p, _ := newPingTestHandler(t, "mods", addr)
	local := newInitialPing(p, version.Minecraft_1_20_3.Protocol)

	got := h.resolveInitialPing(version.Minecraft_1_20_3.Protocol)
	if got == nil {
		t.Fatal("expected local status with backend mod info")
	}
	if got.Version.Name != local.Version.Name {
		t.Fatalf("version name = %q, want local %q", got.Version.Name, local.Version.Name)
	}
	if got.Players == nil || got.Players.Online != local.Players.Online {
		t.Fatalf("players = %+v, want local online %d", got.Players, local.Players.Online)
	}
	if got.Description != local.Description {
		t.Fatal("mods mode must keep the local description")
	}
	if got.ModInfo == nil || got.ModInfo.Type != "FML" || len(got.ModInfo.Mods) != 1 || got.ModInfo.Mods[0].ID != "forge" {
		t.Fatalf("modinfo = %+v, want backend FML mods", got.ModInfo)
	}
	if _, ok := got.Extra["forgeData"]; !ok {
		t.Fatalf("extra = %v, want forgeData copied", got.Extra)
	}
}

func TestResolveInitialPingFallsBackToLocalOnBackendError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	h, p, _ := newPingTestHandler(t, "all", addr)
	local := newInitialPing(p, version.Minecraft_1_20_3.Protocol)
	got := h.resolveInitialPing(version.Minecraft_1_20_3.Protocol)
	if got == nil {
		t.Fatal("expected local fallback status")
	}
	if got.Version.Name != local.Version.Name || got.Description != local.Description {
		t.Fatalf("fallback status = %+v, want local %+v", got, local)
	}
}

func TestPassthroughVirtualHostStripsSeparators(t *testing.T) {
	inbound := &pingTestInbound{vhost: &testVhostAddr{network: "tcp", addr: "Play.Example.COM:25565\x00FML\x00"}}
	host, port := passthroughVirtualHost(inbound)
	if host != "play.example.com" {
		t.Fatalf("host = %q, want play.example.com", host)
	}
	if port != 25565 {
		t.Fatalf("port = %d, want 25565", port)
	}
}

type testVhostAddr struct {
	network string
	addr    string
}

func (a *testVhostAddr) Network() string { return a.network }
func (a *testVhostAddr) String() string  { return a.addr }
