package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"go.minekube.com/gate/pkg/edition/java/ping"
	"go.minekube.com/gate/pkg/edition/java/proto/codec"
	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proto/state"
	"go.minekube.com/gate/pkg/edition/java/proto/version"
	"go.minekube.com/gate/pkg/gate/proto"
	"go.minekube.com/gate/pkg/util/netutil"
)

// PingPassthroughFunc resolves the server list status of a backend for a
// client's server list ping. It is installed by WireWithLogger so the union
// MUA plugin's dynamic forced hosts can take precedence over Gate's static
// configuration; a nil resolver falls back to ResolvePingPassthroughDefault.
type PingPassthroughFunc func(ctx context.Context, proxy *Proxy, inbound Inbound, protocol proto.Protocol) (*ping.ServerPing, error)

// SetPingPassthroughResolver installs the full-mode ping passthrough resolver.
// A nil function removes it and restores the default static resolver.
func (p *Proxy) SetPingPassthroughResolver(f PingPassthroughFunc) {
	if p == nil {
		return
	}
	if f == nil {
		p.pingPassthrough.Store(nil)
		return
	}
	p.pingPassthrough.Store(&f)
}

// resolvePingPassthrough resolves a backend status using the installed
// resolver, or Gate's static forced hosts / try list when none is installed.
func (p *Proxy) resolvePingPassthrough(ctx context.Context, inbound Inbound, protocol proto.Protocol) (*ping.ServerPing, error) {
	if p == nil {
		return nil, errors.New("ping passthrough: proxy is nil")
	}
	if f := p.pingPassthrough.Load(); f != nil {
		return (*f)(ctx, p, inbound, protocol)
	}
	return p.ResolvePingPassthroughDefault(ctx, inbound, protocol)
}

// ResolvePingPassthroughDefault resolves the backend status from the static
// configuration: the virtual host's forced host first, then the try list.
func (p *Proxy) ResolvePingPassthroughDefault(ctx context.Context, inbound Inbound, protocol proto.Protocol) (*ping.ServerPing, error) {
	if p == nil {
		return nil, errors.New("ping passthrough: proxy is nil")
	}
	host, _ := passthroughVirtualHost(inbound)
	servers := p.config().ForcedHosts[host]
	if len(servers) == 0 {
		servers = p.config().Try
	}
	return ResolvePingPassthroughServers(ctx, p, servers, inbound, protocol)
}

// ResolvePingPassthroughServers tries the named backend servers in order and
// returns the first status response. It is exported so a plugin (the union
// MUA bridge) can pass a dynamic forced-host server list.
func ResolvePingPassthroughServers(ctx context.Context, p *Proxy, servers []string, inbound Inbound, protocol proto.Protocol) (*ping.ServerPing, error) {
	if p == nil {
		return nil, errors.New("ping passthrough: proxy is nil")
	}
	if !version.Protocol(protocol).Supported() {
		return nil, fmt.Errorf("ping passthrough: unsupported protocol %d", protocol)
	}
	host, port := passthroughVirtualHost(inbound)
	var lastErr error
	for _, name := range servers {
		rs := p.Server(name)
		if rs == nil {
			continue
		}
		addr := rs.ServerInfo().Addr()
		if addr == nil {
			continue
		}
		status, err := fetchBackendPing(ctx, addr.String(), host, port, protocol)
		if err == nil {
			return status, nil
		}
		lastErr = fmt.Errorf("backend %q (%s): %w", name, addr, err)
	}
	if lastErr == nil {
		lastErr = errors.New("ping passthrough: no backend server available")
	}
	return nil, lastErr
}

// passthroughVirtualHost returns the hostname and port a client used for its
// handshake, after stripping Forge/TCPShield separators like the rest of the
// proxy does. A missing virtual host yields empty values.
func passthroughVirtualHost(inbound Inbound) (host string, port int) {
	if inbound == nil || inbound.VirtualHost() == nil {
		return "", 0
	}
	vhost := inbound.VirtualHost()
	cleared := clearVirtualHostSeparators(vhost.String())
	host = strings.ToLower(netutil.HostStr(cleared))
	port = int(netutil.PortStr(cleared))
	return host, port
}

// clearVirtualHostSeparators removes the NUL-separated Forge/TCPShield data
// from a handshake host. The OpenCode union fork must not import the Lite
// package here (Lite is disabled together with union plugins), so this is a
// small local equivalent of lite.ClearVirtualHost for the first NUL field.
func clearVirtualHostSeparators(vhost string) string {
	vhost = strings.Split(vhost, "\x00")[0] // Forge FML separator
	vhost = strings.Split(vhost, "///")[0]  // TCPShield real IP separator
	return strings.Trim(vhost, ".")
}

func fetchBackendPing(ctx context.Context, backendAddr, vhost string, vhostPort int, protocol proto.Protocol) (*ping.ServerPing, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", backendAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if vhost == "" {
		vhost = netutil.HostStr(backendAddr)
	}
	if vhostPort == 0 {
		vhostPort = int(netutil.PortStr(backendAddr))
	}

	log := logr.Discard()
	enc := codec.NewEncoder(conn, proto.ServerBound, log)
	enc.SetProtocol(protocol)
	enc.SetState(state.Handshake)
	if _, err = enc.WritePacket(&packet.Handshake{
		ProtocolVersion: int(protocol),
		ServerAddress:   vhost,
		Port:            vhostPort,
		NextStatus:      1, // status
	}); err != nil {
		return nil, fmt.Errorf("write handshake: %w", err)
	}

	enc.SetState(state.Status)
	if _, err = enc.WritePacket(&packet.StatusRequest{}); err != nil {
		return nil, fmt.Errorf("write status request: %w", err)
	}

	dec := codec.NewDecoder(conn, proto.ClientBound, log)
	dec.SetProtocol(protocol)
	dec.SetState(state.Status)
	pc, err := dec.Decode()
	if err != nil && !errors.Is(err, proto.ErrDecoderLeftBytes) {
		return nil, fmt.Errorf("read status response: %w", err)
	}
	if pc == nil {
		return nil, errors.New("read status response: empty packet")
	}
	res, ok := pc.Packet.(*packet.StatusResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected status response packet %T", pc.Packet)
	}

	var status ping.ServerPing
	if err = json.Unmarshal([]byte(res.Status), &status); err != nil {
		return nil, fmt.Errorf("decode status json: %w", err)
	}
	return &status, nil
}
