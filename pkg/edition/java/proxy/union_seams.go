package proxy

import (
	"net"
	"net/netip"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Union seams: optional extension points for the union plugin set (pkg/union)
// that need to hook core paths without an import cycle - the dependency
// direction is union -> proxy, never the reverse, so the hooks are plain
// function variables the union wiring assigns.
//
// All seams are nil by default; callers MUST nil-check before invoking. They
// are assigned exactly once by union.Wire while the proxy is not running
// (pkg/gate gate.New, before the process collection starts any runnable) and
// must not be reassigned while a proxy is serving: the core paths read them
// without synchronization.

// UnionDimensionRewrite, when non-nil, is consulted by the backend
// play-packet path for join/respawn packets before they are encoded to the
// player. It rewrites the decoded packet in place and reports whether it
// changed. The intended implementation is a nil-guarded call to
// dimension.Default().RewritePacket, installed by union.Wire when the
// dimension plugin is enabled.
//
// Call sites: session_backend_play.go handleDimensionRewrite (JoinGame/
// Respawn during play, re-encoded via WritePacket when changed) and
// session_client_play.go handleBackendJoinGame (first JoinGame entry; the
// fast-switch synthetic Respawn derives from the same rewritten struct).
var UnionDimensionRewrite func(playerID uuid.UUID, pkt any) bool

// UnionForwardedRemoteAddr, when non-nil, maps a username to the client
// address an upstream entry recorded for that login (proxied-proxy
// forwarding); ok is false when the login was not forwarded. The intended
// implementation is proxiedproxy.ForwardedRemoteAddr, installed by union.Wire
// when a proxied-proxy role is enabled. The record only exists while the
// login is in flight (between the profile request and PostLoginEvent), so a
// call site must look it up inside that window.
//
// Call site: authSessionHandler.Activated (session_client_auth.go) consults
// it via unionForwardedRemoteAddr immediately after the GameProfileRequestEvent
// returns and applies the address to the login-phase inbound and the
// connectedPlayer it creates, so downstream forwarding (ProxyProtocolBackend
// header, legacy/bungeeguard forwarding data), logging and permission
// decisions observe the entry-forwarded client address instead of the
// proxied-proxy tunnel address.
var UnionForwardedRemoteAddr func(username string) (string, bool)

// unionForwardedRemoteAddr consults UnionForwardedRemoteAddr for the login
// with the given (offline) profile name and returns the forwarded client
// address as a *net.TCPAddr (matching the net.Addr type the underlying
// connections report), or nil when the seam is uninstalled, the login was
// not forwarded, or the recorded address is not an ip:port - a parse failure
// is logged at V(1) and never fails the login.
func unionForwardedRemoteAddr(profileName string, log logr.Logger) net.Addr {
	if UnionForwardedRemoteAddr == nil {
		return nil
	}
	raw, ok := UnionForwardedRemoteAddr(profileName)
	if !ok {
		return nil
	}
	ap, err := netip.ParseAddrPort(raw)
	if err != nil {
		log.V(1).Info("forwarded remote address is not ip:port; keeping the connection's peer address",
			"username", profileName, "forwardedRemoteAddr", raw, "err", err)
		return nil
	}
	ip := ap.Addr().Unmap()
	return &net.TCPAddr{IP: ip.AsSlice(), Port: int(ap.Port()), Zone: ip.Zone()}
}
