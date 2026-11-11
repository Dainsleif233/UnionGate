// Package dimension is a Gate port of work.art1st:mappeddimensionname
// (Velocity plugin, source: /tmp/opencode/MappedDimensionName —
// work.art1st.mappeddimensionname.MappedDimensionName), which namespaces the
// Minecraft dimension level names sent to a client with the name of the
// backend server the player connects to, so that map mods (Xaero's Minimap,
// VoxelMap, ...) can tell worlds of different backend servers apart.
//
// In Velocity the plugin intercepts JoinGamePacket/RespawnPacket on their way
// to the client (UPSTREAM direction, via Protocolize) and rewrites their
// dimension level names with mapName(name, serverName). Gate currently
// exposes no public play-packet intercept, so this package provides:
//
//   - MapName: the byte-exact name-mapping function;
//   - Mapper: per-player server bookkeeping driven entirely by public events
//     (ServerPreConnectEvent, DisconnectEvent), so it is already functional;
//   - RewriteJoinGame/RewriteRespawn as pure functions plus a Rewriter
//     registry keyed by packet type name, ready for the core seam below.
//
// # Core seam (session_backend_play.go handleDimensionRewrite,
// session_client_play.go handleBackendJoinGame entry)
//
// The hooks call dimension.Default().RewritePacket(playerID, pkt) through
// the proxy.UnionDimensionRewrite seam (installed by union.Wire when the
// plugin is enabled): JoinGame/Respawn arriving during play re-encode via
// WritePacket when changed (raw-payload fast path when unchanged), and the
// first JoinGame is rewritten at handleBackendJoinGame entry, so the
// fast-switch synthetic Respawn (respawnFromJoinGame, same rewritten struct)
// inherits the mapping. No Mapper state changes at the hook sites; the
// Mapper's ServerPreConnect/Disconnect bookkeeping is independent.
package dimension

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"

	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// MapName is the byte-exact Go port of MappedDimensionName.mapName.
// The parameter order is (prefix, input), mirroring the task specification;
// Java's original signature is mapName(input, prefix) (MappedDimensionName.java:111).
//
// Java source, MappedDimensionName.java:111-122:
//
//	public static String mapName(String input, String prefix) {
//	    prefix = prefix.toLowerCase();
//	    if (input == null) {
//	        return prefix;
//	    }
//	    String[] split = input.split(":", 2);
//	    if (split.length == 1) {
//	        return input + prefix;
//	    } else {
//	        return split[0] + ":" + prefix + "_" + split[1];
//	    }
//	}
//
// Port notes:
//   - Go strings have no nil, so Java's null input is represented by "" and
//     returns the lower-cased prefix (Java would too: "" splits to [""] and
//     yields ""+prefix = prefix).
//   - Java's input.split(":", 2) is Go's strings.SplitN(input, ":", 2): split
//     at the first colon only, keep the remainder verbatim (extra colons and
//     trailing empty strings included). No colon → input+prefix; colon →
//     firstPart+":"+lowercasedPrefix+"_"+remainder.
//   - Java's toLowerCase() uses the default locale (Turkish-I divergence);
//     strings.ToLower is locale-independent Unicode lowercasing. Identical
//     for all ASCII server names.
func MapName(prefix, input string) string {
	prefix = strings.ToLower(prefix)
	if input == "" { // Java: input == null → return prefix
		return prefix
	}
	split := strings.SplitN(input, ":", 2)
	if len(split) == 1 { // Java: no colon → input + prefix
		return input + prefix
	}
	return split[0] + ":" + prefix + "_" + split[1]
}

// Mapper records, per player, the backend server the player is (about to be)
// connected to — the Velocity plugin's playerServerMap
// (MappedDimensionName.java:131, driven by onPreJoin/onDisconnect :143-152) —
// and applies the registered dimension Rewriters with that server name as
// prefix.
type Mapper struct {
	// log is only assigned before Attach (NewMapper/NewMapperWithLogger);
	// event handlers read it without synchronization, so it must stay
	// immutable from Attach on.
	log logr.Logger

	mu           sync.Mutex // Protects playerServer
	playerServer map[uuid.UUID]string

	attached atomic.Bool
}

// NewMapper returns a ready-to-use Mapper with a discard logger.
func NewMapper() *Mapper {
	return &Mapper{
		log:          logr.Discard(),
		playerServer: map[uuid.UUID]string{},
	}
}

// NewMapperWithLogger returns a ready-to-use Mapper with the given logger.
func NewMapperWithLogger(log logr.Logger) *Mapper {
	m := NewMapper()
	if log.GetSink() != nil {
		m.log = log
	}
	return m
}

// Attach subscribes the Mapper to the proxy's ServerPreConnectEvent and
// DisconnectEvent. Attaching more than once (or to more than one proxy) is a
// no-op; a Mapper is expected to serve exactly one proxy.
func (m *Mapper) Attach(p *proxy.Proxy) {
	if p == nil || !m.attached.CompareAndSwap(false, true) {
		return
	}
	setDefault(m)
	event.Subscribe(p.Event(), 0, m.onPreConnect)
	event.Subscribe(p.Event(), 0, m.onDisconnect)
}

// RecordServer records the backend server name the given player is connecting
// to. Exposed for tests and manual bookkeeping; Attach wires it automatically.
func (m *Mapper) RecordServer(playerID uuid.UUID, server string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.playerServer[playerID] = server
}

// Forget removes any recorded server for the given player.
// Exposed for tests and manual bookkeeping; Attach wires it automatically.
func (m *Mapper) Forget(playerID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.playerServer, playerID)
}

// ServerFor returns the backend server name recorded for the given player.
// The second return reports whether a record exists.
func (m *Mapper) ServerFor(playerID uuid.UUID) (server string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	server, ok = m.playerServer[playerID]
	return server, ok
}

// RewritePacket applies the registered Rewriter for pkt's Go type (see
// RegisterRewriter) with the server name recorded for playerID as prefix and
// reports whether the packet was rewritten.
//
// This is the single call the core play-packet seam needs at both hook sites
// described in the package comment; the Mapper's bookkeeping stays correct
// regardless of whether the seam exists.
func (m *Mapper) RewritePacket(playerID uuid.UUID, pkt any) bool {
	if pkt == nil {
		return false
	}
	prefix, ok := m.ServerFor(playerID)
	if !ok {
		// Java logs "Failed to map levelNames in JoinPacket: server is null."
		// (MappedDimensionName.java:59/:86) and leaves the packet untouched.
		return false
	}
	r, ok := RewriterFor(pkt)
	if !ok {
		if log := m.logger(); log.GetSink() != nil {
			log.V(1).Info("dimension rewrite requires play-packet seam (TODO)",
				"packetType", fmt.Sprintf("%T", pkt), "playerID", playerID)
		}
		return false
	}
	return r.RewriteDimension(prefix, pkt)
}

func (m *Mapper) logger() logr.Logger {
	if m.log.GetSink() == nil {
		return logr.Discard()
	}
	return m.log
}

// onPreConnect is the port of MappedDimensionName.onPreJoin (:143-148):
// playerServerMap.put(player, result.getServer()).
// Java stores the result server even as an empty Optional when the connect is
// denied, which later makes the packet listeners log "server is null"; here an
// absent entry plays the role of that empty Optional, so a denied (or
// server-less) connect forgets any previous record.
func (m *Mapper) onPreConnect(e *proxy.ServerPreConnectEvent) {
	if e == nil {
		return
	}
	pl := e.Player()
	if pl == nil {
		return
	}
	if srv := e.Server(); srv != nil {
		m.RecordServer(pl.ID(), srv.ServerInfo().Name())
	} else {
		m.Forget(pl.ID())
	}
}

// onDisconnect is the port of MappedDimensionName.onDisconnect (:150-152):
// playerServerMap.remove(player).
func (m *Mapper) onDisconnect(e *proxy.DisconnectEvent) {
	if e == nil {
		return
	}
	if pl := e.Player(); pl != nil {
		m.Forget(pl.ID())
	}
}

// Rewriter rewrites the dimension level names of a decoded play packet in
// place, using prefix (the backend server name) as namespace.
type Rewriter interface {
	// RewriteDimension applies prefix to the packet's dimension level names
	// in place and reports whether anything was rewritten.
	// pkt is a decoded play packet, e.g. *packet.JoinGame or *packet.Respawn.
	RewriteDimension(prefix string, pkt any) bool
}

// RewriterFunc adapts a function to the Rewriter interface.
type RewriterFunc func(prefix string, pkt any) bool

// RewriteDimension implements Rewriter.
func (f RewriterFunc) RewriteDimension(prefix string, pkt any) bool {
	return f(prefix, pkt)
}

// packetTypeName returns the registry key for a packet's Go type, e.g.
// "*packet.JoinGame". The same format is used by RewriterFor.
func packetTypeName(pkt any) string {
	return fmt.Sprintf("%T", pkt)
}

var rewriters = struct {
	sync.RWMutex
	byType map[string]Rewriter
}{byType: map[string]Rewriter{}}

// RegisterRewriter registers r as the dimension rewriter for packets whose Go
// type formats as packetTypeName (fmt "%T"), e.g. "*packet.JoinGame" or
// "*packet.Respawn". Registering a type twice replaces the previous rewriter.
func RegisterRewriter(packetTypeName string, r Rewriter) {
	rewriters.Lock()
	defer rewriters.Unlock()
	rewriters.byType[packetTypeName] = r
}

// RewriterFor returns the registered Rewriter for pkt's Go type and whether
// one exists. Packets without a registered rewriter are skipped by
// Mapper.RewritePacket with a "dimension rewrite requires play-packet seam
// (TODO)" log — the default no-op behavior.
func RewriterFor(pkt any) (Rewriter, bool) {
	if pkt == nil {
		return nil, false
	}
	rewriters.RLock()
	defer rewriters.RUnlock()
	r, ok := rewriters.byType[packetTypeName(pkt)]
	return r, ok
}

func init() {
	RegisterRewriter(packetTypeName((*packet.JoinGame)(nil)),
		RewriterFunc(func(prefix string, pkt any) bool {
			jg, ok := pkt.(*packet.JoinGame)
			if !ok {
				return false
			}
			return RewriteJoinGame(prefix, jg)
		}))
	RegisterRewriter(packetTypeName((*packet.Respawn)(nil)),
		RewriterFunc(func(prefix string, pkt any) bool {
			rp, ok := pkt.(*packet.Respawn)
			if !ok {
				return false
			}
			return RewriteRespawn(prefix, rp)
		}))
}

// RewriteJoinGame maps the dimension level names in a JoinGame packet in place
// with prefix and reports whether anything was rewritten.
//
// Port of MappedDimensionName.JoinGamePacketListener.packetSend
// (MappedDimensionName.java:41-61), which maps dimensionInfo.levelName and
// every entry of the levelNames set.
//
// Divergences from the Java original, both defensive:
//   - a nil DimensionInfo (Gate's packet.JoinGame.DimensionInfo is nil-able for
//     pre-1.16 protocols) is skipped instead of raising the NPE the Java
//     reflection helpers would raise on a null field owner;
//   - a nil/empty LevelNames set is skipped instead of logging Java's
//     "Failed to map levelNames in JoinPacket: levelNames is null." warning.
//
// Neither packet.JoinGame nor packet.Respawn is version-branched at the struct
// level (version handling lives in their Encode/Decode), so no version logic
// is needed here.
func RewriteJoinGame(prefix string, jg *packet.JoinGame) bool {
	if jg == nil {
		return false
	}
	changed := false
	if di := jg.DimensionInfo; di != nil {
		// Java maps dimensionInfo.levelName even when it is null;
		// mapName(null, prefix) returns the lower-cased prefix, which is
		// MapName(prefix, "") here.
		in := ""
		if di.LevelName != nil {
			in = *di.LevelName
		}
		mapped := MapName(prefix, in)
		if di.LevelName == nil || *di.LevelName != mapped {
			di.LevelName = &mapped
			changed = true
		}
	}
	for i, name := range jg.LevelNames {
		mapped := MapName(prefix, name)
		if mapped != name {
			jg.LevelNames[i] = mapped
			changed = true
		}
	}
	return changed
}

// RewriteRespawn maps the dimension level name in a Respawn packet in place
// with prefix and reports whether anything was rewritten.
//
// Port of MappedDimensionName.RespawnPacketListener.packetSend
// (MappedDimensionName.java:72-88), which maps dimensionInfo.levelName when
// the dimensionInfo field is present. A nil DimensionInfo is skipped (Java
// logs "Failed to map levelNames in RespawnPacket: dimensionInfo is null.").
func RewriteRespawn(prefix string, rp *packet.Respawn) bool {
	if rp == nil {
		return false
	}
	di := rp.DimensionInfo
	if di == nil {
		return false
	}
	in := ""
	if di.LevelName != nil {
		in = *di.LevelName
	}
	mapped := MapName(prefix, in)
	if di.LevelName == nil || *di.LevelName != mapped {
		di.LevelName = &mapped
		return true
	}
	return false
}

var (
	defaultMu     sync.RWMutex
	defaultMapper *Mapper
)

// Default returns the Mapper most recently attached to a proxy via Attach,
// NewPlugin or NewPluginWithLogger. It exists so the future core play-packet
// seam can reach the wired mapper with a single call
// (dimension.Default().RewritePacket(playerID, pkt)) without importing
// plugin bootstrap code. Returns nil until a Mapper is attached.
func Default() *Mapper {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultMapper
}

func setDefault(m *Mapper) {
	defaultMu.Lock()
	defaultMapper = m
	defaultMu.Unlock()
}

// NewPlugin returns the Mapper wired as a Gate plugin for proxy.Plugins.
// Gate's proxy.Plugin is a struct (Name + Init hook), not an interface: the
// Init hook runs before the proxy serves connections and receives the proxy
// again, which is where the events are subscribed to.
//
// For convenience, if p is non-nil the mapper is attached immediately (before
// the Init hook runs); the Init hook then attaches to the proxy it receives
// only if the mapper is not attached yet (Attach is idempotent).
func NewPlugin(p *proxy.Proxy) proxy.Plugin {
	m := NewMapper()
	if p != nil {
		m.Attach(p)
	}
	return proxy.Plugin{
		Name: "union.dimension",
		Init: func(ctx context.Context, pr *proxy.Proxy) error {
			if pr != nil {
				m.Attach(pr)
			} else if p != nil {
				m.Attach(p)
			}
			return nil
		},
	}
}

// NewPluginWithLogger is NewPlugin with an explicit logger for the mapper
// (used by RewritePacket's no-op fallback logging).
func NewPluginWithLogger(p *proxy.Proxy, log logr.Logger) proxy.Plugin {
	m := NewMapperWithLogger(log)
	if p != nil {
		m.Attach(p)
	}
	return proxy.Plugin{
		Name: "union.dimension",
		Init: func(ctx context.Context, pr *proxy.Proxy) error {
			if pr != nil {
				m.Attach(pr)
			} else if p != nil {
				m.Attach(p)
			}
			return nil
		},
	}
}
