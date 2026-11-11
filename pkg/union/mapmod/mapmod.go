// Package mapmod is a minimal Gate bridge for turikhay/MapModCompanion
// (Velocity plugin), the companion that lets world-map mods (Xaero's Minimap /
// World Map, VoxelMap) work behind a proxy by mediating the mods' "world id"
// plugin channels.
//
// # What upstream does (verified 2026-11-11 against turikhay/MapModCompanion @ main)
//
// Channel IDs come from common/src/main/java/com/turikhay/mc/mapmodcompanion/Channels.java:
//
//	XAERO_MINIMAP_CHANNEL  = "xaerominimap:main"
//	XAERO_WORLDMAP_CHANNEL = "xaeroworldmap:main"
//	WORLDID_CHANNEL        = "worldinfo:world_id"   (modern 1.13+ form)
//	WORLDID_LEGACY_CHANNEL = "world_id"             (legacy <1.13 form)
//
// (The task draft's "world_id_mappings" channel does NOT exist upstream.)
// On a matching message whose source is a ServerConnection and whose target is
// a Player, the Velocity handler (velocity/.../MessageHandler.java)
// deserializes the payload, blends the id with
// server.getServerInfo().getName().hashCode(), and RESENDS a rewritten payload
// to the player — it does not forward verbatim.
//
// # What this package does
//
// A stateless, forward-only bridge: it registers the channels on Gate's
// ChannelRegistrar (that is what makes Gate surface them as PluginMessageEvent
// at all — unregistered channels never fire the event) and lets matched
// messages pass through to the other side unmodified. No payload
// deserialization, no world-id synthesis, no blending — see TODO below.
//
// # TODO full mediation
//
// Porting upstream's rewrite behavior needs: the payload deserializers
// (PrefixedId for world_id, LevelMapProperties for the Xaero channels, with
// MalformedPacketException → leave the message alone), the IdBlender port
// (blend(id, serverName.hashCode()) — Java String.hashCode semantics), a
// per-player converter (map id → configured id) and re-serialization per
// channel. Until then the bridge is pass-through only, so per-server world id
// isolation (the reason MapModCompanion exists) is NOT provided.
package mapmod

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"

	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/edition/java/proxy/message"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Channels verified against turikhay/MapModCompanion Channels.java (main
// branch, fetched 2026-11-11). DefaultConfig uses exactly these; any operator
// override replaces the whole set.
const (
	// XaeroMinimapChannel is XAERO_MINIMAP_CHANNEL upstream.
	XaeroMinimapChannel = "xaerominimap:main"
	// XaeroWorldMapChannel is XAERO_WORLDMAP_CHANNEL upstream.
	XaeroWorldMapChannel = "xaeroworldmap:main"
	// WorldIDChannel is WORLDID_CHANNEL upstream (modern 1.13+ form).
	WorldIDChannel = "worldinfo:world_id"
	// WorldIDLegacyChannel is WORLDID_LEGACY_CHANNEL upstream (legacy <1.13).
	WorldIDLegacyChannel = "world_id"
)

// worldIDSuffix identifies the world-id channels for per-player tracking
// (WorldIDChannel and WorldIDLegacyChannel both end in "world_id").
const worldIDSuffix = "world_id"

// Config configures the mapmod bridge.
type Config struct {
	// Channels are the plugin-message channel IDs to register and bridge.
	// An entry containing ":" is parsed as a modern 1.13+ channel
	// (message.ChannelIdentifierFrom); any other entry is registered as a
	// legacy channel verbatim (message.NewLegacyChannelIdentifier). Invalid
	// entries are skipped with a log line.
	// Defaults to the four channels above, verified against upstream.
	// NOTE: unverified channel sets are possible via overrides; the defaults
	// themselves were confirmed against upstream (see package comment).
	Channels []string

	// ForwardToBackend also requests forwarding for client→backend messages
	// on the bridged channels. Gate already forwards those by default in
	// play state, so this mainly documents intent; leaving it false never
	// blocks a message (this bridge never consumes one).
	ForwardToBackend bool
}

// DefaultConfig returns the upstream-verified channel set and pass-through
// forwarding.
func DefaultConfig() Config {
	return Config{
		Channels: []string{
			XaeroMinimapChannel,
			XaeroWorldMapChannel,
			WorldIDChannel,
			WorldIDLegacyChannel,
		},
		ForwardToBackend: true,
	}
}

// Bridge is the mapmod channel bridge. Attach it to one proxy.
type Bridge struct {
	log logr.Logger
	cfg Config

	mu      sync.Mutex // Protects worlds
	worlds  map[uuid.UUID][]byte
	channs  map[string]message.ChannelIdentifier // by channel ID
	attachd atomic.Bool
}

// NewBridge returns a bridge for cfg with a discard logger. Invalid channel
// entries in cfg are skipped (with a log line when a logger is provided via
// NewBridgeWithLogger).
func NewBridge(cfg Config) *Bridge {
	return NewBridgeWithLogger(cfg, logr.Discard())
}

// NewBridgeWithLogger is NewBridge with an explicit logger.
func NewBridgeWithLogger(cfg Config, log logr.Logger) *Bridge {
	if log.GetSink() == nil {
		log = logr.Discard()
	}
	if len(cfg.Channels) == 0 {
		cfg.Channels = DefaultConfig().Channels
	}
	b := &Bridge{
		log:    log,
		cfg:    cfg,
		worlds: map[uuid.UUID][]byte{},
		channs: map[string]message.ChannelIdentifier{},
	}
	for _, ch := range cfg.Channels {
		id, err := parseChannel(ch)
		if err != nil {
			log.Error(err, "skipping invalid mapmod channel", "channel", ch)
			continue
		}
		b.channs[id.ID()] = id
	}
	return b
}

// parseChannel parses a channel ID string into a Gate ChannelIdentifier:
// entries containing ":" are modern 1.13+ channels (first-colon split with the
// "minecraft" fallback, validated); other entries are legacy channels whose ID
// is taken verbatim (legacy names predate the namespace validation rules).
func parseChannel(channel string) (message.ChannelIdentifier, error) {
	if strings.Contains(channel, ":") {
		return message.ChannelIdentifierFrom(channel)
	}
	return message.NewLegacyChannelIdentifier(channel), nil
}

// Attach registers the bridged channels on the proxy's ChannelRegistrar and
// subscribes the message handler. Attaching more than once (or to more than
// one proxy) is a no-op; a Bridge is expected to serve exactly one proxy.
func (b *Bridge) Attach(p *proxy.Proxy) {
	if p == nil || !b.attachd.CompareAndSwap(false, true) {
		return
	}
	ids := make([]message.ChannelIdentifier, 0, len(b.channs))
	for _, id := range b.channs {
		ids = append(ids, id)
	}
	p.ChannelRegistrar().Register(ids...)
	// Priority 0: default order among plugins.
	event.Subscribe(p.Event(), 0, b.onPluginMessage)
}

// World returns the last raw payload the given player sent on a world-id
// channel ("worldinfo:world_id" / "world_id"), if any. The returned slice is
// a copy; no deserialization is attempted (see the package TODO) — this is
// the seam where world tracking attaches once payload codecs are ported.
func (b *Bridge) World(playerID uuid.UUID) (data []byte, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok = b.worlds[playerID]
	if ok {
		clone := make([]byte, len(data))
		copy(clone, data)
		data = clone
	}
	return data, ok
}

func (b *Bridge) trackWorld(playerID uuid.UUID, identifier message.ChannelIdentifier, data []byte) {
	if playerID == uuid.Nil || !strings.HasSuffix(identifier.ID(), worldIDSuffix) {
		return
	}
	clone := make([]byte, len(data))
	copy(clone, data)
	b.mu.Lock()
	b.worlds[playerID] = clone
	b.mu.Unlock()
}

// onPluginMessage is the pass-through handler. Gate only fires
// PluginMessageEvent for channels registered on its ChannelRegistrar, but
// other plugins may register other channels, so the identifier is matched
// against the bridge's own set first.
func (b *Bridge) onPluginMessage(e *proxy.PluginMessageEvent) {
	if e == nil || e.Identifier() == nil {
		return
	}
	id, ok := b.channs[e.Identifier().ID()]
	if !ok {
		return // not one of ours; leave the event untouched
	}
	b.handleMatched(msg{
		source:     e.Source(),
		identifier: id,
		data:       e.Data(),
		forward:    e.SetForward,
	})
}

// msg is the minimal view of a PluginMessageEvent the bridge acts on. It
// exists so the decision logic is testable without constructing the event
// (proxy.PluginMessageEvent has unexported fields and is only built inside
// the proxy package).
type msg struct {
	source     any // message.ChannelMessageSource: proxy.Player or *serverConnection
	identifier message.ChannelIdentifier
	data       []byte
	forward    func(bool) // sets the event's forward flag (e.SetForward)
}

// handleMatched applies the pass-through decision to one matched message.
// Direction handling is driven by Gate's PluginMessageEvent fire sites:
//
//   - source is a proxy.Player (client→backend, play state —
//     proxy/session_client_initial_connect.go:56): forwarded by Gate by
//     default (forward=true); the bridge requests forwarding only when
//     Config.ForwardToBackend is set.
//   - source is anything else (backend→player in play state —
//     proxy/session_backend_play.go:227, and both configuration-phase paths —
//     proxy/session_backend_config.go:229 and
//     proxy/session_client_config.go:204, where Gate initializes forward to
//     false and the message is dropped unless a subscriber sets it): the
//     bridge sets forward so the message flows through. In the
//     configuration-phase paths the continuation decides the actual
//     destination, so "set forward" is pass-through for both directions; the
//     config-phase client→backend path mislabels source=serverConn, which the
//     type assertion alone cannot tell apart from backend→player — harmless
//     for a forward-only bridge, noted here for the future full mediation.
func (b *Bridge) handleMatched(m msg) {
	// proxy.Player is not implemented by *serverConnection, so this type
	// assertion cleanly separates the directions.
	if pl, isPlayer := m.source.(proxy.Player); isPlayer {
		if b.cfg.ForwardToBackend {
			m.forward(true)
		}
		b.trackWorld(pl.ID(), m.identifier, m.data)
		return
	}
	m.forward(true)
}

// NewPlugin returns the bridge wired as a Gate plugin (proxy.Plugin is a
// struct with a Name and an Init hook, not an interface). If p is non-nil the
// bridge is attached immediately; the Init hook attaches to the proxy it
// receives otherwise (Attach is idempotent).
func NewPlugin(p *proxy.Proxy, cfg Config) proxy.Plugin {
	return NewPluginWithLogger(p, cfg, logr.Discard())
}

// NewPluginWithLogger is NewPlugin with an explicit logger.
func NewPluginWithLogger(p *proxy.Proxy, cfg Config, log logr.Logger) proxy.Plugin {
	b := NewBridgeWithLogger(cfg, log)
	if p != nil {
		b.Attach(p)
	}
	return proxy.Plugin{
		Name: "union.mapmod",
		Init: func(ctx context.Context, pr *proxy.Proxy) error {
			if pr != nil {
				b.Attach(pr)
			} else if p != nil {
				b.Attach(p)
			}
			return nil
		},
	}
}
