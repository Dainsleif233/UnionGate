package mapmod

import (
	"context"
	"testing"

	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// TestParseChannel is the identifier parse smoke test: modern channel strings
// split at the first colon and validate; legacy strings are taken verbatim.
func TestParseChannel(t *testing.T) {
	tests := []struct {
		name    string
		channel string
		wantID  string
		wantErr bool
	}{
		{name: "xaero minimap modern", channel: XaeroMinimapChannel, wantID: "xaerominimap:main"},
		{name: "xaero worldmap modern", channel: XaeroWorldMapChannel, wantID: "xaeroworldmap:main"},
		{name: "world id modern", channel: WorldIDChannel, wantID: "worldinfo:world_id"},
		{
			// Legacy channels keep their verbatim ID; the "minecraft"
			// namespace fallback is NOT applied (that would silently change
			// the wire name for <1.13 clients).
			name: "world id legacy verbatim", channel: WorldIDLegacyChannel, wantID: "world_id",
		},
		{
			// No colon and uppercase: registered verbatim as legacy (modern
			// parsing would reject the uppercase).
			name: "legacy name kept verbatim", channel: "World_ID", wantID: "World_ID",
		},
		{
			// Leading colon parses to the "minecraft" namespace.
			name: "leading colon", channel: ":main", wantID: "minecraft:main",
		},
		{
			// Invalid modern namespace character: uppercase is rejected.
			name: "invalid namespace uppercase", channel: "BadNs:name", wantErr: true,
		},
		{
			// Invalid modern name character.
			name: "invalid name char", channel: "ns:ba d", wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := parseChannel(tt.channel)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseChannel(%q) = %v, want error", tt.channel, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseChannel(%q): %v", tt.channel, err)
			}
			if got := id.ID(); got != tt.wantID {
				t.Errorf("parseChannel(%q).ID() = %q, want %q", tt.channel, got, tt.wantID)
			}
		})
	}
}

// TestDefaultConfig pins the upstream-verified channel set (Channels.java):
// xaerominimap:main, xaeroworldmap:main, worldinfo:world_id, world_id — and
// NOT the task draft's nonexistent "world_id_mappings".
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	want := []string{
		"xaerominimap:main",
		"xaeroworldmap:main",
		"worldinfo:world_id",
		"world_id",
	}
	if len(cfg.Channels) != len(want) {
		t.Fatalf("DefaultConfig().Channels = %v, want %v", cfg.Channels, want)
	}
	for i, ch := range want {
		if cfg.Channels[i] != ch {
			t.Errorf("DefaultConfig().Channels[%d] = %q, want %q", i, cfg.Channels[i], ch)
		}
	}
	if !cfg.ForwardToBackend {
		t.Error("DefaultConfig().ForwardToBackend = false, want true (pass-through)")
	}

	// Every default channel must parse.
	for _, ch := range cfg.Channels {
		if _, err := parseChannel(ch); err != nil {
			t.Errorf("default channel %q does not parse: %v", ch, err)
		}
	}
}

// TestNewBridgeRegistersChannels verifies the bridge registers its channels
// on a real ChannelRegistrar so Gate's fire sites surface them as
// PluginMessageEvent (they only fire for registered channels).
func TestNewBridgeRegistersChannels(t *testing.T) {
	b := NewBridge(DefaultConfig())
	if len(b.channs) != len(DefaultConfig().Channels) {
		t.Fatalf("bridge channels = %v, want all %d defaults", b.channs, len(DefaultConfig().Channels))
	}
	for _, ch := range DefaultConfig().Channels {
		id, err := parseChannel(ch)
		if err != nil {
			t.Fatalf("default channel %q does not parse: %v", ch, err)
		}
		if got := b.channs[id.ID()]; got == nil {
			t.Errorf("channel %q missing from bridge registry", id.ID())
		}
	}

	// Invalid entries are skipped, valid ones kept.
	bad := NewBridge(Config{Channels: []string{"xaerominimap:main", "BadNs:name"}})
	if _, ok := bad.channs["xaerominimap:main"]; !ok {
		t.Error("valid channel dropped in mixed config")
	}
	if len(bad.channs) != 1 {
		t.Errorf("invalid channel not skipped: %v", bad.channs)
	}

	// Empty Channels falls back to the defaults.
	empty := NewBridge(Config{})
	if len(empty.channs) != len(DefaultConfig().Channels) {
		t.Errorf("empty config should fall back to defaults, got %v", empty.channs)
	}
}

// fakePlayer satisfies the proxy.Player subset the bridge touches (only
// ID()); embedding the interface keeps the rest nil.
type fakePlayer struct {
	proxy.Player
	id uuid.UUID
}

func (f fakePlayer) ID() uuid.UUID { return f.id }

// mustParseUUID panics on purpose: test UUIDs are compile-time constants.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", s, err)
	}
	return id
}

// forwardSpy records SetForward calls on behalf of a PluginMessageEvent.
type forwardSpy struct {
	calls []bool
}

func (f *forwardSpy) setForward(v bool) { f.calls = append(f.calls, v) }
func (f *forwardSpy) last() (bool, bool) {
	if len(f.calls) == 0 {
		return false, false
	}
	return f.calls[len(f.calls)-1], true
}

// TestHandleMatchedPlayerToBackend covers the client→backend branch: with
// ForwardToBackend the bridge requests forwarding; the world payload is
// tracked on world-id channels; unrelated channels are not tracked.
func TestHandleMatchedPlayerToBackend(t *testing.T) {
	cfg := DefaultConfig() // ForwardToBackend: true
	b := NewBridge(cfg)
	playerID := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a1111")

	worldCh, err := parseChannel(WorldIDChannel)
	if err != nil {
		t.Fatal(err)
	}
	spy := &forwardSpy{}
	b.handleMatched(msg{
		source:     fakePlayer{id: playerID},
		identifier: worldCh,
		data:       []byte{0x01, 0x02},
		forward:    spy.setForward,
	})
	if v, ok := spy.last(); !ok || !v {
		t.Errorf("ForwardToBackend=true must SetForward(true), got %v %v", v, ok)
	}
	if got, ok := b.World(playerID); !ok || string(got) != "\x01\x02" {
		t.Errorf("World(playerID) = %v, %v; want world payload tracked", got, ok)
	}
	// Tracked bytes must be a copy, not the caller's slice.
	if _, ok := b.World(playerID); ok {
		raw, _ := b.World(playerID)
		raw[0] = 0xFF
		if again, _ := b.World(playerID); again[0] == 0xFF {
			t.Error("World returns the internal slice; must be a copy")
		}
	}

	// Xaero channels are bridged but not tracked as worlds.
	xaeroCh, err := parseChannel(XaeroMinimapChannel)
	if err != nil {
		t.Fatal(err)
	}
	b.handleMatched(msg{
		source:     fakePlayer{id: playerID},
		identifier: xaeroCh,
		data:       []byte{0x09},
		forward:    spy.setForward,
	})
	if got, ok := b.World(playerID); !ok || string(got) != "\x01\x02" {
		t.Errorf("xaero channel overwrote world tracking: %q %v", got, ok)
	}
}

// TestHandleMatchedPlayerToBackendDisabled covers ForwardToBackend=false: the
// bridge leaves the event untouched (Gate forwards client→backend messages in
// play state by default; this bridge never consumes a message).
func TestHandleMatchedPlayerToBackendDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ForwardToBackend = false
	b := NewBridge(cfg)
	playerID := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a2222")
	worldCh, err := parseChannel(WorldIDChannel)
	if err != nil {
		t.Fatal(err)
	}
	spy := &forwardSpy{}
	b.handleMatched(msg{
		source:     fakePlayer{id: playerID},
		identifier: worldCh,
		data:       []byte{0x01},
		forward:    spy.setForward,
	})
	if _, called := spy.last(); called {
		t.Error("ForwardToBackend=false must not call SetForward")
	}
	if _, ok := b.World(playerID); !ok {
		t.Error("world tracking is independent of ForwardToBackend")
	}
}

// TestHandleMatchedBackendToPlayer covers the non-player branch (backend→player
// in play state, and the configuration-phase paths where Gate initializes
// forward to false): the bridge must SetForward(true) or the message is
// dropped by Gate's continuations.
func TestHandleMatchedBackendToPlayer(t *testing.T) {
	b := NewBridge(DefaultConfig())
	worldCh, err := parseChannel(WorldIDChannel)
	if err != nil {
		t.Fatal(err)
	}
	spy := &forwardSpy{}
	// source is a *serverConnection in the real event; any non-Player value
	// takes this branch, so a plain struct stands in for it.
	b.handleMatched(msg{
		source:     struct{}{},
		identifier: worldCh,
		data:       []byte{0x05},
		forward:    spy.setForward,
	})
	if v, ok := spy.last(); !ok || !v {
		t.Errorf("backend→player must SetForward(true), got %v %v", v, ok)
	}

	// nil source (defensive) also passes through, not tracked.
	spy2 := &forwardSpy{}
	b.handleMatched(msg{
		identifier: worldCh,
		data:       []byte{0x06},
		forward:    spy2.setForward,
	})
	if v, ok := spy2.last(); !ok || !v {
		t.Errorf("nil source must SetForward(true), got %v %v", v, ok)
	}
}

// TestNewPluginShape verifies the Gate plugin wiring (proxy.Plugin is a
// struct: Name + Init hook, not an interface).
func TestNewPluginShape(t *testing.T) {
	p := NewPlugin(nil, DefaultConfig())
	if p.Name == "" {
		t.Fatal("plugin must have a name")
	}
	if p.Init == nil {
		t.Fatal("plugin must have an Init hook")
	}
	if err := p.Init(context.Background(), nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
}
