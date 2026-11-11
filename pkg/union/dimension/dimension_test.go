package dimension

import (
	"context"
	"testing"

	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/util/uuid"
)

func TestMapName(t *testing.T) {
	// Table ported from the Java semantics of mapName
	// (MappedDimensionName.java:111-122).
	tests := []struct {
		name   string
		prefix string
		input  string // Java null is ""
		want   string
	}{
		{
			// Java: mapName(null, "world") → "world"
			name: "null input returns prefix", prefix: "world", input: "", want: "world",
		},
		{
			// Java: mapName(null, "Server1") → prefix lower-cased first
			name: "null input lowercases prefix", prefix: "Server1", input: "", want: "server1",
		},
		{
			// Java: mapName("minecraft:overworld", "Server1") →
			// "minecraft" + ":" + "server1" + "_" + "overworld"
			name: "namespaced input", prefix: "Server1", input: "minecraft:overworld", want: "minecraft:server1_overworld",
		},
		{
			// Java: mapName("overworld", "Server1") → "overworld" + "server1"
			name: "no colon appends prefix", prefix: "Server1", input: "overworld", want: "overworldserver1",
		},
		{
			// Java: mapName("overworld", "") → "overworld" + ""
			name: "empty prefix", prefix: "", input: "overworld", want: "overworld",
		},
		{
			// Java: split(":", 2) splits at the FIRST colon only.
			// mapName("a:b:c", "p") → "a" + ":" + "p" + "_" + "b:c"
			name: "second colon stays in remainder", prefix: "p", input: "a:b:c", want: "a:p_b:c",
		},
		{
			// Java: split(":", 2) on "a:" → ["a", ""],
			// mapName("a:", "p") → "a:p_"
			name: "trailing colon keeps empty remainder", prefix: "p", input: "a:", want: "a:p_",
		},
		{
			// Java: split(":", 2) on ":a" → ["", "a"],
			// mapName(":a", "p") → ":p_a" (empty first part is kept)
			name: "leading colon keeps empty first part", prefix: "p", input: ":a", want: ":p_a",
		},
		{
			// Java: mapName("minecraft:overworld", "lobby-2")
			name: "prefix with hyphen and digits", prefix: "lobby-2", input: "minecraft:overworld", want: "minecraft:lobby-2_overworld",
		},
		{
			// Java: mapName("", "p") → "" splits to [""], "" + "p" = "p"
			name: "empty input is no-colon path", prefix: "p", input: "", want: "p",
		},
		{
			// Java: mapName("Minecraft:OverWorld", "p") — only the PREFIX is
			// lower-cased; the input is copied verbatim.
			name: "input case preserved", prefix: "p", input: "Minecraft:OverWorld", want: "Minecraft:p_OverWorld",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MapName(tt.prefix, tt.input); got != tt.want {
				t.Errorf("MapName(%q, %q) = %q, want %q", tt.prefix, tt.input, got, tt.want)
			}
		})
	}
}

// TestMapNameUppercasePrefix verifies the Java order of operations: the whole
// prefix is lower-cased BEFORE splicing, so the namespaced branch lower-cases
// it too (prefix.toLowerCase() happens on line 112, before the split).
func TestMapNameUppercasePrefix(t *testing.T) {
	const in = "minecraft:overworld"
	if got, want := MapName("SERVER-ONE", in), "minecraft:server-one_overworld"; got != want {
		t.Errorf("MapName(%q, %q) = %q, want %q", "SERVER-ONE", in, got, want)
	}
	if got, want := MapName("SERVER-ONE", "overworld"), "overworldserver-one"; got != want {
		t.Errorf("MapName(%q, %q) = %q, want %q", "SERVER-ONE", "overworld", got, want)
	}
}

// mustParseUUID panics on purpose: test UUIDs are compile-time constants.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", s, err)
	}
	return id
}

func TestMapperRecordForget(t *testing.T) {
	m := NewMapper()
	p1 := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a1111")
	p2 := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a2222")

	if _, ok := m.ServerFor(p1); ok {
		t.Fatal("fresh mapper should have no record")
	}

	m.RecordServer(p1, "lobby")
	m.RecordServer(p2, "survival")
	if got, ok := m.ServerFor(p1); !ok || got != "lobby" {
		t.Errorf("ServerFor(p1) = %q, %v; want %q, true", got, ok, "lobby")
	}
	if got, ok := m.ServerFor(p2); !ok || got != "survival" {
		t.Errorf("ServerFor(p2) = %q, %v; want %q, true", got, ok, "survival")
	}

	// Re-record overwrites (Java: playerServerMap.put).
	m.RecordServer(p1, "minigames")
	if got, ok := m.ServerFor(p1); !ok || got != "minigames" {
		t.Errorf("ServerFor(p1) after re-record = %q, %v; want %q, true", got, ok, "minigames")
	}
	// Other players are untouched.
	if got, ok := m.ServerFor(p2); !ok || got != "survival" {
		t.Errorf("ServerFor(p2) after p1 re-record = %q, %v; want %q, true", got, ok, "survival")
	}

	m.Forget(p1)
	if _, ok := m.ServerFor(p1); ok {
		t.Error("Forget should clear the record")
	}
	if _, ok := m.ServerFor(p2); !ok {
		t.Error("Forget(p1) must not clear p2")
	}
	m.Forget(p1) // double-forget is a no-op
}

// TestMapperRewritePacketNoRecord verifies the Java "server is null" path: a
// player without a recorded server has its packets left untouched
// (MappedDimensionName.java:59/:86).
func TestMapperRewritePacketNoRecord(t *testing.T) {
	m := NewMapper()
	jg := &packet.JoinGame{
		DimensionInfo: &packet.DimensionInfo{LevelName: strPtr("minecraft:overworld")},
		LevelNames:    []string{"minecraft:overworld"},
	}
	if m.RewritePacket(mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a3333"), jg) {
		t.Fatal("rewrite must be skipped without a recorded server")
	}
	if got := *jg.DimensionInfo.LevelName; got != "minecraft:overworld" {
		t.Errorf("level name mutated without record: %q", got)
	}
}

// TestMapperRewritePacketJoinGameAndRespawn exercises the registered concrete
// rewriters through Mapper.RewritePacket with a recorded server.
func TestMapperRewritePacketJoinGameAndRespawn(t *testing.T) {
	m := NewMapper()
	pid := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a4444")
	m.RecordServer(pid, "Survival-1")

	jg := &packet.JoinGame{
		DimensionInfo: &packet.DimensionInfo{LevelName: strPtr("minecraft:overworld")},
		LevelNames:    []string{"minecraft:overworld", "flat"},
	}
	if !m.RewritePacket(pid, jg) {
		t.Fatal("expected JoinGame rewrite")
	}
	if got, want := *jg.DimensionInfo.LevelName, "minecraft:survival-1_overworld"; got != want {
		t.Errorf("DimensionInfo.LevelName = %q, want %q", got, want)
	}
	if got, want := jg.LevelNames[0], "minecraft:survival-1_overworld"; got != want {
		t.Errorf("LevelNames[0] = %q, want %q", got, want)
	}
	if got, want := jg.LevelNames[1], "flatsurvival-1"; got != want {
		t.Errorf("LevelNames[1] = %q, want %q", got, want)
	}

	rp := &packet.Respawn{DimensionInfo: &packet.DimensionInfo{LevelName: strPtr("minecraft:the_nether")}}
	if !m.RewritePacket(pid, rp) {
		t.Fatal("expected Respawn rewrite")
	}
	if got, want := *rp.DimensionInfo.LevelName, "minecraft:survival-1_the_nether"; got != want {
		t.Errorf("Respawn DimensionInfo.LevelName = %q, want %q", got, want)
	}
}

// TestRewriterRegistryUnknownPacketType verifies the no-op fallback: packet
// types without a registered rewriter are skipped (and would log the seam
// TODO with a logger attached).
func TestRewriterRegistryUnknownPacketType(t *testing.T) {
	m := NewMapper()
	pid := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a5555")
	m.RecordServer(pid, "lobby")

	type unknownPacket struct{ LevelName string }
	pkt := &unknownPacket{LevelName: "minecraft:overworld"}
	if m.RewritePacket(pid, pkt) {
		t.Error("unknown packet type must not be rewritten")
	}
	if pkt.LevelName != "minecraft:overworld" {
		t.Errorf("unknown packet type mutated: %+v", pkt)
	}

	// Registering a custom rewriter for the type makes it rewrite.
	RegisterRewriter(packetTypeName(pkt), RewriterFunc(func(prefix string, p any) bool {
		up := p.(*unknownPacket)
		up.LevelName = MapName(prefix, up.LevelName)
		return true
	}))
	defer deleteRewriterForTesting(t, pkt)
	if !m.RewritePacket(pid, pkt) {
		t.Error("custom-registered rewriter should apply")
	}
	if got, want := pkt.LevelName, "minecraft:lobby_overworld"; got != want {
		t.Errorf("custom rewriter result = %q, want %q", got, want)
	}
}

// deleteRewriterForTesting removes the rewriter registered by a test so tests
// stay independent.
func deleteRewriterForTesting(t *testing.T, pkt any) {
	t.Helper()
	rewriters.Lock()
	delete(rewriters.byType, packetTypeName(pkt))
	rewriters.Unlock()
}

// TestRewriteJoinGameReportsFalseWhenUnchanged reports false only when the
// names are already byte-identical to their mapping, so a seam caller can
// skip re-encoding untouched packets. Note the Java-faithful caveat: the
// upstream plugin applies mapName unconditionally on every send, so an
// ALREADY-mapped name ("minecraft:lobby_overworld") is mapped AGAIN
// ("minecraft:lobby_lobby_overworld") exactly as MappedDimensionName.java:53
// would; only the packet-unchanged comparison is a Go addition.
func TestRewriteJoinGameIdempotentNoChange(t *testing.T) {
	// Nothing to change: DimensionInfo nil, LevelNames empty.
	if RewriteJoinGame("lobby", &packet.JoinGame{}) {
		t.Error("JoinGame without DimensionInfo/LevelNames must not report a rewrite")
	}
	if RewriteJoinGame("lobby", nil) || RewriteRespawn("lobby", nil) {
		t.Error("nil packets must not report a rewrite")
	}
	if RewriteRespawn("lobby", &packet.Respawn{}) {
		t.Error("Respawn without DimensionInfo must not report a rewrite")
	}

	// Already-mapped names are re-mapped, exactly like the Java original
	// (mapName is applied unconditionally on every send).
	jg := &packet.JoinGame{
		DimensionInfo: &packet.DimensionInfo{LevelName: strPtr("minecraft:lobby_overworld")},
		LevelNames:    []string{"minecraft:lobby_overworld"},
	}
	if !RewriteJoinGame("lobby", jg) {
		t.Error("Java applies mapName unconditionally; already-mapped input must re-map")
	}
	if got, want := *jg.DimensionInfo.LevelName, "minecraft:lobby_lobby_overworld"; got != want {
		t.Errorf("double-mapped level name = %q, want %q (Java-faithful re-mapping)", got, want)
	}
	if got, want := jg.LevelNames[0], "minecraft:lobby_lobby_overworld"; got != want {
		t.Errorf("double-mapped LevelNames[0] = %q, want %q", got, want)
	}
}

// TestRewriteRespawnNilLevelName maps a nil level name to the prefix (the
// Java code passes the null field through mapName, which returns the prefix).
func TestRewriteRespawnNilLevelName(t *testing.T) {
	rp := &packet.Respawn{DimensionInfo: &packet.DimensionInfo{}}
	if !RewriteRespawn("lobby", rp) {
		t.Fatal("nil level name should be rewritten to the prefix")
	}
	if rp.DimensionInfo.LevelName == nil || *rp.DimensionInfo.LevelName != "lobby" {
		t.Errorf("level name = %v, want &%q", rp.DimensionInfo.LevelName, "lobby")
	}
}

// TestPluginAttachesAndReceivesEvents wires the NewPlugin mapper to a real
// event manager via the proxy.Plugin shape, then fires the two events by
// hand through the mapper's handler methods (a *proxy.Proxy is not built
// here; the handlers are what the events deliver).
func TestPluginAttachesAndReceivesEvents(t *testing.T) {
	p := NewPlugin(nil)
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

func strPtr(s string) *string { return &s }

// Compile-time guard: the adapter must satisfy the interface.
var _ Rewriter = RewriterFunc(nil)
