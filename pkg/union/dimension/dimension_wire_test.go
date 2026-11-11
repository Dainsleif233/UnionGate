package dimension

// Dimension wire test: hermetic functional proof that the union dimension
// rewrite fires on LIVE JoinGame/Respawn packet values through the
// UnionDimensionRewrite seam shape — no network, no bound proxy, no event
// machinery. The seam type is declared at
// pkg/edition/java/proxy/union_seams.go:33 as
//
//	var UnionDimensionRewrite func(playerID uuid.UUID, pkt any) bool
//
// and the implementation Wire installs, guarded by cfg.Union.Dimension.Enabled
// (pkg/union/union.go:122-140, closure at :131-137), is exactly
// wireDimensionRewrite below: a nil-guarded dimension.Default().RewritePacket.
//
// What this file stands in for — the two core call sites it documents without
// touching:
//
//   - pkg/edition/java/proxy/session_backend_play.go:545-553
//     backendPlaySessionHandler.handleDimensionRewrite (dispatched for
//     JoinGame/Respawn at :107/:109) consults the seam at :546-547 for every
//     backend join/respawn packet during play. On change the mutated struct is
//     re-encoded to the player via WritePacket (:548); unchanged packets keep
//     the zero-copy raw-payload fast path, forwardToPlayer (:552). The
//     rewrite's bool return is what selects between those two paths.
//   - pkg/edition/java/proxy/session_client_play.go:505-515
//     clientPlaySessionHandler.handleBackendJoinGame consults the seam at
//     :513-514 on the FIRST JoinGame at entry, so the BufferPacket/doFast/
//     doSafe paths further down re-encode the rewritten struct — and the
//     fast-switch synthetic Respawn derived from that same struct inherits the
//     mapping (dimension.go's package comment, "Core seam").
//
// The Mapper's server bookkeeping these tests drive via RecordServer is the
// same state Attach fills through ServerPreConnectEvent/DisconnectEvent
// (dimension.go:201-224); driving it directly keeps the test hermetic while
// exercising the identical RewritePacket path the live seam runs.

import (
	"reflect"
	"testing"

	"github.com/go-logr/logr"

	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// wireDimensionRewrite mirrors, verbatim, the closure pkg/union/union.go:131-137
// assigns to proxy.UnionDimensionRewrite when cfg.Union.Dimension.Enabled:
//
//	jproxy.UnionDimensionRewrite = func(playerID uuid.UUID, pkt any) bool {
//		m := dimension.Default()
//		if m == nil {
//			return false
//		}
//		return m.RewritePacket(playerID, pkt)
//	}
//
// Kept as a package-level function so both the parity and the negative tests
// drive the exact shape the live seam resolves through.
func wireDimensionRewrite(playerID uuid.UUID, pkt any) bool {
	m := Default()
	if m == nil {
		return false
	}
	return m.RewritePacket(playerID, pkt)
}

// Compile-time shape parity: the closure above must satisfy the exact type of
// the seam variable declared at pkg/edition/java/proxy/union_seams.go:33 — a
// signature drift upstream fails this build. The var is nil until union.Wire
// runs, so reading it here is side-effect free; proxy is already a direct
// import of this package (dimension.go:43), so this adds no new dependency
// edge.
var _ func(playerID uuid.UUID, pkt any) bool = proxy.UnionDimensionRewrite

// installDefault swaps m in as the process-global Default mapper that the
// Wire closure resolves through dimension.Default(), restoring the previous
// value on cleanup. This is the same state dimension.NewPluginWithLogger
// reaches during Wire (pkg/union/union.go:128 → Attach → setDefault,
// dimension.go:126-133).
func installDefault(t *testing.T, m *Mapper) {
	t.Helper()
	prev := Default()
	setDefault(m)
	t.Cleanup(func() { setDefault(prev) })
}

// newLiveJoinGame returns a JoinGame shaped like a live 1.16+ backend packet:
// a namespaced dimension registry identifier plus the level-name set and
// dimensionInfo.levelName whose names MapName must namespace with the backend
// server name. Not version-branched at the struct level (joingame.go's Encode/
// Decode own that), which is why these values are the live rewrite surface.
func newLiveJoinGame() *packet.JoinGame {
	return &packet.JoinGame{
		EntityID: 1,
		DimensionInfo: &packet.DimensionInfo{
			RegistryIdentifier: "minecraft:overworld",
			LevelName:          strPtr("minecraft:overworld"),
		},
		LevelNames: []string{"minecraft:overworld", "minecraft:the_nether"},
	}
}

// newLiveRespawn returns a Respawn shaped like a live 1.16+ dimension-switch
// packet: the same DimensionInfo shape whose level name the seam rewrites.
func newLiveRespawn() *packet.Respawn {
	return &packet.Respawn{
		DimensionInfo: &packet.DimensionInfo{
			RegistryIdentifier: "minecraft:the_nether",
			LevelName:          strPtr("minecraft:the_nether"),
		},
	}
}

// TestRewritePacketLiveJoinGameRespawn drives Mapper.RewritePacket — the one
// call both seam call sites make — with a real Mapper (NewMapper, the same
// constructor NewPluginWithLogger builds) and real decoded packet values.
func TestRewritePacketLiveJoinGameRespawn(t *testing.T) {
	m := NewMapper()
	playerID := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a6001")
	m.RecordServer(playerID, "lobby")

	// JoinGame: both the dimensionInfo.levelName and every levelNames entry
	// gain the lower-cased server-name namespace; the registry identifier is
	// NOT part of the rewrite surface (the Java port maps levelName +
	// levelNames only, MappedDimensionName.java:41-61).
	jg := newLiveJoinGame()
	if !m.RewritePacket(playerID, jg) {
		t.Fatal("RewritePacket(JoinGame) = false, want true (level names changed)")
	}
	if got, want := *jg.DimensionInfo.LevelName, "minecraft:lobby_overworld"; got != want {
		t.Errorf("DimensionInfo.LevelName = %q, want %q", got, want)
	}
	if got := jg.DimensionInfo.RegistryIdentifier; got != "minecraft:overworld" {
		t.Errorf("DimensionInfo.RegistryIdentifier = %q, want untouched %q", got, "minecraft:overworld")
	}
	if got, want := jg.LevelNames[0], "minecraft:lobby_overworld"; got != want {
		t.Errorf("LevelNames[0] = %q, want %q", got, want)
	}
	if got, want := jg.LevelNames[1], "minecraft:lobby_the_nether"; got != want {
		t.Errorf("LevelNames[1] = %q, want %q", got, want)
	}
	if len(jg.LevelNames) != 2 {
		t.Errorf("len(LevelNames) = %d, want 2 (set must not be rescaled)", len(jg.LevelNames))
	}

	// Respawn: the dimension-switch packet carries the same DimensionInfo
	// shape; its level name gets the same namespace.
	rp := newLiveRespawn()
	if !m.RewritePacket(playerID, rp) {
		t.Fatal("RewritePacket(Respawn) = false, want true (level name changed)")
	}
	if got, want := *rp.DimensionInfo.LevelName, "minecraft:lobby_the_nether"; got != want {
		t.Errorf("Respawn DimensionInfo.LevelName = %q, want %q", got, want)
	}
	if got := rp.DimensionInfo.RegistryIdentifier; got != "minecraft:the_nether" {
		t.Errorf("Respawn DimensionInfo.RegistryIdentifier = %q, want untouched %q", got, "minecraft:the_nether")
	}

	// Already-prefixed names: the implementation applies MapName
	// unconditionally — exactly like the Java original
	// (MappedDimensionName.java:53 has no prefix check; see
	// TestRewriteJoinGameIdempotentNoChange) — so a second pass through the
	// live seam re-maps the already-namespaced names and reports a change.
	// The bool therefore means "packet differs from its mapping, re-encode",
	// not idempotence; handleDimensionRewrite takes the WritePacket path.
	if !m.RewritePacket(playerID, jg) {
		t.Fatal("second pass = false, want true (Java applies mapName unconditionally)")
	}
	if got, want := *jg.DimensionInfo.LevelName, "minecraft:lobby_lobby_overworld"; got != want {
		t.Errorf("double-mapped DimensionInfo.LevelName = %q, want %q", got, want)
	}
	if got, want := jg.LevelNames[0], "minecraft:lobby_lobby_overworld"; got != want {
		t.Errorf("double-mapped LevelNames[0] = %q, want %q", got, want)
	}
	if got, want := jg.LevelNames[1], "minecraft:lobby_lobby_the_nether"; got != want {
		t.Errorf("double-mapped LevelNames[1] = %q, want %q", got, want)
	}

	// Unknown player (no recorded server): Java logs "server is null" and
	// leaves the packet untouched (MappedDimensionName.java:59/:86);
	// RewritePacket mirrors that with a false and zero mutation.
	fresh := newLiveJoinGame()
	if m.RewritePacket(mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a6002"), fresh) {
		t.Fatal("RewritePacket for a player without a recorded server = true, want false")
	}
	if got := *fresh.DimensionInfo.LevelName; got != "minecraft:overworld" {
		t.Errorf("level name mutated without a recorded server: %q", got)
	}
}

// TestWireSeamClosureParity runs identical live packets through the exact
// Wire closure shape (nil-guarded dimension.Default().RewritePacket) and a
// direct Mapper.RewritePacket call, asserting identical mutations. The Default
// mapper is swapped in for the test and restored afterwards, so the
// process-global state Wire relies on does not leak across the package's
// tests. Uses NewMapperWithLogger(logr.Discard()), the constructor Wire's
// NewPluginWithLogger path builds.
func TestWireSeamClosureParity(t *testing.T) {
	m := NewMapperWithLogger(logr.Discard())
	playerID := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a6003")
	m.RecordServer(playerID, "Survival-1")
	installDefault(t, m)

	// Twin JoinGame packets: one through the direct call the seam wraps,
	// one through the closure union.Wire assigns to the seam variable.
	directJG, seamJG := newLiveJoinGame(), newLiveJoinGame()
	if !m.RewritePacket(playerID, directJG) {
		t.Fatal("direct RewritePacket(JoinGame) = false, want true")
	}
	if !wireDimensionRewrite(playerID, seamJG) {
		t.Fatal("seam closure(JoinGame) = false, want true")
	}
	if !reflect.DeepEqual(directJG, seamJG) {
		t.Fatalf("JoinGame mutations differ:\n direct: %+v\n   seam: %+v", directJG, seamJG)
	}
	// Spot-check the mutation so a coincidental DeepEqual (both untouched)
	// cannot pass.
	if got, want := *seamJG.DimensionInfo.LevelName, "minecraft:survival-1_overworld"; got != want {
		t.Errorf("seam JoinGame level name = %q, want %q", got, want)
	}
	if got, want := seamJG.LevelNames[0], "minecraft:survival-1_overworld"; got != want {
		t.Errorf("seam JoinGame LevelNames[0] = %q, want %q", got, want)
	}

	// Twin Respawn packets through both paths.
	directRP, seamRP := newLiveRespawn(), newLiveRespawn()
	if !m.RewritePacket(playerID, directRP) {
		t.Fatal("direct RewritePacket(Respawn) = false, want true")
	}
	if !wireDimensionRewrite(playerID, seamRP) {
		t.Fatal("seam closure(Respawn) = false, want true")
	}
	if !reflect.DeepEqual(directRP, seamRP) {
		t.Fatalf("Respawn mutations differ:\n direct: %+v\n   seam: %+v", directRP, seamRP)
	}
	if got, want := *seamRP.DimensionInfo.LevelName, "minecraft:survival-1_the_nether"; got != want {
		t.Errorf("seam Respawn level name = %q, want %q", got, want)
	}

	// The closure's nil-Default guard: before NewPluginWithLogger attaches
	// (or with the plugin disabled, Wire sets the seam to nil) a call must be
	// a no-op. Swap Default out, assert, and put m back for the remainder;
	// installDefault's cleanup still restores the pre-test value.
	setDefault(nil)
	if wireDimensionRewrite(playerID, newLiveJoinGame()) {
		t.Error("seam closure without an installed Default must be a no-op (false)")
	}
	setDefault(m)
}

// TestWireSeamNegativeAndNoPanic verifies the seam closure's fallback paths
// return false without panicking: a nil packet, a packet type without a
// registered rewriter, typed-nil packet pointers (the seam's `any` parameter
// admits them; the concrete rewriters nil-guard), and a real packet for a
// player with no recorded server.
func TestWireSeamNegativeAndNoPanic(t *testing.T) {
	m := NewMapper()
	playerID := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a6004")
	m.RecordServer(playerID, "lobby")
	installDefault(t, m)

	if wireDimensionRewrite(playerID, nil) {
		t.Error("nil packet must return false")
	}
	if wireDimensionRewrite(playerID, struct{}{}) {
		t.Error("packet type without a registered rewriter must return false")
	}
	if wireDimensionRewrite(playerID, (*packet.JoinGame)(nil)) {
		t.Error("typed-nil JoinGame must return false (RewriteJoinGame nil guard)")
	}
	if wireDimensionRewrite(playerID, (*packet.Respawn)(nil)) {
		t.Error("typed-nil Respawn must return false (RewriteRespawn nil guard)")
	}

	// Unknown player: false, and the packets are left byte-identical to a
	// fresh construction (in-place mutation contract observed from outside).
	unknown := mustParseUUID(t, "069a79f4-44e9-4726-a5be-fca90e2a6005")
	jg, rp := newLiveJoinGame(), newLiveRespawn()
	if wireDimensionRewrite(unknown, jg) || wireDimensionRewrite(unknown, rp) {
		t.Error("packets for a player without a recorded server must not be rewritten")
	}
	if !reflect.DeepEqual(jg, newLiveJoinGame()) {
		t.Errorf("JoinGame mutated for an unknown player: %+v", jg)
	}
	if !reflect.DeepEqual(rp, newLiveRespawn()) {
		t.Errorf("Respawn mutated for an unknown player: %+v", rp)
	}
}
