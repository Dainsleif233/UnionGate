package proxiedproxy

// This file is the hermetic functional proof for ENTRY<->PROXY signed
// forwarding through the real crypto and plugin paths - no network, temp dirs
// only. It walks the same lifecycle union.WireWithLogger drives in production:
//
//  1. ENTRY materialization: plugin init generates (or loads) the RSA-3072 key
//     pair, saves both PEM files and writes entry.json for PROXY operators.
//  2. PROXY trust: the operator copies entry.json into TrustedEntries.json,
//     LoadTrustedEntries builds the Verifier, and a packet signed with the
//     ENTRY key survives marshal -> Verify with freshness + replay checks.
//  3. Plugin wiring: the forwarded packet reaches the login plugin message
//     consumer, the GameProfileRequestEvent handler applies the forwarded
//     profile and stores the forwarded address for the core seam
//     (proxy.UnionForwardedRemoteAddr), and the PostLogin cleanup clears it.
//  4. Tamper negatives: a flipped byte in the profile, vHost or signature is
//     rejected.
//
// The SignBody/ProfileBytes unit patterns live in forwarding_test.go and are
// not duplicated here; this file only adds what those cannot prove: the real
// files, the real key sizes, the real event/consumer wiring and the seam
// round-trip.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/robinbraemer/event"
	"go.minekube.com/gate/pkg/edition/java/config"
	"go.minekube.com/gate/pkg/edition/java/profile"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Live fixtures. Every packet gets its own remote address so two packets built
// within the same millisecond never collide in the verifier's replay cache
// (the remote address is part of the signed body).
const (
	liveEntryID    = "entry-live-1"
	liveKeyEntryID = "entry-live-key"
	liveKeySecret  = "live-shared-secret-15"

	liveRoundTripVHost = "live.gate.example"
	liveRoundTripName  = "LiveRoundTrip"
	liveSeamVHost      = "seam.gate.example"
	liveSeamName       = "LiveSeamPlayer"
	liveTamperVHost    = "tamper.gate.example"

	// Forwarded profile ids are deliberately NOT the offline-derived ids of
	// the same usernames, so applying the forwarded profile is observable.
	liveRoundTripID = "11111111-2222-3333-4444-555555555555"
	liveSeamID      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// TestLiveSignedForwardingRoundTrip runs the whole ENTRY->PROXY lifecycle
// hermetically. One t.TempDir and one RSA-3072 keygen keep the runtime small.
func TestLiveSignedForwardingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "PrivateKey.pem")
	pubPath := filepath.Join(dir, "PublicKey.pem")
	entryPath := filepath.Join(dir, "entry.json")
	trustedPath := filepath.Join(dir, "TrustedEntries.json")

	entryCfg := Config{
		Role:             RoleEntry,
		EntryID:          liveEntryID,
		VerificationType: VerificationRSA,
		PrivateKeyPath:   privPath,
		PublicKeyPath:    pubPath,
		EntryJSONPath:    entryPath,
	}

	// A real *proxy.Proxy, the way gate.New builds it, without Start: New is
	// cheap (no listeners, no I/O; the bedrock proxy tests do the same) and
	// provides the ChannelRegistrar and event manager initEntry/initProxy use.
	pr, err := proxy.New(proxy.Options{Config: &config.DefaultConfig, EventMgr: event.Nop})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ctx := context.Background()

	var gen *plugin
	t.Run("entry_materialization", func(t *testing.T) {
		// Init-equivalent construction: (&plugin{cfg}).init is exactly the
		// body NewPlugin's Init closure runs (and union.go:110 calls).
		gen = &plugin{cfg: entryCfg}
		if err := gen.init(ctx, pr); err != nil {
			t.Fatalf("ENTRY init (generate branch): %v", err)
		}

		// The private key PEM exists, parses as RSA-3072 and is owner-only.
		privPEM, err := os.ReadFile(privPath)
		if err != nil {
			t.Fatalf("read %s: %v", privPath, err)
		}
		priv, err := ParsePrivateKeyPEM(string(privPEM))
		if err != nil {
			t.Fatalf("parse private key PEM: %v", err)
		}
		if got := priv.N.BitLen(); got != RSAKeyBits {
			t.Errorf("private key size = %d bits, want %d", got, RSAKeyBits)
		}
		if fi, err := os.Stat(privPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", privPath, fi.Mode().Perm())
		}

		// The public key PEM exists and matches the private key.
		pubPEM, err := os.ReadFile(pubPath)
		if err != nil {
			t.Fatalf("read %s: %v", pubPath, err)
		}
		pub, err := ParsePublicKeyPEM(string(pubPEM))
		if err != nil {
			t.Fatalf("parse public key PEM: %v", err)
		}
		if pub.N.Cmp(priv.PublicKey.N) != 0 || pub.E != priv.PublicKey.E {
			t.Error("public key PEM does not match the generated private key")
		}

		// entry.json carries the entry id and the public key (and no shared
		// secret for an RSA entry), exactly what a PROXY operator copies into
		// TrustedEntries.json.
		entryRaw, err := os.ReadFile(entryPath)
		if err != nil {
			t.Fatalf("read %s: %v", entryPath, err)
		}
		if !bytes.Contains(entryRaw, []byte(`"id":"`+liveEntryID+`"`)) {
			t.Errorf("entry.json misses the entry id: %s", entryRaw)
		}
		if !bytes.Contains(entryRaw, []byte(`"publicKey"`)) {
			t.Errorf("entry.json misses the public key: %s", entryRaw)
		}
		if bytes.Contains(entryRaw, []byte(`"key":`)) {
			t.Errorf("RSA entry.json must not carry a shared secret: %s", entryRaw)
		}
		entry, err := ReadEntryJSON(entryPath)
		if err != nil {
			t.Fatalf("ReadEntryJSON: %v", err)
		}
		if entry.ID != liveEntryID || entry.Key != "" {
			t.Errorf("entry record = %+v", entry)
		}
		if entryPub, err := ParsePublicKeyPEM(entry.PublicKey); err != nil {
			t.Errorf("entry.json publicKey does not parse: %v", err)
		} else if entryPub.N.Cmp(priv.PublicKey.N) != 0 {
			t.Error("entry.json publicKey does not match the generated key")
		}

		// Production wiring shape: the exact call union.go:102/110 makes.
		pl := NewPlugin(nil, entryCfg)
		if pl.Name != "proxied-proxy" {
			t.Errorf("plugin name = %q", pl.Name)
		}
		privBytesBefore, _ := os.ReadFile(privPath)
		pubBytesBefore, _ := os.ReadFile(pubPath)
		if err := pl.Init(ctx, pr); err != nil {
			t.Fatalf("NewPlugin.Init: %v", err)
		}
		// The files still exist byte-identical: the second init took the
		// load branch (loadOrGenerateKeyPair), it did not regenerate.
		privBytesAfter, _ := os.ReadFile(privPath)
		pubBytesAfter, _ := os.ReadFile(pubPath)
		if !bytes.Equal(privBytesBefore, privBytesAfter) || !bytes.Equal(pubBytesBefore, pubBytesAfter) {
			t.Error("second ENTRY init rewrote the key files (load branch expected)")
		}

		// And a third init loads the very same key from disk, so a restart of
		// an ENTRY keeps the identity its entry.json already distributed.
		loader := &plugin{cfg: entryCfg}
		if err := loader.init(ctx, pr); err != nil {
			t.Fatalf("ENTRY init (load branch): %v", err)
		}
		if loader.privateKey.D.Cmp(gen.privateKey.D) != 0 {
			t.Error("load branch returned a different key than the generated one")
		}
	})

	// PROXY side: the operator copies entry.json into TrustedEntries.json
	// (mixed array with a KEY entry to prove the file->verifier path handles
	// both record types), then packets signed by the ENTRY verify.
	entries := map[string]*TrustedEntry{}
	var verifier *Verifier
	t.Run("proxy_trust_and_replay", func(t *testing.T) {
		if gen == nil {
			t.Fatal("entry_materialization subtest failed; nothing to trust")
		}
		entry, err := ReadEntryJSON(entryPath)
		if err != nil {
			t.Fatalf("ReadEntryJSON: %v", err)
		}
		if err := WriteTrustedEntriesFile(trustedPath, []TrustedEntryFile{
			entry,
			{ID: liveKeyEntryID, Key: liveKeySecret},
		}); err != nil {
			t.Fatalf("WriteTrustedEntriesFile: %v", err)
		}
		entries, err = LoadTrustedEntries(trustedPath)
		if err != nil {
			t.Fatalf("LoadTrustedEntries: %v", err)
		}
		if e := entries[liveEntryID]; e == nil || e.Type() != VerificationRSA {
			t.Errorf("trusted RSA entry = %+v", e)
		}
		if e := entries[liveKeyEntryID]; e == nil || e.Type() != VerificationKEY {
			t.Errorf("trusted KEY entry = %+v", e)
		}
		verifier = NewVerifier(entries)

		// Production constants behind the freshness and replay checks.
		if ForwardingPacketTimeout != 10*time.Second {
			t.Errorf("ForwardingPacketTimeout = %v, want 10s", ForwardingPacketTimeout)
		}
		if defaultReplayTTL != 15*time.Second {
			t.Errorf("defaultReplayTTL = %v, want 15s", defaultReplayTTL)
		}

		// The ENTRY signs with the key loaded from its own PEM files - the
		// same materialization a restart uses.
		priv, err := LoadPrivateKeyPEM(privPath)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM: %v", err)
		}
		roundTripProf := profile.GameProfile{
			ID:   mustParseUUID(t, liveRoundTripID),
			Name: liveRoundTripName,
			Properties: []profile.Property{
				{Name: "textures", Value: "c2lkbnRleHR1cmVz"},
			},
		}
		profileJSON, err := marshalNoEscape(&roundTripProf)
		if err != nil {
			t.Fatalf("marshalNoEscape(profile): %v", err)
		}

		f, err := NewForwarding(liveRoundTripVHost, "203.0.113.7", profileJSON, liveEntryID, VerificationRSA, priv, "", time.Now())
		if err != nil {
			t.Fatalf("NewForwarding: %v", err)
		}
		wire, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal packet: %v", err)
		}
		gotProf, remote, vhost, err := verifier.Verify(wire, time.Now())
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if gotProf.ID.String() != roundTripProf.ID.String() || gotProf.Name != roundTripProf.Name {
			t.Errorf("verified profile = %s, want id %s name %s", gotProf.String(), roundTripProf.ID, roundTripProf.Name)
		}
		if len(gotProf.Properties) != 1 || gotProf.Properties[0].Value != "c2lkbnRleHR1cmVz" {
			t.Errorf("profile properties did not survive the wire verbatim: %+v", gotProf.Properties)
		}
		if remote.String() != "203.0.113.7:0" {
			t.Errorf("remote = %q, want 203.0.113.7:0", remote.String())
		}
		if vhost != liveRoundTripVHost {
			t.Errorf("vhost = %q, want %q", vhost, liveRoundTripVHost)
		}

		// SignBody order: vHost + remoteAddress + profile + timestamp + entryId.
		manual := f.VHost + f.RemoteAddress + string(f.Profile) + strconv.FormatInt(f.Timestamp, 10) + f.EntryID
		if string(f.SignBody()) != manual {
			t.Errorf("SignBody = %q, want %q", f.SignBody(), manual)
		}
		// ...and the order is load-bearing in the crypto: the same signature
		// validates over the documented order and not over a permutation.
		if err := ValidateRSA([]byte(manual), f.Verification.Value, &priv.PublicKey); err != nil {
			t.Errorf("signature does not validate over the documented body order: %v", err)
		}
		permuted := string(f.Profile) + f.VHost + f.RemoteAddress + strconv.FormatInt(f.Timestamp, 10) + f.EntryID
		if err := ValidateRSA([]byte(permuted), f.Verification.Value, &priv.PublicKey); err == nil {
			t.Error("signature accepted over a permuted body order")
		}

		// Freshness window with real time: accepted inside 10s, rejected past it.
		freshProf := profile.GameProfile{ID: mustParseUUID(t, liveRoundTripID), Name: liveRoundTripName}
		freshJSON, _ := marshalNoEscape(&freshProf)
		fresh, err := NewForwarding("fresh.gate.example", "203.0.113.8", freshJSON, liveEntryID, VerificationRSA, priv, "", time.Now().Add(-ForwardingPacketTimeout+2*time.Second))
		if err != nil {
			t.Fatalf("NewForwarding(fresh): %v", err)
		}
		freshWire, _ := json.Marshal(fresh)
		if _, _, _, err := verifier.Verify(freshWire, time.Now()); err != nil {
			t.Errorf("packet aged %v rejected: %v", ForwardingPacketTimeout-2*time.Second, err)
		}
		expired, err := NewForwarding("expired.gate.example", "203.0.113.9", freshJSON, liveEntryID, VerificationRSA, priv, "", time.Now().Add(-ForwardingPacketTimeout-2*time.Second))
		if err != nil {
			t.Fatalf("NewForwarding(expired): %v", err)
		}
		expiredWire, _ := json.Marshal(expired)
		if _, _, _, err := verifier.Verify(expiredWire, time.Now()); err == nil {
			t.Errorf("packet aged %v past the timeout accepted", ForwardingPacketTimeout+2*time.Second)
		} else if !errors.Is(err, ErrUntrusted) {
			t.Errorf("expired packet error does not wrap ErrUntrusted: %v", err)
		}

		// Replay cache (15s since last access): the same packet body verifies
		// once and is then consumed; the token expires after the TTL.
		replayVerifier := NewVerifier(entries) // isolated so the TTL mutation below stays local
		replay, err := NewForwarding("replay.gate.example", "203.0.113.10", freshJSON, liveEntryID, VerificationRSA, priv, "", time.Now())
		if err != nil {
			t.Fatalf("NewForwarding(replay): %v", err)
		}
		replayWire, _ := json.Marshal(replay)
		if _, _, _, err := replayVerifier.Verify(replayWire, time.Now()); err != nil {
			t.Fatalf("first verify of the replay packet: %v", err)
		}
		if _, _, _, err := replayVerifier.Verify(replayWire, time.Now()); err == nil {
			t.Error("same packet accepted twice (replay)")
		} else if !errors.Is(err, ErrUntrusted) {
			t.Errorf("replayed packet error does not wrap ErrUntrusted: %v", err)
		}
		replayVerifier.replayTTL = 50 * time.Millisecond // shrink so the expiry is observable without waiting 15s
		time.Sleep(120 * time.Millisecond)
		if _, _, _, err := replayVerifier.Verify(replayWire, time.Now()); err != nil {
			t.Errorf("token did not expire after the replay TTL: %v", err)
		}

		// The KEY entry in the same TrustedEntries.json file verifies too.
		keyF, err := NewForwarding("key.gate.example", "203.0.113.11", freshJSON, liveKeyEntryID, VerificationKEY, nil, liveKeySecret, time.Now())
		if err != nil {
			t.Fatalf("NewForwarding(KEY): %v", err)
		}
		keyWire, _ := json.Marshal(keyF)
		if _, _, _, err := verifier.Verify(keyWire, time.Now()); err != nil {
			t.Errorf("KEY packet against the KEY entry rejected: %v", err)
		}
	})

	// Tamper negatives: a flipped byte in the profile, in the vHost or in the
	// signature must fail verification. The flips are applied to the raw wire
	// bytes - no re-marshal - exactly like a corrupted packet on the wire.
	t.Run("tamper_negatives", func(t *testing.T) {
		if verifier == nil {
			t.Fatal("proxy_trust subtest failed; no verifier")
		}
		priv, err := LoadPrivateKeyPEM(privPath)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM: %v", err)
		}
		profJSON, _ := marshalNoEscape(&profile.GameProfile{ID: mustParseUUID(t, liveRoundTripID), Name: liveRoundTripName})
		base, err := NewForwarding(liveTamperVHost, "203.0.113.12", profJSON, liveEntryID, VerificationRSA, priv, "", time.Now())
		if err != nil {
			t.Fatalf("NewForwarding: %v", err)
		}
		wire, err := json.Marshal(base)
		if err != nil {
			t.Fatalf("marshal packet: %v", err)
		}
		// Sanity: the untouched packet verifies, so the rejections below are
		// caused by the flips alone.
		tv := NewVerifier(entries)
		if _, _, _, err := tv.Verify(wire, time.Now()); err != nil {
			t.Fatalf("untouched packet rejected: %v", err)
		}

		flipInPlace := func(want []byte, at int, desc string) []byte {
			t.Helper()
			bad := append([]byte(nil), wire...)
			if at < 0 || at >= len(bad) {
				t.Fatalf("%s: flip index %d out of range", desc, at)
			}
			bad[at] = flipASCIILetter(bad[at], desc)
			return bad
		}

		// Profile region: flip the first byte of the profile name.
		nameAt := bytes.Index(wire, []byte(liveRoundTripName))
		if nameAt < 0 {
			t.Fatal("profile name not found in the wire body")
		}
		badProfile := flipInPlace(wire, nameAt, "profile")
		if _, _, _, err := tv.Verify(badProfile, time.Now()); err == nil {
			t.Error("packet with a flipped profile byte accepted")
		} else if !errors.Is(err, ErrUntrusted) {
			t.Errorf("profile tamper error does not wrap ErrUntrusted: %v", err)
		}

		// vHost region: flip the first byte of the vHost.
		vhostAt := bytes.Index(wire, []byte(liveTamperVHost))
		if vhostAt < 0 {
			t.Fatal("vHost not found in the wire body")
		}
		badVHost := flipInPlace(wire, vhostAt, "vHost")
		if _, _, _, err := tv.Verify(badVHost, time.Now()); err == nil {
			t.Error("packet with a flipped vHost byte accepted")
		} else if !errors.Is(err, ErrUntrusted) {
			t.Errorf("vHost tamper error does not wrap ErrUntrusted: %v", err)
		}

		// Signature: flip the last base64 character of the verification value.
		// The value is the last string in the body (verification is the last
		// field), so its last char sits before the closing quote. Walk back
		// over any non-alphanumeric tail (e.g. '=' padding) so the flip keeps
		// the value decodable - the rejection must come from the signature
		// check, not from base64 decoding.
		sigAt := bytes.LastIndexByte(wire, '"') - 1
		for sigAt >= 0 && !isAlnum(wire[sigAt]) {
			sigAt--
		}
		badSig := flipInPlace(wire, sigAt, "signature")
		if _, _, _, err := tv.Verify(badSig, time.Now()); err == nil {
			t.Error("packet with a flipped signature byte accepted")
		} else if !errors.Is(err, ErrUntrusted) {
			t.Errorf("signature tamper error does not wrap ErrUntrusted: %v", err)
		}
	})

	// Plugin wiring: the real PROXY-side init, the real login plugin message
	// consumer, the real GameProfileRequestEvent dispatch and the
	// ForwardedRemoteAddr seam round-trip.
	t.Run("proxy_plugin_wiring", func(t *testing.T) {
		if verifier == nil {
			t.Fatal("proxy_trust subtest failed; no trusted entries")
		}

		// Hermetic seam registry: only this subtest's plugin is visible to
		// ForwardedRemoteAddr for the duration of the subtest.
		activeMu.Lock()
		savedPlugs := activePlugs
		activePlugs = nil
		activeMu.Unlock()
		t.Cleanup(func() {
			activeMu.Lock()
			activePlugs = savedPlugs
			activeMu.Unlock()
		})
		if _, ok := ForwardedRemoteAddr(liveSeamName); ok {
			t.Fatalf("%q already recorded before the test", liveSeamName)
		}

		// A real proxy with a real event manager so initProxy's subscriptions
		// are live: the profile event below is dispatched by the manager, not
		// by calling the handler directly.
		mgr := event.New()
		proxyPr, err := proxy.New(proxy.Options{Config: &config.DefaultConfig, EventMgr: mgr})
		if err != nil {
			t.Fatalf("proxy.New: %v", err)
		}
		proxyPlug := &plugin{cfg: Config{
			Role:                  RoleProxy,
			TrustedEntriesPath:    trustedPath,
			AllowClientConnection: true,
		}}
		if err := proxyPlug.init(ctx, proxyPr); err != nil {
			t.Fatalf("PROXY init: %v", err)
		}
		if proxyPlug.verifier == nil || proxyPlug.pending == nil {
			t.Fatal("PROXY init did not build the verifier/pending state")
		}

		// The ENTRY signs with the key loaded from its own PEM file (the
		// operator hand-off path) and the reply reaches the login plugin
		// message consumer - the same MessageConsumer the core hands to
		// SendLoginPluginMessage and invokes via consumer.OnMessageResponse
		// (pkg/edition/java/proxy/login_inbound.go:146).
		entryPriv, err := LoadPrivateKeyPEM(privPath)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM: %v", err)
		}
		seamProf := profile.GameProfile{ID: mustParseUUID(t, liveSeamID), Name: liveSeamName}
		seamJSON, err := marshalNoEscape(&seamProf)
		if err != nil {
			t.Fatalf("marshalNoEscape(profile): %v", err)
		}
		f, err := NewForwarding(liveSeamVHost, "198.51.100.42", seamJSON, liveEntryID, VerificationRSA, entryPriv, "", time.Now())
		if err != nil {
			t.Fatalf("NewForwarding: %v", err)
		}
		wire, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal packet: %v", err)
		}
		if err := proxyPlug.consumer().OnMessageResponse(wire); err != nil {
			t.Fatalf("consumer.OnMessageResponse: %v", err)
		}

		// The core fires GameProfileRequestEvent right after authentication
		// (pkg/edition/java/proxy/session_client_auth.go:93) and then looks up
		// the forwarded address for the same username through the seam
		// (session_client_auth.go:108, unionForwardedRemoteAddr ->
		// proxy.UnionForwardedRemoteAddr, installed as
		// proxiedproxy.ForwardedRemoteAddr by pkg/union/union.go:116 and
		// applied to inbound/player via setRemoteAddr at
		// session_client_auth.go:110 and :125).
		offline := profile.NewOffline(liveSeamName)
		ev := proxy.NewGameProfileRequestEvent(nil, *offline, false)
		mgr.Fire(ev)
		got := ev.GameProfile()
		if got.ID.String() != mustParseUUID(t, liveSeamID).String() {
			t.Errorf("applied profile id = %s, want the forwarded id %s (offline id would be %s)", got.ID, liveSeamID, offline.ID)
		}
		if got.Name != liveSeamName {
			t.Errorf("applied profile name = %q, want %q", got.Name, liveSeamName)
		}

		// The seam lookup sees the forwarded address inside the
		// GameProfileRequest -> PostLogin window.
		addr, ok := ForwardedRemoteAddr(liveSeamName)
		if !ok {
			t.Fatal("ForwardedRemoteAddr did not see the recorded address")
		}
		if want := "198.51.100.42:0"; addr != want {
			t.Errorf("ForwardedRemoteAddr = %q, want %q", addr, want)
		}

		// PostLogin cleanup. PostLoginEvent has no exported constructor (the
		// core builds it with its unexported player field and fires it at
		// session_client_auth.go:262), so onPostLogin itself cannot be
		// exercised from outside package proxy; the two state mutations it
		// performs are invoked exactly as the handler runs them:
		// onPostLogin -> takePending(name) + forwardedAddrs.Delete(name).
		pend, had := proxyPlug.takePending(liveSeamName)
		if !had || !pend.ok {
			t.Errorf("pending record = %+v, had %v; want a verified record", pend, had)
		}
		proxyPlug.forwardedAddrs.Delete(liveSeamName)
		if _, ok := ForwardedRemoteAddr(liveSeamName); ok {
			t.Error("PostLogin-path delete did not clear the seam record")
		}

		// Failed-verification branch: a tampered packet reaches the consumer,
		// the pending record is marked not-ok, the profile event then keeps
		// the original offline profile and no address is recorded for the
		// seam.
		badF, err := NewForwarding(liveSeamVHost, "198.51.100.43", seamJSON, liveEntryID, VerificationRSA, entryPriv, "", time.Now())
		if err != nil {
			t.Fatalf("NewForwarding(bad): %v", err)
		}
		badWire, err := json.Marshal(badF)
		if err != nil {
			t.Fatalf("marshal packet: %v", err)
		}
		// Flip the first vHost byte on the raw wire: verification fails while
		// the profile name (the pending key) stays intact.
		vhostAt := bytes.Index(badWire, []byte(liveSeamVHost))
		if vhostAt < 0 {
			t.Fatal("vHost not found in the wire body")
		}
		badWire[vhostAt] = flipASCIILetter(badWire[vhostAt], "vHost")

		// A corrupted packet through the consumer must record ok:false
		// (handleForwardingResponse nil-guards the nil net.Addr from a
		// failed Verify) instead of panicking the proxy.
		if err := proxyPlug.consumer().OnMessageResponse(badWire); err != nil {
			t.Fatalf("consumer OnMessageResponse: %v", err)
		}
		pendBad, ok := proxyPlug.getPending(liveSeamName)
		if !ok || pendBad.ok {
			t.Fatalf("not-ok pending record not recorded: %+v had %v", pendBad, ok)
		}
		if pendBad.remoteAddr != "" {
			t.Errorf("failed packet recorded remoteAddr %q, want empty", pendBad.remoteAddr)
		}
		// Prove the plugin's failure branch: profileName(badWire) is still
		// liveSeamName (only the vHost byte was flipped), so the pending
		// key matches and getPending hits the not-ok record, which must
		// leave the original offline profile untouched and must not store
		// a seam address.
		offlineBad := profile.NewOffline(liveSeamName)
		evBad := proxy.NewGameProfileRequestEvent(nil, *offlineBad, false)
		mgr.Fire(evBad)
		if gotBad := evBad.GameProfile(); gotBad.ID != offlineBad.ID {
			t.Errorf("failed packet changed the profile: got id %s, want the offline id %s", gotBad.ID, offlineBad.ID)
		}
		if _, ok := ForwardedRemoteAddr(liveSeamName); ok {
			t.Error("failed verification recorded a seam address")
		}

		// PROXY bootstrap with a missing TrustedEntries.json writes the "[]"
		// template, like the original PPlugin init. (WriteTrustedEntriesFile
		// does not create parent directories - the operator's config dir
		// exists in production - so the directory is created first.)
		freshDir := filepath.Join(dir, "fresh")
		if err := os.MkdirAll(freshDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		freshPath := filepath.Join(freshDir, "TrustedEntries.json")
		fresh := &plugin{cfg: Config{Role: RoleProxy, TrustedEntriesPath: freshPath}}
		if err := fresh.init(ctx, proxyPr); err != nil {
			t.Fatalf("PROXY init (template branch): %v", err)
		}
		b, err := os.ReadFile(freshPath)
		if err != nil {
			t.Fatalf("read %s: %v", freshPath, err)
		}
		if string(b) != "[]" {
			t.Errorf("template file = %q, want \"[]\"", b)
		}
		if list, err := LoadTrustedEntries(freshPath); err != nil || len(list) != 0 {
			t.Errorf("template entries = %+v err %v, want empty", list, err)
		}
	})
}

// mustParseUUID parses one of the fixed test UUIDs.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", s, err)
	}
	return id
}

// flipASCIILetter flips an ASCII letter or digit to a different one, keeping
// the surrounding JSON valid (a corrupted-but-parseable byte is what the
// signed body must reject; flipping a quote would only prove the JSON was
// rejected). Letters stay letters and digits stay digits so flipped base64
// and hex values remain decodable.
func flipASCIILetter(b byte, what string) byte {
	switch {
	case b >= 'a' && b <= 'z':
		return 'a' + (b-'a'+1)%26
	case b >= 'A' && b <= 'Z':
		return 'A' + (b-'A'+1)%26
	case b >= '0' && b <= '9':
		return '0' + (b-'0'+1)%10
	}
	panic("flipASCIILetter: " + what + " byte is not an ASCII letter or digit")
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
