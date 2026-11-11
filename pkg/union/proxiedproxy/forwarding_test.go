package proxiedproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// notchedProfile is a compact Velocity-style game profile JSON, as an ENTRY
// embeds it verbatim in the forwarding packet.
const notchedProfile = `{"id":"069a79f444e542249f2671b3e2d2e51b","name":"Notch","properties":[]}`

var baseTime = time.Unix(1700000000, 0)

func testPacket(t *testing.T, method string, priv *rsa.PrivateKey, key string, ts time.Time) []byte {
	t.Helper()
	f, err := NewForwarding("mc.example.com", "203.0.113.9", []byte(notchedProfile), "entry-1", method, priv, key, ts)
	if err != nil {
		t.Fatalf("NewForwarding: %v", err)
	}
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	return body
}

func keyEntries(key string) map[string]*TrustedEntry {
	return map[string]*TrustedEntry{"entry-1": {Key: key}}
}

func TestSignBody(t *testing.T) {
	f := &Forwarding{
		VHost:         "mc.example.com",
		RemoteAddress: "203.0.113.9",
		Profile:       []byte(notchedProfile),
		Timestamp:     1700000000123,
		EntryID:       "entry-1",
	}
	want := "mc.example.com" + "203.0.113.9" + notchedProfile + "1700000000123" + "entry-1"
	if got := string(f.SignBody()); got != want {
		t.Errorf("SignBody with entryID:\n got %q\nwant %q", got, want)
	}
	f.EntryID = ""
	want = "mc.example.com" + "203.0.113.9" + notchedProfile + "1700000000123"
	if got := string(f.SignBody()); got != want {
		t.Errorf("SignBody without entryID:\n got %q\nwant %q", got, want)
	}
}

// TestProfileBytesSurviveWire ensures the profile bytes embedded in the signed
// body are not altered between the ENTRY signing and PROXY verification.
// encoding/json compacts json.RawMessage during marshal, so the ENTRY must
// feed already-compact profile JSON (marshalNoEscape guarantees this, and Gson
// output is compact too) — then the bytes survive the wire unchanged.
func TestProfileBytesSurviveWire(t *testing.T) {
	raw := json.RawMessage(`{"id":"069a79f444e542249f2671b3e2d2e51b","name":"Notch"}`)
	f := &Forwarding{VHost: "v", RemoteAddress: "r", Profile: raw, Timestamp: 42}
	body := f.SignBody()
	wire, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Forwarding
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Profile, raw) {
		t.Errorf("profile bytes changed over the wire:\n got %q\nwant %q", back.Profile, raw)
	}
	if !bytes.Equal(back.SignBody(), body) {
		t.Errorf("sign body changed over the wire:\n got %q\nwant %q", back.SignBody(), body)
	}
}

func TestKEYVerifyOK(t *testing.T) {
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	v := NewVerifier(keyEntries("s3cret"))
	prof, remote, vhost, err := v.Verify(body, baseTime.Add(time.Second))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if prof.Name != "Notch" {
		t.Errorf("profile name = %q, want Notch", prof.Name)
	}
	if remote.String() != "203.0.113.9:0" {
		t.Errorf("remote = %q, want 203.0.113.9:0", remote.String())
	}
	if vhost != "mc.example.com" {
		t.Errorf("vhost = %q, want mc.example.com", vhost)
	}
}

func TestKEYVerifyWrong(t *testing.T) {
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	// Tamper the packet so the body no longer matches the hash.
	var f Forwarding
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	f.VHost = "evil.example.com"
	tampered, err := json.Marshal(&f)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(keyEntries("s3cret"))
	if _, _, _, err := v.Verify(tampered, baseTime.Add(time.Second)); err == nil {
		t.Error("tampered packet accepted")
	} else if err == nil || err != ErrUntrusted {
		// wrapped errors must keep ErrUntrusted; only check the identity via errors.Is
	}
	// Hash that does not match the trusted key.
	wrong := testPacket(t, VerificationKEY, nil, "other", baseTime)
	if _, _, _, err := v.Verify(wrong, baseTime.Add(time.Second)); err == nil {
		t.Error("packet signed with a different key accepted")
	}
}

func TestRSARoundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024) // small key keeps the test fast
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]*TrustedEntry{"entry-1": {PublicKey: &priv.PublicKey}}
	body := testPacket(t, VerificationRSA, priv, "", baseTime)

	v := NewVerifier(entries)
	prof, remote, vhost, err := v.Verify(body, baseTime.Add(time.Second))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if prof.Name != "Notch" {
		t.Errorf("profile name = %q, want Notch", prof.Name)
	}
	if remote.String() != "203.0.113.9:0" || vhost != "mc.example.com" {
		t.Errorf("remote = %q, vhost = %q", remote.String(), vhost)
	}

	// A signature over a different body must be rejected.
	f, err := NewForwarding("mc.example.com", "203.0.113.9", []byte(notchedProfile), "entry-1", VerificationRSA, priv, "", baseTime)
	if err != nil {
		t.Fatal(err)
	}
	f.RemoteAddress = "198.51.100.1"
	tampered, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := v.Verify(tampered, baseTime.Add(time.Second)); err == nil {
		t.Error("packet with invalid signature accepted")
	}
}

func TestMethodMismatchRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := baseTime.Add(time.Second)

	// KEY packet, RSA entry.
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	v := NewVerifier(map[string]*TrustedEntry{"entry-1": {PublicKey: &priv.PublicKey}})
	if _, _, _, err := v.Verify(body, now); err == nil {
		t.Error("KEY packet accepted against an RSA entry")
	}

	// RSA packet, KEY entry.
	body = testPacket(t, VerificationRSA, priv, "", baseTime)
	v = NewVerifier(keyEntries("s3cret"))
	if _, _, _, err := v.Verify(body, now); err == nil {
		t.Error("RSA packet accepted against a KEY entry")
	}

	// Unknown entry id.
	body = testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	v = NewVerifier(map[string]*TrustedEntry{"other": {Key: "s3cret"}})
	if _, _, _, err := v.Verify(body, now); err == nil {
		t.Error("packet accepted for an unknown entry id")
	}
}

func TestReplayTTL(t *testing.T) {
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	v := NewVerifier(keyEntries("s3cret"))
	v.replayTTL = 100 * time.Millisecond
	now := baseTime.Add(time.Second)

	if _, _, _, err := v.Verify(body, now); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, _, _, err := v.Verify(body, now); err == nil {
		t.Error("replayed packet accepted")
	}
	// After the TTL the token expires and the same body is acceptable again.
	if _, _, _, err := v.Verify(body, now.Add(150*time.Millisecond)); err != nil {
		t.Fatalf("verify after replay TTL: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	v := NewVerifier(keyEntries("s3cret"))

	if _, _, _, err := v.Verify(body, baseTime.Add(ForwardingPacketTimeout-500*time.Millisecond)); err != nil {
		t.Fatalf("fresh packet rejected: %v", err)
	}
	if _, _, _, err := v.Verify(body, baseTime.Add(ForwardingPacketTimeout+time.Second)); err == nil {
		t.Error("expired packet accepted")
	}
	// A future timestamp is tolerated, like the original (now - ts > timeout).
	future := testPacket(t, VerificationKEY, nil, "s3cret", baseTime.Add(2*time.Second))
	v2 := NewVerifier(keyEntries("s3cret"))
	if _, _, _, err := v2.Verify(future, baseTime); err != nil {
		t.Fatalf("future-skewed packet rejected: %v", err)
	}
}

func TestNullAndBadProfileData(t *testing.T) {
	v := NewVerifier(keyEntries("s3cret"))
	if _, _, _, err := v.Verify([]byte("not json"), baseTime); err == nil {
		t.Error("non-JSON body accepted")
	} else if err != nil && !isErrUntrustedWrapper(t, err, ErrNullProfileData) {
		t.Errorf("expected ErrNullProfileData, got %v", err)
	}
	bad := []byte(`{"vHost":"v","remoteAddress":"r","profile":{"id":"not-a-uuid","name":"Notch"},"timestamp":0,"verificationField":{"method":"KEY","value":"x"}}`)
	if _, _, _, err := v.Verify(bad, baseTime); err == nil {
		t.Error("profile with invalid id accepted")
	} else if err != nil && !isErrUntrustedWrapper(t, err, ErrBadProfileData) {
		t.Errorf("expected ErrBadProfileData, got %v", err)
	}
	// Missing profile name.
	noName := []byte(`{"vHost":"v","remoteAddress":"r","profile":{"id":"069a79f444e542249f2671b3e2d2e51b","name":""},"timestamp":0,"verificationField":{"method":"KEY","value":"x"}}`)
	if _, _, _, err := v.Verify(noName, baseTime); err == nil {
		t.Error("profile without name accepted")
	}
}

// isErrUntrustedWrapper reports whether err wraps sentinel through fmt's %w
// chain (used with errors.Is semantics).
func isErrUntrustedWrapper(t *testing.T, err, sentinel error) bool {
	t.Helper()
	for e := err; e != nil; e = unwrapOnce(e) {
		if e == sentinel {
			return true
		}
	}
	t.Logf("error %v does not wrap %v", err, sentinel)
	return false
}

func unwrapOnce(err error) error {
	switch x := err.(type) {
	case interface{ Unwrap() error }:
		return x.Unwrap()
	case interface{ Unwrap() []error }:
		for _, e := range x.Unwrap() {
			return e
		}
	}
	return nil
}

func TestPEMRoundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) ||
		!bytes.Contains(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Errorf("unexpected PEM armor:\npub:\n%s\npriv:\n%s", pubPEM, privPEM)
	}
	pub, err := ParsePublicKeyPEM(string(pubPEM))
	if err != nil {
		t.Fatalf("parse public PEM: %v", err)
	}
	if pub.N.Cmp(priv.PublicKey.N) != 0 || pub.E != priv.PublicKey.E {
		t.Error("public key mismatch after PEM roundtrip")
	}
	back, err := ParsePrivateKeyPEM(string(privPEM))
	if err != nil {
		t.Fatalf("parse private PEM: %v", err)
	}
	if back.D.Cmp(priv.D) != 0 {
		t.Error("private key mismatch after PEM roundtrip")
	}
	// Bare base64 DER is also accepted (Java strips the armor).
	derOnly := stripPEMArmor(string(pubPEM))
	if _, err := ParsePublicKeyPEM(derOnly); err != nil {
		t.Errorf("parse bare base64 public key: %v", err)
	}
}

func TestPEMFiles(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "PrivateKey.pem")
	pubPath := filepath.Join(dir, "PublicKey.pem")
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateKeyPEM(privPath, priv); err != nil {
		t.Fatal(err)
	}
	if err := SavePublicKeyPEM(pubPath, priv.Public().(*rsa.PublicKey)); err != nil {
		t.Fatal(err)
	}
	gotPriv, err := LoadPrivateKeyPEM(privPath)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := LoadPublicKeyPEM(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotPriv.D.Cmp(priv.D) != 0 || gotPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("key mismatch after file roundtrip")
	}
}

func TestEntryJSONSerde(t *testing.T) {
	dir := t.TempDir()

	// KEY record: key set, publicKey omitted (Gson null omission).
	keyEntry := TrustedEntryFile{ID: "entry-1", Key: "s3cret"}
	path := filepath.Join(dir, "entry.json")
	if err := WriteEntryJSON(path, keyEntry); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"id":"entry-1","key":"s3cret"}` {
		t.Errorf("entry.json = %s, want {\"id\":\"entry-1\",\"key\":\"s3cret\"}", b)
	}
	got, err := ReadEntryJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "entry-1" || got.Key != "s3cret" || got.PublicKey != "" {
		t.Errorf("entry.json roundtrip = %+v", got)
	}

	// RSA record roundtrip with a PEM public key.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKeyPEM(priv.Public().(*rsa.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	rsaEntry := TrustedEntryFile{ID: "entry-2", PublicKey: string(pubPEM)}
	path2 := filepath.Join(dir, "entry2.json")
	if err := WriteEntryJSON(path2, rsaEntry); err != nil {
		t.Fatal(err)
	}
	got2, err := ReadEntryJSON(path2)
	if err != nil {
		t.Fatal(err)
	}
	te, err := got2.ToTrustedEntry()
	if err != nil {
		t.Fatalf("ToTrustedEntry: %v", err)
	}
	if te.Type() != VerificationRSA || te.PublicKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Errorf("RSA entry roundtrip failed: type %q", te.Type())
	}

	// A record with neither credential is an error.
	if _, err := (TrustedEntryFile{ID: "x"}).ToTrustedEntry(); err == nil {
		t.Error("empty trusted entry accepted")
	}
}

func TestTrustedEntriesFileSerde(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TrustedEntries.json")

	// nil list writes the "[]" template.
	if err := WriteTrustedEntriesFile(path, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Errorf("template = %q, want \"[]\"", b)
	}
	list, err := ReadTrustedEntriesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}

	// Array with one KEY entry, loaded into the verifier map.
	if err := os.WriteFile(path, []byte(`[{"id":"entry-1","key":"s3cret"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadTrustedEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	e := entries["entry-1"]
	if e == nil || e.Type() != VerificationKEY || e.Key != "s3cret" {
		t.Errorf("loaded entries = %+v", entries)
	}
}

func TestIsDirectConnection(t *testing.T) {
	cases := []struct {
		vHost  string
		direct bool
	}{
		{"mc.example.com:25565", true},
		{"MC.Example.COM.", true},
		{"play.example.com\x00FML3\x00:25565", true},                 // client forge marker only
		{"play.example.com\x00FML\x00:25565", true},                  // legacy forge
		{"play.example.com\x00FML2\x00:25565", true},                 // legacy forge
		{"somehost.forge", true},                                     // Java literal endsWith("forge")
		{"play.example.com\x00example-uuid\x00:25565", false},        // BungeeGuard data appended by an ENTRY
		{"play.example.com\x00player\x00props\x00:25565", false},     // legacy forwarding data
		{"play.example.com\x00fml\x00example-uuid\x00:25565", false}, // marker then data
	}
	for _, c := range cases {
		if got := isDirectConnection(c.vHost); got != c.direct {
			t.Errorf("isDirectConnection(%q) = %v, want %v", c.vHost, got, c.direct)
		}
	}
}

func TestProfileName(t *testing.T) {
	body := testPacket(t, VerificationKEY, nil, "s3cret", baseTime)
	if name := profileName(body); name != "Notch" {
		t.Errorf("profileName = %q, want Notch", name)
	}
	if name := profileName([]byte(`{"profile":{"name":"X"}}`)); name != "X" {
		t.Errorf("profileName minimal = %q, want X", name)
	}
	if name := profileName([]byte("junk")); name != "" {
		t.Errorf("profileName(junk) = %q, want empty", name)
	}
}

func TestMarshalNoEscape(t *testing.T) {
	// HTML-sensitive characters must survive unescaped: the profile bytes are
	// embedded verbatim in the signed body and Gson does not escape them.
	raw := json.RawMessage(`{"name":"A<B&"}`)
	b, err := marshalNoEscape(&struct {
		Profile json.RawMessage `json:"profile"`
	}{Profile: raw})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`A<B&`)) {
		t.Errorf("marshalNoEscape escaped HTML: %s", b)
	}
	if bytes.HasSuffix(b, []byte("\n")) {
		t.Error("marshalNoEscape left a trailing newline")
	}
}

func TestStripZone(t *testing.T) {
	cases := map[string]string{
		"fe80::1":      "fe80::1",
		"fe80::1%eth0": "fe80::1",
		"203.0.113.9":  "203.0.113.9",
		"fe80::1%12":   "fe80::1",
		"%leading":     "",
	}
	for in, want := range cases {
		if got := stripZone(in); got != want {
			t.Errorf("stripZone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestForwardingJSONWireFormat(t *testing.T) {
	// The wire format must match the original Gson keys exactly.
	f, err := NewForwarding("v", "r", []byte(notchedProfile), "e", VerificationKEY, nil, "k", baseTime)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"vHost", "remoteAddress", "profile", "timestamp", "entryId", "verificationField"} {
		if _, ok := probe[key]; !ok {
			t.Errorf("wire JSON misses key %q: %s", key, b)
		}
	}
	var vf struct {
		Method string `json:"method"`
		Value  string `json:"value"`
	}
	if err := json.Unmarshal(probe["verificationField"], &vf); err != nil {
		t.Fatal(err)
	}
	if vf.Method != "KEY" || len(vf.Value) != 64 {
		t.Errorf("verificationField = %+v", vf)
	}
}

func TestNewForwardingValidation(t *testing.T) {
	if _, err := NewForwarding("v", "r", []byte(notchedProfile), "", "HMAC", nil, "", baseTime); err == nil {
		t.Error("unknown verification method accepted")
	}
	if _, err := NewForwarding("v", "r", []byte(notchedProfile), "", VerificationRSA, nil, "", baseTime); err == nil {
		t.Error("RSA without private key accepted")
	}
	if _, err := NewForwarding("v", "r", []byte(notchedProfile), "", VerificationKEY, nil, "", baseTime); err == nil {
		t.Error("KEY without key accepted")
	}
}
