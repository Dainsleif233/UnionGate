package proxiedproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.minekube.com/gate/pkg/edition/java/profile"
	"go.minekube.com/gate/pkg/util/uuid"
)

const testProfileID = "069a79f4-44e5-4224-9f26-71b3e2d2e51b"

// TestMarshalNoEscapeKeepsGsonSignBodyRaw pins the form the Java side signs.
// Gson's JsonObject.toString() uses htmlSafe=false, so base64 '=' and quotes
// stay raw. HTML-escaping them changes the signed body.
func TestMarshalNoEscapeKeepsGsonSignBodyRaw(t *testing.T) {
	in := forwardingProfile{
		ID:         testProfileID,
		UndashedID: strings.ReplaceAll(testProfileID, "-", ""),
		Name:       "Notch",
		Properties: []forwardingProperty{{
			Name:      "textures",
			Value:     "eyJ0aW1lc3RhbXAiOjB9==",
			Signature: "c2lnbmF0dXJl'==",
		}},
	}
	b, err := marshalNoEscape(in)
	if err != nil {
		t.Fatalf("marshalNoEscape: %v", err)
	}
	s := string(b)
	if !bytes.Contains(b, []byte("=")) {
		t.Fatalf("raw '=' must be preserved, got %s", s)
	}
	if !bytes.Contains(b, []byte("'")) {
		t.Fatalf("raw single quote must be preserved, got %s", s)
	}
	if bytes.Contains(b, []byte(`\u003d`)) {
		t.Fatalf("'=' must not be HTML-escaped, got %s", s)
	}
	if bytes.Contains(b, []byte(`\u0027`)) {
		t.Fatalf("single quote must not be HTML-escaped, got %s", s)
	}
	if bytes.Contains(b, []byte("\n")) {
		t.Fatalf("output must be compact, got %q", s)
	}
}

// TestMarshalForwardingProfileMatchesVelocityShape pins the two UUID fields
// Velocity's GameProfile exposes to Gson. The Java PROXY deserializes the
// profile into a Velocity GameProfile whose UUID adapter requires the dashed
// form; the undashedId field is part of the same object.
func TestMarshalForwardingProfileMatchesVelocityShape(t *testing.T) {
	id, err := uuid.Parse(testProfileID)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	b, err := marshalForwardingProfile(profile.GameProfile{
		ID:   id,
		Name: "Notch",
		Properties: []profile.Property{{
			Name:  "textures",
			Value: "abc==",
		}},
	})
	if err != nil {
		t.Fatalf("marshalForwardingProfile: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"id":"`+testProfileID+`"`) {
		t.Fatalf("expected dashed id, got %s", s)
	}
	if !strings.Contains(s, `"undashedId":"`+strings.ReplaceAll(testProfileID, "-", "")+`"`) {
		t.Fatalf("expected undashedId, got %s", s)
	}
	if !strings.Contains(s, `"value":"abc=="`) {
		t.Fatalf("expected raw base64 padding, got %s", s)
	}
	if !strings.Contains(s, `"properties":[`) {
		t.Fatalf("expected a properties array, got %s", s)
	}
	if strings.Contains(s, `"signature":""`) {
		t.Fatalf("expected empty signatures to be omitted, got %s", s)
	}
}

// TestGsonCanonicalProfileUnescapesJavaWire mirrors the Java PROXY, which
// parses an HTML-safe packet profile into a JsonObject and then calls
// toString() (htmlSafe=false) before verifying the signature.
func TestGsonCanonicalProfileUnescapesJavaWire(t *testing.T) {
	raw := []byte(`{"id":"` + testProfileID + `","undashedId":"` + strings.ReplaceAll(testProfileID, "-", "") + `","name":"Notch","properties":[{"name":"textures","value":"abc\u003d\u003d","signature":"x\u0027y\u003c\u003e\u0026"}]}`)
	want := `{"id":"` + testProfileID + `","undashedId":"` + strings.ReplaceAll(testProfileID, "-", "") + `","name":"Notch","properties":[{"name":"textures","value":"abc==","signature":"x'y<>&"}]}`
	if got := string(gsonCanonicalProfile(raw)); got != want {
		t.Fatalf("canonical profile mismatch:\n got: %s\nwant: %s", got, want)
	}
	if got := string(gsonCanonicalProfile([]byte(want))); got != want {
		t.Fatalf("canonical profile must be idempotent:\n got: %s\nwant: %s", got, want)
	}
}

// TestVerifierAcceptsJavaEscapedProfile proves the PROXY side accepts a packet
// produced by a Java ENTRY: the signature covers the raw profile (Gson's
// JsonObject.toString()), while the wire profile is HTML-safe escaped (Gson's
// default Gson.toJson).
func TestVerifierAcceptsJavaEscapedProfile(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	now := time.Unix(1700000000, 0)
	rawProfile := []byte(`{"id":"` + testProfileID + `","undashedId":"` + strings.ReplaceAll(testProfileID, "-", "") + `","name":"Notch","properties":[{"name":"textures","value":"abc==","signature":""}]}`)

	f, err := NewForwarding("vhost.example", "203.0.113.7", rawProfile, "entry-1", VerificationRSA, priv, "", now)
	if err != nil {
		t.Fatalf("NewForwarding: %v", err)
	}
	wire, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	// Simulate Gson.toJson's HTML-safe escaping of the profile field.
	wire = bytes.ReplaceAll(wire, []byte("abc=="), []byte(`abc\u003d\u003d`))

	v := NewVerifier(map[string]*TrustedEntry{
		"entry-1": {PublicKey: &priv.PublicKey},
	})
	got, addr, vhost, err := v.Verify(wire, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Name != "Notch" {
		t.Fatalf("profile name = %q, want Notch", got.Name)
	}
	if addr == nil || addr.String() != "203.0.113.7:0" {
		t.Fatalf("forwarded addr = %v, want 203.0.113.7:0", addr)
	}
	if vhost != "vhost.example" {
		t.Fatalf("vhost = %q, want vhost.example", vhost)
	}
}
