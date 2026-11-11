// Package proxiedproxy is a Go port of the ProxiedProxy plugin
// (work.art1st.proxiedproxy) implementing signed player forwarding between an
// ENTRY proxy and a PROXY proxy over a login plugin-message channel.
//
// ENTRY replies to a "forward" request on the proxied-proxy:login channel with
// a signed forwarding packet containing the connecting player's game profile;
// PROXY validates the packet against its trusted entries and applies the
// forwarded profile to the login. The wire format, signing scheme and checks
// mirror the original Java implementation exactly so both interoperate.
//
// This package is read-only against Gate's public API; it must not require
// changes in the core proxy.
package proxiedproxy

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.minekube.com/gate/pkg/edition/java/profile"
)

// Shared plugin channel and contents, mirroring the original PluginChannel /
// VPluginChannel classes.
const (
	// ChannelID is the login plugin-message channel shared by ENTRY and PROXY.
	ChannelID = "proxied-proxy:login"
	// ForwardingRequest is the request contents a PROXY sends on ChannelID;
	// an ENTRY replies with the serialized forwarding packet.
	ForwardingRequest = "forward"
)

// Wire values of the original VerificationType enum, as serialized by Gson.
const (
	VerificationRSA = "RSA"
	VerificationKEY = "KEY"
)

// ForwardingPacketTimeout is the maximum age of a forwarding packet.
// Java constant FORWARDING_PACKET_TIMEOUT = 10 (seconds).
const ForwardingPacketTimeout = 10 * time.Second

// defaultReplayTTL is how long a consumed forwarding token is remembered.
// Java uses a Caffeine cache with expireAfterAccess of 15s (timeout + 5s).
const defaultReplayTTL = 15 * time.Second

// Verification is the authenticity proof attached to a forwarding packet.
type Verification struct {
	Method string `json:"method"` // VerificationRSA or VerificationKEY
	Value  string `json:"value"`  // base64 RSA signature or 64-char hex KEY hash
}

// Forwarding is the JSON payload an ENTRY sends to a PROXY on the
// proxied-proxy:login channel. Field names and layout match the original Gson
// wire format exactly for interoperability.
type Forwarding struct {
	VHost         string `json:"vHost"`
	RemoteAddress string `json:"remoteAddress"`
	// Profile is the game profile JSON embedded verbatim: its exact bytes are
	// part of the signed body, so they must never be re-marshaled.
	Profile      json.RawMessage `json:"profile"`
	Timestamp    int64           `json:"timestamp"` // unix milliseconds
	EntryID      string          `json:"entryId,omitempty"`
	Verification Verification    `json:"verificationField"`
}

// SignBody returns the exact byte string a packet is signed or hashed over:
// vHost + remoteAddress + profile JSON (verbatim) + timestamp [+ entryId].
//
// Java ForwardingParser.getSignBody().
func (f *Forwarding) SignBody() []byte {
	var b strings.Builder
	b.WriteString(f.VHost)
	b.WriteString(f.RemoteAddress)
	b.Write(f.Profile)
	b.WriteString(strconv.FormatInt(f.Timestamp, 10))
	if f.EntryID != "" {
		b.WriteString(f.EntryID)
	}
	return []byte(b.String())
}

// NewForwarding assembles and signs a forwarding packet as an ENTRY would,
// replying to a FORWARDING_REQUEST. method must be VerificationRSA (with
// privateKey != nil) or VerificationKEY (with key != "").
func NewForwarding(vHost, remoteAddress string, profileJSON json.RawMessage, entryID, method string, privateKey *rsa.PrivateKey, key string, now time.Time) (*Forwarding, error) {
	switch method {
	case VerificationRSA:
		if privateKey == nil {
			return nil, errors.New("RSA verification requires a private key")
		}
	case VerificationKEY:
		if key == "" {
			return nil, errors.New("KEY verification requires a key")
		}
	default:
		return nil, fmt.Errorf("unknown verification method %q", method)
	}
	f := &Forwarding{
		VHost:         vHost,
		RemoteAddress: remoteAddress,
		Profile:       profileJSON,
		Timestamp:     now.UnixMilli(),
		EntryID:       entryID,
	}
	body := f.SignBody()
	var err error
	if method == VerificationRSA {
		f.Verification.Value, err = SignRSA(body, privateKey)
	} else {
		f.Verification.Value = KEYHash(body, key)
	}
	if err != nil {
		return nil, err
	}
	f.Verification.Method = method
	return f, nil
}

// TrustedEntry identifies a trusted ENTRY by its verification credentials.
// Exactly one of PublicKey (RSA) or Key (KEY) must be set.
type TrustedEntry struct {
	PublicKey *rsa.PublicKey // RSA public key of the entry
	Key       string         // shared secret for KEY verification
}

// Type reports the verification type the entry supports (Java TrustedEntry.getType).
func (e *TrustedEntry) Type() string {
	switch {
	case e == nil:
		return ""
	case e.PublicKey != nil:
		return VerificationRSA
	case e.Key != "":
		return VerificationKEY
	default:
		return ""
	}
}

// Verifier validates forwarding packets on a PROXY side against its trusted
// entries and a replay cache.
type Verifier struct {
	trusted map[string]*TrustedEntry

	replayMu  sync.Mutex
	replay    map[string]time.Time // signBody -> last seen time
	replayTTL time.Duration

	maxAge time.Duration
}

// NewVerifier returns a Verifier trusting the given entries, keyed by entry id.
// A nil or empty map is allowed: every packet is then rejected as untrusted.
func NewVerifier(entries map[string]*TrustedEntry) *Verifier {
	if entries == nil {
		entries = map[string]*TrustedEntry{}
	}
	return &Verifier{
		trusted:   entries,
		replay:    map[string]time.Time{},
		replayTTL: defaultReplayTTL,
		maxAge:    ForwardingPacketTimeout,
	}
}

// Verification errors. ErrUntrusted covers every rejection the original maps
// to checkUntrusted() == true ("You are connecting from an untrusted entry.").
var (
	// ErrNullProfileData: the packet body is not valid JSON ("Invalid login
	// packet: Null profile data." in the original).
	ErrNullProfileData = errors.New("invalid login packet: null profile data")
	// ErrBadProfileData: the profile is missing fields ("Invalid login packet:
	// Can not parse profile data." in the original).
	ErrBadProfileData = errors.New("invalid login packet: cannot parse profile data")
	// ErrUntrusted: unknown entry, expired, replayed, method mismatch or
	// invalid signature ("You are connecting from an untrusted entry.").
	ErrUntrusted = errors.New("you are connecting from an untrusted entry")
)

// Verify parses and authenticates a forwarding packet body received on the
// proxied-proxy:login channel. now is the current time. It returns the
// forwarded game profile, the forwarded remote address (port 0, like the
// original's InetSocketAddress(host, 0)) and the forwarded virtual host.
//
// Java ForwardingParser.fromJson + checkSanity + checkUntrusted.
func (v *Verifier) Verify(body []byte, now time.Time) (profile.GameProfile, net.Addr, string, error) {
	var f Forwarding
	if err := json.Unmarshal(body, &f); err != nil {
		return profile.GameProfile{}, nil, "", fmt.Errorf("%w: %w", ErrNullProfileData, err)
	}
	prof, err := f.verify(v, now)
	if err != nil {
		return profile.GameProfile{}, nil, "", err
	}
	return prof, forwardedAddr(f.RemoteAddress), f.VHost, nil
}

func (f *Forwarding) verify(v *Verifier, now time.Time) (profile.GameProfile, error) {
	// Sanity: the embedded profile must contain a valid id and a name.
	// profile.GameProfile.UnmarshalJSON already fails when id is absent or not
	// a parseable UUID; the name is checked below.
	// (Java ForwardingParser.checkSanity via GameProfileWrapper.)
	var prof profile.GameProfile
	if err := json.Unmarshal(f.Profile, &prof); err != nil {
		return prof, fmt.Errorf("%w: %w", ErrBadProfileData, err)
	}
	if prof.Name == "" {
		return prof, fmt.Errorf("%w: missing profile name", ErrBadProfileData)
	}

	// Trusted entry must exist.
	entry := v.trusted[f.EntryID]
	if entry == nil {
		return prof, fmt.Errorf("%w: unknown entry id %q", ErrUntrusted, f.EntryID)
	}

	// Freshness: reject stale packets. A timestamp in the future is tolerated,
	// exactly like the original (now - timestamp > timeout).
	if now.UnixMilli()-f.Timestamp > v.maxAge.Milliseconds() {
		return prof, fmt.Errorf("%w: packet expired", ErrUntrusted)
	}

	body := f.SignBody()
	if err := v.claimToken(body, now); err != nil {
		return prof, err
	}

	switch f.Verification.Method {
	case VerificationRSA:
		if entry.Type() != VerificationRSA {
			return prof, fmt.Errorf("%w: method mismatch", ErrUntrusted)
		}
		if err := ValidateRSA(body, f.Verification.Value, entry.PublicKey); err != nil {
			return prof, fmt.Errorf("%w: %w", ErrUntrusted, err)
		}
	default:
		// Anything not RSA is treated as KEY, mirroring the original's
		// if/else (an unknown or missing method therefore fails here too).
		if entry.Type() != VerificationKEY {
			return prof, fmt.Errorf("%w: method mismatch", ErrUntrusted)
		}
		if KEYHash(body, entry.Key) != f.Verification.Value {
			return prof, fmt.Errorf("%w: hash mismatch", ErrUntrusted)
		}
	}
	return prof, nil
}

// claimToken implements the replay cache: a signed body may only be consumed
// once. The token is recorded on first sight, before the signature is checked,
// exactly like the original Caffeine entryTokenCache (15s since last access).
func (v *Verifier) claimToken(token []byte, now time.Time) error {
	key := string(token)
	v.replayMu.Lock()
	defer v.replayMu.Unlock()
	for k, seen := range v.replay {
		if now.Sub(seen) > v.replayTTL {
			delete(v.replay, k)
		}
	}
	if seen, ok := v.replay[key]; ok && now.Sub(seen) <= v.replayTTL {
		return fmt.Errorf("%w: replayed packet", ErrUntrusted)
	}
	v.replay[key] = now
	return nil
}

// KEYHash returns the zero-padded 64-character lowercase hex SHA-256 of
// body+key, matching Java ForwardingParser.calculateHash
// (BigInteger(1, hash).toString(16) left-padded with '0' to 64 chars).
func KEYHash(body []byte, key string) string {
	h := sha256.Sum256([]byte(string(body) + key))
	return fmt.Sprintf("%064x", h)
}

// forwardedAddr wraps a forwarded remote address as a net.Addr with port 0,
// like the original's InetSocketAddress(remoteAddress, 0) used until a core
// seam lets us override the inbound connection's remote address.
func forwardedAddr(host string) net.Addr {
	return simpleAddr{network: "tcp", addr: host + ":0"}
}

// simpleAddr is a trivial net.Addr implementation (same shape as
// pkg/util/netutil's addr type) so this file stays free of further imports.
type simpleAddr struct {
	network, addr string
}

func (a simpleAddr) Network() string { return a.network }
func (a simpleAddr) String() string  { return a.addr }
