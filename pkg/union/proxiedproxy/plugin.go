package proxiedproxy

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/profile"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/edition/java/proxy/message"
	"go.minekube.com/gate/pkg/util/netutil"
)

// Role is the plugin operation mode, mirroring Java PPlugin.Role.
type Role string

// Plugin roles. An ENTRY forwards player data to downstream PROXY connections;
// a PROXY consumes forwarded data from upstream ENTRY connections.
const (
	RoleEntry         Role = "ENTRY"
	RoleProxy         Role = "PROXY"
	RoleEntryAndProxy Role = "ENTRY_AND_PROXY"
	RoleDisabled      Role = "DISABLED"
)

// Config configures the plugin, mirroring the original config.toml entries.
type Config struct {
	// Role selects the operation mode (RoleEntry, RoleProxy, RoleEntryAndProxy
	// or RoleDisabled). An empty role is treated as disabled.
	Role Role
	// EntryID uniquely identifies this entry among the PROXY's trusted
	// entries. Required for ENTRY roles (Java entry.entry-id).
	EntryID string
	// VerificationType selects how packets are authenticated:
	// VerificationRSA or VerificationKEY (Java entry.verification-type).
	VerificationType string
	// PrivateKeyPath is the RSA private key PEM file used to sign packets.
	// Defaults to "PrivateKey.pem" when a key pair is generated.
	PrivateKeyPath string
	// PublicKeyPath is the RSA public key PEM file of the entry.
	// Defaults to "PublicKey.pem" when a key pair is generated.
	PublicKeyPath string
	// EntryJSONPath is where ENTRY roles write the entry.json record for PROXY
	// operators to copy into their TrustedEntries.json. Defaults to "entry.json".
	EntryJSONPath string
	// Key is the shared secret used by KEY verification on ENTRY roles
	// (Java entry.key.key).
	Key string
	// TrustedEntriesPath is the TrustedEntries.json file read by PROXY roles.
	// Defaults to "TrustedEntries.json"; a missing file is created with the
	// template contents "[]" and a warning, like the original.
	TrustedEntriesPath string
	// AllowClientConnection tolerates direct client connections on PROXY
	// roles (Java proxy.allow-client-connection). Direct clients keep their
	// own (possibly offline-mode) profile instead of being refused.
	AllowClientConnection bool
	// SendV1Verification is accepted for config compatibility with the
	// original but intentionally not implemented: the V1 legacy signature/hash
	// covers the Java GameProfile object's toString() representation, which
	// does not exist in this port. (Java entry.send-v1-verification.)
	// TODO: implement once a portable V1 body is defined.
	SendV1Verification bool
}

// NewPlugin returns a proxy.Plugin implementing ProxiedProxy ENTRY<->PROXY
// signed forwarding. The plugin is read-only against Gate's public API.
//
// Operators note: like the original's configCheck (which demands Velocity
// player-info-forwarding-mode legacy or bungeeguard), an ENTRY must be
// configured to append its own forwarding data to downstream handshakes, so a
// PROXY can tell entry connections apart from direct clients.
func NewPlugin(_ *proxy.Proxy, cfg Config) proxy.Plugin {
	return proxy.Plugin{
		Name: "proxied-proxy",
		Init: func(ctx context.Context, p *proxy.Proxy) error {
			return (&plugin{cfg: cfg}).init(ctx, p)
		},
	}
}

// Wired instances of the plugin. UnionWire installs plugins synchronously
// before the proxy starts serving, so init-time registration (and the reads
// made by ForwardedRemoteAddr on the login path) need no per-instance
// bookkeeping beyond the mutex guarding the slice itself.
var (
	activeMu    sync.Mutex
	activePlugs []*plugin
)

func registerActive(p *plugin) {
	activeMu.Lock()
	defer activeMu.Unlock()
	activePlugs = append(activePlugs, p)
}

// ForwardedRemoteAddr returns the client address an upstream ENTRY forwarded
// for the given username's login, as recorded by any wired plugin's PROXY
// side. ok is false when no wired plugin recorded an address for the name -
// the common case for direct (non-forwarded) clients.
//
// The record only exists while the login is in flight: it is stored at the
// GameProfileRequestEvent and deleted at PostLoginEvent, so a caller must
// look it up inside that window (e.g. to override the inbound connection's
// RemoteAddr). This is the package accessor behind the
// proxy.UnionForwardedRemoteAddr core seam, which union.Wire installs.
func ForwardedRemoteAddr(username string) (addr string, ok bool) {
	activeMu.Lock()
	plugins := make([]*plugin, len(activePlugs))
	copy(plugins, activePlugs)
	activeMu.Unlock()
	for _, p := range plugins {
		if v, has := p.forwardedAddrs.Load(username); has {
			if s, is := v.(string); is && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// pendingProfile is the per-login result of a forwarding verification, keyed
// by the forwarded profile's username.
type pendingProfile struct {
	ok         bool // the packet verified successfully
	prof       profile.GameProfile
	remoteAddr string
	vHost      string
}

type plugin struct {
	cfg Config
	log logr.Logger

	// ENTRY side
	channel    message.ChannelIdentifier
	privateKey *rsa.PrivateKey
	key        string // KEY verification secret

	// PROXY side
	verifier *Verifier

	pendingMu sync.Mutex
	pending   map[string]pendingProfile

	// forwardedAddrs records the forwarded remote address per username as a
	// placeholder for the inbound RemoteAddr override core seam (see TODO in
	// onGameProfileRequest). Entries are deleted at PostLoginEvent.
	forwardedAddrs sync.Map // username(string) -> remote addr(string)
}

func (p *plugin) init(ctx context.Context, pr *proxy.Proxy) error {
	p.log = logr.FromContextOrDiscard(ctx).WithName("proxiedproxy")
	registerActive(p) // visible to ForwardedRemoteAddr (ENTRY roles never record addresses)
	switch p.cfg.Role {
	case RoleDisabled, "":
		p.log.Info("ProxiedProxy is disabled.")
		return nil
	case RoleEntry, RoleProxy, RoleEntryAndProxy:
	default:
		return fmt.Errorf("proxiedproxy: unknown role %q", p.cfg.Role)
	}

	if p.cfg.Role == RoleEntry || p.cfg.Role == RoleEntryAndProxy {
		if err := p.initEntry(pr); err != nil {
			return err
		}
	}
	if p.cfg.Role == RoleProxy || p.cfg.Role == RoleEntryAndProxy {
		if err := p.initProxy(pr); err != nil {
			return err
		}
	}
	return nil
}

func (p *plugin) initEntry(pr *proxy.Proxy) error {
	if p.cfg.EntryID == "" {
		return errors.New("proxiedproxy: Config.EntryID is required for ENTRY roles")
	}
	id, err := message.NewChannelIdentifier("proxied-proxy", "login")
	if err != nil {
		return fmt.Errorf("proxiedproxy: invalid channel: %w", err)
	}
	p.channel = id
	pr.ChannelRegistrar().Register(p.channel)

	switch p.cfg.VerificationType {
	case VerificationRSA:
		privPath, pubPath := p.cfg.PrivateKeyPath, p.cfg.PublicKeyPath
		if privPath == "" {
			privPath = "PrivateKey.pem"
		}
		if pubPath == "" {
			pubPath = "PublicKey.pem"
		}
		key, err := loadOrGenerateKeyPair(privPath, pubPath)
		if err != nil {
			return fmt.Errorf("proxiedproxy: %w", err)
		}
		p.privateKey = key
	case VerificationKEY:
		if p.cfg.Key == "" {
			return errors.New("proxiedproxy: KEY verification requires Config.Key")
		}
		p.key = p.cfg.Key
	default:
		return fmt.Errorf("proxiedproxy: unknown verification type %q", p.cfg.VerificationType)
	}

	// Write the entry.json record (overwrites) for PROXY operators, like the
	// original PPlugin ENTRY initialization.
	entryPath := p.cfg.EntryJSONPath
	if entryPath == "" {
		entryPath = "entry.json"
	}
	self := TrustedEntryFile{ID: p.cfg.EntryID}
	switch p.cfg.VerificationType {
	case VerificationRSA:
		pub, err := EncodePublicKeyPEM(p.privateKey.Public().(*rsa.PublicKey))
		if err != nil {
			return fmt.Errorf("proxiedproxy: %w", err)
		}
		self.PublicKey = string(pub)
	case VerificationKEY:
		self.Key = p.key
	}
	if err := WriteEntryJSON(entryPath, self); err != nil {
		return fmt.Errorf("proxiedproxy: write %s: %w", entryPath, err)
	}

	event.Subscribe(pr.Event(), 0, p.onServerLoginPluginMessage)
	return nil
}

func (p *plugin) initProxy(pr *proxy.Proxy) error {
	path := p.cfg.TrustedEntriesPath
	if path == "" {
		path = "TrustedEntries.json"
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		p.log.Info("No TrustedEntries.json found; writing an empty template. Copy the entry.json of each entry into this file.")
		if err := WriteTrustedEntriesFile(path, nil); err != nil {
			return fmt.Errorf("proxiedproxy: write %s: %w", path, err)
		}
	}
	entries, err := LoadTrustedEntries(path)
	if err != nil {
		return fmt.Errorf("proxiedproxy: %w", err)
	}
	if len(entries) == 0 {
		p.log.Info("There are no entries trusted.")
	}
	p.verifier = NewVerifier(entries)
	p.pending = map[string]pendingProfile{}

	event.Subscribe(pr.Event(), 0, p.onPreLogin)
	event.Subscribe(pr.Event(), 0, p.onGameProfileRequest)
	event.Subscribe(pr.Event(), 0, p.onPostLogin)
	return nil
}

//
// ENTRY side
//

// onServerLoginPluginMessage replies to a FORWARDING_REQUEST from a downstream
// PROXY with the signed forwarding packet.
func (p *plugin) onServerLoginPluginMessage(e *proxy.ServerLoginPluginMessageEvent) {
	// GAP (core seam TODO): proxy.ServerLoginPluginMessageEvent exposes no
	// channel identifier accessor, so the event cannot prove it was sent over
	// the registered proxied-proxy:login channel. The original checks
	// event.getIdentifier().getId() here; matching its behavior for
	// BungeeCord-style compatibility, the request contents is the only
	// discriminator available without a core change.
	if string(e.Contents()) != ForwardingRequest {
		return
	}
	sc := e.ServerConnection()
	if sc == nil {
		return
	}
	player := sc.Player()
	if player == nil {
		return
	}
	prof := player.GameProfile()
	profileJSON, err := marshalNoEscape(&prof)
	if err != nil {
		p.log.Error(err, "Failed marshaling the game profile for forwarding.")
		return
	}

	// Java: player.getVirtualHost().orElseGet(serverInfo address).getHostString()
	vHost := ""
	if vh := player.VirtualHost(); vh != nil {
		vHost = netutil.Host(vh)
	}
	if vHost == "" {
		if rs := sc.Server(); rs != nil {
			if si := rs.ServerInfo(); si != nil {
				vHost = netutil.Host(si.Addr())
			}
		}
	}
	// Java VForwardingParser.getPlayerRemoteAddressAsString: host address with
	// an IPv6 scope zone stripped.
	remote := stripZone(netutil.Host(player.RemoteAddr()))

	f, err := NewForwarding(vHost, remote, profileJSON, p.cfg.EntryID, p.cfg.VerificationType, p.privateKey, p.key, time.Now())
	if err != nil {
		// Java disconnects "Entry internal error: InvalidKeyException" here;
		// Gate has no public disconnect for this event, so the response is
		// left unset and the downstream PROXY treats the login as unforwarded.
		p.log.Error(err, "Failed building the forwarding response.")
		return
	}
	resp, err := marshalNoEscape(f)
	if err != nil {
		p.log.Error(err, "Failed encoding the forwarding response.")
		return
	}
	e.Result().Response = resp
}

//
// PROXY side
//

// onPreLogin asks upstream entries for forwarding data and refuses direct
// clients unless they are allowed.
func (p *plugin) onPreLogin(e *proxy.PreLoginEvent) {
	conn := e.Conn()
	vHost := ""
	if conn.VirtualHost() != nil {
		// Gate's virtual host is the raw handshake address, including any
		// appended \0-separated legacy forwarding data or forge markers.
		vHost = conn.VirtualHost().String()
	}
	if !isDirectConnection(vHost) {
		p.log.V(1).Info("A client connects to the server from an ENTRY.")
		lpc, ok := conn.(proxy.LoginPhaseConnection)
		if !ok {
			p.log.Error(nil, "Connection does not implement LoginPhaseConnection; cannot request forwarding.")
			return
		}
		// Request player info forwarding. The message is queued by the core
		// while the pre-login event is being fired and flushed afterwards.
		_ = lpc.SendLoginPluginMessage(p.channel, []byte(ForwardingRequest), p.consumer())
		// Disable encryption: an entry (e.g. Velocity) does not support an
		// encrypted connection to a downstream server.
		e.ForceOfflineMode()
		return
	}
	p.log.V(1).Info("A client tries to directly connect to the server.")
	if !p.cfg.AllowClientConnection {
		e.Deny(text("Connection refused: Please connect to an entry server."))
	}
}

// consumer returns the login plugin message consumer validating the forwarded
// packet of one entry connection.
func (p *plugin) consumer() proxy.MessageConsumer {
	return consumerFunc(func(body []byte) error {
		p.handleForwardingResponse(body)
		return nil
	})
}

type consumerFunc func(responseBody []byte) error

func (f consumerFunc) OnMessageResponse(responseBody []byte) error { return f(responseBody) }

// handleForwardingResponse verifies a forwarding packet and remembers the
// result for the GameProfileRequestEvent of the same login.
//
// GAP (core seam TODO): the original disconnects with distinct messages here
// ("Invalid login packet: ...", "You are connecting from an untrusted entry."),
// but Gate's public login API has no disconnect for the consumer phase; the
// failure is recorded and surfaces as a disconnect at PostLoginEvent.
func (p *plugin) handleForwardingResponse(body []byte) {
	prof, remote, vHost, err := p.verifier.Verify(body, time.Now())
	name := profileName(body)
	// Verify returns a nil net.Addr on every error path: only stringify it
	// on success, so a corrupted/expired/replayed packet records ok:false
	// (and disconnects at PostLoginEvent) instead of panicking the proxy
	// with a nil-pointer dereference.
	remoteStr := ""
	if remote != nil {
		remoteStr = remote.String()
	}
	p.setPending(name, pendingProfile{
		ok:         err == nil,
		prof:       prof,
		remoteAddr: remoteStr,
		vHost:      vHost,
	})
	if err != nil {
		p.log.Error(err, "Rejecting the forwarded packet.", "username", name)
	}
}

// onGameProfileRequest applies the forwarded profile to the login.
//
// GAP (core seam TODO): Gate's GameProfileRequestEvent exposes no username
// accessor, so correlation relies on e.Original().Name (the offline profile
// derived from the ServerLogin username) matching the forwarded profile's
// name — the same username-based key the original uses. A connection-unique
// identifier (e.g. the login UUID from PreLoginEvent.ID) would be spoof-safe
// but cannot reach the consumer callback through the public API.
func (p *plugin) onGameProfileRequest(e *proxy.GameProfileRequestEvent) {
	name := e.Original().Name
	pend, ok := p.getPending(name)
	if !ok {
		// No forwarding data: direct clients are tolerated when allowed, and
		// unforwarded entry connections are refused at PostLoginEvent.
		p.log.V(1).Info("No forwarded profile found for the login.", "username", name)
		return
	}
	if !pend.ok {
		// Verified-and-failed: leave the original (offline) profile, the
		// connection is disconnected at PostLoginEvent.
		return
	}
	e.SetGameProfile(pend.prof)

	// The forwarded address is recorded for the core seam
	// (proxy.UnionForwardedRemoteAddr, applied by the core between this event
	// and PostLoginEvent; see pkg/edition/java/proxy/union_seams.go and the
	// authSessionHandler.Activated call site in session_client_auth.go).
	// The Store stays so ForwardedRemoteAddr remains truthful for that window.
	p.forwardedAddrs.Store(name, pend.remoteAddr)
	p.log.V(1).Info("Forwarded remote address recorded for the core seam.",
		"username", name, "forwardedRemoteAddr", pend.remoteAddr)
}

// onPostLogin cleans the pending state and refuses logins that produced no
// verified forwarding data.
func (p *plugin) onPostLogin(e *proxy.PostLoginEvent) {
	player := e.Player()
	name := player.Username()
	pend, ok := p.takePending(name)
	p.forwardedAddrs.Delete(name)

	// Java checks only !isOnlineMode(); direct connections that fail the
	// allowClientConnection policy were already refused at PreLogin, and a
	// verified-but-failed packet is refused regardless of the policy below.
	if player.OnlineMode() {
		return
	}
	switch {
	case ok && pend.ok:
		return // forwarded profile was applied
	case ok:
		// The forwarding packet existed but failed verification (untrusted
		// entry): always refuse, Java disconnected such connections already in
		// the consumer callback.
	case !p.cfg.AllowClientConnection:
		// No forwarding data and direct clients are not allowed: refuse.
	default:
		return // tolerated direct offline-mode client
	}
	player.Disconnect(text("Invalid player profile."))
}

//
// pending map helpers
//

func (p *plugin) setPending(name string, pend pendingProfile) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	p.pending[name] = pend
}

func (p *plugin) getPending(name string) (pendingProfile, bool) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	pend, ok := p.pending[name]
	return pend, ok
}

func (p *plugin) takePending(name string) (pendingProfile, bool) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	pend, ok := p.pending[name]
	delete(p.pending, name)
	return pend, ok
}

//
// helpers
//

// isDirectConnection reports whether a login's raw handshake address looks
// like a direct client instead of an upstream ENTRY.
//
// Java PLoginInboundConnection.isVHostFromClient: an ENTRY appends
// legacy/BungeeGuard forwarding data to the handshake address, which a direct
// client never does; FML/forge markers at the end are client artifacts and
// still count as a direct connection.
func isDirectConnection(vHost string) bool {
	vHost = strings.ToLower(strings.TrimSuffix(vHost, "."))
	// Gate's virtual host is the raw handshake address plus ":port"; strip the
	// trailing port of the final \0-part before comparing (Java compares the
	// handshake server address, which carries no port).
	if i := strings.LastIndex(vHost, ":"); i >= 0 && isDigits(vHost[i+1:]) {
		vHost = vHost[:i]
	}
	// Java's literal endsWith("forge") tolerance.
	if strings.HasSuffix(vHost, "forge") {
		return true
	}
	parts := strings.Split(vHost, "\x00")
	if len(parts) == 1 {
		return true // no appended data
	}
	for _, part := range parts[1:] {
		switch part {
		case "", "fml", "fml2", "fml3", "fml4": // client-side forge markers
		default:
			return false // appended data from an upstream ENTRY
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// stripZone removes an IPv6 scope zone suffix ("fe80::1%eth0" -> "fe80::1"),
// like Java VForwardingParser.getPlayerRemoteAddressAsString.
func stripZone(host string) string {
	if i := strings.Index(host, "%"); i >= 0 {
		return host[:i]
	}
	return host
}

// profileName extracts the forwarded profile's username from a packet body,
// used to correlate the response with the later profile events (see TODO).
func profileName(body []byte) string {
	var probe struct {
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	return probe.Profile.Name
}

// marshalNoEscape encodes v as compact JSON without HTML escaping, matching
// the original Gson output: the profile bytes are embedded verbatim and must
// survive the wire unchanged for the signature to validate.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// text returns a plain text component for disconnect reasons.
func text(s string) component.Component {
	return &component.Text{Content: s}
}

// loadOrGenerateKeyPair loads both PEM files when they exist, otherwise
// generates a fresh key pair and saves it, like Java PPlugin ENTRY init.
func loadOrGenerateKeyPair(privPath, pubPath string) (*rsa.PrivateKey, error) {
	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)
	if privExists && pubExists {
		priv, err := LoadPrivateKeyPEM(privPath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", privPath, err)
		}
		pub, err := LoadPublicKeyPEM(pubPath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", pubPath, err)
		}
		if priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E {
			return nil, fmt.Errorf("invalid RSA keypair: %s and %s do not match", privPath, pubPath)
		}
		return priv, nil
	}
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate RSA keypair: %w", err)
	}
	if err = SavePrivateKeyPEM(privPath, priv); err != nil {
		return nil, fmt.Errorf("save %s: %w", privPath, err)
	}
	if err = SavePublicKeyPEM(pubPath, priv.Public().(*rsa.PublicKey)); err != nil {
		return nil, fmt.Errorf("save %s: %w", pubPath, err)
	}
	return priv, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
