// Package union wires Gate's union plugin set (mua, proxiedproxy, dimension,
// mapmod) into the Java proxy at startup - synchronously, from gate.New, so
// every global registration they perform happens before the proxy or the
// embedded frps service starts serving.
//
// The former startup race: registering an frp server plugin inside a
// proxy.Plugin Init hook queues it into frp's unionPluginPending list, and
// process.Collection starts every runnable in its own goroutine (Add already
// starts them once started), so the frps service's queue drain at Run entry
// (third_party/frp/server/service.go Run) raced the Java proxy's
// initPlugins. Wire runs in gate.New before any runnable is added, so the
// drain is guaranteed to find every queued plugin.
package union

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	jproxy "go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/gate/config"
	"go.minekube.com/gate/pkg/union/dimension"
	"go.minekube.com/gate/pkg/union/frps"
	"go.minekube.com/gate/pkg/union/mapmod"
	"go.minekube.com/gate/pkg/union/mua"
	"go.minekube.com/gate/pkg/union/proxiedproxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Wire installs every enabled union plugin onto javaProxy synchronously with
// a discard logger: plugins wired through it log nothing. It is kept for
// existing callers (gate.New runs before a logger is available); prefer
// WireWithLogger where a logger exists.
func Wire(javaProxy *jproxy.Proxy, cfg *config.Config) error {
	return WireWithLogger(javaProxy, cfg, logr.Discard())
}

// WireWithLogger is Wire with an explicit logger threaded into every enabled
// union plugin: the mua frp plugin core, the proxiedproxy plugin (through its
// Init context), the dimension mapper and the mapmod bridge. A nil/zero
// logger (log.GetSink() == nil) falls back to the discard logger Wire uses,
// so the two behave identically for an empty logger.
//
// WireWithLogger installs every enabled union plugin onto javaProxy
// synchronously, before the proxy or the embedded frps service starts serving
// (call it from gate.New after jproxy.New and BEFORE adding any runnable to
// the process collection).
//
// Order guarantees established here:
//   - the MUA frp server plugin is queued via frps.RegisterPlugin BEFORE
//     proc.Start, so the frps service's drain at Run entry cannot miss it
//     (this is the fix for the registration race the old 3-second shim
//     papered over);
//   - the MUA forced-host routing subscription and the proxiedproxy login
//     subscriptions are attached before the proxy can accept a connection;
//   - the dimension mapper and mapmod bridge attach to the proxy
//     immediately, so their event subscriptions precede serving too.
//
// Nothing is appended to the jproxy.Plugins global: registering there from a
// library-level New (as this package is called from gate.New) would duplicate
// the plugins across multiple Gate instances created in the same process
// (tests boot several), and initPlugins would then run each Init again. The
// plugins here are wired exactly once, at construction, synchronously.
//
// Wiring is idempotent per Gate instance but must not be called concurrently
// with itself for the same proxy (gate.New is the only caller). It installs
// the proxy.UnionDimensionRewrite and proxy.UnionForwardedRemoteAddr seams
// for the enabled plugins and clears them for the disabled ones, so
// consecutive Gate instances (tests) do not leak seams into each other.
func WireWithLogger(javaProxy *jproxy.Proxy, cfg *config.Config, log logr.Logger) error {
	if javaProxy == nil || cfg == nil {
		return nil // nothing to wire (or no proxy: Lite-only/edge builds)
	}
	if log.GetSink() == nil {
		log = logr.Discard() // nil/zero logger: discard, like Wire
	}
	var errs []error

	// --- MUA frp control plane ---------------------------------------------
	// mua requires the frps library service; config.Validate already rejects
	// mua.enabled with frps disabled, and the second check here keeps Wire
	// safe for callers that bypass validation.
	if cfg.Frps.Enabled && cfg.Union.Mua.Enabled {
		muaCfg := mua.Config{
			FrpAddress:   cfg.Union.Mua.FrpAddress,
			RestrictPort: cfg.Union.Mua.RestrictPort,
			AllowMin:     cfg.Union.Mua.AllowMin,
			AllowMax:     cfg.Union.Mua.AllowMax,
		}
		core := mua.NewCoreForProxyWithLogger(javaProxy, muaCfg, log)
		// Queue BEFORE the process collection starts: frps drains the queue
		// at Run entry and Run cannot start earlier than proc.Start, which
		// is only called after Wire returns.
		frps.RegisterPlugin(core)
		mua.SubscribeRouting(javaProxy, core)
	}

	// --- proxied-proxy signed forwarding ------------------------------------
	if role := proxiedproxy.Role(cfg.Union.ProxiedProxy.Role); role != "" && role != proxiedproxy.RoleDisabled {
		pl := proxiedproxy.NewPlugin(nil, cfg2pp(cfg.Union.ProxiedProxy))
		// Run Init synchronously: it registers the proxied-proxy channel,
		// loads/verifies keys, reads TrustedEntries.json and subscribes to
		// the login events - all before the proxy binds. Init is a no-op
		// for disabled roles, which are filtered out above. The logger is
		// passed through the context: Init derives it with
		// logr.FromContextOrDiscard, so a discard logger (Wire) behaves
		// exactly like a bare Background did.
		if err := pl.Init(logr.NewContext(context.Background(), log), javaProxy); err != nil {
			errs = append(errs, fmt.Errorf("proxiedproxy: %w", err))
			jproxy.UnionForwardedRemoteAddr = nil
		} else {
			// Core seam for applying the forwarded remote address during
			// login (call sites pending in the hot-path lane).
			jproxy.UnionForwardedRemoteAddr = proxiedproxy.ForwardedRemoteAddr
		}
	} else {
		jproxy.UnionForwardedRemoteAddr = nil
	}

	// --- dimension packet rewriting -----------------------------------------
	if cfg.Union.Dimension.Enabled {
		// NewPluginWithLogger attaches the mapper to javaProxy immediately
		// (Attach is idempotent), installing it as dimension.Default and
		// subscribing the ServerPreConnect/Disconnect listeners before
		// serving.
		dimension.NewPluginWithLogger(javaProxy, log)
		// Core seam for join/respawn rewriting (call sites pending in the
		// hot-path lane); nil-guarded so a missing attach stays a no-op.
		jproxy.UnionDimensionRewrite = func(playerID uuid.UUID, pkt any) bool {
			m := dimension.Default()
			if m == nil {
				return false
			}
			return m.RewritePacket(playerID, pkt)
		}
	} else {
		jproxy.UnionDimensionRewrite = nil
	}

	// --- map-mod channel bridge ---------------------------------------------
	if cfg.Union.MapMod.Enabled {
		mapCfg := mapmod.Config{
			Channels:         cfg.Union.MapMod.Channels,
			ForwardToBackend: cfg.Union.MapMod.ForwardToBackend,
		}
		if len(mapCfg.Channels) == 0 {
			// Operator enabled the bridge without naming channels: use the
			// upstream default channel set wholesale.
			mapCfg = mapmod.DefaultConfig()
		}
		mapmod.NewPluginWithLogger(javaProxy, mapCfg, log)
	}

	return errors.Join(errs...)
}

// cfg2pp converts the config section to the plugin's own Config type; the
// plugin keeps a dependency-free Config, so the mirror stays in one place.
func cfg2pp(in config.ProxiedProxyConfig) proxiedproxy.Config {
	return proxiedproxy.Config{
		Role:                  proxiedproxy.Role(in.Role),
		EntryID:               in.EntryID,
		ServerCommandAlias:    in.ServerCommandAlias,
		VerificationType:      in.VerificationType,
		PrivateKeyPath:        in.PrivateKeyPath,
		PublicKeyPath:         in.PublicKeyPath,
		EntryJSONPath:         in.EntryJSONPath,
		Key:                   in.Key,
		TrustedEntriesPath:    in.TrustedEntriesPath,
		AllowClientConnection: in.AllowClientConnection,
	}
}
