package server

import (
	"sync"

	plugin "github.com/fatedier/frp/pkg/plugin/server"
)

var (
	unionPluginMu      sync.Mutex
	unionPluginPending []plugin.Plugin
)

// UnionRegisterPlugin queues an in-process frp server plugin to be registered
// when the next Service created from this package starts running.
//
// Rationale: Service.pluginManager is intentionally unexported and only fed
// from cfg.HTTPPlugins. Going through loopback HTTP (the upstream-supported
// path) would add a TCP+JSON round trip to every Login/NewProxy/CloseProxy
// event the entry node handles. UnionGate embeds frps in the same process as
// the proxy, so direct Go callbacks are cheaper and do not open a :8080 that
// must be firewalled. Plugins queued here apply to the next Run call; call it
// before starting the frp service.
func UnionRegisterPlugin(p plugin.Plugin) {
	unionPluginMu.Lock()
	defer unionPluginMu.Unlock()
	unionPluginPending = append(unionPluginPending, p)
}

func unionPreRegisteredPlugins() []plugin.Plugin {
	unionPluginMu.Lock()
	defer unionPluginMu.Unlock()
	out := unionPluginPending
	unionPluginPending = nil
	return out
}
