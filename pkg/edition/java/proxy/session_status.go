package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/forge/modinfo"
	"go.minekube.com/gate/pkg/edition/java/netmc"
	"go.minekube.com/gate/pkg/edition/java/ping"
	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proto/version"
	"go.minekube.com/gate/pkg/gate/proto"
	"go.minekube.com/gate/pkg/util/errs"
)

type statusSessionHandler struct {
	*sessionHandlerDeps

	conn                netmc.MinecraftConn
	inbound             Inbound
	log                 logr.Logger
	resolvePingResponse pingResolveFunc // used in lite mode

	receivedRequest bool

	nopSessionHandler
}

type pingResolveFunc func(log logr.Logger, statusRequestCtx *proto.PacketContext) (logr.Logger, *packet.StatusResponse, error)

func newStatusSessionHandler(
	conn netmc.MinecraftConn,
	inbound Inbound,
	sessionHandlerDeps *sessionHandlerDeps,
	pingResolveFunc pingResolveFunc,
) netmc.SessionHandler {
	return &statusSessionHandler{
		sessionHandlerDeps: sessionHandlerDeps,
		conn:               conn,
		inbound:            inbound,
		log: logr.FromContextOrDiscard(conn.Context()).WithName("statusSession").WithValues(
			"inbound", inbound,
			"protocol", conn.Protocol()),
		resolvePingResponse: pingResolveFunc,
	}
}

func (h *statusSessionHandler) Activated() {
	cfg := h.config()
	var log logr.Logger
	if cfg.Status.LogPingRequests || cfg.Debug {
		log = h.log
	} else {
		log = h.log.V(1)
	}
	log.Info("got server list status request")
}

func (h *statusSessionHandler) HandlePacket(pc *proto.PacketContext) {
	if !pc.KnownPacket() {
		// What even is going on? ;D
		_ = h.conn.Close()
		return
	}

	switch pc.Packet.(type) {
	case *packet.StatusRequest:
		h.handleStatusRequest(pc)
	case *packet.StatusPing:
		h.handleStatusPing(pc)
	// TODO add LegacyPing
	default:
		// unexpected packet, simply close
		_ = h.conn.Close()
	}
}

// defaultVersionName is the server list version string when
// status.versionName is not configured.
var defaultVersionName = fmt.Sprintf("Gate %s", version.SupportedVersionsString)

func newInitialPing(p *Proxy, protocol proto.Protocol) *ping.ServerPing {
	if !version.Protocol(protocol).Supported() {
		protocol = version.MaximumVersion.Protocol
	}
	versionName := p.config().Status.VersionName
	if versionName == "" {
		versionName = defaultVersionName
	}
	var modInfo *modinfo.ModInfo
	if p.config().AnnounceForge {
		modInfo = modinfo.Default
	}
	return &ping.ServerPing{
		Version: ping.Version{
			Protocol: protocol,
			Name:     versionName,
		},
		Players: &ping.Players{
			Online: p.PlayerCount(),
			Max:    p.config().Status.ShowMaxPlayers,
		},
		Description: p.config().Status.Motd.C(),
		Favicon:     p.config().Status.Favicon,
		ModInfo:     modInfo,
	}
}

// resolveInitialPing builds the response used in full mode. With
// status.pingPassthrough enabled it asks the configured backend for its
// status and either returns it wholesale ("all") or only copies its mod
// metadata onto Gate's local status ("mods"). Any resolution error falls back
// to the local status so an unavailable backend never breaks the server list.
func (h *statusSessionHandler) resolveInitialPing(protocol proto.Protocol) *ping.ServerPing {
	local := newInitialPing(h.proxy, protocol)
	mode := strings.ToLower(strings.TrimSpace(h.config().Status.PingPassthrough))
	if mode == "" || mode == "disabled" {
		return local
	}
	if h.inbound == nil {
		return local
	}
	ctx := h.inbound.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	backend, err := h.proxy.resolvePingPassthrough(ctx, h.inbound, protocol)
	if err != nil {
		h.log.V(1).Info("ping passthrough failed, using local status", "error", err)
		return local
	}
	if backend == nil {
		return local
	}
	if mode == "mods" {
		local.ModInfo = backend.ModInfo
		local.Extra = backend.Extra
		return local
	}
	return backend
}

func (h *statusSessionHandler) handleStatusRequest(pc *proto.PacketContext) {
	if h.receivedRequest {
		// Already sent response
		_ = h.conn.Close()
		return
	}
	h.receivedRequest = true

	e := &PingEvent{
		inbound: h.inbound,
	}

	log := h.log
	if h.resolvePingResponse == nil {
		e.ping = h.resolveInitialPing(pc.Protocol)
	} else {
		var err error
		var res *packet.StatusResponse
		log, res, err = h.resolvePingResponse(h.log, pc)
		if err != nil {
			errs.V(log, err).Info("could not resolve ping", "error", err)
			_ = h.conn.Close()
			return
		}
		if !h.eventMgr.HasSubscriber(e) {
			// Fast path: No event handler, just send response
			h.writeStatusResponse(log, res)
			return
		}
		// Need to unmarshal status response to ping struct for event handlers
		e.ping = new(ping.ServerPing)
		if err = json.Unmarshal([]byte(res.Status), e.ping); err != nil {
			h.log.V(1).Error(err, "failed to unmarshal status response")
			_ = h.conn.Close()
			return
		}
	}

	h.eventMgr.Fire(e)

	if e.ping == nil {
		_ = h.conn.Close()
		log.V(1).Info("ping response was set to nil by an event handler, no response is sent")
		return
	}
	if !h.inbound.Active() {
		log.V(1).Info("status response not sent because inbound is inactive")
		return
	}

	response, err := json.Marshal(e.ping)
	if err != nil {
		_ = h.conn.Close()
		log.Error(err, "error marshaling ping response to json")
		return
	}
	h.writeStatusResponse(log, &packet.StatusResponse{
		Status: string(response),
	})
}

func (h *statusSessionHandler) writeStatusResponse(log logr.Logger, response *packet.StatusResponse) {
	if err := h.conn.WritePacket(response); err != nil {
		statusResponseWriteErrorLog(log, err).Info("error writing status response", "error", err)
		return
	}
	log.V(1).Info("sent status response")
}

func statusResponseWriteErrorLog(log logr.Logger, err error) logr.Logger {
	var netErr net.Error
	if errors.Is(err, netmc.ErrClosedConn) || errors.Is(err, io.ErrClosedPipe) ||
		errs.IsConnClosedErr(err) || errors.Is(err, syscall.EPIPE) || errors.As(err, &netErr) {
		return log.V(1)
	}
	return log
}

func (h *statusSessionHandler) handleStatusPing(p *proto.PacketContext) {
	// Just return again and close
	defer h.conn.Close()
	if err := h.conn.Write(p.Payload); err != nil {
		h.log.V(1).Info("error writing StatusPing response", "error", err)
	}
}
