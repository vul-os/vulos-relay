// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// streamsignal.go — WebRTC signaling relay + STUN responder + egress-aware
// TURN fallback for low-latency desktop/game streaming (STREAM-RELAY-01).
//
// Pairs with STREAM-SIGNAL-01 (cloud session orchestration, separate repo) and
// STREAM-BYO-01 (BYO GPU host, separate repo). This file is the relay side.
//
// Design (and what this file deliberately is NOT):
//   - The fabric is used ONLY for WebRTC signaling: SDP offer / SDP answer /
//     trickled ICE candidates are exchanged between the client peer and the
//     streaming host peer. The signaling messages ride the existing peering
//     envelope as a versioned payload sub-protocol (VULOS-STREAM/1) — exactly
//     the pattern syncp2p.go uses for VULOS-SYNC/1. NO new crypto: every
//     signaling frame is sealed/opened by peering.Seal / peering.Open and is
//     subject to the full §7 replay window and §8 receiver-side checks.
//   - MEDIA goes peer-to-peer over the WebRTC connection the two peers
//     negotiate. This relay is NOT an always-on media bridge.
//   - The relay is a TURN fallback ONLY when P2P fails: the host (or client)
//     MUST emit an explicit `msgP2PFailed` signal naming the session, and the
//     relay then opens a short-lived TURN slot for that session. Media bytes
//     are only relayed while a slot is open (gated). Egress is metered per
//     session (bytes/packets sent + received) and exposed via Snapshot, and a
//     fallback counter + ratio gauge are emitted as Prometheus metrics so an
//     operator can alarm on a too-high TURN-fallback rate.
//   - STUN responder: answers RFC 5389 Binding Requests for ICE candidate
//     discovery (mapped-address reflection). This is a tiny stdlib-only UDP
//     responder; it shares no state with the TURN slot table and never logs
//     payloads. It does NOT implement the full STUN/TURN spec — only the
//     Binding-Request path ICE needs to learn its server-reflexive candidate.
//
// Reused peering primitives (no new crypto, no parallel auth):
//   - peering.Identity / peering.PeerDescriptor / peering.Resolver — identity
//   - peering.Seal / peering.Open                                   — AEAD + Ed25519 + §7 replay
//   - peering.PeerTransport / SyncResponder                         — carrier
//   - peering.ReplayGuard                                           — §7 window
//
// Wire-format note: VULOS-STREAM/1 is a new payload sub-protocol; per
// spec/VERSIONS.md "What does NOT require a bump", adding a new payload
// sub-protocol does NOT bump VULOS-PEER. See spec/VERSIONS.md for the registry
// entry. The envelope wire format is unchanged.

package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// StreamProtoV1 is the payload-level sub-protocol identifier for WebRTC
// signaling + TURN-control frames carried inside a peering envelope. It is
// INDEPENDENT of the envelope wire version (VULOS-PEER/1); bumping it does not
// touch the frozen peering wire format. See spec/VERSIONS.md.
const StreamProtoV1 = "VULOS-STREAM/1"

// Stream signaling is box-to-box, not mail. Each box uses its pinned authority
// domain (StreamRelay.Domain) with a reserved "stream@" local-part in the MAIL
// FROM / RCPT TO slots, exactly as syncp2p uses "sync@" and reputation uses its
// own side-channel addresses.

// --- sub-protocol message types (VULOS-STREAM/1) ---

const (
	msgSDPOffer  = byte(1) // client→host (or vice versa): SDP offer
	msgSDPAnswer = byte(2) // host→client: SDP answer
	msgICECand   = byte(3) // either direction: trickled ICE candidate
	msgP2PFailed = byte(4) // either direction: P2P negotiation/keepalive failed → open TURN slot
	msgTURNAck   = byte(5) // relay→requester: TURN slot opened (carries slot token + endpoint)
	msgTURNClose = byte(6) // either direction: close the TURN slot for this session
)

// signalMsg is the decoded VULOS-STREAM/1 message. Exactly one field group is
// populated per typ.
type signalMsg struct {
	typ       byte
	session   string // session identifier (opaque; the cloud orchestrator chose it)
	sdp       []byte // msgSDPOffer / msgSDPAnswer
	candidate []byte // msgICECand (opaque ICE candidate line)
	reason    []byte // msgP2PFailed: opaque failure reason
	token     []byte // msgTURNAck: relay-issued slot token
	endpoint  string // msgTURNAck: TURN media endpoint (host:port) the requester sends to
}

// --- TURN slot bookkeeping (egress-aware fallback) ---

// turnSlot is a short-lived authorization to relay media bytes for one
// session. It is opened only after the requester signals msgP2PFailed; closed
// on msgTURNClose, on idle expiry, or when egress quota is exhausted.
type turnSlot struct {
	session string
	opened  time.Time
	expires time.Time
	// quotaBytes is the maximum total bytes (sent+recv) the slot may relay
	// before it is closed. 0 means "no quota" (operator policy).
	quotaBytes uint64
	// bytesIn / bytesOut are the running egress meters for this slot.
	bytesIn  uint64
	bytesOut uint64
	// peers maps a media-source UDP addr.String() to the destination addr it
	// is relayed to. The slot is established by the first packet from each
	// side; subsequent packets are bridged between the two endpoints.
	peers map[string]*net.UDPAddr
}

// --- StreamRelay ---

// StreamRelay drives WebRTC signaling relay + STUN/TURN NAT-traversal for one
// node. Signaling rides the peering fabric (reusing the full §7–§8 receiver
// checks); STUN is a small UDP responder; TURN media relay is gated on an
// explicit P2P-failure signal and egress is metered.
//
// One StreamRelay services arbitrarily many sessions. It is safe for
// concurrent use.
type StreamRelay struct {
	// Identity is this node's long-term peering key material.
	Identity *peering.Identity
	// Domain is the authority domain this node claims in signaling envelopes.
	Domain string
	// Resolver maps a peer domain to its PeerDescriptor (the same seam
	// syncp2p uses).
	Resolver peering.Resolver
	// Transport is the carrier; if it implements SyncResponder it is treated
	// as request/reply (LAN/loopback), otherwise fire-and-forget.
	Transport peering.PeerTransport

	// Deliver is the LOCAL signaling sink: when a signaling envelope is
	// addressed to this node, the decoded message for a known session is
	// delivered here so the upstream (cloud orchestrator / local streaming
	// stack) can act on it. May be nil, in which case received signals are
	// dropped after the §7/§8 checks (useful for relay-only nodes).
	Deliver func(peerDomain string, m StreamMessage)

	// DefaultSlotTTL is how long a freshly-opened TURN slot remains valid
	// without traffic. Zero defaults to 30s.
	DefaultSlotTTL time.Duration
	// DefaultSlotQuotaBytes is the per-slot egress cap. Zero = unlimited
	// (operator policy).
	DefaultSlotQuotaBytes uint64

	guard *peering.ReplayGuard

	mu               sync.Mutex
	slots            map[string]*turnSlot // keyed by session id
	turnEndpointAddr string               // published TURN listener address

	// signalCount / fallbackCount drive the TURN-fallback-rate metric.
	signalCount   atomic.Uint64
	fallbackCount atomic.Uint64

	once sync.Once
}

// StreamMessage is the decoded, application-facing view of an inbound
// VULOS-STREAM/1 signal. The upstream consumes it; the relay never inspects
// SDP/ICE contents.
type StreamMessage struct {
	Type      StreamMsgType
	Session   string
	SDP       []byte
	Candidate []byte
	Reason    []byte
	Token     []byte
	Endpoint  string
}

// StreamMsgType is the application-facing enum mirroring the wire msg type.
type StreamMsgType uint8

const (
	StreamSDPOffer  StreamMsgType = 1
	StreamSDPAnswer StreamMsgType = 2
	StreamICECand   StreamMsgType = 3
	StreamP2PFailed StreamMsgType = 4
	StreamTURNAck   StreamMsgType = 5
	StreamTURNClose StreamMsgType = 6
)

func (s *StreamRelay) init() {
	s.once.Do(func() {
		if s.guard == nil {
			s.guard = peering.NewReplayGuard()
		}
		if s.slots == nil {
			s.slots = make(map[string]*turnSlot)
		}
		if s.DefaultSlotTTL <= 0 {
			s.DefaultSlotTTL = 30 * time.Second
		}
		registerStreamMetricsOnce()
	})
}

// ErrStreamRelay is returned for relay-internal errors (slot exhaustion,
// unknown session, quota exceeded).
var ErrStreamRelay = errors.New("relay: stream relay error")

// --- signaling: send + receive ---

// SendSignal seals and ships one VULOS-STREAM/1 signaling message to the peer
// authoritative for peerDomain. Idempotent re-signaling is the caller's
// concern at the application layer (sessions are keyed by id; re-sending the
// same offer is safe — the receiver dedups by (session,type)). The reply, if
// any, arrives as a separate inbound envelope and is dispatched via
// HandleEnvelope to s.Deliver.
func (s *StreamRelay) SendSignal(ctx context.Context, peerDomain string, m StreamMessage) error {
	s.init()
	desc, err := s.Resolver.Resolve(ctx, peerDomain)
	if err != nil {
		return err
	}

	wire, err := s.sealSignal(desc, peerDomain, m)
	if err != nil {
		return err
	}
	s.signalCount.Add(1)
	streamSignalsTotal.Inc()
	if m.Type == StreamP2PFailed {
		s.fallbackCount.Add(1)
		streamP2PFailureTotal.Inc()
		updateFallbackRatio(s.signalCount.Load(), s.fallbackCount.Load())
	}

	// If the carrier supports synchronous request/reply (LAN / loopback /
	// tests), use it so a same-process reply arrives inline; otherwise the
	// reply (if any) comes back asynchronously via HandleEnvelope on the
	// peer.
	if rr, ok := s.Transport.(SyncResponder); ok {
		resp, err := rr.Exchange(ctx, desc.Endpoint, wire)
		if err != nil {
			if errors.Is(err, errStreamNoReply) {
				return nil
			}
			return err
		}
		if len(resp) > 0 {
			// The receiver may return an inline ack envelope; open it through
			// the full peering checks and dispatch.
			env, perr := peering.UnmarshalEnvelope(resp)
			if perr == nil {
				_ = s.dispatchPlain(peerDomain, env)
			}
		}
		return nil
	}
	return s.Transport.Deliver(ctx, desc.Endpoint, wire)
}

// HandleEnvelope is the receiver leg for a store-and-forward carrier: open one
// inbound peering envelope (running the full §7–§8 checks via peering.Open),
// decode the VULOS-STREAM/1 message, and either dispatch to s.Deliver (an
// SDP/ICE/close signal) or act on it (msgP2PFailed → open a TURN slot and
// return an msgTURNAck sealed back to the asker).
//
// authorized reports whether a domain is one this node serves for streaming
// signaling; pinned returns the pinned identity key for a stream peer domain
// (same seam peering.Open uses). Both are supplied by the operator wiring,
// exactly like the sync sub-protocol.
//
// Returns the wire-bytes reply envelope to hand back over the carrier, or nil
// if the message is purely fire-and-forget.
func (s *StreamRelay) HandleEnvelope(
	wire []byte,
	authorized func(domain string) bool,
	pinned func(domain string) (ed25519.PublicKey, bool),
) ([]byte, error) {
	s.init()
	env, err := peering.UnmarshalEnvelope(wire)
	if err != nil {
		return nil, err
	}
	plain, err := peering.Open(env, peering.OpenParams{
		Receiver:         s.Identity,
		AuthorizedDomain: authorized,
		PinnedSenderKey:  pinned,
	}, s.guard)
	if err != nil {
		return nil, err
	}
	msg, err := unmarshalSignal(plain)
	if err != nil {
		return nil, err
	}

	s.signalCount.Add(1)
	streamSignalsTotal.Inc()

	askerDomain := env.Header.SenderDomain
	out := toAppMessage(msg)
	if s.Deliver != nil {
		s.Deliver(askerDomain, out)
	}

	switch msg.typ {
	case msgP2PFailed:
		// Gated TURN fallback: open a slot for this session and return an ack
		// to the requester so it knows where (endpoint) and with what token
		// to send media bytes.
		s.fallbackCount.Add(1)
		streamP2PFailureTotal.Inc()
		updateFallbackRatio(s.signalCount.Load(), s.fallbackCount.Load())

		slot := s.openSlot(msg.session)
		askerDesc, rerr := s.Resolver.Resolve(context.Background(), askerDomain)
		if rerr != nil {
			return nil, rerr
		}
		ack := StreamMessage{
			Type:     StreamTURNAck,
			Session:  msg.session,
			Token:    slot.tokenSnapshot(),
			Endpoint: s.turnEndpoint(),
		}
		ackWire, sealErr := s.sealSignal(askerDesc, askerDomain, ack)
		if sealErr != nil {
			return nil, sealErr
		}
		return ackWire, nil
	case msgTURNClose:
		s.closeSlot(msg.session)
		return nil, nil
	default:
		// Pure signaling (SDP/ICE/Ack): handled by Deliver above; no reply
		// payload at the relay layer.
		return nil, nil
	}
}

// errStreamNoReply is returned by the loopback carrier when a fire-and-forget
// signaling delivery succeeds with no inline reply (SDP/ICE legs).
var errStreamNoReply = errors.New("relay: stream: no inline reply")

// dispatchPlain opens an already-unmarshaled envelope-wire reply through the
// caller's own guard and pushes the decoded message into Deliver.
func (s *StreamRelay) dispatchPlain(peerDomain string, env *peering.Envelope) error {
	// On the asker side, the reply opened here was already opened by the
	// LoopbackStreamTransport on its way back — by the time it arrives here
	// it is plaintext-equivalent. We re-decode the inner signal directly.
	msg, err := unmarshalSignal(env.Payload)
	if err != nil {
		return err
	}
	if s.Deliver != nil {
		s.Deliver(peerDomain, toAppMessage(msg))
	}
	return nil
}

// --- TURN slot management + egress accounting ---

// openSlot creates (or refreshes) a TURN slot for the given session and
// returns it. Calling openSlot twice for the same session is idempotent:
// the existing slot is refreshed and its token preserved.
func (s *StreamRelay) openSlot(session string) *turnSlot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.slots[session]; ok {
		cur.expires = time.Now().Add(s.DefaultSlotTTL)
		return cur
	}
	now := time.Now()
	slot := &turnSlot{
		session:    session,
		opened:     now,
		expires:    now.Add(s.DefaultSlotTTL),
		quotaBytes: s.DefaultSlotQuotaBytes,
		peers:      make(map[string]*net.UDPAddr),
	}
	s.slots[session] = slot
	streamTURNSlotsOpen.Inc()
	return slot
}

func (s *StreamRelay) closeSlot(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.slots[session]; ok {
		delete(s.slots, session)
		streamTURNSlotsOpen.Dec()
	}
}

// turnEndpoint is the host:port a peer should send media to for an open TURN
// slot. The relay's TURN listener publishes its address via SetTURNEndpoint;
// if unset, the empty string is returned and the requester is expected to know
// it via its operator config.
func (s *StreamRelay) turnEndpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turnEndpointAddr
}

// SetTURNEndpoint records the public host:port the TURN relay listens on, so
// the relay can include it in msgTURNAck replies.
func (s *StreamRelay) SetTURNEndpoint(addr string) {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turnEndpointAddr = addr
}

// RelayMediaInbound records `n` media bytes received by the TURN listener for
// session, gating on an open, unexpired, non-exhausted slot. It returns the
// destination *net.UDPAddr to send the packet to, or nil/ErrStreamRelay if the
// slot is closed/expired/quota'd or the destination side has not yet
// registered (in which case the caller MUST buffer or drop per its policy —
// the relay never blocks).
//
// from is the source address of the inbound media packet. The slot bridges the
// first two distinct source addresses it sees: typical WebRTC layout is
// client-side and host-side, each behind NAT.
func (s *StreamRelay) RelayMediaInbound(session string, from *net.UDPAddr, n int) (*net.UDPAddr, error) {
	s.init()
	if from == nil {
		return nil, ErrStreamRelay
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.slots[session]
	if !ok {
		return nil, fmt.Errorf("%w: no slot for session %q", ErrStreamRelay, session)
	}
	if time.Now().After(slot.expires) {
		delete(s.slots, session)
		streamTURNSlotsOpen.Dec()
		return nil, fmt.Errorf("%w: slot expired", ErrStreamRelay)
	}
	if slot.quotaBytes > 0 && slot.bytesIn+slot.bytesOut+uint64(n) > slot.quotaBytes {
		delete(s.slots, session)
		streamTURNSlotsOpen.Dec()
		return nil, fmt.Errorf("%w: egress quota exhausted", ErrStreamRelay)
	}

	key := from.String()
	if _, known := slot.peers[key]; !known {
		// First time we've seen this source; remember it.
		slot.peers[key] = from
	}

	// Egress accounting: the byte count of an inbound packet is "received";
	// when we relay it out it will also count as "sent" via RelayMediaSent.
	slot.bytesIn += uint64(n)
	streamTURNBytesRelayed.Add(float64(n))

	// Pick the OTHER known peer as destination.
	var dst *net.UDPAddr
	for k, p := range slot.peers {
		if k != key {
			dst = p
			break
		}
	}
	if dst == nil {
		// Bridge not yet established (the other side has not sent its first
		// packet); the caller MUST drop / buffer per its policy.
		return nil, nil
	}
	// Speculatively account for the outbound side too — RelayMediaSent is
	// the post-write hook for callers that want to confirm bytes actually
	// hit the wire; many use cases combine the two.
	slot.bytesOut += uint64(n)
	streamTURNBytesRelayed.Add(float64(n))
	slot.expires = time.Now().Add(s.DefaultSlotTTL) // refresh on activity
	return dst, nil
}

// SlotEgress returns the (bytesIn, bytesOut, open) accounting tuple for a
// session. Exposed for tests and operator dashboards.
func (s *StreamRelay) SlotEgress(session string) (uint64, uint64, bool) {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.slots[session]
	if !ok {
		return 0, 0, false
	}
	return slot.bytesIn, slot.bytesOut, true
}

// FallbackRate returns (turn-fallback events) / (total signaling events) as a
// 0-1 ratio. Returns 0 if no signals have been observed. Mirrors the
// Prometheus gauge updated on every signal.
func (s *StreamRelay) FallbackRate() float64 {
	s.init()
	total := s.signalCount.Load()
	if total == 0 {
		return 0
	}
	return float64(s.fallbackCount.Load()) / float64(total)
}

// Snapshot returns a point-in-time view of the relay's stream state for
// metrics/tests.
type StreamSnapshot struct {
	SignalsTotal   uint64
	FallbacksTotal uint64
	FallbackRate   float64
	OpenSlots      int
}

// Snapshot returns the current StreamSnapshot.
func (s *StreamRelay) Snapshot() StreamSnapshot {
	s.init()
	s.mu.Lock()
	open := len(s.slots)
	s.mu.Unlock()
	total := s.signalCount.Load()
	fbk := s.fallbackCount.Load()
	var rate float64
	if total > 0 {
		rate = float64(fbk) / float64(total)
	}
	return StreamSnapshot{
		SignalsTotal:   total,
		FallbacksTotal: fbk,
		FallbackRate:   rate,
		OpenSlots:      open,
	}
}

// tokenSnapshot is a stable, opaque per-slot token. We use the slot's open
// nanoseconds + session hash; the relay does not authenticate media packets
// with it (slot lifetime + addr binding are the gates) — it is an opaque
// identifier the requester can echo to confirm it received the ack.
func (t *turnSlot) tokenSnapshot() []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(t.opened.UnixNano()))
	// Cheap session hash so two sessions don't collide on the same opened
	// nanosecond.
	var h uint64
	for i := 0; i < len(t.session); i++ {
		h = h*1099511628211 ^ uint64(t.session[i])
	}
	binary.BigEndian.PutUint64(buf[8:16], h)
	return append([]byte(nil), buf[:]...)
}

// --- STUN responder (RFC 5389 Binding-Request only) ---
//
// This is the smallest possible stdlib-only STUN responder: it answers Binding
// Requests with a XOR-MAPPED-ADDRESS reflecting the sender's source IP+port,
// so an ICE agent can learn its server-reflexive candidate. It does NOT
// implement authentication, fingerprint, message-integrity, or any TURN
// allocation — TURN allocations in this relay are gated by the VULOS-STREAM/1
// msgP2PFailed signal, not by STUN-level ALLOCATE.

const (
	stunMethodBinding        = 0x0001
	stunClassRequest         = 0x0000
	stunClassSuccessResponse = 0x0100
	stunMagicCookie          = 0x2112A442
	stunAttrXORMappedAddress = 0x0020
	stunFamilyIPv4           = 0x01
	stunHeaderLen            = 20
)

// HandleSTUNPacket answers one STUN packet. If the packet is a well-formed
// Binding Request, it returns the Success Response bytes to send back to
// `from`. Any other packet returns nil (silently dropped). The function is
// pure (no goroutines, no I/O) so it composes with any UDP listener.
func HandleSTUNPacket(pkt []byte, from *net.UDPAddr) []byte {
	if len(pkt) < stunHeaderLen {
		return nil
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if cookie != stunMagicCookie {
		return nil
	}
	if msgType != (stunClassRequest | stunMethodBinding) {
		return nil
	}
	// Reflect the transaction ID (bytes 8:20).
	var txid [12]byte
	copy(txid[:], pkt[8:20])

	// Build XOR-MAPPED-ADDRESS attribute for from.
	ip4 := from.IP.To4()
	if ip4 == nil {
		return nil // IPv6 caller; the BYO ICE agent still gets host candidates
	}
	xport := uint16(from.Port) ^ uint16(stunMagicCookie>>16)
	var cookieBytes [4]byte
	binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
	var xaddr [4]byte
	for i := 0; i < 4; i++ {
		xaddr[i] = ip4[i] ^ cookieBytes[i]
	}
	attr := make([]byte, 0, 12)
	// Attribute header: type(2) || length(2) — value is 8 bytes
	attr = append(attr, byte(stunAttrXORMappedAddress>>8), byte(stunAttrXORMappedAddress))
	attr = append(attr, 0, 8)
	// Value: 0(1) || family(1) || xport(2) || xaddr(4)
	attr = append(attr, 0, stunFamilyIPv4)
	attr = append(attr, byte(xport>>8), byte(xport))
	attr = append(attr, xaddr[:]...)

	// Message: header(20) || attr(12)
	resp := make([]byte, stunHeaderLen+len(attr))
	binary.BigEndian.PutUint16(resp[0:2], uint16(stunClassSuccessResponse|stunMethodBinding))
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txid[:])
	copy(resp[20:], attr)
	return resp
}

// ServeSTUN runs a stdlib UDP STUN responder on conn until ctx is cancelled.
// It uses HandleSTUNPacket per inbound datagram. Errors on individual reads
// are tolerated (the responder is best-effort); a permanent listener error
// returns from the goroutine.
func ServeSTUN(ctx context.Context, conn *net.UDPConn) error {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		}
		if resp := HandleSTUNPacket(buf[:n], from); resp != nil {
			_, _ = conn.WriteToUDP(resp, from)
		}
	}
}

// --- sealing / unmarshaling ---

func (s *StreamRelay) sealSignal(desc *peering.PeerDescriptor, peerDomain string, m StreamMessage) ([]byte, error) {
	payload := marshalSignal(fromAppMessage(m))
	env, err := peering.Seal(peering.SealParams{
		Sender:       s.Identity,
		SenderDomain: s.Domain,
		Receiver:     desc,
		MailFrom:     "stream@" + s.Domain,
		RcptTo:       []string{"stream@" + peerDomain},
		RawRFC822:    payload,
		Proto:        peering.ProtoV1,
		Suite:        peering.SuiteV1,
	})
	if err != nil {
		return nil, err
	}
	return peering.MarshalEnvelope(env), nil
}

func fromAppMessage(m StreamMessage) *signalMsg {
	return &signalMsg{
		typ:       byte(m.Type),
		session:   m.Session,
		sdp:       m.SDP,
		candidate: m.Candidate,
		reason:    m.Reason,
		token:     m.Token,
		endpoint:  m.Endpoint,
	}
}

func toAppMessage(m *signalMsg) StreamMessage {
	return StreamMessage{
		Type:      StreamMsgType(m.typ),
		Session:   m.session,
		SDP:       m.sdp,
		Candidate: m.candidate,
		Reason:    m.reason,
		Token:     m.token,
		Endpoint:  m.endpoint,
	}
}

// --- VULOS-STREAM/1 wire codec (length-prefixed, big-endian) ---

func marshalSignal(m *signalMsg) []byte {
	var b []byte
	b = putStr(b, StreamProtoV1)
	b = append(b, m.typ)
	b = putStr(b, m.session)
	switch m.typ {
	case msgSDPOffer, msgSDPAnswer:
		b = putBytes(b, m.sdp)
	case msgICECand:
		b = putBytes(b, m.candidate)
	case msgP2PFailed:
		b = putBytes(b, m.reason)
	case msgTURNAck:
		b = putBytes(b, m.token)
		b = putStr(b, m.endpoint)
	case msgTURNClose:
		// session only
	}
	return b
}

func unmarshalSignal(b []byte) (*signalMsg, error) {
	r := &syncReader{b: b}
	proto, ok := r.str()
	if !ok || proto != StreamProtoV1 {
		return nil, fmt.Errorf("relay: stream: unsupported sub-protocol %q", proto)
	}
	typ, ok := r.byteV()
	if !ok {
		return nil, errStreamCorrupt
	}
	session, ok := r.str()
	if !ok {
		return nil, errStreamCorrupt
	}
	m := &signalMsg{typ: typ, session: session}
	switch typ {
	case msgSDPOffer, msgSDPAnswer:
		v, ok := r.bytesV()
		if !ok {
			return nil, errStreamCorrupt
		}
		m.sdp = v
	case msgICECand:
		v, ok := r.bytesV()
		if !ok {
			return nil, errStreamCorrupt
		}
		m.candidate = v
	case msgP2PFailed:
		v, ok := r.bytesV()
		if !ok {
			return nil, errStreamCorrupt
		}
		m.reason = v
	case msgTURNAck:
		tok, ok1 := r.bytesV()
		ep, ok2 := r.str()
		if !ok1 || !ok2 {
			return nil, errStreamCorrupt
		}
		m.token = tok
		m.endpoint = ep
	case msgTURNClose:
		// session only
	default:
		return nil, fmt.Errorf("relay: stream: unknown msg type %d", typ)
	}
	if !r.empty() {
		return nil, errStreamCorrupt
	}
	return m, nil
}

var errStreamCorrupt = errors.New("relay: stream: corrupt frame")

// --- in-process responder for tests / direct path ---

// LoopbackStreamTransport is an in-memory SyncResponder that wires two (or
// more) StreamRelays together in one process, running the full peering
// Seal/Open path on each leg. It is the reference carrier for tests.
type LoopbackStreamTransport struct {
	mu        sync.Mutex
	endpoints map[string]*streamEndpoint
}

type streamEndpoint struct {
	sr         *StreamRelay
	authorized func(string) bool
	pinned     func(string) (ed25519.PublicKey, bool)
}

// NewLoopbackStreamTransport creates an empty in-memory stream carrier.
func NewLoopbackStreamTransport() *LoopbackStreamTransport {
	return &LoopbackStreamTransport{endpoints: make(map[string]*streamEndpoint)}
}

// Register attaches a receiving StreamRelay at endpoint with the receiver-side
// authority/pinning seams peering.Open requires.
func (t *LoopbackStreamTransport) Register(endpoint string, sr *StreamRelay, authorized func(string) bool, pinned func(string) (ed25519.PublicKey, bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endpoints[endpoint] = &streamEndpoint{sr: sr, authorized: authorized, pinned: pinned}
}

// Deliver implements peering.PeerTransport (fire-and-forget). For stream
// signaling we route through Exchange so any inline ack is processed and
// dropped on the sender side; the message itself is still dispatched to the
// receiver's Deliver hook by HandleEnvelope.
func (t *LoopbackStreamTransport) Deliver(ctx context.Context, endpoint string, wire []byte) error {
	_, err := t.Exchange(ctx, endpoint, wire)
	if errors.Is(err, errStreamNoReply) {
		return nil
	}
	return err
}

// Exchange implements SyncResponder. It runs the receiver's HandleEnvelope and
// returns its sealed reply (if any). If the receiver produces no reply the
// sentinel errStreamNoReply is returned so callers can distinguish "delivered,
// no reply" from a real error.
func (t *LoopbackStreamTransport) Exchange(_ context.Context, endpoint string, req []byte) ([]byte, error) {
	t.mu.Lock()
	ep := t.endpoints[endpoint]
	t.mu.Unlock()
	if ep == nil {
		return nil, peering.ErrMisrouted
	}
	reply, err := ep.sr.HandleEnvelope(req, ep.authorized, ep.pinned)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, errStreamNoReply
	}
	// On the asker side, open the reply through its own guard so the full
	// peering checks run on the return leg too. Find the asker by matching
	// the inbound envelope's sender identity to a registered endpoint.
	env, perr := peering.UnmarshalEnvelope(req)
	if perr != nil {
		return reply, nil
	}
	asker := t.endpointByIdentity(env.Header.SenderIdentityPub)
	if asker == nil {
		return reply, nil
	}
	repEnv, perr := peering.UnmarshalEnvelope(reply)
	if perr != nil {
		return reply, nil
	}
	plain, perr := peering.Open(repEnv, peering.OpenParams{
		Receiver:         asker.sr.Identity,
		AuthorizedDomain: asker.authorized,
		PinnedSenderKey:  asker.pinned,
	}, asker.sr.guard)
	if perr != nil {
		return nil, perr
	}
	// Re-package the now-opened payload as an envelope-wire so SendSignal's
	// dispatch path (which unmarshals an envelope from the response) finds
	// the plaintext as the envelope payload. We reuse the reply envelope
	// bytes but swap in the plaintext; simpler is to hand back the plaintext
	// pre-wrapped: SendSignal calls UnmarshalEnvelope then reads .Payload.
	out := &peering.Envelope{Header: repEnv.Header, Payload: plain, Signature: repEnv.Signature}
	return peering.MarshalEnvelope(out), nil
}

func (t *LoopbackStreamTransport) endpointByIdentity(identityPub []byte) *streamEndpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ep := range t.endpoints {
		if bytesEq(ep.sr.Identity.SignPub, identityPub) {
			return ep
		}
	}
	return nil
}

// --- Prometheus metrics (TURN-fallback-rate is the headline metric) ---

var (
	streamMetricsOnce sync.Once

	streamSignalsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Subsystem: "stream",
		Name:      "signals_total",
		Help:      "Total VULOS-STREAM/1 signaling messages sent or received.",
	})
	streamP2PFailureTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Subsystem: "stream",
		Name:      "p2p_failure_total",
		Help:      "Total P2P-failure signals that triggered a TURN fallback slot.",
	})
	streamTURNSlotsOpen = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vulos_relay",
		Subsystem: "stream",
		Name:      "turn_slots_open",
		Help:      "Currently open TURN fallback slots.",
	})
	streamTURNBytesRelayed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Subsystem: "stream",
		Name:      "turn_bytes_relayed_total",
		Help:      "Total media bytes relayed through TURN fallback slots (egress meter).",
	})
	streamFallbackRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vulos_relay",
		Subsystem: "stream",
		Name:      "turn_fallback_ratio",
		Help:      "Fraction of signaling events that resulted in a TURN fallback (0-1).",
	})
)

func registerStreamMetricsOnce() {
	streamMetricsOnce.Do(func() {
		for _, c := range []prometheus.Collector{
			streamSignalsTotal, streamP2PFailureTotal,
			streamTURNSlotsOpen, streamTURNBytesRelayed, streamFallbackRatio,
		} {
			_ = prometheus.DefaultRegisterer.Register(c)
		}
	})
}

func updateFallbackRatio(total, fallbacks uint64) {
	if total == 0 {
		streamFallbackRatio.Set(0)
		return
	}
	streamFallbackRatio.Set(float64(fallbacks) / float64(total))
}
