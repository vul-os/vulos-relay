//! The libp2p relay **server**: a Circuit Relay v2 (RFC-less libp2p spec, `libp2p::relay`)
//! forwarder for NAT'd mesh peers (CONTRACT §5 `relay` row).
//!
//! ## Why this is content-blind by construction
//!
//! A Circuit Relay v2 server forwards **opaque byte streams between two already-Noise-secured
//! libp2p connections**: peer A dials the relay, peer B has a standing reservation on the same
//! relay, and the relay simply splices A's substream to B's substream. Both substreams carry
//! Noise-encrypted (and, above that, the application's own end-to-end-encrypted) bytes — the
//! relay's `relay::Behaviour` never terminates the Noise session running *inside* the relayed
//! circuit (that session is between A and B, not A-relay or relay-B) and holds no key that could
//! decrypt it. This is `blind`/`structural` per `coordinator/CONTRACT.md` §3.3: the role *has no
//! key*, not merely a promise not to look — the strongest, provable assurance level. See the
//! crate root docs for the (deliberately fenced) `reachability-adapter` comparison.
//!
//! ## What is wired
//!
//! - **Transport:** TCP, secured by **Noise**, multiplexed by **Yamux** — the same transport-
//!   security stack envoir's `dmtap-p2p` mesh transport runs (matched libp2p major/minor +
//!   feature shape, BUILD-PLAN.md W5), so a wakala relay and an envoir/dmtap-p2p mesh node
//!   interoperate on the wire.
//! - **[`relay`](libp2p::relay) (Circuit Relay v2), server role only:** this crate is a relay,
//!   never a relay *client* — it does not reserve slots on other relays or dial peers through
//!   one. (Contrast dmtap-p2p, whose *mesh nodes* run both roles because a mesh node is
//!   sometimes the NAT'd party needing relay service and sometimes the public node serving it.)
//! - **[`identify`](libp2p::identify):** required in practice for Circuit Relay v2 to work at
//!   all — a relay client verifies the relay's identity and observed address through it.
//!
//! ## Async containment
//!
//! libp2p is async (tokio); [`RelayServer`] contains that runtime internally (its own
//! multi-thread tokio runtime + a background swarm task) so callers — including
//! [`crate::RelayCoordinator`], which is plain synchronous posture data — never need to be async
//! themselves. This mirrors dmtap-p2p's containment shape exactly.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, relay, tcp, yamux};
use libp2p::{Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc;

/// A boxed, thread-safe error for swarm construction (libp2p builder + bind failures) — the same
/// shape dmtap-p2p uses for its own `BuildError`.
pub type BuildError = Box<dyn std::error::Error + Send + Sync>;

/// Idle-connection timeout: how long a circuit with no traffic is kept open before libp2p closes
/// it. Matches dmtap-p2p's own relay-server-role timeout.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Identify protocol version this relay advertises. Versioned so a future change to what the
/// relay identifies as is an additive protocol, not a silent break.
const IDENTIFY_PROTOCOL: &str = "/wakala/relay/id/1.0.0";

/// The relay server's composed libp2p behaviour: Circuit Relay v2 (server role) + Identify. No
/// `kad`, no `request-response`, no application protocol of any kind — a relay has nothing to
/// say about the bytes it forwards, which is the structural half of its blindness (the other
/// half is "holds no decryption key"; this half is "runs no protocol that would even give it a
/// reason to look").
#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

/// Work items handed from the synchronous [`RelayServer`] handle to the background swarm task.
enum Command {
    /// Declare `addr` as one of this relay's externally-reachable addresses. Circuit Relay v2
    /// requires at least one **confirmed external address** before it will hand out a dialable
    /// circuit address in a reservation ack — without this, reservations are accepted at the
    /// protocol level but the reserving client's own listener fails closed with
    /// `NoAddressesInReservation` (observed empirically building dmtap-p2p's own relay test).
    /// Deliberately **not** automatic on every bound listener: a relay behind its own NAT
    /// auto-declaring a LAN address as "external" would hand peers a useless address, so this is
    /// an opt-in the operator of a genuinely public relay makes.
    AddExternalAddress(Multiaddr),
}

/// A running libp2p Circuit Relay v2 server. Construct with [`RelayServer::start`]; it runs a
/// background swarm until dropped or explicitly [`shutdown`](RelayServer::shutdown)'d.
pub struct RelayServer {
    peer_id: PeerId,
    cmd_tx: mpsc::UnboundedSender<Command>,
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
    /// Owns the tokio runtime; dropping it (directly, or via [`shutdown`](Self::shutdown))
    /// tears down the background swarm task and closes every open socket/circuit.
    _runtime: tokio::runtime::Runtime,
}

impl RelayServer {
    /// Start a relay server bound to `listen_on` (e.g. `/ip4/0.0.0.0/tcp/4001` for a real public
    /// relay, or `/ip4/127.0.0.1/tcp/0` for a loopback test). The libp2p keypair is freshly
    /// generated per process — the relay's *transport* identity; the coordinator's *substrate*
    /// identity ([`crate::RelayCoordinator`]'s [`broker_economics::IdentityKey`]) is separate,
    /// same split dmtap-p2p draws between a node's DMTAP address and its libp2p `PeerId`.
    ///
    /// Blocks only briefly to build the swarm and start listening; the swarm then runs in the
    /// background. Use [`wait_for_listener`](Self::wait_for_listener) to learn the bound
    /// address(es), and [`add_external_address`](Self::add_external_address) to opt this relay
    /// in to handing out a dialable circuit address (see [`Command::AddExternalAddress`]).
    pub fn start(listen_on: &[Multiaddr]) -> Result<Self, BuildError> {
        // Two worker threads: one relayed circuit's I/O should not be able to starve the
        // control-plane (reservation/identify) traffic of another, under load.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let listeners: Arc<Mutex<Vec<Multiaddr>>> = Arc::new(Mutex::new(Vec::new()));

        let listen_on = listen_on.to_vec();
        let listeners_t = listeners.clone();
        let peer_id = runtime.block_on(async move {
            let mut swarm = build_swarm()?;
            for addr in &listen_on {
                swarm.listen_on(addr.clone())?;
            }
            let peer_id = *swarm.local_peer_id();
            tokio::spawn(swarm_loop(swarm, cmd_rx, listeners_t));
            Ok::<PeerId, BuildError>(peer_id)
        })?;

        Ok(RelayServer {
            peer_id,
            cmd_tx,
            listeners,
            _runtime: runtime,
        })
    }

    /// This relay's libp2p [`PeerId`] — hand it (with a listen addr) to peers so they can
    /// reserve a slot / dial through it.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The listen multiaddrs bound so far (each carries a `/p2p/<peer_id>` suffix so it is
    /// directly dialable by a remote). May be empty right after [`start`](Self::start) until the
    /// swarm reports `NewListenAddr`; see [`wait_for_listener`](Self::wait_for_listener).
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.listeners.lock().unwrap().clone()
    }

    /// Spin up to `timeout` for at least one bound listen addr, returning them (empty on
    /// timeout). A `:0` bind resolves its real port asynchronously; callers that need the
    /// resolved address (tests, or an operator logging the bound port) wait here.
    pub fn wait_for_listener(&self, timeout: Duration) -> Vec<Multiaddr> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let ls = self.listeners();
            if !ls.is_empty() || std::time::Instant::now() >= deadline {
                return ls;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Declare `addr` (typically one of this relay's own [`listeners`](Self::listeners)) as an
    /// externally-reachable address — the opt-in that makes reservations on this relay actually
    /// usable (see [`Command::AddExternalAddress`]). A relay operator who has not confirmed real
    /// public reachability should not call this: an unreachable address handed out in a
    /// reservation ack just fails every peer's dial.
    pub fn add_external_address(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(Command::AddExternalAddress(addr));
    }

    /// Clean shutdown: stop the background swarm task and close every open socket/circuit this
    /// relay was serving. Equivalent to dropping the last handle (Rust's ordinary `Drop` already
    /// does this — see the owned runtime field), but named explicitly so a caller has an
    /// unambiguous "I am done relaying" call site rather than relying on scope-exit.
    pub fn shutdown(self) {
        // Dropping `self` drops `cmd_tx` (closing the swarm task's command channel, which ends
        // its select loop) and the owned `tokio::runtime::Runtime` (which tears down every
        // socket/circuit the swarm held). Nothing else to do here — the drop glue *is* the
        // shutdown.
    }
}

/// Build the libp2p swarm with the relay-server behaviour stack over TCP + Noise + Yamux.
fn build_swarm() -> Result<Swarm<RelayBehaviour>, BuildError> {
    let swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            let relay = relay::Behaviour::new(peer_id, relay::Config::default());
            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_string(),
                key.public(),
            ));
            RelayBehaviour { relay, identify }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    Ok(swarm)
}

/// The background swarm event loop: drive libp2p, service [`Command`]s, and record bound
/// listener addresses. Runs until the command channel closes (the [`RelayServer`] was dropped or
/// [`shutdown`](RelayServer::shutdown)'d).
async fn swarm_loop(
    mut swarm: Swarm<RelayBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Command::AddExternalAddress(addr)) => {
                        swarm.add_external_address(addr);
                    }
                    None => return, // Last handle dropped: shut the swarm task down.
                }
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    let full = address.clone().with_p2p(*swarm.local_peer_id()).unwrap_or(address);
                    listeners.lock().unwrap().push(full);
                }
                // Every other event (relay reservation/circuit accepted, identify exchange,
                // connection lifecycle, ...) is driven entirely by the behaviours themselves.
                // There is deliberately nothing else to do here: this relay never inspects, logs,
                // scores, or otherwise looks at what it forwards (CONTRACT §4 has no delivery
                // path for it to gate in the first place — see `RelayCoordinator::delivery_path_gate`).
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPIN: Duration = Duration::from_secs(15);

    #[test]
    fn starts_and_binds_a_listener() {
        let relay =
            RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).expect("relay starts");
        let addrs = relay.wait_for_listener(SPIN);
        assert!(!addrs.is_empty(), "relay should bind a listen addr");
        assert!(
            addrs[0].iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))),
            "bound addr should carry a tcp component: {:?}",
            addrs[0]
        );
        relay.shutdown();
    }

    #[test]
    fn peer_id_is_stable_across_calls() {
        let relay =
            RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).expect("relay starts");
        let a = relay.peer_id();
        let b = relay.peer_id();
        assert_eq!(a, b);
        relay.shutdown();
    }

    #[test]
    fn add_external_address_does_not_panic_or_block() {
        let relay =
            RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).expect("relay starts");
        let addrs = relay.wait_for_listener(SPIN);
        relay.add_external_address(addrs.into_iter().next().expect("a bound listener"));
        // Best-effort fire-and-forget command; nothing to assert beyond "did not panic/hang".
        relay.shutdown();
    }

    #[test]
    fn two_relays_get_distinct_peer_ids() {
        let a = RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
        let b = RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).unwrap();
        assert_ne!(a.peer_id(), b.peer_id());
        a.shutdown();
        b.shutdown();
    }
}
