//! Two-peer Circuit Relay v2 loopback test: `src` peer -> [`RelayServer`] -> `dst` peer.
//!
//! Mirrors the pattern already proven live in envoir's `dmtap-p2p`
//! (`relay_v2_reservation_and_relayed_connection_delivers_a_frame`, read while building this
//! crate — BUILD-PLAN.md W5): `dst` reserves a slot on the relay and **never advertises a
//! directly-dialable address to `src` at all** — `src` learns `dst` only as a circuit multiaddr
//! through the relay. So if a libp2p `ping` round trip between them ever succeeds, it can only
//! have crossed the relayed circuit — proving `RelayServer` forwards a real, independent
//! peer-to-peer connection end to end, structurally blind to its (Noise-encrypted) contents.
//!
//! `src`/`dst` here are minimal **test-only** libp2p peer swarms built directly in this file —
//! they are not part of `relay`'s public API (a relay forwards; it is not itself a mesh-node
//! library). Unlike DCUtR (which envoir's own test suite honestly `#[ignore]`s — hole-punch
//! *upgrade* needs two distinct real NATs, unreproducible on loopback), a Circuit Relay v2
//! reservation + relayed connection is fully exercisable on loopback (envoir's own test proves
//! this reliably, not `#[ignore]`d), so this test runs normally.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, ping, tcp, yamux};
use libp2p::{Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc;

use relay::RelayServer;

/// A generous loopback timeout: real dialing + Noise handshake + Yamux + a relay reservation
/// take tens of ms, occasionally more under load; poll loops below spin up to this bound (same
/// value dmtap-p2p's own relay test uses).
const SPIN: Duration = Duration::from_secs(15);

/// A minimal libp2p peer for this test: Circuit Relay v2 **client** role (to reserve a slot on /
/// dial through `RelayServer`) + identify (required in practice for relay to work) + ping (the
/// liveness protocol whose successful round trip is this test's proof that bytes crossed the
/// circuit). Distinct from [`relay::server`]'s `RelayBehaviour`, which runs the relay **server**
/// role only and no application protocol at all.
#[derive(NetworkBehaviour)]
struct PeerBehaviour {
    relay_client: libp2p::relay::client::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

fn build_peer_swarm() -> Swarm<PeerBehaviour> {
    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .expect("tcp transport")
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .expect("relay client transport")
        .with_behaviour(|key, relay_client| {
            let identify = identify::Behaviour::new(identify::Config::new(
                "/wakala/relay-test/id/1.0.0".to_string(),
                key.public(),
            ));
            // Short interval + timeout: the default ping cadence is tuned for a long-lived
            // production connection, not a test that wants a fast, unambiguous "did it cross the
            // circuit" signal.
            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_millis(100))
                    .with_timeout(Duration::from_secs(5)),
            );
            PeerBehaviour { relay_client, identify, ping }
        })
        .expect("peer behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

enum PeerCommand {
    Dial(Multiaddr),
}

/// A running test peer + its background swarm task, following the exact same synchronous-handle/
/// async-task-behind-a-channel shape [`relay::server::RelayServer`] uses (and dmtap-p2p before
/// it) — kept local to this test file since it is test-only scaffolding, not crate API.
struct TestPeer {
    peer_id: PeerId,
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
    ping_ok: Arc<Mutex<bool>>,
    cmd_tx: mpsc::UnboundedSender<PeerCommand>,
    _runtime: tokio::runtime::Runtime,
}

impl TestPeer {
    fn start(listen_on: &[Multiaddr]) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let listeners: Arc<Mutex<Vec<Multiaddr>>> = Arc::new(Mutex::new(Vec::new()));
        let ping_ok = Arc::new(Mutex::new(false));

        let listen_on = listen_on.to_vec();
        let (listeners_t, ping_ok_t) = (listeners.clone(), ping_ok.clone());
        let peer_id = runtime.block_on(async move {
            let mut swarm = build_peer_swarm();
            for addr in &listen_on {
                swarm.listen_on(addr.clone()).expect("listen_on");
            }
            let peer_id = *swarm.local_peer_id();
            tokio::spawn(peer_loop(swarm, cmd_rx, listeners_t, ping_ok_t));
            peer_id
        });

        TestPeer {
            peer_id,
            listeners,
            ping_ok,
            cmd_tx,
            _runtime: runtime,
        }
    }

    fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn listeners(&self) -> Vec<Multiaddr> {
        self.listeners.lock().unwrap().clone()
    }

    /// Find this peer's confirmed reservation address (the one carrying `/p2p-circuit`), waiting
    /// up to `timeout` for the relay to ack the reservation.
    fn wait_for_circuit_listener(&self, timeout: Duration) -> Multiaddr {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(a) = self
                .listeners()
                .into_iter()
                .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)))
            {
                return a;
            }
            if std::time::Instant::now() >= deadline {
                panic!("no circuit listen addr reported within {timeout:?}: {:?}", self.listeners());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(PeerCommand::Dial(addr));
    }

    fn wait_for_ping_ok(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *self.ping_ok.lock().unwrap() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

async fn peer_loop(
    mut swarm: Swarm<PeerBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<PeerCommand>,
    listeners: Arc<Mutex<Vec<Multiaddr>>>,
    ping_ok: Arc<Mutex<bool>>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PeerCommand::Dial(addr)) => {
                        let _ = swarm.dial(addr);
                    }
                    None => return,
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let full = address.clone().with_p2p(*swarm.local_peer_id()).unwrap_or(address);
                        listeners.lock().unwrap().push(full);
                    }
                    SwarmEvent::Behaviour(PeerBehaviourEvent::Ping(ev)) => {
                        if ev.result.is_ok() {
                            *ping_ok.lock().unwrap() = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// THE headline test: a real `RelayServer` forwards a real connection between two peers that
/// have no other route to each other.
#[test]
fn ping_crosses_the_relay_circuit_between_two_peers_with_no_direct_route() {
    // A real `RelayServer` (the crate's own production type, not test scaffolding).
    let relay_srv =
        RelayServer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]).expect("relay starts");
    let relay_addr = relay_srv
        .wait_for_listener(SPIN)
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("relay bound a tcp listener");
    // Opt the relay in to handing out a dialable address in reservation acks (see
    // `RelayServer::add_external_address`'s doc comment for why this is required, not optional).
    relay_srv.add_external_address(relay_addr.clone());

    // `dst`'s ONLY listen address is a reservation request on the relay — it never binds a plain
    // TCP listener of its own, exactly like a node with no directly-reachable address.
    let circuit_listen: Multiaddr = relay_addr.clone().with(libp2p::multiaddr::Protocol::P2pCircuit);
    let dst = TestPeer::start(&[circuit_listen]);
    let dst_circuit_addr = dst.wait_for_circuit_listener(SPIN);
    assert!(
        dst_circuit_addr.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)),
        "the confirmed reservation address should still carry /p2p-circuit: {dst_circuit_addr}"
    );
    assert_ne!(dst.peer_id(), relay_srv.peer_id());

    // `src` has an ordinary loopback listener but is never told about it — `dst`'s circuit
    // address is the only route `src` is ever given.
    let src = TestPeer::start(&["/ip4/127.0.0.1/tcp/0".parse().unwrap()]);
    src.dial(dst_circuit_addr);

    assert!(
        src.wait_for_ping_ok(SPIN),
        "a ping between src and dst should cross the Circuit-Relay-v2 hop and succeed"
    );
}
