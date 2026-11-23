//! Multi-hop store-and-forward relay of sealed frames, simulated in rounds.
//!
//! Relays forward every sealed extension they hear (they cannot tell an SOS from wellness data),
//! drop duplicates by nonce and stop at the hop limit. An envelope carries only its TTL and the
//! opaque sealed bytes: no origin, destination or relay identity. The responder sink is an
//! in-memory stand-in for a trusted contact; nothing is dispatched anywhere.

use crate::disguise::{self, Decoded};
use crate::ephemeral_crypto::{
    self, KeyRatchet, LocationFix, SealedBox, SessionKey, TokenLedger, KEY_LEN, NONCE_LEN,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEnvelope {
    pub ttl: u8,
    pub sealed: SealedBox,
}

impl MeshEnvelope {
    pub fn from_frame(frame: &[u8], ttl: u8) -> Option<Self> {
        Some(Self {
            ttl,
            sealed: disguise::extension(frame)?,
        })
    }

    pub fn id(&self) -> [u8; NONCE_LEN] {
        self.sealed.nonce
    }

    /// Wire form: TTL, then the sealed extension. Nothing else.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + disguise::EXTENSION_LEN);
        out.push(self.ttl);
        out.extend_from_slice(&self.sealed.nonce);
        out.extend_from_slice(&self.sealed.ciphertext);
        out.extend_from_slice(&self.sealed.tag);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDecision {
    /// Stored for forwarding.
    Forward,
    /// Accepted but the hop limit is used up.
    Exhausted,
    Duplicate,
}

/// Remembers recently seen nonces (bounded) so loops and multi-path copies die out.
#[derive(Debug, Clone)]
pub struct RelayNode {
    seen: HashSet<[u8; NONCE_LEN]>,
    order: VecDeque<[u8; NONCE_LEN]>,
    capacity: usize,
}

impl RelayNode {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Records the envelope's nonce; true if it was new.
    pub fn remember(&mut self, id: [u8; NONCE_LEN]) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    pub fn receive(&mut self, envelope: &MeshEnvelope) -> RelayDecision {
        if !self.remember(envelope.id()) {
            RelayDecision::Duplicate
        } else if envelope.ttl == 0 {
            RelayDecision::Exhausted
        } else {
            RelayDecision::Forward
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SosAlert {
    pub fix: LocationFix,
    pub epoch: u64,
    pub counter: u16,
    pub hops: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Sos,
    Wellness,
    Rejected,
}

/// Simulated trusted contact holding the pairing secret.
pub struct ResponderSink {
    ratchet: KeyRatchet,
    /// Keys of epochs skipped while catching up, kept briefly for frames that arrive late.
    skipped: VecDeque<SessionKey>,
    ledger: TokenLedger,
    pub alerts: Vec<SosAlert>,
    pub wellness_discarded: u64,
    pub rejected: u64,
}

const LOOKAHEAD_EPOCHS: u64 = 64;
const SKIPPED_KEYS: usize = 8;

impl ResponderSink {
    pub fn new(pairing_secret: &[u8; KEY_LEN]) -> Self {
        Self {
            ratchet: KeyRatchet::from_pairing_secret(pairing_secret),
            skipped: VecDeque::new(),
            ledger: TokenLedger::default(),
            alerts: Vec::new(),
            wellness_discarded: 0,
            rejected: 0,
        }
    }

    pub fn deliver(&mut self, sealed: &SealedBox, hops: u8) -> Delivery {
        let mut found: Option<(Decoded, SessionKey)> = None;
        for key in &self.skipped {
            if let Some(decoded) = disguise::decode_extension(sealed, key) {
                found = Some((decoded, key.clone()));
                break;
            }
        }
        if found.is_none() {
            let mut probe = self.ratchet.clone();
            let mut passed: Vec<SessionKey> = Vec::new();
            for _ in 0..=LOOKAHEAD_EPOCHS {
                if let Some(decoded) = disguise::decode_extension(sealed, probe.current()) {
                    found = Some((decoded, probe.current().clone()));
                    for key in passed.drain(..) {
                        self.skipped.push_back(key);
                        while self.skipped.len() > SKIPPED_KEYS {
                            self.skipped.pop_front();
                        }
                    }
                    self.ratchet = probe;
                    break;
                }
                passed.push(probe.current().clone());
                probe.advance();
            }
        }
        let Some((decoded, key)) = found else {
            self.rejected += 1;
            return Delivery::Rejected;
        };
        match decoded {
            Decoded::Wellness => {
                self.wellness_discarded += 1;
                Delivery::Wellness
            }
            Decoded::Distress {
                counter,
                token,
                fix,
            } => {
                let expected = ephemeral_crypto::distress_token(&key, counter);
                if ephemeral_crypto::ct_eq(&expected, &token) && self.ledger.redeem(&token) {
                    self.alerts.push(SosAlert {
                        fix,
                        epoch: key.epoch(),
                        counter,
                        hops,
                    });
                    Delivery::Sos
                } else {
                    self.rejected += 1;
                    Delivery::Rejected
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub a: usize,
    pub b: usize,
    /// The link only exists from this round on (a relay walking into range).
    pub up_from_round: u32,
}

impl Link {
    pub fn new(a: usize, b: usize) -> Self {
        Self {
            a,
            b,
            up_from_round: 0,
        }
    }

    fn other(&self, node: usize) -> Option<usize> {
        if self.a == node {
            Some(self.b)
        } else if self.b == node {
            Some(self.a)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopEvent {
    pub round: u32,
    pub from: usize,
    pub to: usize,
    pub ttl: u8,
    pub outcome: String,
}

/// Observable side effects on the paired phone. A silent SOS must leave this untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneEffects {
    pub notifications: u32,
    pub vibrations: u32,
    pub sounds: u32,
    pub screen_wakes: u32,
}

impl PhoneEffects {
    pub fn is_silent(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshStats {
    pub rounds: u32,
    pub transmissions: u64,
    pub delivered_sos: usize,
    pub wellness_discarded: u64,
    pub rejected: u64,
    pub duplicates_dropped: u64,
    pub ttl_exhausted: u64,
    /// Transmissions that waited in a relay's store for a link to come up.
    pub stored_then_forwarded: u64,
    pub max_hops: u8,
}

struct Stored {
    envelope: MeshEnvelope,
    from: Option<usize>,
    sent_to: Vec<usize>,
    stored_round: u32,
    hops: u8,
}

pub struct MeshSim {
    nodes: Vec<RelayNode>,
    links: Vec<Link>,
    stores: Vec<Vec<Stored>>,
    pub responder: usize,
    pub sink: ResponderSink,
    pub events: Vec<HopEvent>,
    pub stats: MeshStats,
}

impl MeshSim {
    pub fn new(node_count: usize, links: Vec<Link>, responder: usize, sink: ResponderSink) -> Self {
        Self {
            nodes: (0..node_count).map(|_| RelayNode::new(4096)).collect(),
            links,
            stores: (0..node_count).map(|_| Vec::new()).collect(),
            responder,
            sink,
            events: Vec::new(),
            stats: MeshStats::default(),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The wearable (or any node) puts an envelope on the air.
    pub fn inject(&mut self, source: usize, envelope: MeshEnvelope) {
        if source >= self.nodes.len() || !self.nodes[source].remember(envelope.id()) {
            return;
        }
        self.stores[source].push(Stored {
            envelope,
            from: None,
            sent_to: Vec::new(),
            stored_round: self.stats.rounds,
            hops: 0,
        });
    }

    fn neighbours(&self, node: usize) -> Vec<usize> {
        let mut out: Vec<usize> = self.links.iter().filter_map(|l| l.other(node)).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Runs rounds until nothing is left to forward (or `max_rounds`).
    pub fn run(&mut self, max_rounds: u32) -> &MeshStats {
        for _ in 0..max_rounds {
            let round = self.stats.rounds;
            self.stats.rounds += 1;
            let mut deliveries: Vec<(usize, usize, MeshEnvelope, u8)> = Vec::new();
            for node in 0..self.nodes.len() {
                let up: Vec<usize> = self
                    .links
                    .iter()
                    .filter(|l| l.up_from_round <= round)
                    .filter_map(|l| l.other(node))
                    .collect();
                for item in &mut self.stores[node] {
                    if item.envelope.ttl == 0 {
                        continue;
                    }
                    for &peer in &up {
                        if Some(peer) == item.from || item.sent_to.contains(&peer) {
                            continue;
                        }
                        item.sent_to.push(peer);
                        if round > item.stored_round {
                            self.stats.stored_then_forwarded += 1;
                        }
                        let mut copy = item.envelope.clone();
                        copy.ttl -= 1;
                        deliveries.push((node, peer, copy, item.hops + 1));
                    }
                }
            }
            for node in 0..self.nodes.len() {
                let neighbours = self.neighbours(node);
                self.stores[node].retain(|item| {
                    item.envelope.ttl > 0
                        && neighbours
                            .iter()
                            .any(|n| Some(*n) != item.from && !item.sent_to.contains(n))
                });
            }
            if deliveries.is_empty() && self.stores.iter().all(Vec::is_empty) {
                break;
            }
            for (from, to, envelope, hops) in deliveries {
                self.stats.transmissions += 1;
                let ttl = envelope.ttl;
                let outcome = self.receive(from, to, envelope, hops, round + 1);
                self.events.push(HopEvent {
                    round,
                    from,
                    to,
                    ttl,
                    outcome: outcome.to_string(),
                });
            }
        }
        &self.stats
    }

    fn receive(
        &mut self,
        from: usize,
        to: usize,
        envelope: MeshEnvelope,
        hops: u8,
        next_round: u32,
    ) -> &'static str {
        if to == self.responder {
            if !self.nodes[to].remember(envelope.id()) {
                self.stats.duplicates_dropped += 1;
                return "duplicate";
            }
            return match self.sink.deliver(&envelope.sealed, hops) {
                Delivery::Sos => {
                    self.stats.delivered_sos += 1;
                    self.stats.max_hops = self.stats.max_hops.max(hops);
                    "sos_delivered"
                }
                Delivery::Wellness => {
                    self.stats.wellness_discarded += 1;
                    "wellness_discarded"
                }
                Delivery::Rejected => {
                    self.stats.rejected += 1;
                    "rejected"
                }
            };
        }
        match self.nodes[to].receive(&envelope) {
            RelayDecision::Duplicate => {
                self.stats.duplicates_dropped += 1;
                "duplicate"
            }
            RelayDecision::Exhausted => {
                self.stats.ttl_exhausted += 1;
                "ttl_exhausted"
            }
            RelayDecision::Forward => {
                self.stores[to].push(Stored {
                    envelope,
                    from: Some(from),
                    sent_to: Vec::new(),
                    stored_round: next_round,
                    hops,
                });
                "stored"
            }
        }
    }
}
