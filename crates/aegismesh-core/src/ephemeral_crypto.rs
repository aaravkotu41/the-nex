//! Short-lived keys, one-time distress tokens and buffers that are wiped right after dispatch.
//!
//! Simulation-grade construction from SHA-256 only (the workspace's audited primitive): a hash
//! ratchet, a SHA-256 counter-mode keystream and an HMAC-SHA256 tag. Real hardware should use a
//! reviewed AEAD such as ChaCha20-Poly1305.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const TOKEN_LEN: usize = 16;
/// Bytes of sensitive state held while one SOS is in flight.
pub const LOCATION_BYTES: usize = 4 + 4 + 2 + 8;

/// Fresh bytes from the operating system's CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("operating system random number generator unavailable");
    out
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&sha256(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0u8; BLOCK]);
    let mut inner = Sha256::new();
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x36;
    }
    inner.update(pad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x5c;
    }
    outer.update(pad.as_slice());
    outer.update(inner_hash);
    outer.finalize().into()
}

/// Comparison whose duration does not depend on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One epoch's key. Zeroized when dropped or replaced.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    bytes: [u8; KEY_LEN],
    epoch: u64,
}

impl SessionKey {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn sub_key(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(sha256(&[label, self.bytes.as_slice()]))
    }

    /// Short public fingerprint for display; reveals nothing usable about the key.
    pub fn fingerprint(&self) -> String {
        let digest = self.sub_key(b"aegismesh/fingerprint");
        digest[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SessionKey(epoch {}, {})",
            self.epoch,
            self.fingerprint()
        )
    }
}

/// Hash ratchet: each step is one-way, so a seized device cannot recompute earlier keys.
#[derive(Clone, Debug)]
pub struct KeyRatchet {
    current: SessionKey,
}

impl KeyRatchet {
    pub fn from_pairing_secret(secret: &[u8; KEY_LEN]) -> Self {
        Self {
            current: SessionKey {
                bytes: sha256(&[b"aegismesh/epoch0".as_slice(), secret.as_slice()]),
                epoch: 0,
            },
        }
    }

    pub fn current(&self) -> &SessionKey {
        &self.current
    }

    pub fn epoch(&self) -> u64 {
        self.current.epoch
    }

    pub fn advance(&mut self) {
        let next = SessionKey {
            bytes: sha256(&[
                b"aegismesh/ratchet".as_slice(),
                self.current.bytes.as_slice(),
            ]),
            epoch: self.current.epoch + 1,
        };
        // Assigning drops (and so zeroizes) the previous key.
        self.current = next;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

fn keystream_xor(key: &[u8; 32], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    for (counter, chunk) in data.chunks_mut(32).enumerate() {
        let counter = (counter as u64).to_le_bytes();
        let mut block = sha256(&[
            b"aegismesh/ctr".as_slice(),
            key.as_slice(),
            nonce.as_slice(),
            counter.as_slice(),
        ]);
        for (byte, k) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= k;
        }
        block.zeroize();
    }
}

fn tag_for(key: &SessionKey, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mac = key.sub_key(b"aegismesh/mac");
    let full = hmac_sha256(mac.as_slice(), &[nonce.as_slice(), ciphertext]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

pub fn seal(key: &SessionKey, plaintext: &[u8]) -> SealedBox {
    let nonce = random_bytes::<NONCE_LEN>();
    let enc = key.sub_key(b"aegismesh/enc");
    let mut ciphertext = plaintext.to_vec();
    keystream_xor(&enc, &nonce, &mut ciphertext);
    let tag = tag_for(key, &nonce, &ciphertext);
    SealedBox {
        nonce,
        ciphertext,
        tag,
    }
}

/// None when the tag does not verify under `key` (wrong epoch, tampering or forgery).
pub fn open(key: &SessionKey, sealed: &SealedBox) -> Option<Zeroizing<Vec<u8>>> {
    let expected = tag_for(key, &sealed.nonce, &sealed.ciphertext);
    if !ct_eq(&expected, &sealed.tag) {
        return None;
    }
    let enc = key.sub_key(b"aegismesh/enc");
    let mut plaintext = Zeroizing::new(sealed.ciphertext.clone());
    keystream_xor(&enc, &sealed.nonce, &mut plaintext);
    Some(plaintext)
}

/// One-time token for distress `counter` in this epoch; the responder accepts each once.
pub fn distress_token(key: &SessionKey, counter: u16) -> [u8; TOKEN_LEN] {
    let mac = key.sub_key(b"aegismesh/token");
    let counter = counter.to_le_bytes();
    let full = hmac_sha256(mac.as_slice(), &[b"sos".as_slice(), counter.as_slice()]);
    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&full[..TOKEN_LEN]);
    token
}

/// Responder-side replay protection.
#[derive(Debug, Default)]
pub struct TokenLedger {
    redeemed: HashSet<[u8; TOKEN_LEN]>,
}

impl TokenLedger {
    /// True the first time a token is seen, false for every replay.
    pub fn redeem(&mut self, token: &[u8; TOKEN_LEN]) -> bool {
        self.redeemed.insert(*token)
    }

    pub fn len(&self) -> usize {
        self.redeemed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.redeemed.is_empty()
    }
}

/// A position fix. Integer degrees * 1e7, like GNSS receivers report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LocationFix {
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub accuracy_m: u16,
    pub unix_ms: i64,
}

impl LocationFix {
    pub fn is_zero(&self) -> bool {
        self.lat_e7 == 0 && self.lon_e7 == 0 && self.accuracy_m == 0 && self.unix_ms == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeReport {
    pub wiped_bytes: usize,
    pub elapsed_ns: u64,
    pub verified_zero: bool,
}

/// Everything sensitive that exists while one SOS is being sent. Wiped right after the frame
/// leaves the radio, and again on drop.
pub struct DispatchBuffers {
    pub fix: LocationFix,
    pub token: [u8; TOKEN_LEN],
    pub plaintext: [u8; crate::disguise::PLAINTEXT_LEN],
}

impl DispatchBuffers {
    pub fn new(fix: LocationFix) -> Self {
        Self {
            fix,
            token: [0u8; TOKEN_LEN],
            plaintext: [0u8; crate::disguise::PLAINTEXT_LEN],
        }
    }

    pub fn total_bytes(&self) -> usize {
        LOCATION_BYTES + TOKEN_LEN + self.plaintext.len()
    }

    /// Bytes still holding anything other than zero.
    pub fn sensitive_bytes(&self) -> usize {
        let fix = [
            self.fix.lat_e7 != 0,
            self.fix.lon_e7 != 0,
            self.fix.accuracy_m != 0,
            self.fix.unix_ms != 0,
        ]
        .iter()
        .filter(|set| **set)
        .count();
        fix + self.token.iter().filter(|b| **b != 0).count()
            + self.plaintext.iter().filter(|b| **b != 0).count()
    }

    pub fn wipe(&mut self) -> WipeReport {
        let started = Instant::now();
        self.fix.zeroize();
        self.token.zeroize();
        self.plaintext.zeroize();
        let elapsed = started.elapsed().as_nanos();
        WipeReport {
            wiped_bytes: self.total_bytes(),
            elapsed_ns: u64::try_from(elapsed).unwrap_or(u64::MAX),
            verified_zero: self.sensitive_bytes() == 0,
        }
    }
}

impl Drop for DispatchBuffers {
    fn drop(&mut self) {
        self.wipe();
    }
}
