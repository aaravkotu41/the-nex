//! Every frame the wearable sends looks like an ordinary step-counter advertisement: the same
//! header, the same length and the same fixed cadence. An SOS hides in the sealed "wellness
//! extension" that every frame carries; without the pairing key it is indistinguishable from the
//! random filler of a normal frame.

use crate::ephemeral_crypto::{
    self, LocationFix, SealedBox, SessionKey, NONCE_LEN, TAG_LEN, TOKEN_LEN,
};
use serde::{Deserialize, Serialize};

/// Bluetooth SIG company identifier reserved for internal use and testing.
pub const COMPANY_ID: u16 = 0xFFFF;
pub const AD_TYPE_MANUFACTURER: u8 = 0xFF;
pub const FRAME_TYPE_ACTIVITY: u8 = 0x01;
/// AD length, AD type, company id (2), frame type, sequence, steps (4), heart rate, battery.
pub const HEADER_LEN: usize = 12;
pub const PLAINTEXT_LEN: usize = 40;
pub const EXTENSION_LEN: usize = NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;
/// Fits a BLE 5 extended advertisement.
pub const FRAME_LEN: usize = HEADER_LEN + EXTENSION_LEN;

const KIND_WELLNESS: u8 = 0;
const KIND_DISTRESS: u8 = 1;

/// The benign fitness data every frame shows in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Telemetry {
    pub sequence: u8,
    pub steps: u32,
    pub heart_rate: u8,
    pub battery: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Wellness,
    Distress {
        counter: u16,
        token: [u8; TOKEN_LEN],
        fix: LocationFix,
    },
}

/// Random filler; the kind byte is encrypted like everything else.
pub fn write_wellness_plaintext(out: &mut [u8; PLAINTEXT_LEN]) {
    out.copy_from_slice(&ephemeral_crypto::random_bytes::<PLAINTEXT_LEN>());
    out[0] = KIND_WELLNESS;
}

pub fn write_distress_plaintext(
    out: &mut [u8; PLAINTEXT_LEN],
    counter: u16,
    token: &[u8; TOKEN_LEN],
    fix: &LocationFix,
) {
    out[0] = KIND_DISTRESS;
    out[1..3].copy_from_slice(&counter.to_le_bytes());
    out[3] = 0;
    out[4..20].copy_from_slice(token);
    out[20..24].copy_from_slice(&fix.lat_e7.to_le_bytes());
    out[24..28].copy_from_slice(&fix.lon_e7.to_le_bytes());
    out[28..30].copy_from_slice(&fix.accuracy_m.to_le_bytes());
    out[30..38].copy_from_slice(&fix.unix_ms.to_le_bytes());
    out[38..40].copy_from_slice(&ephemeral_crypto::random_bytes::<2>());
}

pub fn encode_frame(
    telemetry: &Telemetry,
    plaintext: &[u8; PLAINTEXT_LEN],
    key: &SessionKey,
) -> Vec<u8> {
    let sealed = ephemeral_crypto::seal(key, plaintext);
    let mut frame = Vec::with_capacity(FRAME_LEN);
    frame.push((FRAME_LEN - 1) as u8);
    frame.push(AD_TYPE_MANUFACTURER);
    frame.extend_from_slice(&COMPANY_ID.to_le_bytes());
    frame.push(FRAME_TYPE_ACTIVITY);
    frame.push(telemetry.sequence);
    frame.extend_from_slice(&telemetry.steps.to_le_bytes());
    frame.push(telemetry.heart_rate);
    frame.push(telemetry.battery);
    frame.extend_from_slice(&sealed.nonce);
    frame.extend_from_slice(&sealed.ciphertext);
    frame.extend_from_slice(&sealed.tag);
    frame
}

/// What any observer can read from a frame.
pub fn parse_header(frame: &[u8]) -> Option<Telemetry> {
    if frame.len() != FRAME_LEN
        || usize::from(frame[0]) != FRAME_LEN - 1
        || frame[1] != AD_TYPE_MANUFACTURER
        || u16::from_le_bytes([frame[2], frame[3]]) != COMPANY_ID
        || frame[4] != FRAME_TYPE_ACTIVITY
    {
        return None;
    }
    Some(Telemetry {
        sequence: frame[5],
        steps: u32::from_le_bytes([frame[6], frame[7], frame[8], frame[9]]),
        heart_rate: frame[10],
        battery: frame[11],
    })
}

/// The opaque sealed extension that relays carry.
pub fn extension(frame: &[u8]) -> Option<SealedBox> {
    parse_header(frame)?;
    let ext = &frame[HEADER_LEN..];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&ext[..NONCE_LEN]);
    let ciphertext = ext[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN].to_vec();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ext[NONCE_LEN + PLAINTEXT_LEN..]);
    Some(SealedBox {
        nonce,
        ciphertext,
        tag,
    })
}

/// Only the holder of the epoch key can tell a distress frame from a wellness frame.
pub fn decode_extension(sealed: &SealedBox, key: &SessionKey) -> Option<Decoded> {
    if sealed.ciphertext.len() != PLAINTEXT_LEN {
        return None;
    }
    let plain = ephemeral_crypto::open(key, sealed)?;
    match plain[0] {
        KIND_WELLNESS => Some(Decoded::Wellness),
        KIND_DISTRESS => {
            let mut token = [0u8; TOKEN_LEN];
            token.copy_from_slice(&plain[4..20]);
            let fix = LocationFix {
                lat_e7: i32::from_le_bytes(<[u8; 4]>::try_from(&plain[20..24]).ok()?),
                lon_e7: i32::from_le_bytes(<[u8; 4]>::try_from(&plain[24..28]).ok()?),
                accuracy_m: u16::from_le_bytes([plain[28], plain[29]]),
                unix_ms: i64::from_le_bytes(<[u8; 8]>::try_from(&plain[30..38]).ok()?),
            };
            Some(Decoded::Distress {
                counter: u16::from_le_bytes([plain[1], plain[2]]),
                token,
                fix,
            })
        }
        _ => None,
    }
}

/// Frames leave on a fixed timetable whatever they carry, so timing the advertisements cannot
/// reveal when an SOS was sent. Missed slots are skipped, never sent in a burst.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CadenceScheduler {
    interval_ms: u64,
    next_due_ms: u64,
}

impl CadenceScheduler {
    pub fn new(interval_ms: u64, start_ms: u64) -> Self {
        Self {
            interval_ms: interval_ms.max(1),
            next_due_ms: start_ms,
        }
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// True when a frame is due at `now_ms`; books the next slot.
    pub fn due(&mut self, now_ms: u64) -> bool {
        if now_ms < self.next_due_ms {
            return false;
        }
        let missed = (now_ms - self.next_due_ms) / self.interval_ms;
        self.next_due_ms += (missed + 1) * self.interval_ms;
        true
    }
}
