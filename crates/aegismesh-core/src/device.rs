//! The wearable: recognises the tap rhythm, takes one location fix, sends it inside the next
//! ordinary-looking frame and wipes it. It keeps no location history and offers no channel for
//! anyone to pull data, audio or extra beacons out of it.

use crate::disguise::{self, CadenceScheduler, Telemetry, PLAINTEXT_LEN};
use crate::ephemeral_crypto::{
    self, DispatchBuffers, KeyRatchet, LocationFix, SessionKey, WipeReport, KEY_LEN,
};
use crate::mesh_relay::PhoneEffects;
use crate::tap_classifier::{self, RhythmProfile, TapVerdict};
use serde::{Deserialize, Serialize};

/// Benign frames before the session key rotates even without an SOS.
pub const ROTATE_EVERY_FRAMES: u32 = 8;
pub const ADVERTISING_INTERVAL_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFactor {
    Ring,
    Bracelet,
    ClothingTag,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FormSpec {
    pub form: FormFactor,
    pub label: &'static str,
    pub tap_surface: &'static str,
    pub sensor: &'static str,
    pub battery_mah: u16,
    pub radio_range_m: u16,
}

impl FormFactor {
    pub const ALL: [FormFactor; 3] = [
        FormFactor::Ring,
        FormFactor::Bracelet,
        FormFactor::ClothingTag,
    ];

    pub fn parse(name: &str) -> Option<Self> {
        match name
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "ring" => Some(Self::Ring),
            "bracelet" | "band" => Some(Self::Bracelet),
            "clothing_tag" | "tag" | "clothing" => Some(Self::ClothingTag),
            _ => None,
        }
    }

    pub fn spec(self) -> FormSpec {
        match self {
            Self::Ring => FormSpec {
                form: self,
                label: "Ring",
                tap_surface: "thumb against palm or finger",
                sensor: "3-axis accelerometer",
                battery_mah: 22,
                radio_range_m: 10,
            },
            Self::Bracelet => FormSpec {
                form: self,
                label: "Bracelet",
                tap_surface: "fingers against the band",
                sensor: "3-axis accelerometer",
                battery_mah: 120,
                radio_range_m: 30,
            },
            Self::ClothingTag => FormSpec {
                form: self,
                label: "Clothing Tag",
                tap_surface: "through fabric",
                sensor: "piezo tap sensor",
                battery_mah: 40,
                radio_range_m: 15,
            },
        }
    }

    /// Fabric damps taps, so a clothing tag tolerates slower, looser rhythms.
    pub fn default_profile(self) -> RhythmProfile {
        let mut profile = RhythmProfile::triple_tap();
        match self {
            Self::Ring => {}
            Self::Bracelet => profile.max_total_ms = 1000.0,
            Self::ClothingTag => {
                profile.max_total_ms = 1100.0;
                profile.min_gap_ms = 80.0;
                profile.tolerance = 0.18;
            }
        }
        let burst_gap = profile.burst_gap_ms();
        profile.quiet_ms = profile.quiet_ms.max(burst_gap * 1.2);
        profile
    }
}

/// Fictional, fixed coordinates: the simulation never reads a real position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedGnss {
    pub lat_e7: i32,
    pub lon_e7: i32,
}

impl Default for SimulatedGnss {
    fn default() -> Self {
        Self {
            lat_e7: 123_456,
            lon_e7: -654_321,
        }
    }
}

impl SimulatedGnss {
    pub fn fix(&self, unix_ms: i64) -> LocationFix {
        LocationFix {
            lat_e7: self.lat_e7,
            lon_e7: self.lon_e7,
            accuracy_m: 8,
            unix_ms,
        }
    }
}

/// Requests anyone (a paired phone app, an abuser's app, a malicious relay) can send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "query")]
pub enum ExternalQuery {
    Status,
    LocationHistory,
    LastKnownLocation,
    StartAudioCapture,
    ForceBeacon { interval_ms: u64 },
    ExportKeys,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "response")]
pub enum QueryResponse {
    Status {
        battery: u8,
        steps: u32,
        form: FormFactor,
    },
    Denied {
        reason: String,
    },
}

pub struct Wearable {
    pub form: FormFactor,
    profile: RhythmProfile,
    ratchet: KeyRatchet,
    counter: u16,
    telemetry: Telemetry,
    cadence: CadenceScheduler,
    pending: Option<DispatchBuffers>,
    frames_in_epoch: u32,
    last_wipe: Option<WipeReport>,
    phone: PhoneEffects,
    sos_sent: u32,
}

impl Wearable {
    pub fn new(form: FormFactor, pairing_secret: &[u8; KEY_LEN], start_ms: u64) -> Self {
        Self {
            form,
            profile: form.default_profile(),
            ratchet: KeyRatchet::from_pairing_secret(pairing_secret),
            counter: 0,
            telemetry: Telemetry {
                sequence: 0,
                steps: 4_210,
                heart_rate: 72,
                battery: 86,
            },
            cadence: CadenceScheduler::new(ADVERTISING_INTERVAL_MS, start_ms),
            pending: None,
            frames_in_epoch: 0,
            last_wipe: None,
            phone: PhoneEffects::default(),
            sos_sent: 0,
        }
    }

    pub fn profile(&self) -> &RhythmProfile {
        &self.profile
    }

    pub fn set_profile(&mut self, profile: RhythmProfile) -> Result<(), String> {
        profile.validate()?;
        self.profile = profile;
        Ok(())
    }

    /// Feeds recorded tap times. On a match one fix is taken and queued for the next slot;
    /// nothing is shown, played or vibrated anywhere.
    pub fn on_taps(
        &mut self,
        taps_ms: &[f64],
        gnss: &SimulatedGnss,
        now_unix_ms: i64,
    ) -> TapVerdict {
        let verdict = tap_classifier::classify(taps_ms, &self.profile);
        if verdict.accepted && self.pending.is_none() {
            self.pending = Some(DispatchBuffers::new(gnss.fix(now_unix_ms)));
        }
        verdict
    }

    /// A trigger recognised on the user's own camera (an emergency sign or expression): takes
    /// one fix and queues the same silent SOS as the tap rhythm. False if one is already queued.
    pub fn trigger_sos(&mut self, gnss: &SimulatedGnss, now_unix_ms: i64) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.pending = Some(DispatchBuffers::new(gnss.fix(now_unix_ms)));
        true
    }

    pub fn sos_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Radio loop: a frame when an advertising slot is due, whatever it carries.
    pub fn tick(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        if !self.cadence.due(now_ms) {
            return None;
        }
        self.telemetry.sequence = self.telemetry.sequence.wrapping_add(1);
        self.telemetry.steps = self.telemetry.steps.wrapping_add(2);
        let frame = if let Some(mut buffers) = self.pending.take() {
            buffers.token = ephemeral_crypto::distress_token(self.ratchet.current(), self.counter);
            disguise::write_distress_plaintext(
                &mut buffers.plaintext,
                self.counter,
                &buffers.token,
                &buffers.fix,
            );
            let frame =
                disguise::encode_frame(&self.telemetry, &buffers.plaintext, self.ratchet.current());
            self.counter = self.counter.wrapping_add(1);
            self.sos_sent += 1;
            self.last_wipe = Some(buffers.wipe());
            drop(buffers);
            // A new key for whatever comes next: this SOS can never be decrypted from the device.
            self.ratchet.advance();
            self.frames_in_epoch = 0;
            frame
        } else {
            let mut plaintext = [0u8; PLAINTEXT_LEN];
            disguise::write_wellness_plaintext(&mut plaintext);
            let frame = disguise::encode_frame(&self.telemetry, &plaintext, self.ratchet.current());
            self.frames_in_epoch += 1;
            if self.frames_in_epoch >= ROTATE_EVERY_FRAMES {
                self.ratchet.advance();
                self.frames_in_epoch = 0;
            }
            frame
        };
        Some(frame)
    }

    pub fn last_wipe(&self) -> Option<&WipeReport> {
        self.last_wipe.as_ref()
    }

    pub fn sos_sent(&self) -> u32 {
        self.sos_sent
    }

    /// Location bytes still held anywhere on the device.
    pub fn retained_location_bytes(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, DispatchBuffers::sensitive_bytes)
    }

    pub fn cadence_interval_ms(&self) -> u64 {
        self.cadence.interval_ms()
    }

    pub fn epoch(&self) -> u64 {
        self.ratchet.epoch()
    }

    /// What someone who seizes the device can read: only the current key.
    pub fn seized_key(&self) -> SessionKey {
        self.ratchet.current().clone()
    }

    pub fn phone_effects(&self) -> &PhoneEffects {
        &self.phone
    }

    /// An ordinary, user-facing event, to show the phone-effects recorder does work.
    pub fn low_battery_warning(&mut self) {
        self.phone.notifications += 1;
        self.phone.vibrations += 1;
    }

    pub fn handle_query(&mut self, query: &ExternalQuery) -> QueryResponse {
        let denied = |reason: &str| QueryResponse::Denied {
            reason: reason.to_string(),
        };
        match query {
            ExternalQuery::Status => QueryResponse::Status {
                battery: self.telemetry.battery,
                steps: self.telemetry.steps,
                form: self.form,
            },
            ExternalQuery::LocationHistory | ExternalQuery::LastKnownLocation => {
                denied("no location is ever stored; a fix exists only until its frame is sent")
            }
            ExternalQuery::StartAudioCapture => {
                denied("the device has no microphone or audio path")
            }
            ExternalQuery::ForceBeacon { .. } => {
                denied("advertising cadence is fixed in firmware and cannot be changed remotely")
            }
            ExternalQuery::ExportKeys => denied("keys never leave the device"),
        }
    }
}
