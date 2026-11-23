//! AegisMesh: a silent SOS for everyday wearables (ring, bracelet, clothing tag).
//!
//! Everything here is a local simulation: radios, relays, the responder and the GNSS fix are
//! in-memory models. Nothing contacts an emergency service, a network or a real device.

pub mod camera_taps;
pub mod console;
pub mod device;
pub mod disguise;
pub mod ephemeral_crypto;
pub mod mesh_relay;
pub mod scenario;
pub mod tap_classifier;
