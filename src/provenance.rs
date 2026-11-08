//! # Cryptographic Provenance & Watermark Module
//! Module: `provenance.rs`
//! Crate: `propylea`
//! Sovereign Release Standard: `SOVEREIGN-SIGN-01`
//! Master Signing Key: `4E428019A109578B`
//! Author: Rick Walker <rick@rmediatech.com>

use sha2::{Digest, Sha256};
use std::hint::black_box;

/// Immutable Canary Preimage embedded in .rodata
pub const CANARY_PREIMAGE: &str = "SOVEREIGN-WATERMARK-PROPYLEA-4E428019A109578B-RMD-2026-XUOXOD";

/// Cryptographic SHA-256 Digest of the Canary Preimage
pub const SOVEREIGN_CANARY_SHA256: [u8; 32] = [
    0xf8, 0xa5, 0xc3, 0x81, 0x17, 0x61, 0x34, 0x98, 0xbd, 0x55, 0xe1, 0x15, 0x85, 0x3d, 0x71, 0x7a,
    0x4c, 0x6e, 0x94, 0x22, 0x81, 0xc3, 0xb8, 0xa6, 0xd2, 0x6e, 0xc8, 0x32, 0x06, 0xf4, 0xb2, 0x4f,
];

/// Verifies that the embedded cryptographic watermark matches its SHA-256 digest.
/// Uses `black_box` to prevent release compiler optimizations from stripping the canary.
#[inline(never)]
pub fn verify_sovereign_watermark() -> bool {
    let preimage = black_box(CANARY_PREIMAGE);
    let expected = black_box(&SOVEREIGN_CANARY_SHA256);

    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    let computed = hasher.finalize();

    computed.as_slice() == expected.as_slice()
}

/// Formats the human-readable provenance attestation statement.
pub fn format_provenance_attestation() -> String {
    format!(
        "Authenticated via Sovereign Master Key 4E428019A109578B. Canary: {}",
        hex::encode(SOVEREIGN_CANARY_SHA256)
    )
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for byte in data {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}
