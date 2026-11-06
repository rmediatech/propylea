//! # Fleet Deception & Quarantine Mesh Synchronization Engine (`mesh_sync.rs`)
//!
//! Implements Phase 3 of `SOVEREIGN-TRINITY-ULTIMATE-01`:
//! 1. **Cross-Node Canary, Decoy Trap & CIDR Quarantine Synchronization**:
//!    Synchronizes active `QuarantineRecord`s, `phylax::XdpWireShield` LPM bans, and promoted
//!    `ThreatHarvester` zero-day decoy trap URIs across fleet nodes (Node 1 `lin`, Node 2, Outposts).
//! 2. **Cryptographic HMAC-SHA256 Envelope Authentication & Anti-Replay Guard**:
//!    Every `MeshSyncEnvelope` is signed over canonical payload bytes using RFC 2104 HMAC-SHA256
//!    and verified in constant time with a strict $\pm 60\text{s}$ replay window.
//! 3. **Trusted CIDR & RFC 1918 Collateral Containment**:
//!    Refuses to ingest quarantine bans targeting loopback, RFC 1918 private LANs, or configured
//!    operator `trusted_cidrs`, preventing mesh self-lockout even under misconfiguration.

use crate::defense::EdgeDefense;
use crate::quarantine::QuarantineRecord;
use ipnet::IpNet;
use phylax::decoy_uri::DecoyCategory;
use phylax::xdp_shield::XdpBanReason;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Maximum allowed clock skew / replay window for mesh envelopes (60 seconds)
pub const MESH_REPLAY_WINDOW_MS: u64 = 60_000;
/// Hard ceiling on envelope byte size over TCP (1 MiB) to defeat allocation bombs
pub const MAX_MESH_ENVELOPE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum MeshSyncError {
    #[error("I/O error during mesh sync: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("HMAC-SHA256 cryptographic signature verification failed")]
    SignatureInvalid,
    #[error(
        "Mesh sync envelope timestamp ({envelope_ms}) outside replay window vs local ({now_ms})"
    )]
    ReplayWindowExceeded { envelope_ms: u64, now_ms: u64 },
    #[error("Mesh sync payload exceeded safety ceiling ({0} bytes)")]
    PayloadTooLarge(usize),
}

/// Promoted zero-day decoy trap path synchronized across fleet nodes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedDecoyTrap {
    pub path: String,
    pub category: DecoyCategory,
    pub distinct_subnets: usize,
    pub promoted_at_ms: u64,
}

/// Unsigned inner payload of a fleet synchronization frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSyncPayload {
    pub node_id: String,
    pub timestamp_ms: u64,
    pub quarantine_bans: Vec<QuarantineRecord>,
    pub promoted_decoys: Vec<PromotedDecoyTrap>,
}

/// Cryptographically signed Fleet Deception Mesh Synchronization Envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSyncEnvelope {
    pub payload: MeshSyncPayload,
    pub signature_hex: String,
}

/// Summary report returned after ingesting a peer's `MeshSyncEnvelope`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MeshIngestReport {
    pub bans_ingested: usize,
    pub bans_skipped_protected: usize,
    pub decoys_ingested: usize,
}

/// Fleet Deception Mesh Synchronization Engine
#[derive(Clone)]
pub struct MeshSyncEngine {
    node_id: String,
    shared_secret: Vec<u8>,
    defense: Arc<EdgeDefense>,
}

impl MeshSyncEngine {
    pub fn new(
        node_id: impl Into<String>,
        shared_secret: impl Into<Vec<u8>>,
        defense: Arc<EdgeDefense>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            shared_secret: shared_secret.into(),
            defense,
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Compute RFC 2104 HMAC-SHA256 over canonical JSON representation of `MeshSyncPayload`
    fn sign_payload(&self, payload: &MeshSyncPayload) -> Result<String, MeshSyncError> {
        let canonical_bytes = serde_json::to_vec(payload)?;
        let tag = phylax::xdp_shield::sign_hmac_sha256(&self.shared_secret, &canonical_bytes);
        Ok(hex_encode(&tag))
    }

    /// Constant-time verification of `MeshSyncEnvelope` HMAC-SHA256 tag
    pub fn verify_envelope(
        &self,
        envelope: &MeshSyncEnvelope,
        now_ms: u64,
    ) -> Result<(), MeshSyncError> {
        let diff = now_ms.abs_diff(envelope.payload.timestamp_ms);
        if diff > MESH_REPLAY_WINDOW_MS {
            return Err(MeshSyncError::ReplayWindowExceeded {
                envelope_ms: envelope.payload.timestamp_ms,
                now_ms,
            });
        }

        let canonical_bytes = serde_json::to_vec(&envelope.payload)?;
        let sig_bytes =
            hex_decode(&envelope.signature_hex).ok_or(MeshSyncError::SignatureInvalid)?;
        if phylax::xdp_shield::verify_hmac_sha256(&self.shared_secret, &canonical_bytes, &sig_bytes)
        {
            Ok(())
        } else {
            Err(MeshSyncError::SignatureInvalid)
        }
    }

    /// Export local node's active quarantine bans and promoted zero-day decoy traps into a signed envelope
    pub fn export_envelope(&self, now_ms: u64) -> Result<MeshSyncEnvelope, MeshSyncError> {
        let active_bans = self
            .defense
            .pipeline()
            .quarantine()
            .active_bans(now_ms)
            .into_iter()
            .map(|(net, expires_at)| QuarantineRecord {
                cidr: net.to_string(),
                ip_version: if net.addr().is_ipv4() { 4 } else { 6 },
                trigger_ip: net.addr().to_string(),
                infraction_type: format!("MeshSyncExport({})", self.node_id),
                infraction_count: 1,
                quarantined_at: now_ms,
                expires_at,
                user_agent: None,
                active: true,
            })
            .collect();

        let promoted_decoys = self
            .defense
            .pipeline()
            .threat_harvester()
            .promoted_records()
            .into_iter()
            .map(|rec| PromotedDecoyTrap {
                path: rec.path,
                category: rec.category,
                distinct_subnets: rec.participating_subnets.len(),
                promoted_at_ms: rec.last_seen_ms,
            })
            .collect();

        let payload = MeshSyncPayload {
            node_id: self.node_id.clone(),
            timestamp_ms: now_ms,
            quarantine_bans: active_bans,
            promoted_decoys,
        };
        let signature_hex = self.sign_payload(&payload)?;
        Ok(MeshSyncEnvelope {
            payload,
            signature_hex,
        })
    }

    /// Verify and ingest a peer node's `MeshSyncEnvelope` into local `AutonomousQuarantine`,
    /// `XdpWireShield`, `QuarantineManager`, and `DecoyUriSentinel`.
    pub fn ingest_envelope(
        &self,
        envelope: &MeshSyncEnvelope,
        now_ms: u64,
    ) -> Result<MeshIngestReport, MeshSyncError> {
        self.verify_envelope(envelope, now_ms)?;

        let mut report = MeshIngestReport::default();

        for ban in &envelope.payload.quarantine_bans {
            if ban.expires_at <= now_ms {
                continue;
            }
            let Ok(net) = IpNet::from_str(&ban.cidr) else {
                continue;
            };
            let addr = net.addr();
            if is_protected_or_private_ip(addr) || self.defense.is_trusted(addr) {
                report.bans_skipped_protected += 1;
                continue;
            }

            self.defense
                .pipeline()
                .quarantine()
                .add_ban(net, ban.expires_at);
            self.defense.pipeline().xdp_shield().upsert_ban(
                net,
                ban.expires_at,
                XdpBanReason::FleetMeshSync,
            );
            if let Some(qm) = self.defense.quarantine_manager() {
                qm.queue_record(ban.clone());
            }
            report.bans_ingested += 1;
        }

        for decoy in &envelope.payload.promoted_decoys {
            let normalized = phylax::DecoyUriSentinel::normalize_path(&decoy.path);
            if !normalized.is_empty()
                && normalized != "/"
                && !self
                    .defense
                    .pipeline()
                    .decoy_uri()
                    .contains_trap(&normalized)
            {
                self.defense
                    .pipeline()
                    .decoy_uri()
                    .add_exact_trap_with_category(&normalized, decoy.category);
                report.decoys_ingested += 1;
            }
        }

        Ok(report)
    }

    /// Serve bidirectional Fleet Mesh Sync over a TCP listener (receives peer envelope, responds with local envelope)
    pub async fn serve_tcp_once(
        &self,
        listener: &TcpListener,
        now_ms: u64,
    ) -> Result<MeshIngestReport, MeshSyncError> {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n > MAX_MESH_ENVELOPE_BYTES {
            return Err(MeshSyncError::PayloadTooLarge(n));
        }
        let peer_env: MeshSyncEnvelope = serde_json::from_str(line.trim())?;
        let report = self.ingest_envelope(&peer_env, now_ms)?;

        let local_env = self.export_envelope(now_ms)?;
        let mut resp_bytes = serde_json::to_vec(&local_env)?;
        resp_bytes.push(b'\n');
        writer.write_all(&resp_bytes).await?;
        writer.flush().await?;
        Ok(report)
    }

    /// Connect to a remote Fleet Mesh peer over TCP, push local envelope, and ingest the peer's response envelope
    pub async fn sync_with_tcp_peer(
        &self,
        peer_addr: SocketAddr,
        now_ms: u64,
    ) -> Result<MeshIngestReport, MeshSyncError> {
        let stream = TcpStream::connect(peer_addr).await?;
        let (reader, mut writer) = stream.into_split();
        let local_env = self.export_envelope(now_ms)?;
        let mut req_bytes = serde_json::to_vec(&local_env)?;
        req_bytes.push(b'\n');
        writer.write_all(&req_bytes).await?;
        writer.flush().await?;

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n > MAX_MESH_ENVELOPE_BYTES {
            return Err(MeshSyncError::PayloadTooLarge(n));
        }
        let peer_env: MeshSyncEnvelope = serde_json::from_str(line.trim())?;
        self.ingest_envelope(&peer_env, now_ms)
    }
}

fn is_protected_or_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let is_cgnat = v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64;
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || is_cgnat
        }
        IpAddr::V6(v6) => {
            let is_ula = (v6.segments()[0] & 0xFE00) == 0xFC00;
            let is_ll = (v6.segments()[0] & 0xFFC0) == 0xFE80;
            v6.is_loopback() || v6.is_unspecified() || is_ula || is_ll
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex_digit(bytes[i])?;
        let lo = from_hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn from_hex_digit(d: u8) -> Option<u8> {
    match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        b'A'..=b'F' => Some(d - b'A' + 10),
        _ => None,
    }
}
