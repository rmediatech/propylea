//! # Universal Sovereign Sibling Reverse Proxy Peering (`SOVEREIGN-SIBLING-01`)
//! Single Job: Extract, verify, and forward Sibling Attestation proofs at the L7 reverse proxy boundary.

use hyper::header::{HeaderMap, HeaderValue};
use hyper::Request;
pub use phylax::sibling::{
    SiblingChallenge, SiblingError, SiblingProof, SiblingVerifier, LINEAGE_CANARY_PREIMAGE,
    MAX_TIMESTAMP_DRIFT_MS,
};

pub const HEADER_SIBLING_NAME: &str = "x-sovereign-sibling-name";
pub const HEADER_SIBLING_NONCE: &str = "x-sovereign-sibling-nonce";
pub const HEADER_SIBLING_TIMESTAMP: &str = "x-sovereign-sibling-timestamp";
pub const HEADER_SIBLING_SIGNATURE: &str = "x-sovereign-sibling-signature";
pub const HEADER_LINEAGE_STATUS: &str = "x-sovereign-lineage";
pub const HEADER_LINEAGE_CALLER: &str = "x-sovereign-sibling-caller";

/// Extracts SiblingProof from HTTP headers if all required fields are present
pub fn extract_sibling_proof_from_headers(headers: &HeaderMap) -> Option<SiblingProof> {
    let caller_name = headers.get(HEADER_SIBLING_NAME)?.to_str().ok()?.to_string();
    let nonce = headers
        .get(HEADER_SIBLING_NONCE)?
        .to_str()
        .ok()?
        .to_string();
    let ts_str = headers.get(HEADER_SIBLING_TIMESTAMP)?.to_str().ok()?;
    let timestamp_ms = ts_str.parse::<u64>().ok()?;
    let signature = headers
        .get(HEADER_SIBLING_SIGNATURE)?
        .to_str()
        .ok()?
        .to_string();

    Some(SiblingProof {
        caller_name,
        nonce,
        timestamp_ms,
        signature,
    })
}

/// Helper to extract proof directly from a Hyper Request
#[inline]
pub fn extract_sibling_proof<B>(req: &Request<B>) -> Option<SiblingProof> {
    extract_sibling_proof_from_headers(req.headers())
}

/// Injects verified sibling status into upstream headers
pub fn inject_sibling_upstream_headers<B>(req: &mut Request<B>, caller: &str) {
    let headers = req.headers_mut();
    headers.insert(
        HEADER_LINEAGE_STATUS,
        HeaderValue::from_static("Sibling-Elevated"),
    );
    if let Ok(val) = HeaderValue::from_str(caller) {
        headers.insert(HEADER_LINEAGE_CALLER, val);
    }
}

/// Sibling Gatekeeper for Reverse Proxy ingress
#[derive(Debug, Clone, Default)]
pub struct SiblingGatekeeper;

impl SiblingGatekeeper {
    /// Evaluates if an incoming request qualifies for diplomatic sibling immunity
    #[inline]
    pub fn verify_ingress_proof(proof: &SiblingProof, now_ms: u64) -> Result<(), SiblingError> {
        SiblingVerifier::verify_proof(proof, now_ms)
    }

    /// Issues challenge for edge clients requesting an ephemeral nonce
    #[inline]
    pub fn issue_challenge(now_ms: u64, seed_nonce: u64) -> SiblingChallenge {
        SiblingVerifier::issue_challenge(now_ms, seed_nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[test]
    fn test_extract_sibling_proof_complete() {
        let now_ms = 1_700_000_000_000;
        let challenge = SiblingVerifier::issue_challenge(now_ms, 999);
        let proof = SiblingVerifier::generate_proof("vox", &challenge.nonce, now_ms);

        let req = Request::builder()
            .header(HEADER_SIBLING_NAME, &proof.caller_name)
            .header(HEADER_SIBLING_NONCE, &proof.nonce)
            .header(HEADER_SIBLING_TIMESTAMP, proof.timestamp_ms.to_string())
            .header(HEADER_SIBLING_SIGNATURE, &proof.signature)
            .body(())
            .unwrap();

        let extracted = extract_sibling_proof(&req).expect("Should extract proof");
        assert_eq!(extracted.caller_name, "vox");
        assert!(SiblingGatekeeper::verify_ingress_proof(&extracted, now_ms).is_ok());
    }

    #[test]
    fn test_extract_sibling_proof_missing_header_returns_none() {
        let req = Request::builder()
            .header(HEADER_SIBLING_NAME, "vox")
            .body(())
            .unwrap();
        assert!(extract_sibling_proof(&req).is_none());
    }

    #[test]
    fn test_inject_sibling_upstream_headers() {
        let mut req = Request::builder().body(()).unwrap();
        inject_sibling_upstream_headers(&mut req, "ashwin");

        assert_eq!(
            req.headers().get(HEADER_LINEAGE_STATUS).unwrap(),
            "Sibling-Elevated"
        );
        assert_eq!(req.headers().get(HEADER_LINEAGE_CALLER).unwrap(), "ashwin");
    }
}
