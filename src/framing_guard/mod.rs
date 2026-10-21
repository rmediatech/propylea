//! # Sovereign HTTP Request Framing & Smuggling Defense Engine (`framing_guard/mod.rs`)
//!
//! Strict RFC 9112 / RFC 7230 protocol framing validation and payload sanitization.
//! Defends against HTTP request smuggling (TE.CL / CL.TE desync attacks), ambiguous
//! header injections, control character / ANSI escape poisoning, and payload allocation bombs.

#[cfg(test)]
mod tests;

use hyper::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::net::IpAddr;
use thiserror::Error;

/// Violations detected during strict HTTP framing inspection
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FramingViolation {
    #[error("RFC 9112 §6.1 / RFC 7230 §3.3.3: Request contains conflicting Transfer-Encoding and Content-Length headers (HTTP Desync Attack)")]
    ConflictingFraming,

    #[error("Multiple conflicting Content-Length headers detected")]
    MultipleContentLengths,

    #[error("Malformed Content-Length header: '{0}'")]
    MalformedContentLength(String),

    #[error("Unsupported or malformed Transfer-Encoding: '{0}'")]
    UnsupportedTransferEncoding(String),

    #[error("Illegal control character (NUL, ANSI ESC, or bare CR/LF) detected in header '{0}'")]
    IllegalHeaderCharacter(String),

    #[error("Payload exceeds maximum allowable body size: {requested} bytes > {limit} bytes")]
    PayloadTooLarge { limit: u64, requested: u64 },
}

impl FramingViolation {
    pub fn status_code(&self) -> StatusCode {
        match self {
            FramingViolation::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    pub fn public_response(&self) -> Response<http_body_util::Full<bytes::Bytes>> {
        use http_body_util::Full;
        let body = format!("400 Bad Request: {}\n", self);
        let mut res = Response::new(Full::new(bytes::Bytes::from(body)));
        *res.status_mut() = self.status_code();
        res.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        res
    }
}

/// Sovereign HTTP Framing Guard
#[derive(Debug, Clone)]
pub struct FramingGuard {
    max_body_bytes: u64,
}

impl Default for FramingGuard {
    fn default() -> Self {
        Self {
            // Default 10 MB payload limit for general edge traffic
            max_body_bytes: 10 * 1024 * 1024,
        }
    }
}

impl FramingGuard {
    pub fn new(max_body_bytes: u64) -> Self {
        Self { max_body_bytes }
    }

    /// Retrieve the maximum allowable body size in bytes.
    #[inline]
    pub fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    /// Validates that header bytes contain no NUL, bare CR/LF, ANSI ESC (`0x1b`),
    /// DEL (`0x7f`), or other C0 control bytes (except HTAB `\t` per RFC 9110 §5.5).
    #[inline]
    pub fn check_header_value_bytes(name: &str, bytes: &[u8]) -> Result<(), FramingViolation> {
        if bytes
            .iter()
            .any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err(FramingViolation::IllegalHeaderCharacter(name.to_string()));
        }
        Ok(())
    }

    /// Evaluates headers for protocol framing compliance, smuggling signatures,
    /// and payload boundary limits. Executes in sub-microsecond time.
    #[inline]
    pub fn validate_headers(
        &self,
        headers: &HeaderMap,
        method: &Method,
    ) -> Result<(), FramingViolation> {
        let has_cl = headers.contains_key(CONTENT_LENGTH);
        let has_te = headers.contains_key(TRANSFER_ENCODING);

        // 1. Smuggling Guard: RFC 9112 §6.1 / RFC 7230 §3.3.3: Reject both CL and TE
        if has_cl && has_te {
            return Err(FramingViolation::ConflictingFraming);
        }

        // 2. Validate Content-Length if present
        if has_cl {
            self.validate_content_length(headers)?;
        }

        // 3. Validate Transfer-Encoding if present
        if has_te {
            for te in headers.get_all(TRANSFER_ENCODING) {
                let te_str = te.to_str().map_err(|_| {
                    FramingViolation::UnsupportedTransferEncoding(
                        "Non-ASCII Transfer-Encoding".into(),
                    )
                })?;
                let lower = te_str.trim().to_ascii_lowercase();
                if !lower.ends_with("chunked") {
                    return Err(FramingViolation::UnsupportedTransferEncoding(
                        te_str.to_string(),
                    ));
                }
            }
        }

        // 4. Header Hygiene: Check for NUL-bytes, raw CR/LF, ANSI ESC, or ASCII control characters
        for (name, val) in headers.iter() {
            Self::check_header_value_bytes(name.as_str(), val.as_bytes())?;
        }

        // 5. Method-specific check: GET and HEAD should not carry body length > 0
        if (*method == Method::GET || *method == Method::HEAD) && has_cl {
            if let Some(cl_val) = headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()) {
                if let Ok(len) = cl_val.trim().parse::<u64>() {
                    if len > 0 {
                        return Err(FramingViolation::MalformedContentLength(format!(
                            "GET/HEAD method carries Content-Length > 0 ({} bytes)",
                            len
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_content_length(&self, headers: &HeaderMap) -> Result<(), FramingViolation> {
        let cl_values: Vec<_> = headers.get_all(CONTENT_LENGTH).iter().collect();
        if cl_values.len() > 1 {
            let first = cl_values[0].to_str().map_err(|_| {
                FramingViolation::MalformedContentLength("Non-ASCII Content-Length".into())
            })?;
            for val in &cl_values[1..] {
                let s = val.to_str().map_err(|_| {
                    FramingViolation::MalformedContentLength("Non-ASCII Content-Length".into())
                })?;
                if s.trim() != first.trim() {
                    return Err(FramingViolation::MultipleContentLengths);
                }
            }
        }

        let cl_str = cl_values[0].to_str().map_err(|_| {
            FramingViolation::MalformedContentLength("Non-ASCII Content-Length".into())
        })?;

        if cl_str.contains(',') {
            let parts: Vec<&str> = cl_str.split(',').map(|s| s.trim()).collect();
            let first_val = parts[0];
            for part in &parts[1..] {
                if *part != first_val {
                    return Err(FramingViolation::MultipleContentLengths);
                }
            }
        }

        let parsed_len: u64 = cl_str
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|_| FramingViolation::MalformedContentLength(cl_str.to_string()))?;

        if parsed_len > self.max_body_bytes {
            return Err(FramingViolation::PayloadTooLarge {
                limit: self.max_body_bytes,
                requested: parsed_len,
            });
        }

        Ok(())
    }

    /// Strips untrusted client-supplied identity/proxy headers and sets authoritative
    /// values based on the cryptographically verified socket peer.
    #[inline]
    pub fn sanitize_ingress_headers<B>(req: &mut Request<B>, client_ip: IpAddr) {
        let headers = req.headers_mut();

        headers.remove("X-Forwarded-For");
        headers.remove("X-Forwarded-Proto");
        headers.remove("X-Forwarded-Host");
        headers.remove("X-Real-IP");
        headers.remove("X-Client-IP");
        headers.remove("CF-Connecting-IP");
        headers.remove("True-Client-IP");

        let ip_val = client_ip.to_string();
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&ip_val) {
            headers.insert("X-Forwarded-For", hv.clone());
            headers.insert("X-Real-IP", hv);
        }
        headers.insert(
            "X-Forwarded-Proto",
            hyper::header::HeaderValue::from_static("https"),
        );
    }
}
