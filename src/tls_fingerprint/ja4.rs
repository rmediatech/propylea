//! # JA4 & JA4H TLS/HTTP Fingerprint Engine
//! Implements FoxIO JA4 (TLS Client) and JA4H (HTTP Client) fingerprint algorithms in pure Rust.

use sha2::{Digest, Sha256};
use std::fmt;

/// Formatted JA4 TLS Client Fingerprint: `[a]_[b]_[c]`
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Ja4Fingerprint(pub String);

impl fmt::Display for Ja4Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Ja4Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Formatted JA4H HTTP Client Fingerprint: `[a]_[b]_[c]_[d]`
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Ja4hFingerprint(pub String);

impl fmt::Display for Ja4hFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Ja4hFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Computes JA4 fingerprint from TLS ClientHello parameters
pub fn compute_ja4_fingerprint(
    version_id: u16,
    has_sni: bool,
    ciphers: &[u16],
    extensions: &[u16],
    alpn_first: Option<&str>,
    supported_versions: Option<&[u16]>,
    signature_algorithms: Option<&[u16]>,
) -> Ja4Fingerprint {
    // 1. Determine effective TLS version: TLS 1.3 is advertised in supported_versions (0x0304)
    let ver_str = if let Some(sv) = supported_versions {
        if sv.contains(&0x0304) {
            "13"
        } else if sv.contains(&0x0303) {
            "12"
        } else {
            version_to_ja4_str(version_id)
        }
    } else {
        version_to_ja4_str(version_id)
    };

    // 2. SNI indicator: 'd' if domain present, 'i' if IP or missing
    let sni_str = if has_sni { "d" } else { "i" };

    // 3. Counts (capped at 99 per spec)
    let c_count = ciphers.len().min(99);
    let e_count = extensions.len().min(99);

    // 4. ALPN 2-char representation (first char + last char of first ALPN string, or "00")
    let alpn_str = match alpn_first {
        Some(s) if s.len() >= 2 => {
            let first = s.chars().next().unwrap_or('0');
            let last = s.chars().last().unwrap_or('0');
            format!("{}{}", first, last)
        }
        Some(s) if s.len() == 1 => format!("{}0", s),
        _ => "00".to_string(),
    };

    // Part A: 10 chars: t + ver(2) + sni(1) + ciphers(2) + exts(2) + alpn(2)
    let part_a = format!("t{}{}{:02}{:02}{}", ver_str, sni_str, c_count, e_count, alpn_str);

    // Part B: 12-char SHA256 of sorted hex ciphers
    let part_b = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        let mut sorted_ciphers = ciphers.to_vec();
        sorted_ciphers.sort_unstable();
        let hex_list: Vec<String> = sorted_ciphers.iter().map(|c| format!("{:04x}", c)).collect();
        hash12(hex_list.join(",").as_bytes())
    };

    // Part C: 12-char SHA256 of sorted hex extensions (+ sorted sig algs if present)
    let part_c = if extensions.is_empty() {
        "000000000000".to_string()
    } else {
        let mut sorted_exts = extensions.to_vec();
        sorted_exts.sort_unstable();
        let mut ext_str: String = sorted_exts
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");

        if let Some(sigs) = signature_algorithms {
            if !sigs.is_empty() {
                let mut sorted_sigs = sigs.to_vec();
                sorted_sigs.sort_unstable();
                let sig_str = sorted_sigs
                    .iter()
                    .map(|s| format!("{:04x}", s))
                    .collect::<Vec<_>>()
                    .join(",");
                ext_str.push('_');
                ext_str.push_str(&sig_str);
            }
        }
        hash12(ext_str.as_bytes())
    };

    Ja4Fingerprint(format!("{}_{}_{}", part_a, part_b, part_c))
}

/// Computes JA4H HTTP fingerprint from HTTP request headers
pub fn compute_ja4h_fingerprint(
    method: &str,
    http_version: &str,
    headers: &hyper::HeaderMap,
) -> Ja4hFingerprint {
    let upper_method = method.to_uppercase();
    let method_code = match upper_method.as_str() {
        "GET" => "ge",
        "POST" => "po",
        "PUT" => "pu",
        "DELETE" => "de",
        "HEAD" => "he",
        "OPTIONS" => "op",
        "PATCH" => "pa",
        m if m.len() >= 2 => &m[..2],
        _ => "xx",
    };

    let ver_code = match http_version {
        "HTTP/1.1" => "11",
        "HTTP/2.0" | "HTTP/2" => "20",
        "HTTP/3.0" | "HTTP/3" => "30",
        "HTTP/1.0" => "10",
        _ => "00",
    };

    let has_cookie = if headers.contains_key(hyper::header::COOKIE) { "c" } else { "n" };
    let has_referer = if headers.contains_key(hyper::header::REFERER) { "r" } else { "n" };

    // Header count excluding Cookie and Referer
    let mut header_names = Vec::new();
    let mut accept_lang = "0000".to_string();

    for (key, val) in headers {
        let name = key.as_str().to_lowercase();
        if name == "accept-language" {
            if let Ok(val_str) = val.to_str() {
                accept_lang = extract_ja4h_lang(val_str);
            }
        }
        if name != "cookie" && name != "referer" {
            header_names.push(name);
        }
    }

    let header_count = header_names.len().min(99);
    let part_a = format!("{}{}{}{}{:02}{}", method_code, ver_code, has_cookie, has_referer, header_count, accept_lang);

    // Part B: Sorted header names hash
    let part_b = if header_names.is_empty() {
        "000000000000".to_string()
    } else {
        header_names.sort_unstable();
        hash12(header_names.join(",").as_bytes())
    };

    // Part C & D: Cookie names and values
    let (part_c, part_d) = if let Some(cookie_val) = headers.get(hyper::header::COOKIE).and_then(|v| v.to_str().ok()) {
        parse_and_hash_cookies(cookie_val)
    } else {
        ("000000000000".to_string(), "000000000000".to_string())
    };

    Ja4hFingerprint(format!("{}_{}_{}_{}", part_a, part_b, part_c, part_d))
}

fn version_to_ja4_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn hash12(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn extract_ja4h_lang(val: &str) -> String {
    let parts: Vec<&str> = val.split(',').collect();
    if parts.is_empty() {
        return "0000".to_string();
    }
    let first = parts[0].trim().replace('-', "");
    let first_2 = if first.len() >= 2 { &first[..2] } else { "00" };

    let last = parts.last().unwrap_or(&parts[0]).trim().replace('-', "");
    let last_2 = if last.len() >= 2 { &last[..2] } else { "00" };

    format!("{}{}", first_2.to_lowercase(), last_2.to_lowercase())
}

fn parse_and_hash_cookies(cookie_header: &str) -> (String, String) {
    let mut pairs = Vec::new();
    for item in cookie_header.split(';') {
        let trimmed = item.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            pairs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    if pairs.is_empty() {
        return ("000000000000".to_string(), "000000000000".to_string());
    }

    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let names: Vec<String> = pairs.iter().map(|p| p.0.clone()).collect();
    let values: Vec<String> = pairs.iter().map(|p| p.1.clone()).collect();

    (hash12(names.join(",").as_bytes()), hash12(values.join(",").as_bytes()))
}
