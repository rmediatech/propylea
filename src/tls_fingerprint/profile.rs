//! # Client TLS Profile & ClientHello Wire Parser

use crate::tls_fingerprint::ja4::{compute_ja4_fingerprint, Ja4Fingerprint};
use serde::{Deserialize, Serialize};

/// Bitwise check for RFC 8701 GREASE values (0x0a0a, 0x1a1a, ..., 0xfafa)
#[inline(always)]
pub fn is_grease_u16(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0x00ff))
}

/// Extracted TLS ClientHello profile
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClientTlsProfile {
    /// True if client sent RFC 8701 GREASE cipher suites or extensions (Standard in Chrome/Edge/Safari/WebKit)
    pub has_grease: bool,
    /// Number of cipher suites offered
    pub cipher_count: usize,
    /// True if ALPN extension offered HTTP/2 ('h2')
    pub offers_h2: bool,
    /// True if SNI extension was present
    pub has_sni: bool,
    /// First 3 non-GREASE cipher suites offered (ordered by client preference)
    pub primary_ciphers: Vec<u16>,
    /// Calculated RFC JA4 TLS Fingerprint (e.g. t13d1516h2_8daaf6152771_e562703ab85e)
    pub ja4: Option<Ja4Fingerprint>,
}

impl ClientTlsProfile {
    /// Parse a raw TLS ClientHello from a peeked byte buffer (e.g. from TcpStream::peek).
    /// Safe, zero-allocation parser operating in $<250\text{ns}$.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    pub fn parse_client_hello(buf: &[u8]) -> Option<Self> {
        if buf.len() < 43 || buf[0] != 0x16 || buf[5] != 0x01 {
            return None;
        }

        let legacy_version = u16::from_be_bytes([buf[9], buf[10]]);
        let mut idx = 43;

        // Session ID
        if buf.len() <= idx {
            return None;
        }
        let session_id_len = buf[idx] as usize;
        idx += 1 + session_id_len;

        // Cipher suites
        if buf.len() < idx + 2 {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
        idx += 2;

        if buf.len() < idx + cipher_suites_len {
            return None;
        }

        let cipher_count = cipher_suites_len / 2;
        let mut has_grease = false;
        let mut primary_ciphers = Vec::with_capacity(3);
        let mut valid_ciphers = Vec::with_capacity(cipher_count);

        for chunk in buf[idx..idx + cipher_suites_len].chunks_exact(2) {
            let cipher = u16::from_be_bytes([chunk[0], chunk[1]]);
            if is_grease_u16(cipher) {
                has_grease = true;
            } else {
                valid_ciphers.push(cipher);
                if primary_ciphers.len() < 3 {
                    primary_ciphers.push(cipher);
                }
            }
        }
        idx += cipher_suites_len;

        // Compression methods
        if buf.len() <= idx {
            return None;
        }
        let compression_len = buf[idx] as usize;
        idx += 1 + compression_len;

        // Extensions
        let mut offers_h2 = false;
        let mut has_sni = false;
        let mut alpn_first: Option<String> = None;
        let mut valid_extensions = Vec::new();
        let mut supported_versions = Vec::new();
        let mut signature_algorithms = Vec::new();

        if buf.len() >= idx + 2 {
            let extensions_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
            idx += 2;

            let ext_end = (idx + extensions_len).min(buf.len());
            while idx + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
                let ext_len = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) as usize;
                idx += 4;

                if is_grease_u16(ext_type) {
                    has_grease = true;
                } else {
                    valid_extensions.push(ext_type);
                }

                if idx + ext_len <= ext_end {
                    let ext_data = &buf[idx..idx + ext_len];
                    if ext_type == 0x0000 {
                        has_sni = true;
                    } else if ext_type == 0x0010 {
                        // ALPN: parse first protocol string
                        if ext_data.len() >= 3 {
                            let alpn_list_len =
                                u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            if ext_data.len() >= 2 + alpn_list_len && alpn_list_len > 0 {
                                let str_len = ext_data[2] as usize;
                                if ext_data.len() >= 3 + str_len {
                                    if let Ok(proto) =
                                        std::str::from_utf8(&ext_data[3..3 + str_len])
                                    {
                                        if proto == "h2" {
                                            offers_h2 = true;
                                        }
                                        alpn_first = Some(proto.to_string());
                                    }
                                }
                            }
                        }
                    } else if ext_type == 0x002b {
                        // Supported versions (0x002b)
                        if !ext_data.is_empty() {
                            let list_len = ext_data[0] as usize;
                            for chunk in
                                ext_data[1..1 + list_len.min(ext_data.len() - 1)].chunks_exact(2)
                            {
                                let v = u16::from_be_bytes([chunk[0], chunk[1]]);
                                if !is_grease_u16(v) {
                                    supported_versions.push(v);
                                }
                            }
                        }
                    } else if ext_type == 0x000d {
                        // Signature algorithms (0x000d)
                        if ext_data.len() >= 2 {
                            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            for chunk in
                                ext_data[2..2 + list_len.min(ext_data.len() - 2)].chunks_exact(2)
                            {
                                signature_algorithms.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                            }
                        }
                    }
                }

                idx += ext_len;
            }
        }

        let ja4 = Some(compute_ja4_fingerprint(
            legacy_version,
            has_sni,
            &valid_ciphers,
            &valid_extensions,
            alpn_first.as_deref(),
            if supported_versions.is_empty() {
                None
            } else {
                Some(&supported_versions)
            },
            if signature_algorithms.is_empty() {
                None
            } else {
                Some(&signature_algorithms)
            },
        ));

        Some(Self {
            has_grease,
            cipher_count,
            offers_h2,
            has_sni,
            primary_ciphers,
            ja4,
        })
    }
}
