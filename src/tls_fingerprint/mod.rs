//! # Sovereign TLS Fingerprint & Handshake Profile Verification Engine
//! Sub-microsecond TLS ClientHello analysis, JA4 / JA4H fingerprinting, and User-Agent coherence verification.

pub mod coherence;
pub mod ja4;
pub mod profile;
pub mod sni;

pub use coherence::UserAgentCoherenceVerdict;
pub use ja4::{compute_ja4_fingerprint, compute_ja4h_fingerprint, Ja4Fingerprint, Ja4hFingerprint};
pub use profile::{is_grease_u16, ClientTlsProfile};
pub use sni::extract_sni_hostname_zero_alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0x1a1a));
        assert!(is_grease_u16(0x2a2a));
        assert!(is_grease_u16(0xfafa));

        assert!(!is_grease_u16(0x0a1a));
        assert!(!is_grease_u16(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease_u16(0xc02f)); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }

    #[test]
    fn test_detects_python_impersonating_chrome() {
        let python_profile = ClientTlsProfile {
            has_grease: false,
            cipher_count: 17,
            offers_h2: false,
            has_sni: true,
            primary_ciphers: vec![0x1301, 0x1302, 0x1303],
            ja4: None,
        };

        let spoofed_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
        let verdict = python_profile.verify_user_agent_coherence(Some(spoofed_ua));
        assert!(matches!(verdict, UserAgentCoherenceVerdict::Spoofed { .. }));
    }

    #[test]
    fn test_allows_genuine_chrome_profile() {
        let chrome_profile = ClientTlsProfile {
            has_grease: true,
            cipher_count: 16,
            offers_h2: true,
            has_sni: true,
            primary_ciphers: vec![0x1301, 0x1302, 0x1303],
            ja4: None,
        };

        let real_chrome_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
        let verdict = chrome_profile.verify_user_agent_coherence(Some(real_chrome_ua));
        assert_eq!(verdict, UserAgentCoherenceVerdict::Coherent);
    }

    #[test]
    fn test_allows_legitimate_googlebot_without_grease() {
        let bot_profile = ClientTlsProfile {
            has_grease: false,
            cipher_count: 15,
            offers_h2: true,
            has_sni: true,
            primary_ciphers: vec![0x1301, 0x1302],
            ja4: None,
        };

        let googlebot_ua =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let verdict = bot_profile.verify_user_agent_coherence(Some(googlebot_ua));
        assert_eq!(verdict, UserAgentCoherenceVerdict::Coherent);
    }

    #[test]
    fn test_allows_unspecified_cli_or_missing_ua() {
        let cli_profile = ClientTlsProfile {
            has_grease: false,
            cipher_count: 10,
            offers_h2: false,
            has_sni: false,
            primary_ciphers: vec![],
            ja4: None,
        };

        assert_eq!(
            cli_profile.verify_user_agent_coherence(None),
            UserAgentCoherenceVerdict::Coherent
        );
        assert_eq!(
            cli_profile.verify_user_agent_coherence(Some("curl/8.5.0")),
            UserAgentCoherenceVerdict::Coherent
        );
    }

    #[test]
    fn test_ja4_fingerprint_deterministic_generation() {
        let ciphers = [0x1301, 0x1302, 0x1303, 0xc02f, 0xc030];
        let exts = [0x0000, 0x000b, 0x000a, 0x0010, 0x002b];
        let supported_versions = [0x0304, 0x0303];

        let ja4 = compute_ja4_fingerprint(
            0x0303,
            true,
            &ciphers,
            &exts,
            Some("h2"),
            Some(&supported_versions),
            None,
        );

        let ja4_str = ja4.as_str();
        assert!(
            ja4_str.starts_with("t13d0505h2_"),
            "JA4 Part A must match format, got: {}",
            ja4_str
        );
        let parts: Vec<&str> = ja4_str.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 10);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }
}
