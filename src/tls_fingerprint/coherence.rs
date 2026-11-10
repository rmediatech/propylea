//! # User-Agent Coherence & Bot Spoofing Detection

use crate::tls_fingerprint::profile::ClientTlsProfile;

/// Result of cross-referencing TLS profile with claimed HTTP User-Agent
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAgentCoherenceVerdict {
    /// TLS profile and User-Agent are coherent, or unclassified
    Coherent,
    /// Hostile spoofing: User-Agent claims to be a modern major browser (Chrome/Edge/Safari),
    /// but TLS ClientHello signature is characteristic of Python, Go, or raw CLI scripts.
    Spoofed { reason: &'static str },
}

impl ClientTlsProfile {
    /// Evaluates whether the claimed HTTP User-Agent is coherent with the observed TLS profile.
    /// Execution time: $< 50\text{ns}$ with zero heap allocation.
    pub fn verify_user_agent_coherence(
        &self,
        user_agent: Option<&str>,
    ) -> UserAgentCoherenceVerdict {
        let Some(ua) = user_agent else {
            return UserAgentCoherenceVerdict::Coherent;
        };

        let ua_clean = ua.trim();
        let is_claiming_chrome = ua_clean.contains("Chrome/") || ua_clean.contains("CriOS/");
        let is_claiming_safari = ua_clean.contains("Safari/")
            && !ua_clean.contains("Chrome/")
            && ua_clean.contains("Version/");
        let is_claiming_edge = ua_clean.contains("Edg/") || ua_clean.contains("Edge/");

        // Legitimate search engines often include Chrome in their token (e.g. Googlebot)
        let is_search_spider = ua_clean.contains("Googlebot")
            || ua_clean.contains("bingbot")
            || ua_clean.contains("Baiduspider")
            || ua_clean.contains("YandexBot");

        if is_search_spider {
            return UserAgentCoherenceVerdict::Coherent;
        }

        // Rule 1: Modern Chrome/Edge/Safari on desktop/mobile ALWAYS negotiates GREASE ciphers/extensions.
        if (is_claiming_chrome || is_claiming_edge || is_claiming_safari) && !self.has_grease {
            return UserAgentCoherenceVerdict::Spoofed {
                reason: "User-Agent claims modern Chrome/Safari/Edge browser, but TLS ClientHello lacks mandatory RFC 8701 GREASE signatures (Python/Go/CLI impersonation detected)",
            };
        }

        // Rule 2: Chrome/Edge/Safari without HTTP/2 ALPN
        if (is_claiming_chrome || is_claiming_edge) && !self.offers_h2 && self.cipher_count < 10 {
            return UserAgentCoherenceVerdict::Spoofed {
                reason: "User-Agent claims Chrome/Edge browser, but TLS ClientHello omits HTTP/2 ALPN and has truncated cipher list",
            };
        }

        UserAgentCoherenceVerdict::Coherent
    }
}
