//! # Sovereign Boundary Sanitization & Anti-Poisoning Engine (`sanitize.rs`)
//!
//! Enforces Sovereign Adversarial Security Standard (Pillar III):
//! 1. **ANSI CSI/OSC & Control Byte Scrubbing**: Strips raw terminal escape sequences
//!    (`\x1b[...`, `\x1b]...`) and unprintable C0/DEL control bytes from logs, headers,
//!    SNI/Host banners, and CLI/IPC outputs.
//! 2. **Formula Injection Neutralization**: Prefixes dangerous spreadsheet-triggering
//!    leading characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with a single quote (`'`).
//! 3. **Allocation Bomb Bounds**: Enforces strict character and byte ceilings on untrusted
//!    wire strings prior to persistence or rendering.

/// Maximum length for untrusted User-Agent or log banner strings (4 KiB)
pub const MAX_BANNER_BYTES: usize = 4096;

/// Maximum length for RFC 1035 / SNI hostnames (253 bytes)
pub const MAX_HOSTNAME_BYTES: usize = 253;

/// Scrubs ANSI CSI (`\x1b[...`), OSC (`\x1b]...`), raw ESC (`\x1b`), and unprintable
/// ASCII control characters (`< 0x20` and `0x7f`) from untrusted strings, enforcing `max_bytes`.
pub fn scrub_ansi_and_control(input: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if out.len() >= max_bytes {
            break;
        }

        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // ANSI CSI sequence: \x1b[ followed by parameter bytes (0x30..=0x3f),
                    // intermediate bytes (0x20..=0x2f), and final byte (0x40..=0x7e)
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // ANSI OSC sequence: \x1b] ... terminated by BEL (\x07) or ST (\x1b\\)
                    let _ = chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Two-character escape sequence
                    let _ = chars.next();
                }
                None => {}
            }
            continue;
        }

        // Strip C0 control characters (0x00..=0x1f), DEL (0x7f), and C1 control block (0x80..=0x9f)
        if ch.is_control() {
            if ch == '\t' {
                out.push(' ');
            }
            continue;
        }

        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }

    out
}

/// Sanitizes an HTTP Host header or SNI hostname:
/// - Strips ANSI escape sequences and control bytes
/// - Strips optional `:port` suffix (preserving IPv6 bracketed literals if present)
/// - Enforces RFC 1035 max length (253 bytes) and lowercases ASCII characters
pub fn sanitize_host_banner(raw: &str) -> String {
    let scrubbed = scrub_ansi_and_control(raw.trim(), MAX_HOSTNAME_BYTES + 16);
    let host_only = if scrubbed.starts_with('[') {
        if let Some(end_bracket) = scrubbed.find(']') {
            &scrubbed[..=end_bracket]
        } else {
            scrubbed.as_str()
        }
    } else if let Some(idx) = scrubbed.find(':') {
        &scrubbed[..idx]
    } else {
        scrubbed.as_str()
    };

    let mut clean: String = host_only
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || *c == '.'
                || *c == '-'
                || *c == '['
                || *c == ']'
                || *c == ':'
        })
        .take(MAX_HOSTNAME_BYTES)
        .collect();
    clean.make_ascii_lowercase();
    clean
}

/// Neutralizes spreadsheet formula injection payloads per Sovereign Standard Pillar III.
/// If the raw or whitespace-trimmed string starts with `=`, `+`, `-`, `@`, `\t`, or `\r`,
/// prepends a single quote `'`. Also scrubs embedded ANSI escape sequences.
pub fn neutralize_formula(val: &str) -> String {
    let trimmed = val.trim_start_matches(' ');
    let starts_dangerous = val.starts_with('=')
        || val.starts_with('+')
        || val.starts_with('-')
        || val.starts_with('@')
        || val.starts_with('\t')
        || val.starts_with('\r')
        || trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r');

    // Scrub ANSI sequences while preserving printable text
    let scrubbed = scrub_ansi_and_control(val, MAX_BANNER_BYTES);

    if starts_dangerous
        || scrubbed.starts_with('=')
        || scrubbed.starts_with('+')
        || scrubbed.starts_with('-')
        || scrubbed.starts_with('@')
    {
        format!("'{}", scrubbed)
    } else {
        scrubbed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrubs_ansi_csi_and_osc_sequences() {
        let poisoned = "Mozilla/5.0 \x1b[31mRED_ALERT\x1b[0m \x1b]0;PwnedTitle\x07\x00\r\nNextLine";
        let clean = scrub_ansi_and_control(poisoned, 1024);
        assert_eq!(clean, "Mozilla/5.0 RED_ALERT NextLine");
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x00'));
    }

    #[test]
    fn test_sanitize_host_banner_strips_port_and_control_bytes() {
        let raw = "  ExAmPlE.cOm:8443\x1b[2J\r\nInjected: true  ";
        assert_eq!(sanitize_host_banner(raw), "example.com");
    }

    #[test]
    fn test_neutralize_formula_vectors() {
        assert_eq!(
            neutralize_formula("=cmd|'/C calc'!A0"),
            "'=cmd|'/C calc'!A0"
        );
        assert_eq!(neutralize_formula("\t=2+5"), "' =2+5");
        assert_eq!(neutralize_formula("\r+100"), "'+100");
        assert_eq!(neutralize_formula("normal"), "normal");
    }
}
