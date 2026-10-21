//! # Sovereign Quarantine Multi-Format Export Engine (`quarantine/export/mod.rs`)

mod html;

pub use html::format_html;

use super::store::QuarantineRecord;
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Txt,
    Json,
    Jsonl,
    Md,
    Csv,
    Html,
}

impl std::str::FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "txt" | "text" => Ok(Self::Txt),
            "json" => Ok(Self::Json),
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            "md" | "markdown" => Ok(Self::Md),
            "csv" => Ok(Self::Csv),
            "html" | "htm" => Ok(Self::Html),
            other => Err(format!(
                "Unsupported export format '{}'. Supported: txt, json, jsonl, md, csv, html",
                other
            )),
        }
    }
}

/// Neutralize CSV formula injection payloads per Sovereign Rule Pillar III.
pub fn sanitize_csv_field(val: &str) -> String {
    let trimmed = val.trim_start();
    let dangerous = trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r');

    let sanitized = if dangerous {
        format!("'{}", val)
    } else {
        val.to_string()
    };

    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

pub fn format_txt(records: &[QuarantineRecord]) -> String {
    let mut out = String::new();
    for rec in records {
        out.push_str(&rec.cidr);
        out.push('\n');
    }
    out
}

pub fn format_json(records: &[QuarantineRecord]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(records)
}

pub fn format_jsonl(records: &[QuarantineRecord]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for rec in records {
        let line = serde_json::to_string(rec)?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

pub fn format_md(records: &[QuarantineRecord], now_ms: u64) -> String {
    let mut out = String::new();
    let total = records.len();
    let active_count = records
        .iter()
        .filter(|r| r.active && r.expires_at > now_ms)
        .count();
    let expired_count = total.saturating_sub(active_count);

    let _ = writeln!(
        out,
        "# 🛡️ Propylea Autonomous Quarantine Intelligence Briefing\n"
    );
    let _ = writeln!(
        out,
        "> **Generated at Unix ms**: `{}` | **Zero-Cloud Local Custody**\n",
        now_ms
    );
    let _ = writeln!(out, "### 📊 Fleet Threat Metrics");
    let _ = writeln!(out, "- **Total Monitored Subnets**: `{}`", total);
    let _ = writeln!(out, "- **Actively Enforced Bans**: `{}`", active_count);
    let _ = writeln!(out, "- **Historical / Expired**: `{}`\n", expired_count);
    let _ = writeln!(out, "### 📋 Quarantined Subnets");
    let _ = writeln!(
        out,
        "| Subnet CIDR | IP Ver | Trigger IP | Infraction Vector | Violations | Status | Expires In | Captured UA |"
    );
    let _ = writeln!(
        out,
        "| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :--- |"
    );

    for rec in records {
        let is_active = rec.active && rec.expires_at > now_ms;
        let status = if is_active {
            "🔴 ACTIVE"
        } else {
            "⚪ EXPIRED"
        };
        let remaining_str = if is_active {
            format!("{}s", (rec.expires_at.saturating_sub(now_ms)) / 1000)
        } else {
            "-".to_string()
        };
        let ua_display: String = rec
            .user_agent
            .as_deref()
            .unwrap_or("N/A")
            .chars()
            .take(30)
            .collect();

        let _ = writeln!(
            out,
            "| `{}` | v{} | `{}` | `{}` | {} | {} | {} | `{}` |",
            rec.cidr,
            rec.ip_version,
            rec.trigger_ip,
            rec.infraction_type,
            rec.infraction_count,
            status,
            remaining_str,
            ua_display
        );
    }
    out
}

pub fn format_csv(records: &[QuarantineRecord]) -> String {
    let mut out = String::from(
        "cidr,ip_version,trigger_ip,infraction_type,infraction_count,quarantined_at,expires_at,active,user_agent\n",
    );
    for rec in records {
        let cidr = sanitize_csv_field(&rec.cidr);
        let trigger = sanitize_csv_field(&rec.trigger_ip);
        let infraction = sanitize_csv_field(&rec.infraction_type);
        let ua = sanitize_csv_field(rec.user_agent.as_deref().unwrap_or(""));
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            cidr,
            rec.ip_version,
            trigger,
            infraction,
            rec.infraction_count,
            rec.quarantined_at,
            rec.expires_at,
            rec.active,
            ua
        );
    }
    out
}

pub fn export_records(
    records: &[QuarantineRecord],
    format: ExportFormat,
    now_ms: u64,
) -> Result<String, String> {
    match format {
        ExportFormat::Txt => Ok(format_txt(records)),
        ExportFormat::Json => format_json(records).map_err(|e| e.to_string()),
        ExportFormat::Jsonl => format_jsonl(records).map_err(|e| e.to_string()),
        ExportFormat::Md => Ok(format_md(records, now_ms)),
        ExportFormat::Csv => Ok(format_csv(records)),
        ExportFormat::Html => Ok(format_html(records, now_ms)),
    }
}
