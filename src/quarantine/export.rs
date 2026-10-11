//! # Sovereign Quarantine Multi-Format Export Engine
//!
//! Generates reports across 6 enterprise formats:
//! - TXT: Raw CIDR list for direct piping to `iptables`, `nftables`, `bastion`, or `ipset`
//! - JSON: Pretty-printed structured array for REST API consumption and SIEM ingesters
//! - JSONL: Streaming newline-delimited JSON for high-throughput pipelines (Vector, FluentBit)
//! - MD: GitHub-Flavored Markdown table with summary metrics for sovereign documentation
//! - CSV: RFC 4180 spreadsheet export with formula injection neutralization (Pillar III)
//! - HTML: Standalone, zero-cloud, dark-mode visual operations deck with interactive client-side filtering

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
/// Prefixes dangerous starting characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with a single quote `'`.
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

    // RFC 4180 escaping for quotes and commas
    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

/// Format records as clean newline-separated CIDR strings for firewalls
pub fn format_txt(records: &[QuarantineRecord]) -> String {
    let mut out = String::new();
    for rec in records {
        out.push_str(&rec.cidr);
        out.push('\n');
    }
    out
}

/// Format records as pretty JSON
pub fn format_json(records: &[QuarantineRecord]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(records)
}

/// Format records as streaming JSONL
pub fn format_jsonl(records: &[QuarantineRecord]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for rec in records {
        let line = serde_json::to_string(rec)?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Format records as an executive Markdown table
pub fn format_md(records: &[QuarantineRecord], now_ms: u64) -> String {
    let mut out = String::new();
    let total = records.len();
    let active_count = records.iter().filter(|r| r.active && r.expires_at > now_ms).count();
    let expired_count = total.saturating_sub(active_count);

    let _ = writeln!(out, "# 🛡️ Propylea Autonomous Quarantine Intelligence Briefing");
    let _ = writeln!(out);
    let _ = writeln!(out, "> **Generated at Unix ms**: `{}` | **Zero-Cloud Local Custody**", now_ms);
    let _ = writeln!(out);
    let _ = writeln!(out, "### 📊 Fleet Threat Metrics");
    let _ = writeln!(out, "- **Total Monitored Subnets**: `{}`", total);
    let _ = writeln!(out, "- **Actively Enforced Bans**: `{}`", active_count);
    let _ = writeln!(out, "- **Historical / Expired**: `{}`", expired_count);
    let _ = writeln!(out);
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
        let status = if is_active { "🔴 ACTIVE" } else { "⚪ EXPIRED" };
        let remaining_secs = if is_active {
            (rec.expires_at.saturating_sub(now_ms)) / 1000
        } else {
            0
        };
        let remaining_str = if is_active {
            format!("{}s", remaining_secs)
        } else {
            "-".to_string()
        };
        let ua_display = rec
            .user_agent
            .as_deref()
            .unwrap_or("N/A")
            .chars()
            .take(30)
            .collect::<String>();

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

/// Format records as standard RFC 4180 CSV with formula injection defense
pub fn format_csv(records: &[QuarantineRecord]) -> String {
    let mut out = String::new();
    out.push_str("cidr,ip_version,trigger_ip,infraction_type,infraction_count,quarantined_at,expires_at,active,user_agent\n");

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

/// Format records as a self-contained, responsive, dark-mode HTML visual operations dashboard
pub fn format_html(records: &[QuarantineRecord], now_ms: u64) -> String {
    let total = records.len();
    let active_count = records.iter().filter(|r| r.active && r.expires_at > now_ms).count();
    let ipv4_count = records.iter().filter(|r| r.ip_version == 4).count();
    let ipv6_count = records.iter().filter(|r| r.ip_version == 6).count();

    let mut rows_html = String::new();
    for rec in records {
        let is_active = rec.active && rec.expires_at > now_ms;
        let badge_class = if is_active { "badge-active" } else { "badge-expired" };
        let badge_text = if is_active { "ACTIVE BAN" } else { "EXPIRED" };
        let remaining_secs = if is_active {
            (rec.expires_at.saturating_sub(now_ms)) / 1000
        } else {
            0
        };
        let ua_safe = html_escape(rec.user_agent.as_deref().unwrap_or("N/A"));
        let cidr_safe = html_escape(&rec.cidr);
        let trigger_safe = html_escape(&rec.trigger_ip);
        let infraction_safe = html_escape(&rec.infraction_type);

        let _ = write!(
            rows_html,
            r#"<tr class="{row_filter}">
                <td class="font-mono"><strong>{cidr}</strong></td>
                <td><span class="pill">v{ip_ver}</span></td>
                <td class="font-mono">{trigger}</td>
                <td><span class="tag">{infraction}</span></td>
                <td class="text-center">{violations}</td>
                <td><span class="badge {badge_class}">{badge_text}</span></td>
                <td class="text-right font-mono">{remaining}</td>
                <td class="text-truncate" title="{ua_full}">{ua_truncated}</td>
            </tr>"#,
            row_filter = if is_active { "filter-active" } else { "filter-expired" },
            cidr = cidr_safe,
            ip_ver = rec.ip_version,
            trigger = trigger_safe,
            infraction = infraction_safe,
            violations = rec.infraction_count,
            badge_class = badge_class,
            badge_text = badge_text,
            remaining = if is_active { format!("{}s", remaining_secs) } else { "-".to_string() },
            ua_full = &ua_safe,
            ua_truncated = if ua_safe.len() > 40 { format!("{}...", &ua_safe[..40]) } else { ua_safe.clone() }
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Propylea Autonomous Quarantine Intelligence Deck</title>
    <style>
        :root {{
            --bg-base: #0a0e14;
            --bg-surface: #121820;
            --bg-card: #1a222d;
            --border: #263242;
            --text-main: #e6edf3;
            --text-muted: #8b949e;
            --accent-cyan: #00ffcc;
            --accent-red: #ff3366;
            --accent-orange: #ffaa00;
            --accent-green: #00e676;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-base);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 32px 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 32px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand h1 {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }}
        .brand p {{ color: var(--text-muted); font-size: 13px; }}
        .badge-sovereign {{
            background: rgba(0, 255, 204, 0.1);
            color: var(--accent-cyan);
            border: 1px solid rgba(0, 255, 204, 0.3);
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card-label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }}
        .card-value {{ font-size: 32px; font-weight: 800; font-family: monospace; }}
        .card-value.active {{ color: var(--accent-red); }}
        .card-value.total {{ color: var(--accent-cyan); }}
        .card-value.sub {{ color: var(--text-main); }}
        
        .toolbar {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 14px;
            color: var(--text-main);
            font-size: 14px;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--accent-cyan); }}
        .filter-select {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 14px;
            color: var(--text-main);
            font-size: 14px;
            outline: none;
            cursor: pointer;
        }}
        .table-wrap {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-muted);
            padding: 14px 16px;
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        .font-mono {{ font-family: monospace; font-size: 13px; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }}
        .badge-active {{ background: rgba(255, 51, 102, 0.15); color: var(--accent-red); border: 1px solid rgba(255, 51, 102, 0.4); }}
        .badge-expired {{ background: rgba(139, 148, 158, 0.1); color: var(--text-muted); border: 1px solid rgba(139, 148, 158, 0.3); }}
        .pill {{
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-main);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}
        .tag {{
            background: rgba(0, 255, 204, 0.08);
            color: var(--accent-cyan);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}
        .text-center {{ text-align: center; }}
        .text-right {{ text-align: right; }}
        .text-truncate {{ max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div>
                    <h1>🛡️ Propylea Quarantine Radar</h1>
                    <p>Sovereign Edge Ingress Defense & Subnet Quarantine Operations</p>
                </div>
            </div>
            <div>
                <span class="badge-sovereign">100% Zero-Cloud Custody</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-label">Active Enforced Bans</div>
                <div class="card-value active">{active_count}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Historical Records</div>
                <div class="card-value total">{total}</div>
            </div>
            <div class="card">
                <div class="card-label">IPv4 Subnets (/24)</div>
                <div class="card-value sub">{ipv4_count}</div>
            </div>
            <div class="card">
                <div class="card-label">IPv6 Subnets (/48)</div>
                <div class="card-value sub">{ipv6_count}</div>
            </div>
        </div>

        <div class="toolbar">
            <input type="text" id="searchInput" class="search-box" placeholder="🔍 Filter by CIDR, Trigger IP, or Infraction vector..." onkeyup="filterTable()">
            <select id="statusFilter" class="filter-select" onchange="filterTable()">
                <option value="all">All Records</option>
                <option value="active" selected>Active Bans Only</option>
                <option value="expired">Expired Records Only</option>
            </select>
        </div>

        <div class="table-wrap">
            <table id="quarantineTable">
                <thead>
                    <tr>
                        <th>Subnet CIDR</th>
                        <th>Ver</th>
                        <th>Trigger IP</th>
                        <th>Infraction Vector</th>
                        <th class="text-center">Violations</th>
                        <th>Status</th>
                        <th class="text-right">Expires In</th>
                        <th>Captured User-Agent</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>

        <footer>
            Propylea Sovereign L7 Reverse Proxy & Perimeter Defense • Generated at Unix ms: {now_ms}
        </footer>
    </div>

    <script>
        function filterTable() {{
            const search = document.getElementById('searchInput').value.toLowerCase();
            const status = document.getElementById('statusFilter').value;
            const rows = document.querySelectorAll('#quarantineTable tbody tr');

            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                const matchesSearch = text.includes(search);
                const isActive = row.classList.contains('filter-active');
                
                let matchesStatus = true;
                if (status === 'active') {{
                    matchesStatus = isActive;
                }} else if (status === 'expired') {{
                    matchesStatus = !isActive;
                }}

                row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
            }});
        }}
        // Run filter on initial render
        filterTable();
    </script>
</body>
</html>"#,
        active_count = active_count,
        total = total,
        ipv4_count = ipv4_count,
        ipv6_count = ipv6_count,
        rows = rows_html,
        now_ms = now_ms
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Universal dispatcher exporting records in any requested format
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
