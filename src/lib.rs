//! # Propylea: Sovereign Reverse Proxy & Active Defense Gateway
//!
//! Propylea is an ultra-low-memory L7 reverse proxy, multi-domain SNI TLS multiplexer,
//! and perimeter defense gateway written in pure Rust. It drops hostile reconnaissance
//! scans at the edge before they touch upstream services, tunnels WebSockets bi-directionally,
//! governs host memory with autonomous hygiene passes, and records queryable forensic telemetry.

pub mod acme;
pub mod config;
pub mod defense;
pub mod framing_guard;
pub mod headers;
pub mod http_redirect;
pub mod maintenance;
pub mod proxy;
pub mod quarantine;
pub mod router;
pub mod telemetry;
pub mod tls;
pub mod tls_fingerprint;

// Primary re-exports
pub use acme::{try_serve_acme_challenge, ACME_CHALLENGE_PREFIX};
pub use config::{ConfigError, MaintenanceSettings, PropyleaConfig, RouteConfig, SecurityConfig};
pub use defense::EdgeDefense;
pub use framing_guard::{FramingGuard, FramingViolation};
pub use http_redirect::{run_http_redirect_listener, run_http_redirect_server};
pub use maintenance::{GovernorMetrics, MaintenanceConfig, ResourceGovernor};
pub use proxy::{
    handle_proxy_request, run_https_proxy_listener, run_https_proxy_server, BoxedBody, ProxyError,
    ProxyState,
};
pub use quarantine::{
    export_records, ExportFormat, IpcClient, IpcError, IpcRequest, IpcResponse, IpcServer,
    QuarantineAuditEvent, QuarantineManager, QuarantineRecord, QuarantineStore, QuarantineStoreError,
};
pub use router::{UpstreamRouter, UpstreamTarget};
pub use telemetry::{
    current_time_ms, sanitize_query_string, ExecutionTimer, TelemetryFilter, TelemetryRecord,
    TelemetryRingBuffer,
};
pub use tls::{
    build_sni_tls_acceptor, load_certs, load_private_key, SovereignSniResolver, TlsError,
};
pub use tls_fingerprint::{ClientTlsProfile, UserAgentCoherenceVerdict};
