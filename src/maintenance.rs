//! # Autonomous Resource Governor & Maintenance Manager
//! Enforces bounded memory limits, periodic hygiene passes, and prevents
//! resource exhaustion on edge hosts and development workstations.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Operational configuration for self-maintenance
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Interval between automatic hygiene passes (default: 5 minutes)
    pub interval: Duration,
    /// Maximum in-memory telemetry records to retain in the ring buffer
    pub max_retained_records: usize,
    /// Enable aggressive memory return to the OS (e.g. malloc_trim)
    pub memory_vacuum: bool,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
            max_retained_records: 10_000,
            memory_vacuum: true,
        }
    }
}

/// Real-time vital metrics for the autonomous governor
#[derive(Debug, Default)]
pub struct GovernorMetrics {
    pub total_hygiene_passes: AtomicU64,
    pub total_connections_served: AtomicU64,
    pub current_active_connections: AtomicUsize,
    pub total_trapped_threats: AtomicU64,
}

/// The Autonomous Governor coordinating background resource health
#[derive(Clone)]
pub struct ResourceGovernor {
    config: MaintenanceConfig,
    metrics: Arc<GovernorMetrics>,
    start_time: Instant,
}

impl ResourceGovernor {
    pub fn new(config: MaintenanceConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(GovernorMetrics::default()),
            start_time: Instant::now(),
        }
    }

    pub fn metrics(&self) -> &GovernorMetrics {
        &self.metrics
    }

    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Record connection start
    pub fn register_connection(&self) {
        self.metrics
            .total_connections_served
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .current_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection close
    pub fn deregister_connection(&self) {
        self.metrics
            .current_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Record trapped threat
    pub fn record_threat(&self) {
        self.metrics
            .total_trapped_threats
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Run a single deterministic maintenance hygiene pass
    pub fn run_hygiene_pass(&self) {
        let pass = self
            .metrics
            .total_hygiene_passes
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        debug!(
            pass = pass,
            "🧹 [GOVERNOR] Executing autonomous resource hygiene pass"
        );

        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self.config.memory_vacuum {
            // Advise the system memory allocator to release unused pages to the kernel (glibc)
            unsafe {
                libc::malloc_trim(0);
            }
        }
    }

    /// Spawn a persistent, non-blocking background task running periodic maintenance
    pub fn spawn_maintenance_worker(self) -> tokio::task::JoinHandle<()> {
        let interval = self.config.interval;
        info!(
            interval_secs = interval.as_secs(),
            "🧹 [GOVERNOR] Autonomous resource maintenance worker active."
        );

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip initial immediate tick
            loop {
                ticker.tick().await;
                self.run_hygiene_pass();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_governor_connection_tracking() {
        let governor = ResourceGovernor::new(MaintenanceConfig::default());
        assert_eq!(
            governor
                .metrics()
                .current_active_connections
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            governor
                .metrics()
                .total_connections_served
                .load(Ordering::Relaxed),
            0
        );

        governor.register_connection();
        assert_eq!(
            governor
                .metrics()
                .current_active_connections
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            governor
                .metrics()
                .total_connections_served
                .load(Ordering::Relaxed),
            1
        );

        governor.deregister_connection();
        assert_eq!(
            governor
                .metrics()
                .current_active_connections
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            governor
                .metrics()
                .total_connections_served
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_hygiene_pass_increments_count() {
        let governor = ResourceGovernor::new(MaintenanceConfig::default());
        governor.run_hygiene_pass();
        assert_eq!(
            governor
                .metrics()
                .total_hygiene_passes
                .load(Ordering::Relaxed),
            1
        );
    }
}
