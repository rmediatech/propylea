//! # Sharded Keep-Alive Upstream Connection Pool (`proxy/pool.rs`)
//!
//! High-velocity HTTP/1.1 Keep-Alive connection pool with kernel-level `MSG_PEEK | MSG_DONTWAIT`
//! socket liveness & HTTP desync verification. Eliminates per-request TCP 3-way handshake
//! overhead and ephemeral port (`TIME_WAIT`) exhaustion while guaranteeing that stale or
//! response-smuggled upstream sockets are never reused.

use futures_util::FutureExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::debug;

const DEFAULT_MAX_IDLE_PER_HOST: usize = 64;
const DEFAULT_MAX_IDLE_AGE: Duration = Duration::from_secs(30);

struct PooledEntry {
    sender: SendRequest<Incoming>,
    #[cfg(unix)]
    raw_fd: std::os::unix::io::RawFd,
    last_used: Instant,
}

/// Active upstream connection lease returned by `UpstreamConnectionPool`.
pub struct UpstreamLease {
    pub sender: SendRequest<Incoming>,
    #[cfg(unix)]
    pub raw_fd: std::os::unix::io::RawFd,
    pub reused: bool,
}

/// Thread-safe HTTP/1.1 Keep-Alive connection pool keyed by upstream `SocketAddr`.
pub struct UpstreamConnectionPool {
    buckets: Mutex<HashMap<SocketAddr, VecDeque<PooledEntry>>>,
    max_idle_per_host: usize,
    max_idle_age: Duration,
    hits: AtomicU64,
    misses: AtomicU64,
    stale_evictions: AtomicU64,
}

impl Default for UpstreamConnectionPool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_IDLE_PER_HOST, DEFAULT_MAX_IDLE_AGE)
    }
}

impl UpstreamConnectionPool {
    /// Create a new upstream keep-alive pool with bounded per-host capacity and idle TTL.
    pub fn new(max_idle_per_host: usize, max_idle_age: Duration) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_idle_per_host: max_idle_per_host.max(1),
            max_idle_age,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale_evictions: AtomicU64::new(0),
        }
    }

    /// Acquire a verified-alive `SendRequest` handle from the pool, or dial a fresh `TcpStream`
    /// with `TCP_NODELAY` enabled if no idle connection is available.
    pub async fn acquire(&self, addr: SocketAddr) -> Result<UpstreamLease, io::Error> {
        if let Some(lease) = self.try_acquire_ready(addr).await {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(lease);
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        let stream = TcpStream::connect(addr).await?;
        let _ = stream.set_nodelay(true);
        #[cfg(unix)]
        let raw_fd = stream.as_raw_fd();

        let io = TokioIo::new(stream);
        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(io)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                debug!("Upstream pooled connection closed for {}: {}", addr, err);
            }
        });

        Ok(UpstreamLease {
            sender,
            #[cfg(unix)]
            raw_fd,
            reused: false,
        })
    }

    /// Return a healthy HTTP/1.1 `SendRequest` handle to the pool after a request completes.
    pub fn release(&self, addr: SocketAddr, lease: UpstreamLease) {
        if lease.sender.is_closed() {
            return;
        }
        let mut guard = self.buckets.lock();
        let queue = guard.entry(addr).or_default();
        while queue.len() >= self.max_idle_per_host {
            queue.pop_front();
        }
        queue.push_back(PooledEntry {
            sender: lease.sender,
            #[cfg(unix)]
            raw_fd: lease.raw_fd,
            last_used: Instant::now(),
        });
    }

    /// Scan of the idle bucket for `addr` with kernel liveness verification.
    async fn try_acquire_ready(&self, addr: SocketAddr) -> Option<UpstreamLease> {
        let candidates: Vec<PooledEntry> = {
            let mut guard = self.buckets.lock();
            let queue = guard.get_mut(&addr)?;
            let mut list = Vec::with_capacity(queue.len());
            while let Some(entry) = queue.pop_back() {
                list.push(entry);
            }
            list
        };

        let now = Instant::now();
        let mut busy_entries = Vec::new();
        let mut found = None;

        for mut entry in candidates {
            if found.is_some() {
                busy_entries.push(entry);
                continue;
            }

            if now.duration_since(entry.last_used) > self.max_idle_age || entry.sender.is_closed() {
                self.stale_evictions.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            #[cfg(unix)]
            if !is_socket_clean_and_alive(entry.raw_fd) {
                self.stale_evictions.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Fast poll: if already ready or becomes ready after yielding once to the conn driver
            if entry.sender.ready().now_or_never().is_none() {
                tokio::task::yield_now().await;
            }

            match entry.sender.ready().now_or_never() {
                Some(Ok(())) => {
                    #[cfg(unix)]
                    if !is_socket_clean_and_alive(entry.raw_fd) {
                        self.stale_evictions.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    found = Some(UpstreamLease {
                        sender: entry.sender,
                        #[cfg(unix)]
                        raw_fd: entry.raw_fd,
                        reused: true,
                    });
                }
                Some(Err(_)) => {
                    self.stale_evictions.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    busy_entries.push(entry);
                }
            }
        }

        if !busy_entries.is_empty() {
            let mut guard = self.buckets.lock();
            let queue = guard.entry(addr).or_default();
            for entry in busy_entries.into_iter().rev() {
                if queue.len() < self.max_idle_per_host {
                    queue.push_back(entry);
                }
            }
        }

        found
    }

    /// Total number of requests served via warm pooled keep-alive sockets.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Total number of requests requiring a fresh TCP handshake.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Total number of dead or desynchronized sockets evicted on liveness probe.
    pub fn stale_evictions(&self) -> u64 {
        self.stale_evictions.load(Ordering::Relaxed)
    }
}

/// Kernel-level non-blocking liveness & HTTP desync check (`MSG_PEEK | MSG_DONTWAIT`).
///
/// An idle HTTP/1.1 client socket MUST have zero unread bytes in its receive queue and MUST NOT
/// have received a TCP `FIN` (`n == 0`). Therefore, `recv` MUST return `-1` with `EAGAIN`/`EWOULDBLOCK`.
/// Any other outcome (`n == 0` EOF, `n > 0` smuggled/residual bytes, or socket error) immediately
/// disqualifies the socket from reuse.
#[cfg(unix)]
#[inline]
fn is_socket_clean_and_alive(fd: std::os::unix::io::RawFd) -> bool {
    let mut byte = 0u8;
    let n = unsafe {
        libc::recv(
            fd,
            &mut byte as *mut u8 as *mut libc::c_void,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
    } else {
        // n == 0 means peer sent FIN (EOF); n > 0 means unexpected residual/smuggled bytes!
        false
    }
}
