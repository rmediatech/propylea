//! # Ring-0 Linux `splice(2)` Zero-Copy Pipe Splicer (`proxy/splice.rs`)
//!
//! Bi-directional kernel-space socket splicing engine inspired by zero-copy proxy architectures.
//! Eliminates user-space memory copies and context switches when tunneling raw TCP or
//! Layer-4 SNI passthrough TLS streams by moving page descriptors directly between
//! socket buffers via an anonymous kernel pipe (`SPLICE_F_MOVE | SPLICE_F_NONBLOCK`).

use std::io;
use tokio::net::TcpStream;

/// Optimal kernel pipe chunk size (64 KiB matches default Linux pipe capacity).
pub const SPLICE_CHUNK_LEN: usize = 65_536;

/// RAII wrapper around an anonymous non-blocking Linux kernel pipe (`pipe2`).
/// Guarantees both file descriptors are closed on drop even if a task is aborted.
#[cfg(target_os = "linux")]
pub struct KernelPipe {
    read_fd: std::os::unix::io::RawFd,
    write_fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl KernelPipe {
    /// Allocate a new non-blocking, close-on-exec kernel pipe and tune its ring capacity.
    pub fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        // Best-effort pipe buffer resize to 64 KiB
        unsafe {
            let _ = libc::fcntl(fds[1], libc::F_SETPIPE_SZ, SPLICE_CHUNK_LEN as libc::c_int);
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Raw file descriptor for the read end of the pipe.
    #[inline]
    pub fn read_fd(&self) -> std::os::unix::io::RawFd {
        self.read_fd
    }

    /// Raw file descriptor for the write end of the pipe.
    #[inline]
    pub fn write_fd(&self) -> std::os::unix::io::RawFd {
        self.write_fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for KernelPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.read_fd);
            let _ = libc::close(self.write_fd);
        }
    }
}

/// Unidirectionally splice bytes from `reader` socket into `writer` socket in kernel space.
#[cfg(target_os = "linux")]
pub async fn splice_unidirectional(reader: &TcpStream, writer: &TcpStream) -> io::Result<u64> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    let pipe = KernelPipe::new()?;
    let reader_fd = reader.as_raw_fd();
    let writer_fd = writer.as_raw_fd();
    let mut total_bytes: u64 = 0;

    loop {
        let n_spliced_in = loop {
            reader.readable().await?;
            match reader.try_io(Interest::READABLE, || {
                let n = unsafe {
                    libc::splice(
                        reader_fd,
                        std::ptr::null_mut(),
                        pipe.write_fd,
                        std::ptr::null_mut(),
                        SPLICE_CHUNK_LEN,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(n) => break n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        };

        if n_spliced_in == 0 {
            // Propagate TCP FIN half-close to outbound socket
            unsafe {
                let _ = libc::shutdown(writer_fd, libc::SHUT_WR);
            }
            break;
        }

        let mut remaining = n_spliced_in;
        while remaining > 0 {
            writer.writable().await?;
            match writer.try_io(Interest::WRITABLE, || {
                let n = unsafe {
                    libc::splice(
                        pipe.read_fd,
                        std::ptr::null_mut(),
                        writer_fd,
                        std::ptr::null_mut(),
                        remaining,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "kernel splice(2) wrote 0 bytes to socket",
                    ));
                }
                Ok(written) => {
                    remaining -= written;
                    total_bytes += written as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    Ok(total_bytes)
}

/// Bi-directionally splice two `TcpStream` sockets using Linux `splice(2)` kernel pipes.
/// Returns `(client_to_upstream_bytes, upstream_to_client_bytes)`.
#[cfg(target_os = "linux")]
pub async fn splice_bidirectional(
    client: &TcpStream,
    upstream: &TcpStream,
) -> io::Result<(u64, u64)> {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    tokio::try_join!(
        splice_unidirectional(client, upstream),
        splice_unidirectional(upstream, client)
    )
}

/// Fallback user-space bidirectional tunnel for non-Linux targets (macOS, Windows, BSD).
#[cfg(not(target_os = "linux"))]
async fn forward_half(reader: &TcpStream, writer: &TcpStream) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; SPLICE_CHUNK_LEN];
    loop {
        reader.readable().await?;
        match reader.try_read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                let mut written = 0;
                while written < n {
                    writer.writable().await?;
                    match writer.try_write(&buf[written..n]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "failed to write non-zero bytes to socket",
                            ));
                        }
                        Ok(w) => {
                            written += w;
                            total += w as u64;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Fallback bi-directional tunnel for non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub async fn splice_bidirectional(
    client: &TcpStream,
    upstream: &TcpStream,
) -> io::Result<(u64, u64)> {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    tokio::try_join!(
        forward_half(client, upstream),
        forward_half(upstream, client)
    )
}
