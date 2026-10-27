//! A pseudo-terminal, to run `tb` the way a person or an MCP client does.
#![expect(unsafe_code, reason = "opening a pseudo-terminal and making it a child's terminal takes libc calls")]
#![allow(dead_code, reason = "not every test file uses a terminal")]

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// The controller side of a pseudo-terminal, and the path of its terminal side.
pub struct Pty {
    controller: libc::c_int,
    pub path: CString,
}

impl Pty {
    pub fn open() -> Self {
        // SAFETY: plain flags, no pointers.
        let controller = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(controller >= 0, "posix_openpt: {}", io::Error::last_os_error());
        // SAFETY: `controller` is the descriptor posix_openpt just returned.
        assert_eq!(unsafe { libc::grantpt(controller) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::unlockpt(controller) }, 0);
        // SAFETY: as above. ptsname returns a NUL-terminated string that stays valid
        // until the next call, and it is copied right away.
        let name = unsafe { libc::ptsname(controller) };
        assert!(!name.is_null(), "ptsname: {}", io::Error::last_os_error());
        // SAFETY: checked for null just above.
        let path = unsafe { CStr::from_ptr(name) }.to_owned();
        Self { controller, path }
    }

    /// A handle on the controller side: what you write to it is typed at the terminal.
    pub fn keyboard(&self) -> File {
        // SAFETY: dup takes no pointers and `controller` is open.
        let copy = unsafe { libc::dup(self.controller) };
        assert!(copy >= 0, "dup: {}", io::Error::last_os_error());
        // SAFETY: `copy` is a fresh descriptor that nothing else owns.
        unsafe { File::from_raw_fd(copy) }
    }

    /// Everything the terminal shows, in pieces as it arrives.
    pub fn screen(&self) -> Receiver<String> {
        let mut reader = self.keyboard();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 || tx.send(String::from_utf8_lossy(&buffer[..read]).into_owned()).is_err() {
                    return;
                }
            }
        });
        rx
    }

    /// The terminal side, to hand a program as its stdin.
    pub fn terminal_side(&self) -> File {
        let path = self.path.to_str().unwrap();
        OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOCTTY).open(path).unwrap()
    }
}

/// Reads `screen` until what it showed contains `wanted`, and returns all of it.
pub fn wait_for(screen: &Receiver<String>, wanted: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = String::new();
    while !seen.contains(wanted) {
        match screen.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(more) => seen.push_str(&more),
            Err(timeout) => panic!("the terminal never showed {wanted:?}, only {seen:?} ({timeout})"),
        }
    }
    seen
}

impl Drop for Pty {
    fn drop(&mut self) {
        // SAFETY: the descriptor is ours and closed only here.
        unsafe { libc::close(self.controller) };
    }
}

/// Makes `cmd` start in a new session whose controlling terminal is `path`.
pub fn use_as_terminal(cmd: &mut Command, path: CString) {
    // SAFETY: `take_terminal` only makes async-signal-safe calls, as code between fork
    // and exec must, and allocates nothing.
    unsafe { cmd.pre_exec(move || take_terminal(&path)) };
}

/// Runs in the child before exec: a new session whose controlling terminal is `path`, also
/// used as stderr (clients let servers inherit theirs). Keeping it open keeps it the
/// controlling terminal: macOS drops that when the last handle closes.
fn take_terminal(path: &CStr) -> io::Result<()> {
    // SAFETY: setsid takes no arguments.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is open, and TIOCSCTTY takes no pointer.
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both are open descriptors.
    if unsafe { libc::dup2(fd, 2) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if fd != 2 {
        // SAFETY: `fd` is ours, and stderr now holds its own copy.
        unsafe { libc::close(fd) };
    }
    Ok(())
}
