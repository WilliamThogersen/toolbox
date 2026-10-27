#![expect(unsafe_code, reason = "this module wraps the C calls the rest of the crate makes safely")]

#[cfg(not(target_os = "macos"))]
compile_error!("toolbox runs on macOS only");

pub mod macos;

use std::ffi::CStr;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

static EXEC_GROUP: AtomicI32 = AtomicI32::new(0);

pub fn kill_process_group(leader: u32) {
    signal_process_group(leader, libc::SIGKILL);
}

pub fn terminate_process_group(leader: u32) {
    signal_process_group(leader, libc::SIGTERM);
}

fn signal_process_group(leader: u32, signal: libc::c_int) {
    let Ok(group) = libc::pid_t::try_from(leader) else { return };
    if group <= 1 {
        return;
    }
    // SAFETY: kill(2) takes no pointers. A negative pid targets the process group the
    // program leads. It fails only when that group is already gone, which is fine.
    unsafe { libc::kill(-group, signal) };
}

pub struct WatchedGroup(libc::pid_t);

impl WatchedGroup {
    pub fn new(leader: u32) -> Option<Self> {
        let group = libc::pid_t::try_from(leader).ok().filter(|group| *group > 1)?;
        EXEC_GROUP.store(group, Ordering::SeqCst);
        Some(Self(group))
    }
}

impl Drop for WatchedGroup {
    fn drop(&mut self) {
        let _ = EXEC_GROUP.compare_exchange(self.0, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

pub fn stop_children_on_termination() -> io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: sigaction is plain C data, for which all zeroes is a valid value.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_termination as extern "C" fn(libc::c_int) as libc::sighandler_t;
        action.sa_flags = libc::SA_RESETHAND;
        // SAFETY: `sa_mask` is a sigset_t inside `action`, which outlives the call.
        unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
        // SAFETY: `action` is a complete sigaction, and a null old action is allowed.
        if unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

extern "C" fn on_termination(signal: libc::c_int) {
    let group = EXEC_GROUP.load(Ordering::SeqCst);
    if group > 1 {
        // SAFETY: kill is async-signal-safe and takes no pointers.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    // SAFETY: getsid is async-signal-safe and takes no pointers.
    let session = unsafe { libc::getsid(0) };
    // SAFETY: getpid is async-signal-safe and can't fail.
    let leads_session = session == unsafe { libc::getpid() };
    if leads_session {
        // SAFETY: kill is async-signal-safe. Pid 0 is this process's own group, which a
        // session leader started itself.
        unsafe { libc::kill(0, libc::SIGKILL) };
    }
    // SAFETY: raise is async-signal-safe. SA_RESETHAND restored the default action, so
    // the process ends the way the signal would have ended it.
    unsafe { libc::raise(signal) };
}

pub struct InterruptsIgnored {
    saved: Vec<(libc::c_int, libc::sigaction)>,
}

impl InterruptsIgnored {
    pub fn new() -> Self {
        let saved = [libc::SIGINT, libc::SIGQUIT]
            .into_iter()
            .filter_map(|signal| ignore(signal).map(|old| (signal, old)))
            .collect();
        Self { saved }
    }
}

fn ignore(signal: libc::c_int) -> Option<libc::sigaction> {
    // SAFETY: sigaction is plain C data, for which all zeroes is a valid value.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    // SAFETY: as above.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: both point to complete sigactions that outlive the call.
    let status = unsafe { libc::sigaction(signal, &raw const action, &raw mut old) };
    (status == 0).then_some(old)
}

impl Drop for InterruptsIgnored {
    fn drop(&mut self) {
        for (signal, old) in &self.saved {
            // SAFETY: `old` is the complete sigaction saved by `ignore`, and a null old
            // action is allowed.
            unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
        }
    }
}

pub fn start_new_session(command: &mut Command) {
    let detach = || {
        // SAFETY: setsid takes no arguments and touches no memory.
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: `detach` runs between fork and exec, where only async-signal-safe calls are
    // allowed. setsid is one, and `detach` allocates nothing.
    unsafe { command.pre_exec(detach) };
}

pub fn thread_cpu_time() -> Option<Duration> {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes the timespec it is given.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut now) };
    if status != 0 {
        return None;
    }
    Some(Duration::new(u64::try_from(now.tv_sec).ok()?, u32::try_from(now.tv_nsec).ok()?))
}

pub fn syslog(message: &CStr) {
    // SAFETY: a literal format with one %s, given one NUL-terminated string.
    unsafe { libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), message.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thread_clock_reads() {
        assert!(thread_cpu_time().is_some());
    }

    #[test]
    fn our_own_group_and_init_are_never_killed() {
        kill_process_group(0);
        kill_process_group(1);
        terminate_process_group(0);
        assert!(WatchedGroup::new(0).is_none());
        assert!(WatchedGroup::new(1).is_none());
    }
}
