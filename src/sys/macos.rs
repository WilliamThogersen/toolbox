use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

pub fn parent_pid() -> libc::pid_t {
    // SAFETY: getppid takes no arguments and can't fail.
    unsafe { libc::getppid() }
}

pub fn process(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    // SAFETY: proc_bsdinfo is plain C data, for which all zeroes is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` is a proc_bsdinfo and `size` is its size, as PROC_PIDTBSDINFO expects.
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if got != size {
        return None;
    }
    let mut path = [0 as libc::c_char; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let capacity = u32::try_from(path.len()).ok()?;
    // SAFETY: `path` is a buffer of the size passed in.
    let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), capacity) };
    let program = if len > 0 { text(&path) } else { text(&info.pbi_comm) };
    Some((program, libc::pid_t::try_from(info.pbi_ppid).ok()?))
}

fn text(chars: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = chars.iter().take_while(|c| **c != 0).map(|c| c.cast_unsigned()).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn confirm_presence(reason: &str) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let answer = if ok.as_bool() { Ok(()) } else { Err(describe(error)) };
        let _ = tx.send(answer);
    });
    // SAFETY: a plain LAContext, with no arguments to get wrong.
    let context = unsafe { LAContext::new() };
    let reason = NSString::from_str(reason);
    // SAFETY: `context` is kept alive until the reply arrives. The reply block only
    // captures a `Sender`, which is Send, as evaluatePolicy requires.
    unsafe { context.evaluatePolicy_localizedReason_reply(LAPolicy::DeviceOwnerAuthentication, &reason, &reply) };
    let answer = rx
        .recv()
        .map_err(|_| "macOS closed the Touch ID check without an answer".to_string())?;
    drop(context);
    answer
}

fn describe(error: *mut NSError) -> String {
    // SAFETY: LocalAuthentication passes either null or an NSError that lives for the call.
    match unsafe { error.as_ref() } {
        Some(error) => error.localizedDescription().to_string(),
        None => "no reason given".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_runner_has_a_named_parent() {
        let (program, _) = process(parent_pid()).expect("the parent is running");
        assert!(!program.is_empty());
    }

    #[test]
    fn c_strings_stop_at_the_nul_or_the_end() {
        let chars: Vec<libc::c_char> = b"zsh\0junk".iter().map(|b| b.cast_signed()).collect();
        assert_eq!(text(&chars), "zsh");
        assert_eq!(text(&chars[..3]), "zsh");
    }
}
