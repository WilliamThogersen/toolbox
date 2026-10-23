//! Tool calls in flight, so a cancelled call, or every call when the client goes away, can be
//! stopped. Each call's process leads its own session and process group, so killing the group
//! also stops whatever the script started with `exec`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[derive(Clone, Default)]
pub struct Running(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    calls: HashMap<String, Call>,
    stopping: bool,
}

#[derive(Default)]
struct Call {
    /// Set once its process has started.
    group: Option<libc::pid_t>,
    cancelled: bool,
}

impl Running {
    /// A call the client sent. Keyed by its JSON-RPC id as JSON text, so `1` and `"1"` differ.
    pub fn begin(&self, id: &str) {
        self.state().calls.insert(id.to_string(), Call::default());
    }

    /// The call's process started. Stops it right away if it was cancelled or the server is
    /// shutting down in the meantime.
    pub fn started(&self, id: &str, group: libc::pid_t) {
        let mut state = self.state();
        let stop = state.stopping;
        if let Some(call) = state.calls.get_mut(id) {
            call.group = Some(group);
            if stop || call.cancelled {
                kill(group);
            }
        }
    }

    /// Forgets a finished call. Returns whether the client still wants its reply.
    pub fn finish(&self, id: &str) -> bool {
        self.state().calls.remove(id).is_some_and(|call| !call.cancelled)
    }

    /// `notifications/cancelled`: stop the call and never reply to it.
    pub fn cancel(&self, id: &str) {
        if let Some(call) = self.state().calls.get_mut(id) {
            call.cancelled = true;
            call.group.into_iter().for_each(kill);
        }
    }

    /// The client closed the connection: stop every call, and any that start later.
    pub fn stop_all(&self) {
        let mut state = self.state();
        state.stopping = true;
        state.calls.values().filter_map(|call| call.group).for_each(kill);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Kills a call's whole process group.
fn kill(group: libc::pid_t) {
    // SAFETY: kill(2) takes no pointers. A negative pid targets the process group the call's
    // process leads (it called setsid). It fails only when that group is already gone.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_wanted_unless_cancelled() {
        let running = Running::default();
        running.begin("1");
        running.begin("2");
        running.cancel("2");
        assert!(running.finish("1"));
        assert!(!running.finish("2"));
        assert!(!running.finish("never-sent"));
    }

    #[test]
    fn cancelling_an_unknown_call_does_nothing() {
        let running = Running::default();
        running.cancel("7");
        running.begin("7");
        assert!(running.finish("7"));
    }
}
