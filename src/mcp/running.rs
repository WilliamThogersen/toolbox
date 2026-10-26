use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use crate::sys::{kill_process_group, terminate_process_group};

const GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct Running(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    calls: HashMap<String, Call>,
    stopping: bool,
}

#[derive(Default)]
struct Call {
    group: Option<u32>,
    cancelled: bool,
}

impl Running {
    pub fn begin(&self, id: &str) {
        self.state().calls.insert(id.to_string(), Call::default());
    }

    pub fn started(&self, id: &str, group: u32) {
        let mut state = self.state();
        let stop = state.stopping;
        if let Some(call) = state.calls.get_mut(id) {
            call.group = Some(group);
            if stop || call.cancelled {
                self.stop(id, group);
            }
        }
    }

    pub fn finish(&self, id: &str) -> bool {
        self.state().calls.remove(id).is_some_and(|call| !call.cancelled)
    }

    pub fn cancel(&self, id: &str) {
        if let Some(call) = self.state().calls.get_mut(id) {
            call.cancelled = true;
            if let Some(group) = call.group {
                self.stop(id, group);
            }
        }
    }

    pub fn stop_all(&self) {
        let mut state = self.state();
        state.stopping = true;
        for (id, call) in &state.calls {
            if let Some(group) = call.group {
                self.stop(id, group);
            }
        }
    }

    fn stop(&self, id: &str, group: u32) {
        terminate_process_group(group);
        let running = self.clone();
        let id = id.to_string();
        thread::spawn(move || {
            thread::sleep(GRACE);
            running.kill_if_running(&id);
        });
    }

    fn kill_if_running(&self, id: &str) {
        if let Some(group) = self.state().calls.get(id).and_then(|call| call.group) {
            kill_process_group(group);
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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
