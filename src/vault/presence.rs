//! Proof that a person is at this Mac before the vault changes: Touch ID, or the login
//! password, in the system's own dialog. An agent can fake a terminal and type at a
//! prompt (`script`, `expect`), but it can't answer this.

use std::sync::mpsc;

use anyhow::{Result, anyhow};
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

/// Shows "toolbox is trying to {reason}." and waits until the person answers.
pub fn confirm(reason: &str) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    // Runs once, on a queue of the system's choosing; the sender is all it holds.
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let answer = if ok.as_bool() { Ok(()) } else { Err(describe(error)) };
        // `confirm` is still waiting on the receiver, so this can't fail.
        let _ = tx.send(answer);
    });
    // SAFETY: a plain LAContext, kept alive until the reply arrives. The reply block only
    // captures a `Sender`, which is Send, as evaluatePolicy requires.
    let context = unsafe { LAContext::new() };
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &reply,
        );
    }
    let answer = rx
        .recv()
        .map_err(|_| anyhow!("macOS closed the Touch ID check without an answer. Nothing changed"))?;
    drop(context);
    answer.map_err(|why| {
        anyhow!(
            "macOS did not confirm it is you ({why}). Nothing changed. Vault changes need Touch ID or your \
             password on this Mac itself, so they don't work over SSH"
        )
    })
}

fn describe(error: *mut NSError) -> String {
    // SAFETY: LocalAuthentication passes either null or an NSError that lives for the call.
    match unsafe { error.as_ref() } {
        Some(error) => error.localizedDescription().to_string(),
        None => "no reason given".to_string(),
    }
}
