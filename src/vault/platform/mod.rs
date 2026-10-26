#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod other;

#[cfg(target_os = "macos")]
pub use macos::{ancestors, store};
#[cfg(not(target_os = "macos"))]
pub use other::{ancestors, store};
