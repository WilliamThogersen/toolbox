mod client;
mod pairing;
pub mod push;
mod store;

use std::cell::OnceCell;
use std::rc::Rc;

pub use client::{BoardSecret, ProxyRequest};
pub use store::BoardStore;

#[derive(Clone)]
pub struct Connection {
    base: String,
    token: String,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Connection({}, [REDACTED])", self.base)
    }
}

pub struct Link {
    cell: OnceCell<Option<Connection>>,
}

impl Link {
    pub fn lazy() -> Rc<Self> {
        Rc::new(Self { cell: OnceCell::new() })
    }

    #[cfg(test)]
    pub fn none() -> Rc<Self> {
        Rc::new(Self { cell: OnceCell::from(None) })
    }


    pub fn connection(&self) -> Option<&Connection> {
        self.cell.get_or_init(pairing::find).as_ref()
    }
}
