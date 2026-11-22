//! Viveka: a signed memory of what a system tried and what happened, and of
//! the rule changes a person approved because of it.
//!
//! `SPEC.md` is the format's single source of truth; this crate is one
//! implementation of it. Section and rule numbers in these docs are SPEC.md's.

pub mod chain;
pub mod json;
pub mod record;
pub mod store;

pub use chain::{Chain, ProposalState, Violation, verify};
pub use record::{Address, Key, Kind, Record, Signed, Signer};
pub use store::{FolderStore, MemStore, Store, StoreError};
