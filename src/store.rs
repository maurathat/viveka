//! Where records are kept: SPEC.md section 7.
//!
//! A store only holds bytes under addresses. It is never trusted: every
//! record read from one is re-addressed and its signature checked.

use crate::record::Address;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// A store failed to read or write.
#[derive(Debug)]
pub enum StoreError {
    /// The operating system refused, at this path.
    Io(PathBuf, std::io::Error),
    /// `HEAD` does not hold an address.
    BadHead(String),
    /// A chain name that could escape the store's folder.
    BadChain(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::BadHead(c) => write!(f, "chain `{c}`: HEAD does not hold an address"),
            StoreError::BadChain(c) => write!(f, "`{c}` is not a chain name"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Bytes kept under addresses, one newest address per chain.
pub trait Store {
    /// Keep `bytes` under `address` in `chain`.
    fn put(&mut self, chain: &str, address: &Address, bytes: &[u8]) -> Result<(), StoreError>;
    /// The bytes kept under `address`, if any.
    fn get(&self, chain: &str, address: &Address) -> Result<Option<Vec<u8>>, StoreError>;
    /// The address of the chain's newest record, if the chain exists.
    fn head(&self, chain: &str) -> Result<Option<Address>, StoreError>;
    /// Record `address` as the chain's newest record.
    fn set_head(&mut self, chain: &str, address: &Address) -> Result<(), StoreError>;
}

/// A store in memory, for tests and short-lived chains.
#[derive(Default)]
pub struct MemStore {
    /// Records by chain and address. Public so a test can tamper with one.
    pub records: BTreeMap<(String, Address), Vec<u8>>,
    heads: BTreeMap<String, Address>,
}

impl Store for MemStore {
    fn put(&mut self, chain: &str, address: &Address, bytes: &[u8]) -> Result<(), StoreError> {
        self.records
            .insert((chain.to_string(), address.clone()), bytes.to_vec());
        Ok(())
    }
    fn get(&self, chain: &str, address: &Address) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .records
            .get(&(chain.to_string(), address.clone()))
            .cloned())
    }
    fn head(&self, chain: &str) -> Result<Option<Address>, StoreError> {
        Ok(self.heads.get(chain).cloned())
    }
    fn set_head(&mut self, chain: &str, address: &Address) -> Result<(), StoreError> {
        self.heads.insert(chain.to_string(), address.clone());
        Ok(())
    }
}

/// The folder layout of section 7:
/// `<root>/<chain>/records/<64 hex>.json` and `<root>/<chain>/HEAD`.
pub struct FolderStore {
    root: PathBuf,
}

impl FolderStore {
    /// A store rooted at `root`, created on first write.
    pub fn new(root: impl Into<PathBuf>) -> FolderStore {
        FolderStore { root: root.into() }
    }

    fn dir(&self, chain: &str) -> Result<PathBuf, StoreError> {
        let ok = !chain.is_empty()
            && chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(self.root.join(chain))
        } else {
            Err(StoreError::BadChain(chain.to_string()))
        }
    }
}

/// Write `bytes` to `path` whole: to a temporary name, synced, then renamed,
/// so a reader never sees half a file.
fn write_whole(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let io = |e| StoreError::Io(path.to_path_buf(), e);
    let dir = path.parent().expect("store paths have a parent");
    fs::create_dir_all(dir).map_err(io)?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        path.file_name().and_then(|n| n.to_str()).unwrap_or("x")
    ));
    let mut f = fs::File::create(&tmp).map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)
}

fn read(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Io(path.to_path_buf(), e)),
    }
}

impl Store for FolderStore {
    fn put(&mut self, chain: &str, address: &Address, bytes: &[u8]) -> Result<(), StoreError> {
        write_whole(
            &self
                .dir(chain)?
                .join("records")
                .join(format!("{}.json", address.hex())),
            bytes,
        )
    }
    fn get(&self, chain: &str, address: &Address) -> Result<Option<Vec<u8>>, StoreError> {
        read(
            &self
                .dir(chain)?
                .join("records")
                .join(format!("{}.json", address.hex())),
        )
    }
    fn head(&self, chain: &str) -> Result<Option<Address>, StoreError> {
        match read(&self.dir(chain)?.join("HEAD"))? {
            None => Ok(None),
            Some(b) => std::str::from_utf8(&b)
                .ok()
                .and_then(|s| Address::parse(s.trim()))
                .map(Some)
                .ok_or_else(|| StoreError::BadHead(chain.to_string())),
        }
    }
    fn set_head(&mut self, chain: &str, address: &Address) -> Result<(), StoreError> {
        write_whole(
            &self.dir(chain)?.join("HEAD"),
            format!("{address}\n").as_bytes(),
        )
    }
}
