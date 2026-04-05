use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::error::WatchkeyError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    /// Base64-encoded encrypted master key (nonce + ciphertext).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_key: Option<String>,
    /// Hex-encoded SHA-256 hash of the last Windows Hello signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hash: Option<String>,
    /// Service name → base64-encoded encrypted secret.
    pub secrets: BTreeMap<String, String>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            master_key: None,
            signature_hash: None,
            secrets: BTreeMap::new(),
        }
    }
}

pub fn storage_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("watchkey")
}

pub fn storage_path() -> PathBuf {
    storage_dir().join("secrets.json")
}

pub fn load() -> Result<Store, WatchkeyError> {
    let path = storage_path();
    if !path.exists() {
        return Ok(Store::default());
    }
    let data = fs::read_to_string(&path)?;
    let store: Store = serde_json::from_str(&data)?;
    Ok(store)
}

pub fn save(store: &Store) -> Result<(), WatchkeyError> {
    let dir = storage_dir();
    fs::create_dir_all(&dir)?;

    let data = serde_json::to_string_pretty(store)?;

    // Atomic write: write to tmp file then rename.
    let tmp_path = dir.join("secrets.json.tmp");
    let final_path = storage_path();
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, &final_path)?;

    Ok(())
}

/// Remove all stored data.
pub fn reset() -> Result<(), WatchkeyError> {
    let path = storage_path();
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}
