use crate::credentials;
use crate::db::Db;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tokio::sync::Mutex;

/// faro.db setting (JSON `"true"`/`"false"`) that keeps saved profile passwords
/// in the OS keychain instead of `profiles.json`.
pub const KEYCHAIN_SETTING: &str = "storePasswordsInKeychain";

pub fn keychain_enabled(db: &Db) -> bool {
    db.settings_get(KEYCHAIN_SETTING).ok().flatten().as_deref() == Some("true")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthMethod {
    Password {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        password: String,
    },
    Key {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    Agent,
    /// A reference to private-key material stored in the OS keychain (under
    /// `key_ref`, e.g. `grant-key:<profile-id>`), never on disk. The connect
    /// path resolves it via `credentials::get_secret` at connect time.
    #[serde(rename_all = "camelCase")]
    KeyRef { key_ref: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub id: String,
    pub name: String,
    pub protocol: String, // "sftp" | "ftp" | "ftps" | "s3"
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_remote_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    // Connect automatically on app launch. Optional so existing profile JSON
    // files (written before this field existed) keep loading as `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,
    // Object-store-specific fields. Unused for sftp/ftp protocols. We keep
    // them optional so existing profile JSON files keep loading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    // Azure Blob specific. `account` is the Azure storage account name,
    // and `bucket` doubles as the container. For S3, both stay absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    // Faro Agent (protocol "faro-agent") specific: the daemon's pinned static
    // public key (base64), learned at pairing time. Its presence means this
    // profile is paired; absence means the user still needs to pair with a code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_key: Option<String>,
    // Rail organisation. `group` is a free-form folder name (absent = ungrouped);
    // `sort_order` is the manual drag-and-drop position. Profiles without one
    // sort after ordered ones, by protocol/name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<u32>,
    // Custom bubble glyph for the rail: an emoji (any short string without a
    // colon) or a bundled Iconify key ("prefix:name"). Absent = the name
    // monogram. Optional so existing profile JSON files keep loading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    // Single-hop bastion (ProxyJump). When `jump_host` is set, the SSH connect
    // path first connects there with the SAME auth material, then tunnels to
    // `host:port` over a direct-tcpip channel. `jump_port` defaults to 22,
    // `jump_username` defaults to `username`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_username: Option<String>,
    // FTP/FTPS character set for path names: absent or "auto" negotiates
    // UTF-8 and falls back to Windows-1252; otherwise a WHATWG label
    // ("utf-8", "windows-1252", "shift_jis", "gbk", ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp_encoding: Option<String>,
    // FTP/FTPS data connections in active (PORT) mode instead of passive.
    // Absent = passive, which works through client-side NAT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp_active_mode: Option<bool>,
    // FTP/FTPS: logged-in connections kept for transfers, separate from the
    // browsing connection (Plan 24). Absent = 2. Lowered automatically when
    // the server refuses more logins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp_max_connections: Option<u8>,
    // FTP/FTPS: parallel connections one download may split across. Absent
    // = 1, since many servers cap logins per user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp_segments: Option<u8>,
}

// Plain JSON file in the app data dir. With the keychain setting on, saved
// passwords live in the OS keychain and are left out of this file.
pub struct ProfileStore {
    path: PathBuf,
    keychain: AtomicBool,
    inner: Arc<Mutex<Vec<ConnectionProfile>>>,
}

impl ProfileStore {
    pub fn load_or_create(app: &AppHandle, keychain: bool) -> Result<Self> {
        let dir = app
            .path()
            .app_data_dir()
            .context("resolving app_data_dir")?;
        Self::from_dir(&dir, keychain)
    }

    /// Load (or initialise) the profile store from a known directory. Used by
    /// the CLI binary, which doesn't have a Tauri AppHandle. Resolves to the
    /// same on-disk path the GUI uses — see `default_data_dir`.
    pub fn from_dir(dir: &std::path::Path, keychain: bool) -> Result<Self> {
        std::fs::create_dir_all(dir).ok();
        let path = dir.join("profiles.json");
        let mut profiles: Vec<ConnectionProfile> = if path.exists() {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        if keychain {
            for p in profiles.iter_mut() {
                if let AuthMethod::Password { password } = &mut p.auth {
                    if password.is_empty() {
                        if let Some(v) = credentials::get_secret(&credentials::profile_password_purpose(&p.id))? {
                            *password = v;
                        }
                    }
                }
            }
        }
        Ok(Self {
            path: path.clone(),
            keychain: AtomicBool::new(keychain),
            inner: Arc::new(Mutex::new(profiles)),
        })
    }

    pub fn keychain_enabled(&self) -> bool {
        self.keychain.load(Ordering::SeqCst)
    }

    /// Switch where saved passwords live. Turning it on moves each password into
    /// the keychain before the file drops it; turning it off writes them back to
    /// the file before the keychain entries are removed.
    pub async fn set_keychain(&self, on: bool, db: &Db) -> Result<()> {
        let g = self.inner.lock().await;
        if on {
            for p in g.iter() {
                sync_password_secret(p, db)?;
            }
            self.keychain.store(true, Ordering::SeqCst);
            if let Err(e) = self.write(&g) {
                self.keychain.store(false, Ordering::SeqCst);
                return Err(e);
            }
        } else {
            self.keychain.store(false, Ordering::SeqCst);
            if let Err(e) = self.write(&g) {
                self.keychain.store(true, Ordering::SeqCst);
                return Err(e);
            }
            for p in g.iter() {
                if let AuthMethod::Password { .. } = &p.auth {
                    let purpose = credentials::profile_password_purpose(&p.id);
                    credentials::delete_secret(&purpose);
                    let _ = db.forget_keychain(credentials::SERVICE, &purpose);
                }
            }
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<ConnectionProfile>> {
        Ok(self.inner.lock().await.clone())
    }

    pub async fn get(&self, id: &str) -> Result<Option<ConnectionProfile>> {
        Ok(self.inner.lock().await.iter().find(|p| p.id == id).cloned())
    }

    pub async fn upsert(&self, profile: ConnectionProfile) -> Result<()> {
        let mut g = self.inner.lock().await;
        if let Some(existing) = g.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            g.push(profile);
        }
        self.write(&g)?;
        Ok(())
    }

    /// Persist a manual rail order: each listed profile gets `sort_order` =
    /// its index. Ids not in the store are skipped; one write for the batch.
    pub async fn reorder(&self, ids: &[String]) -> Result<()> {
        let mut g = self.inner.lock().await;
        for (i, id) in ids.iter().enumerate() {
            if let Some(p) = g.iter_mut().find(|p| &p.id == id) {
                p.sort_order = Some(i as u32);
            }
        }
        self.write(&g)?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        let mut g = self.inner.lock().await;
        g.retain(|p| p.id != id);
        self.write(&g)?;
        Ok(())
    }

    fn write(&self, profiles: &[ConnectionProfile]) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&for_disk(profiles, self.keychain_enabled()))?;
        std::fs::write(&self.path, bytes)
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

/// Keychain side of one profile's saved password (only called in keychain mode):
/// write it under the profile's purpose and record it in the manifest so backups
/// pick it up, or clear both when the password is empty.
pub fn sync_password_secret(profile: &ConnectionProfile, db: &Db) -> Result<()> {
    let AuthMethod::Password { password } = &profile.auth else {
        return Ok(());
    };
    let purpose = credentials::profile_password_purpose(&profile.id);
    if password.is_empty() {
        credentials::delete_secret(&purpose);
        db.forget_keychain(credentials::SERVICE, &purpose)
    } else {
        credentials::set_secret(&purpose, password)?;
        db.record_keychain(credentials::SERVICE, &purpose)
    }
}

/// What lands in `profiles.json`: with the keychain on, passwords are blanked so
/// they never reach the file.
fn for_disk(profiles: &[ConnectionProfile], keychain: bool) -> Vec<ConnectionProfile> {
    profiles
        .iter()
        .cloned()
        .map(|mut p| {
            if keychain {
                if let AuthMethod::Password { password } = &mut p.auth {
                    password.clear();
                }
            }
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_profile() -> ConnectionProfile {
        serde_json::from_value(serde_json::json!({
            "id": "p1",
            "name": "box",
            "protocol": "sftp",
            "host": "example.test",
            "port": 22,
            "username": "ivo",
            "auth": { "kind": "password", "password": "hunter2" }
        }))
        .unwrap()
    }

    #[test]
    fn keychain_mode_keeps_password_out_of_file() {
        let profiles = [password_profile()];
        let on = serde_json::to_string(&for_disk(&profiles, true)).unwrap();
        assert!(!on.contains("hunter2"));
        let off = serde_json::to_string(&for_disk(&profiles, false)).unwrap();
        assert!(off.contains("hunter2"));
        // The in-memory profile is untouched either way.
        assert!(matches!(&profiles[0].auth, AuthMethod::Password { password } if password == "hunter2"));
    }
}
