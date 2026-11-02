//! Managed policy: what mods and layouts this machine may use.
//!
//! An administrator writes one JSON file to a system location that
//! ordinary users cannot write. Without it
//! nothing changes. With it, mods and layouts that the policy does not allow
//! are not loaded, listed or switchable, whatever is in the person's app home.
//!
//! ```json
//! { "mods":    { "allow": ["notes", "acme-*"], "block": ["risky"], "allowShipped": true },
//!   "layouts": { "allow": ["acme-*"], "allowShipped": true } }
//! ```
//!
//! Per section: `block` always wins; Herdr's own mods or layouts pass unless
//! blocked while `allowShipped` is true (the default); then `allow`, when
//! present, is the complete list of the rest (`[]` allows none). Without
//! `allow` everything not blocked is allowed. A name is exact, or a prefix
//! ending in `*`. The `main` layout and the app's own `frame-` mods can never
//! be blocked: they are the window itself.
//!
//! A policy file that exists but cannot be read or parsed fails closed: only
//! Herdr's own mods and layouts are allowed, and the reason is logged.
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub allow: Option<Vec<String>>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default = "yes")]
    pub allow_shipped: bool,
}

fn yes() -> bool {
    true
}

impl Rules {
    /// Only Herdr's own.
    fn shipped_only() -> Self {
        Rules { allow: Some(Vec::new()), block: Vec::new(), allow_shipped: true }
    }

    fn permits(&self, name: &str, shipped: bool) -> bool {
        if self.block.iter().any(|p| matches(p, name)) {
            return false;
        }
        if shipped && self.allow_shipped {
            return true;
        }
        self.allow.as_ref().is_none_or(|list| list.iter().any(|p| matches(p, name)))
    }
}

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub mods: Option<Rules>,
    #[serde(default)]
    pub layouts: Option<Rules>,
}

impl Policy {
    pub fn from_json(text: &str) -> Result<Policy, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }

    fn lockdown() -> Policy {
        Policy { mods: Some(Rules::shipped_only()), layouts: Some(Rules::shipped_only()) }
    }

    /// Whether the mod folder `name` may load. `shipped`: it is one of Herdr's own.
    pub fn mod_allowed(&self, name: &str, shipped: bool) -> bool {
        name.starts_with("frame-") || self.mods.as_ref().is_none_or(|r| r.permits(name, shipped))
    }

    pub fn layout_allowed(&self, name: &str, shipped: bool) -> bool {
        name == "main" || self.layouts.as_ref().is_none_or(|r| r.permits(name, shipped))
    }

    #[cfg(test)]
    pub fn is_managed(&self) -> bool {
        self.mods.is_some() || self.layouts.is_some()
    }
}

/// Where the administrator's file lives. Not overridable by the person: an
/// environment variable would let them point at their own. Debug builds and
/// tests may use `HERDR_MANAGED_POLICY`.
pub fn path() -> PathBuf {
    #[cfg(any(test, debug_assertions))]
    if let Some(p) = std::env::var_os("HERDR_MANAGED_POLICY").filter(|v| !v.is_empty()) {
        return p.into();
    }
    system_path()
}

fn system_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/Herdr/managed-policy.json".into()
    } else if cfg!(windows) {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
        base.join("Herdr").join("managed-policy.json")
    } else {
        "/etc/herdr-app/managed-policy.json".into()
    }
}

type Cached = Option<(PathBuf, Option<(SystemTime, u64)>, Arc<Policy>)>;
static CACHE: Mutex<Cached> = Mutex::new(None);

/// The policy in force. Re-read when the file changes, so a changed
/// policy applies to a running app at its next scan.
pub fn current() -> Arc<Policy> {
    current_at(path())
}

fn current_at(path: PathBuf) -> Arc<Policy> {
    let stat = std::fs::metadata(&path).ok().map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
    let mut cache = CACHE.lock().unwrap();
    if let Some((p, s, policy)) = cache.as_ref() {
        if *p == path && *s == stat {
            return policy.clone();
        }
    }
    let policy = Arc::new(match stat {
        None => Policy::default(),
        Some(_) => match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| Policy::from_json(&t)) {
            Ok(p) => {
                tracing::info!("managed policy {} applies", path.display());
                p
            }
            Err(e) => {
                tracing::error!("managed policy {} unusable ({e}): only Herdr's own mods and layouts are allowed", path.display());
                Policy::lockdown()
            }
        },
    });
    *cache = Some((path, stat, policy.clone()));
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(json: &str) -> Policy {
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn no_policy_allows_everything() {
        let none = Policy::default();
        assert!(!none.is_managed());
        assert!(none.mod_allowed("anything", false));
        assert!(none.layout_allowed("anything", false));
    }

    #[test]
    fn allowlist_admits_listed_names_and_prefixes_plus_shipped() {
        let policy = p(r#"{"mods":{"allow":["notes","acme-*"]}}"#);
        assert!(policy.mod_allowed("notes", false));
        assert!(policy.mod_allowed("acme-board", false));
        assert!(!policy.mod_allowed("other", false));
        assert!(policy.mod_allowed("welcome", true));
        assert!(policy.layout_allowed("other", false), "layouts are a separate section");
    }

    #[test]
    fn shipped_can_be_held_to_the_list_and_block_always_wins() {
        let policy = p(r#"{"mods":{"allow":["notes"],"block":["notes"],"allowShipped":false}}"#);
        assert!(!policy.mod_allowed("notes", false));
        assert!(!policy.mod_allowed("welcome", true));
        let policy = p(r#"{"mods":{"block":["welcome"]}}"#);
        assert!(!policy.mod_allowed("welcome", true));
        assert!(policy.mod_allowed("x", false));
    }

    #[test]
    fn empty_allow_means_none_beyond_shipped() {
        let policy = p(r#"{"mods":{"allow":[]},"layouts":{"allow":[]}}"#);
        assert!(!policy.mod_allowed("x", false));
        assert!(policy.mod_allowed("welcome", true));
        assert!(!policy.layout_allowed("mine", false));
        assert!(policy.layout_allowed("win98", true));
    }

    #[test]
    fn the_window_itself_cannot_be_blocked() {
        let policy = p(r#"{"mods":{"allow":[],"block":["frame-*"]},"layouts":{"allow":[],"block":["main"],"allowShipped":false}}"#);
        assert!(policy.mod_allowed("frame-welcome", true));
        assert!(policy.layout_allowed("main", true));
    }

    #[test]
    fn unknown_fields_and_bad_json_are_errors() {
        assert!(Policy::from_json(r#"{"mod":{}}"#).is_err());
        assert!(Policy::from_json(r#"{"mods":{"alow":[]}}"#).is_err());
        assert!(Policy::from_json("{").is_err());
    }

    #[test]
    fn lockdown_leaves_only_shipped() {
        let policy = Policy::lockdown();
        assert!(!policy.mod_allowed("x", false));
        assert!(policy.mod_allowed("welcome", true));
        assert!(!policy.layout_allowed("x", false));
        assert!(policy.layout_allowed("terminals", true));
    }

    #[test]
    fn file_changes_are_picked_up_and_broken_files_fail_closed() {
        let dir = std::env::temp_dir().join(format!("herdr-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("managed-policy.json");
        let current = || current_at(file.clone());
        assert!(!current().is_managed());
        std::fs::write(&file, r#"{"mods":{"allow":["a"]}}"#).unwrap();
        assert!(current().mod_allowed("a", false) && !current().mod_allowed("b", false));
        std::fs::write(&file, "not json at all, longer").unwrap();
        assert!(!current().mod_allowed("a", false) && current().mod_allowed("w", true));
        std::fs::remove_file(&file).unwrap();
        assert!(current().mod_allowed("b", false));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
