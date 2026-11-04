//! Where nebaz keeps its files. Every config, bookmark, macro and cache path
//! goes through here, so Unix and Windows differ in exactly one place.
//!
//! Unix: `$XDG_CONFIG_HOME` / `~/.config`, `$XDG_CACHE_HOME` / `~/.cache`.
//! Windows: `%APPDATA%` and `%LOCALAPPDATA%`, home `%USERPROFILE%` (then
//! `HOME`). An `XDG_*` variable that is set wins on either OS. The resolvers
//! take the environment as a function so they test the same on every OS.

use std::path::PathBuf;

/// Environment lookup; empty values count as unset.
type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn real_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn get(env: Env, key: &str) -> Option<String> {
    env(key).filter(|v| !v.is_empty())
}

fn home_with(env: Env, windows: bool) -> Option<PathBuf> {
    if windows {
        if let Some(h) = get(env, "USERPROFILE") {
            return Some(PathBuf::from(h));
        }
    }
    get(env, "HOME").map(PathBuf::from)
}

fn config_base_with(env: Env, windows: bool) -> Option<PathBuf> {
    if let Some(x) = get(env, "XDG_CONFIG_HOME") {
        return Some(PathBuf::from(x));
    }
    if windows {
        if let Some(a) = get(env, "APPDATA") {
            return Some(PathBuf::from(a));
        }
        return home_with(env, windows).map(|h| h.join("AppData").join("Roaming"));
    }
    home_with(env, windows).map(|h| h.join(".config"))
}

fn cache_base_with(env: Env, windows: bool) -> Option<PathBuf> {
    if let Some(x) = get(env, "XDG_CACHE_HOME") {
        return Some(PathBuf::from(x));
    }
    if windows {
        if let Some(a) = get(env, "LOCALAPPDATA") {
            return Some(PathBuf::from(a));
        }
        return home_with(env, windows).map(|h| h.join("AppData").join("Local"));
    }
    home_with(env, windows).map(|h| h.join(".cache"))
}

/// The user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    home_with(&real_env, cfg!(windows))
}

/// `<config base>/nebaz`.
pub fn config_dir() -> Option<PathBuf> {
    config_base_with(&real_env, cfg!(windows)).map(|d| d.join("nebaz"))
}

/// `<cache base>/nebaz`.
pub fn cache_dir() -> Option<PathBuf> {
    cache_base_with(&real_env, cfg!(windows)).map(|d| d.join("nebaz"))
}

/// Expand a leading `~/` (and `~\` on Windows) in a configured path.
pub fn expand_home(path: &str) -> PathBuf {
    expand_home_with(path, home_dir(), cfg!(windows))
}

fn expand_home_with(path: &str, home: Option<PathBuf>, windows: bool) -> PathBuf {
    let rest = path
        .strip_prefix("~/")
        .or_else(|| if windows { path.strip_prefix("~\\") } else { None });
    match (rest, home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn unix_defaults_and_xdg_override() {
        let e = env(&[("HOME", "/h")]);
        assert_eq!(config_base_with(&e, false), Some(PathBuf::from("/h").join(".config")));
        assert_eq!(cache_base_with(&e, false), Some(PathBuf::from("/h").join(".cache")));
        let e = env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x"), ("XDG_CACHE_HOME", "/c")]);
        assert_eq!(config_base_with(&e, false), Some(PathBuf::from("/x")));
        assert_eq!(cache_base_with(&e, false), Some(PathBuf::from("/c")));
        assert_eq!(config_base_with(&env(&[]), false), None);
        // An empty XDG variable is unset.
        let e = env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "")]);
        assert_eq!(config_base_with(&e, false), Some(PathBuf::from("/h").join(".config")));
    }

    #[test]
    fn windows_uses_appdata_and_userprofile() {
        let e = env(&[("USERPROFILE", "U"), ("APPDATA", "A"), ("LOCALAPPDATA", "L"), ("HOME", "H")]);
        assert_eq!(home_with(&e, true), Some(PathBuf::from("U")));
        assert_eq!(config_base_with(&e, true), Some(PathBuf::from("A")));
        assert_eq!(cache_base_with(&e, true), Some(PathBuf::from("L")));
        // No APPDATA: fall back under the profile. No profile: HOME.
        let e = env(&[("USERPROFILE", "U")]);
        assert_eq!(config_base_with(&e, true), Some(PathBuf::from("U").join("AppData").join("Roaming")));
        assert_eq!(cache_base_with(&e, true), Some(PathBuf::from("U").join("AppData").join("Local")));
        assert_eq!(home_with(&env(&[("HOME", "H")]), true), Some(PathBuf::from("H")));
        // XDG still wins.
        let e = env(&[("APPDATA", "A"), ("XDG_CONFIG_HOME", "X")]);
        assert_eq!(config_base_with(&e, true), Some(PathBuf::from("X")));
    }

    #[test]
    fn expand_home_only_touches_a_leading_tilde() {
        let h = Some(PathBuf::from("H"));
        assert_eq!(expand_home_with("/tmp/x", h.clone(), false), PathBuf::from("/tmp/x"));
        assert_eq!(expand_home_with("~/exports", h.clone(), false), PathBuf::from("H").join("exports"));
        assert_eq!(expand_home_with("~\\exports", h.clone(), false), PathBuf::from("~\\exports"));
        assert_eq!(expand_home_with("~\\exports", h.clone(), true), PathBuf::from("H").join("exports"));
        assert_eq!(expand_home_with("~/exports", None, false), PathBuf::from("~/exports"));
    }
}
