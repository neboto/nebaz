//! Opening a link in the user's browser: `O` (the portal) and `o` in an
//! info card (Microsoft Learn). The system's own opener (`open`,
//! `xdg-open`, `url.dll`), never a shell, and only for an `https://` URL
//! on [`ALLOWED_HOSTS`]: nothing built from Azure data reaches a command
//! line unchecked. Over SSH the browser would be the remote machine's, so
//! the caller copies instead (see [`is_remote`]). The read-only guard
//! keeps process spawning to this file, `editor.rs` and `auth.rs`.

use std::process::{Command, Stdio};

/// The hosts a link may open on.
pub const ALLOWED_HOSTS: &[&str] = &["portal.azure.com", "learn.microsoft.com"];

/// Whether `url` may be handed to the opener: `https://`, an allowed host,
/// and no character a command line could read as anything but the URL.
pub fn allowed(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    ALLOWED_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h))
        && url.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '`' | '\\' | '<' | '>' | '|' | '^' | '&'))
}

/// An SSH session: the browser `open` would start is not the user's.
/// Takes the environment as a parameter (`paths.rs` style) so tests
/// don't depend on how they are run.
pub fn is_remote(env: impl Fn(&str) -> Option<String>) -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"].iter().any(|k| env(k).is_some_and(|v| !v.is_empty()))
}

#[derive(Default)]
pub struct Browser {
    /// The last URL opened. Under `cfg(test)` it is the only effect, so a
    /// test run never starts a browser; the wiring harness reads it back.
    #[cfg_attr(not(test), allow(dead_code))]
    last: Option<String>,
}

impl Browser {
    /// Hand `url` to the system opener. `Err` with the reason when it is
    /// not allowed or the opener can't be started.
    pub fn open(&mut self, url: &str) -> Result<(), String> {
        if !allowed(url) {
            return Err("not a link nebaz opens".into());
        }
        self.last = Some(url.to_string());
        if cfg!(test) {
            return Ok(());
        }
        let mut cmd = opener(url);
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn().map_err(|e| format!("{}: {}", cmd.get_program().to_string_lossy(), e))?;
        // Reap it once it exits (the openers return at once).
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn opener(url: &str) -> Command {
    let mut c = Command::new("open");
    c.arg(url);
    c
}

#[cfg(target_os = "windows")]
fn opener(url: &str) -> Command {
    // `url.dll` opens the default browser without going through `cmd`.
    let mut c = Command::new("rundll32");
    c.arg("url.dll,FileProtocolHandler").arg(url);
    c
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn opener(url: &str) -> Command {
    let mut c = Command::new("xdg-open");
    c.arg(url);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Browser {
        pub(crate) fn last(&self) -> Option<&str> {
            self.last.as_deref()
        }
    }

    #[test]
    fn only_https_links_on_the_allowed_hosts_open() {
        assert!(allowed("https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview"));
        assert!(allowed("https://portal.azure.com/#@t-1/resource/subscriptions/0000/resourceGroups/rg"));
        assert!(!allowed("http://learn.microsoft.com/x"), "not https");
        assert!(!allowed("https://portal.azure.com.evil.example/x"));
        assert!(!allowed("https://portal.azure.com@evil.example/x"), "userinfo is not the host");
        assert!(!allowed("https://example.com/?u=https://portal.azure.com"));
        assert!(!allowed("https://portal.azure.com/x&calc"), "a shell metacharacter");
        assert!(!allowed("https://portal.azure.com/a b"), "whitespace");
        assert!(!allowed("file:///etc/passwd"));
    }

    #[test]
    fn an_ssh_session_is_remote() {
        assert!(is_remote(|k| (k == "SSH_CONNECTION").then(|| "10.0.0.1 5000 10.0.0.2 22".into())));
        assert!(!is_remote(|_| None));
        assert!(!is_remote(|k| (k == "SSH_TTY").then(String::new)));
    }

    #[test]
    fn a_test_build_opens_nothing_and_refuses_a_disallowed_link() {
        let mut b = Browser::default();
        assert_eq!(b.open("https://learn.microsoft.com/azure/automation/overview"), Ok(()));
        assert_eq!(b.last(), Some("https://learn.microsoft.com/azure/automation/overview"));
        assert!(b.open("https://example.com").is_err());
        assert_eq!(b.last(), Some("https://learn.microsoft.com/azure/automation/overview"));
    }
}
