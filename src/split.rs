// ported from neboto-tui src/split.rs @ fc8ca57 (neboto #326 + #328)
//! `|`: open a second nebaz beside this one, at the same place — in a new
//! pane of whichever multiplexer / terminal nebaz is running in.
//!
//! The new process is told where to go with `--at <place>`: the current
//! `NavLocation` (service, sub-tab, subscription, row, section) plus the
//! charts' window when they are open, as base64url JSON, restored at
//! startup the way a bookmark is. The session flags (`-p`, `-r`,
//! `--endpoint-url`, `--demo`, `-w`) travel beside it, because a new pane's
//! shell starts from the terminal's environment, not nebaz's. The login is
//! the az CLI's, on disk, so nothing secret is ever passed: only the
//! non-secret variables in [`FORWARDED_VARS`].
//!
//! The one file besides `auth.rs`, `editor.rs` and `browser.rs` that starts
//! a process (the guard's `SPAWNING_FILES`): only the launchers below, and
//! each one starts nebaz, which is read-only.

use crate::app::NavLocation;
use crate::azure::metrics::MetricWindow;
use crate::azure::resource::shell_quote;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// The terminal or multiplexer nebaz is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Tmux,
    Zellij,
    WezTerm,
    Kitty,
    ITerm,
    Ghostty,
    Alacritty,
    TerminalApp,
    GnomeTerminal,
    Konsole,
    Foot,
}

impl Host {
    pub fn name(self) -> &'static str {
        match self {
            Host::Tmux => "tmux",
            Host::Zellij => "zellij",
            Host::WezTerm => "WezTerm",
            Host::Kitty => "kitty",
            Host::ITerm => "iTerm",
            Host::Ghostty => "Ghostty",
            Host::Alacritty => "Alacritty",
            Host::TerminalApp => "Terminal",
            Host::GnomeTerminal => "GNOME Terminal",
            Host::Konsole => "Konsole",
            Host::Foot => "foot",
        }
    }
}

/// The host nebaz runs in, innermost first: a multiplexer inside a terminal
/// splits the multiplexer's pane (the terminal's variables are inherited
/// into the tmux it runs, so the order matters).
pub fn detect(env: impl Fn(&str) -> Option<String>) -> Option<Host> {
    let set = |k: &str| env(k).is_some_and(|v| !v.is_empty());
    let term_program = env("TERM_PROGRAM").unwrap_or_default();
    if set("TMUX") {
        Some(Host::Tmux)
    } else if set("ZELLIJ") {
        Some(Host::Zellij)
    } else if set("WEZTERM_PANE") {
        Some(Host::WezTerm)
    } else if set("KITTY_WINDOW_ID") {
        Some(Host::Kitty)
    } else if term_program == "iTerm.app" {
        Some(Host::ITerm)
    } else if term_program == "ghostty" || set("GHOSTTY_RESOURCES_DIR") {
        Some(Host::Ghostty)
    } else if set("ALACRITTY_SOCKET") || set("ALACRITTY_WINDOW_ID") {
        Some(Host::Alacritty)
    } else if term_program == "Apple_Terminal" {
        Some(Host::TerminalApp)
    } else if set("KONSOLE_VERSION") {
        Some(Host::Konsole)
    } else if set("GNOME_TERMINAL_SCREEN") || set("GNOME_TERMINAL_SERVICE") {
        Some(Host::GnomeTerminal)
    } else if env("TERM").is_some_and(|t| t == "foot" || t.starts_with("foot-")) {
        Some(Host::Foot)
    } else {
        None
    }
}

/// What a launch opens, for the status line: a window opening where a pane
/// was hoped for shouldn't look like a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opens {
    Pane,
    Tab,
    Window,
    /// Config `split_command`: whatever it does.
    Custom,
}

/// One way to open the new nebaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub prog: String,
    pub args: Vec<String>,
    pub opens: Opens,
    /// The program *is* the new window (`alacritty -e`, `foot`): spawn it and
    /// don't wait, or nebaz would hang until that window closed. The others
    /// are a CLI that returns once the pane exists, so its error is
    /// reportable.
    pub detach: bool,
}

impl Launch {
    fn wait(prog: &str, args: Vec<String>, opens: Opens) -> Self {
        Launch { prog: prog.to_string(), args, opens, detach: false }
    }

    fn detach(prog: &str, args: Vec<String>, opens: Opens) -> Self {
        Launch { prog: prog.to_string(), args, opens, detach: true }
    }

    pub fn describe(&self, host: Option<Host>) -> String {
        let what = match self.opens {
            Opens::Pane => "pane",
            Opens::Tab => "tab",
            Opens::Window => "window",
            Opens::Custom => return "Split out with split_command".to_string(),
        };
        match host {
            Some(h) => format!("Split out into a new {} {what}", h.name()),
            None => format!("Split out into a new {what}"),
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HOST: std::cell::Cell<Option<Host>> = const { std::cell::Cell::new(None) };
    static LAUNCHED: std::cell::RefCell<Vec<(String, Vec<String>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FAILING: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Make launches of `progs` fail on this thread (the kitty → window fallback).
#[cfg(test)]
pub fn set_test_failing(progs: &[&str]) {
    FAILING.with(|f| *f.borrow_mut() = progs.iter().map(|p| p.to_string()).collect());
}

/// The host to split, from the process environment. Under `cfg(test)` it is
/// whatever the test set (`set_test_host`), so a `cargo test` run inside
/// tmux behaves like one outside it.
pub fn current_host() -> Option<Host> {
    #[cfg(test)]
    {
        TEST_HOST.with(|h| h.get())
    }
    #[cfg(not(test))]
    {
        detect(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
pub fn set_test_host(host: Option<Host>) {
    TEST_HOST.with(|h| h.set(host));
}

/// The launches made on this thread (tests never spawn anything).
#[cfg(test)]
pub fn take_launched() -> Vec<(String, Vec<String>)> {
    LAUNCHED.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// What `--at` carries: the place, plus the charts' window when `|` was
/// pressed in them (they reopen at it). Not a `NavLocation` field: back
/// and bookmarks never reopen a view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Place {
    #[serde(flatten)]
    pub loc: NavLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chart_window: Option<MetricWindow>,
}

pub fn encode_place(place: &Place) -> String {
    let json = serde_json::to_vec(place).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

pub fn decode_place(s: &str) -> Result<Place, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("--at: not a nebaz place ({e})"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("--at: not a nebaz place ({e})"))
}

/// What the new nebaz is started with, besides the place.
#[derive(Debug, Default, Clone)]
pub struct Session<'a> {
    pub service: Option<&'a str>,
    pub subscription: Option<&'a str>,
    pub location: &'a str,
    pub endpoint: Option<&'a str>,
    pub demo: bool,
    pub watch: bool,
}

/// The `nebaz …` command line (shell-quoted, ready for `sh -c`).
pub fn nebaz_command(exe: &str, session: &Session, place: Option<&str>) -> String {
    let mut parts = vec![shell_quote(exe)];
    if let Some(s) = session.service {
        parts.extend(["-s".to_string(), shell_quote(s)]);
    }
    // Demo mode has its own subscriptions; `--demo` picks them.
    if let (Some(p), false) = (session.subscription, session.demo) {
        parts.extend(["-p".to_string(), shell_quote(p)]);
    }
    parts.extend(["-r".to_string(), shell_quote(session.location)]);
    if let Some(e) = session.endpoint {
        parts.extend(["--endpoint-url".to_string(), shell_quote(e)]);
    }
    if session.demo {
        parts.push("--demo".to_string());
    }
    if session.watch {
        parts.push("-w".to_string());
    }
    // One update check per run is enough; the first pane already did it.
    parts.push("--no-update-check".to_string());
    if let Some(p) = place {
        parts.extend(["--at".to_string(), p.to_string()]);
    }
    parts.join(" ")
}

/// The environment a new pane needs and may not have (its shell starts from
/// the terminal's, or tmux's, environment): where the az login and nebaz's
/// files live, the credential source, the CA bundles. None is a secret.
/// A proxy goes too, unless its URL carries a user name or password.
pub const FORWARDED_VARS: &[&str] = &[
    "AZURE_CONFIG_DIR",
    "NEBAZ_AUTH",
    "NEBAZ_CONFIG",
    "NEBAZ_BOOKMARKS",
    "NEBAZ_MACROS",
    "NEBAZ_EXPORT_DIR",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// `export K='V'; …` for the [`FORWARDED_VARS`] set here, in front of `cmd`.
pub fn with_forwarded_env(cmd: &str, env: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    for k in FORWARDED_VARS {
        let Some(v) = env(k).filter(|v| !v.is_empty()) else {
            continue;
        };
        if k.to_ascii_lowercase().ends_with("_proxy") && !k.eq_ignore_ascii_case("no_proxy") && v.contains('@') {
            continue;
        }
        out.push_str(&format!("export {k}={}; ", shell_quote(&v)));
    }
    out.push_str(cmd);
    out
}

/// Keep the new pane open on a failed start, so its error can be read.
pub fn hold_shell_on_error(cmd: &str) -> String {
    format!(
        "{cmd}; __ec=$?; if [ \"$__ec\" -ne 0 ]; then printf '\\n[exited with status %s] press Enter to close… ' \"$__ec\"; read __; fi",
    )
}

/// The ways to open a pane (else a tab, else a window) beside this one
/// running `shell_cmd` through `sh -c`, best first: the caller tries each
/// until one works. `env` is read for the pane / window ids, so the split
/// lands beside nebaz rather than beside whichever pane is active.
pub fn launches(host: Host, shell_cmd: &str, env: impl Fn(&str) -> Option<String>, macos: bool) -> Vec<Launch> {
    let s = |v: &str| v.to_string();
    let sh = || vec![s("sh"), s("-c"), shell_cmd.to_string()];
    let with = |mut head: Vec<String>, tail: Vec<String>| {
        head.extend(tail);
        head
    };
    match host {
        Host::Tmux => {
            let mut args = vec![s("split-window"), s("-h")];
            if let Some(pane) = env("TMUX_PANE") {
                args.extend([s("-t"), pane]);
            }
            args.push(shell_cmd.to_string());
            vec![Launch::wait("tmux", args, Opens::Pane)]
        }
        Host::Zellij => vec![Launch::wait(
            "zellij",
            with(vec![s("run"), s("--direction"), s("right"), s("--close-on-exit"), s("--")], sh()),
            Opens::Pane,
        )],
        Host::WezTerm => {
            let mut args = vec![s("cli"), s("split-pane"), s("--right")];
            if let Some(pane) = env("WEZTERM_PANE") {
                args.extend([s("--pane-id"), pane]);
            }
            args.push(s("--"));
            vec![Launch::wait("wezterm", with(args, sh()), Opens::Pane)]
        }
        // A split needs `allow_remote_control` in kitty.conf (and the
        // `splits` layout for it to be vertical); without it, a new window.
        Host::Kitty => vec![
            Launch::wait(
                "kitten",
                with(vec![s("@"), s("launch"), s("--location=vsplit"), s("--cwd=current")], sh()),
                Opens::Pane,
            ),
            Launch::detach("kitty", sh(), Opens::Window),
        ],
        Host::ITerm => vec![osascript(&format!(
            "tell application \"iTerm\" to tell current session of current window \
             to split vertically with default profile command \"{}\"",
            applescript_text(&sh_c(shell_cmd))
        ))],
        // Ghostty 1.3+ scripts splits on macOS. No `shell:` prefix: a
        // surface configuration's command takes it literally (the config
        // file's prefixes don't apply), and with arguments it already runs
        // through a shell. Linux has no split IPC, so a window there.
        Host::Ghostty if macos => vec![osascript(&format!(
            "tell application \"Ghostty\"\n\
             set cfg to new surface configuration\n\
             set command of cfg to \"{}\"\n\
             split (focused terminal of selected tab of front window) direction right with configuration cfg\n\
             end tell",
            applescript_text(&sh_c(shell_cmd))
        ))],
        Host::Ghostty => vec![Launch::detach("ghostty", with(vec![s("-e")], sh()), Opens::Window)],
        // No splits, by design: a window in the running instance, else a
        // new one.
        Host::Alacritty => vec![
            Launch::wait("alacritty", with(vec![s("msg"), s("create-window"), s("-e")], sh()), Opens::Window),
            Launch::detach("alacritty", with(vec![s("-e")], sh()), Opens::Window),
        ],
        Host::TerminalApp => vec![osascript_opens(
            &format!(
                "tell application \"Terminal\"\n\
                 do script \"{}\"\n\
                 activate\n\
                 end tell",
                applescript_text(&sh_c(shell_cmd))
            ),
            Opens::Window,
        )],
        Host::GnomeTerminal => {
            vec![Launch::wait("gnome-terminal", with(vec![s("--tab"), s("--")], sh()), Opens::Tab)]
        }
        Host::Konsole => vec![Launch::detach("konsole", with(vec![s("--new-tab"), s("-e")], sh()), Opens::Tab)],
        Host::Foot => vec![Launch::detach("foot", sh(), Opens::Window)],
    }
}

/// Config `split_command`: the user's own launcher, `{cmd}` replaced by the
/// nebaz command as one shell-quoted word. Without `{cmd}`, `sh -c {cmd}`
/// is appended — what a `-e` / `--` style launcher needs.
pub fn custom_launch(template: &str, shell_cmd: &str) -> Launch {
    let quoted = shell_quote(shell_cmd);
    let line = if template.contains("{cmd}") {
        template.replace("{cmd}", &quoted)
    } else {
        format!("{template} sh -c {quoted}")
    };
    Launch::detach("sh", vec!["-c".to_string(), line], Opens::Custom)
}

fn sh_c(shell_cmd: &str) -> String {
    format!("sh -c {}", shell_quote(shell_cmd))
}

/// A string literal's contents in AppleScript.
fn applescript_text(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn osascript(script: &str) -> Launch {
    osascript_opens(script, Opens::Pane)
}

fn osascript_opens(script: &str, opens: Opens) -> Launch {
    Launch::wait("osascript", vec!["-e".to_string(), script.to_string()], opens)
}

/// Run one launch. A waited-on CLI's own error text is what's reported; a
/// detached one only fails if it can't start (a thread reaps it).
pub fn run(launch: &Launch) -> Result<(), String> {
    #[cfg(test)]
    {
        LAUNCHED.with(|l| l.borrow_mut().push((launch.prog.clone(), launch.args.clone())));
        if FAILING.with(|f| f.borrow().contains(&launch.prog)) {
            return Err(format!("{}: failed", launch.prog));
        }
        Ok(())
    }
    #[cfg(not(test))]
    {
        use std::process::{Command, Stdio};
        let prog = &launch.prog;
        let mut cmd = Command::new(prog);
        cmd.args(&launch.args).stdin(Stdio::null());
        if launch.detach {
            let mut child = cmd
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("{prog}: {e}"))?;
            std::thread::spawn(move || child.wait());
            return Ok(());
        }
        let out = cmd.output().map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim();
            Err(if err.is_empty() { format!("{prog} exited with {}", out.status) } else { format!("{prog}: {err}") })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn the_innermost_host_is_split() {
        assert_eq!(detect(env(&[])), None);
        assert_eq!(detect(env(&[("TERM_PROGRAM", "iTerm.app")])), Some(Host::ITerm));
        assert_eq!(detect(env(&[("KITTY_WINDOW_ID", "3")])), Some(Host::Kitty));
        // tmux run inside WezTerm inherits WEZTERM_PANE: split the tmux pane.
        assert_eq!(
            detect(env(&[("WEZTERM_PANE", "0"), ("TMUX", "/tmp/tmux-501/default,1,0")])),
            Some(Host::Tmux)
        );
        assert_eq!(detect(env(&[("ZELLIJ", "0"), ("TERM_PROGRAM", "iTerm.app")])), Some(Host::Zellij));
        assert_eq!(detect(env(&[("TMUX", "")])), None);
    }

    #[test]
    fn tmux_splits_nebaz_s_own_pane() {
        let l = launches(Host::Tmux, "nebaz -r eastus", env(&[("TMUX_PANE", "%4")]), true);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].prog, "tmux");
        assert_eq!(l[0].args, ["split-window", "-h", "-t", "%4", "nebaz -r eastus"]);
        assert_eq!((l[0].opens, l[0].detach), (Opens::Pane, false));
    }

    #[test]
    fn terminals_without_a_split_get_a_window_or_tab() {
        assert_eq!(detect(env(&[("TERM_PROGRAM", "ghostty")])), Some(Host::Ghostty));
        assert_eq!(detect(env(&[("ALACRITTY_SOCKET", "/tmp/a.sock")])), Some(Host::Alacritty));
        assert_eq!(detect(env(&[("TERM_PROGRAM", "Apple_Terminal")])), Some(Host::TerminalApp));
        assert_eq!(detect(env(&[("KONSOLE_VERSION", "230800")])), Some(Host::Konsole));
        assert_eq!(detect(env(&[("GNOME_TERMINAL_SCREEN", "/org/gnome/x")])), Some(Host::GnomeTerminal));
        assert_eq!(detect(env(&[("TERM", "foot")])), Some(Host::Foot));
        // Ghostty under tmux: the tmux pane splits.
        assert_eq!(detect(env(&[("TERM_PROGRAM", "ghostty"), ("TMUX", "/t,1,0")])), Some(Host::Tmux));

        let alacritty = launches(Host::Alacritty, "x", env(&[]), false);
        assert_eq!(alacritty[0].args, ["msg", "create-window", "-e", "sh", "-c", "x"]);
        assert!(!alacritty[0].detach, "msg returns: its error is readable");
        assert_eq!((alacritty[1].prog.as_str(), alacritty[1].detach), ("alacritty", true));
        assert_eq!(launches(Host::Foot, "x", env(&[]), false)[0].opens, Opens::Window);
        assert_eq!(launches(Host::GnomeTerminal, "x", env(&[]), false)[0].opens, Opens::Tab);
        // Linux Ghostty has no split to script: a window, not osascript.
        let linux = launches(Host::Ghostty, "x", env(&[]), false);
        assert_eq!((linux[0].prog.as_str(), linux[0].opens, linux[0].detach), ("ghostty", Opens::Window, true));
    }

    #[test]
    fn ghostty_on_macos_scripts_a_split() {
        let l = launches(Host::Ghostty, "nebaz -p 'a b'", env(&[]), true);
        assert_eq!((l[0].prog.as_str(), l[0].opens), ("osascript", Opens::Pane));
        let script = &l[0].args[1];
        assert!(script.contains("split (focused terminal of selected tab of front window) direction right"), "{script}");
        assert!(script.contains(r#"set command of cfg to "sh -c 'nebaz -p '\\''a b'\\'''""#), "{script}");
    }

    #[test]
    fn kitty_without_remote_control_falls_back_to_a_window() {
        let l = launches(Host::Kitty, "x", env(&[]), false);
        let shape: Vec<_> = l.iter().map(|l| (l.prog.as_str(), l.opens)).collect();
        assert_eq!(shape, [("kitten", Opens::Pane), ("kitty", Opens::Window)]);
    }

    #[test]
    fn split_command_fills_in_the_nebaz_command() {
        let l = custom_launch("my-term --right -- {cmd}", "nebaz -r eastus");
        assert_eq!(l.args, ["-c", "my-term --right -- 'nebaz -r eastus'"]);
        assert_eq!(custom_launch("my-term -e", "nebaz").args[1], "my-term -e sh -c nebaz");
        assert_eq!(l.describe(Some(Host::Tmux)), "Split out with split_command");
    }

    #[test]
    fn the_command_carries_the_session_and_the_place() {
        let session = Session {
            service: Some("@aks"),
            subscription: Some("00000000-0000-0000-0000-000000000001"),
            location: "westeurope",
            endpoint: Some("https://management.usgovcloudapi.net"),
            demo: false,
            watch: true,
        };
        assert_eq!(
            nebaz_command("/opt/bin/nebaz", &session, Some("eyJ9")),
            "/opt/bin/nebaz -s @aks -p 00000000-0000-0000-0000-000000000001 -r westeurope \
             --endpoint-url https://management.usgovcloudapi.net -w --no-update-check --at eyJ9"
        );
        // Demo: its own subscriptions, so no -p.
        let demo = Session { demo: true, watch: false, endpoint: None, ..session };
        assert_eq!(nebaz_command("nebaz", &demo, None), "nebaz -s @aks -r westeurope --demo --no-update-check");
    }

    #[test]
    fn only_non_secret_variables_are_forwarded() {
        let cmd = with_forwarded_env(
            "nebaz",
            env(&[
                ("AZURE_CONFIG_DIR", "/home/me/.azure prod"),
                ("HTTPS_PROXY", "http://user:pw@proxy:3128"),
                ("NO_PROXY", "localhost"),
                ("AZURE_CLIENT_SECRET", "s3cret"),
            ]),
        );
        assert_eq!(cmd, "export AZURE_CONFIG_DIR='/home/me/.azure prod'; export NO_PROXY=localhost; nebaz");
        assert!(!FORWARDED_VARS.iter().any(|k| k.contains("SECRET") || k.contains("PASSWORD")));
    }

    #[test]
    fn iterm_gets_a_quoted_applescript_command() {
        let l = launches(Host::ITerm, "nebaz -p 'a b'", env(&[]), true);
        assert_eq!(
            l[0].args[1],
            r#"tell application "iTerm" to tell current session of current window to split vertically with default profile command "sh -c 'nebaz -p '\\''a b'\\'''""#
        );
    }

    #[test]
    fn a_place_survives_the_trip() {
        let place = Place {
            loc: NavLocation {
                service: crate::azure::service::ServiceType::Aks,
                view: None,
                subscription: Some("sub-1".into()),
                query: "orders".into(),
                selected_id: Some("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-1".into()),
                label: "AKS · aks-1".into(),
                details_focused: true,
                detail_section: Some("Node pools".into()),
            },
            chart_window: Some(MetricWindow::OneDay),
        };
        let encoded = encode_place(&place);
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let back = decode_place(&encoded).unwrap();
        assert_eq!(back.loc.selected_id, place.loc.selected_id);
        assert_eq!(back.loc.detail_section.as_deref(), Some("Node pools"));
        assert!(back.loc.details_focused);
        assert_eq!(back.chart_window, Some(MetricWindow::OneDay));
        assert!(decode_place("not a place!").is_err());
    }
}
