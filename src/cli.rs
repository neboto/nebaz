// ported from neboto-tui src/cli.rs @ d483900
//! Command-line argument parsing. Every switch is optional and **overrides the
//! config file** (`~/.config/nebaz/config.toml` etc.) for this run only — so you
//! can jump straight to a service/location/subscription without editing config.

use crate::config::Config;
use clap::Parser;

/// nebaz — a read-only Azure resource browser TUI.
///
/// With no arguments it honours your config file (or shows the welcome splash).
/// Flags below override the config for this run, e.g. `nebaz -s vm -r westeurope`.
#[derive(Debug, Parser)]
#[command(name = "nebaz", version, about, long_about = None)]
pub struct Cli {
    /// Service to open on startup (prefix/alias, e.g. vm, storage, aks, @kv).
    #[arg(short = 's', long, value_name = "SERVICE")]
    pub service: Option<String>,

    /// Location filter to start with (e.g. westeurope, eastus; default all).
    #[arg(short = 'r', long, value_name = "LOCATION")]
    pub location: Option<String>,

    /// Subscription to browse, by id or display name (default: the Azure
    /// CLI's current account).
    #[arg(short = 'p', long, value_name = "SUBSCRIPTION")]
    pub subscription: Option<String>,

    /// ARM base URL for a sovereign cloud (default https://management.azure.com).
    #[arg(long, value_name = "URL")]
    pub endpoint_url: Option<String>,

    /// Show the ASCII banner on startup.
    #[arg(long, conflicts_with = "no_banner")]
    pub banner: bool,

    /// Hide the ASCII banner on startup.
    #[arg(long)]
    pub no_banner: bool,

    /// Start in watch mode: auto-refresh the current view (default every 30s;
    /// `w` toggles, `+`/`-` tune the interval once running).
    #[arg(short = 'w', long)]
    pub watch: bool,

    /// Run a saved macro on startup, by name (see `,` in the TUI).
    #[arg(short = 'm', long = "macro", value_name = "NAME")]
    pub macro_name: Option<String>,

    /// Color theme preset: dark (default), light, solarized-dark,
    /// solarized-light, gruvbox-dark, gruvbox-light, dracula, nord,
    /// catppuccin-mocha, catppuccin-latte.
    #[arg(long, value_name = "THEME")]
    pub theme: Option<String>,
}

impl Cli {
    /// Banner preference, if either flag was given (`--banner` → on, `--no-banner`
    /// → off, neither → `None` to defer to config).
    fn banner_pref(&self) -> Option<bool> {
        if self.no_banner {
            Some(false)
        } else if self.banner {
            Some(true)
        } else {
            None
        }
    }

    /// Overlay these CLI switches onto a loaded `Config` (CLI wins where set).
    ///
    /// `--macro` is deliberately absent: it names an *action* for this run, not
    /// a setting, and it's applied by `App::arm_startup_macro` after the app is
    /// built (the saved macros have to be loaded before the name can resolve).
    pub fn apply_to(&self, config: &mut Config) {
        if self.service.is_some() {
            config.default_service = self.service.clone();
        }
        if self.location.is_some() {
            config.default_location = self.location.clone();
        }
        if self.subscription.is_some() {
            config.default_subscription = self.subscription.clone();
        }
        if self.endpoint_url.is_some() {
            config.endpoint_url = self.endpoint_url.clone();
        }
        if let Some(b) = self.banner_pref() {
            config.show_banner = Some(b);
        }
        if self.watch {
            config.watch = Some(true);
        }
        if self.theme.is_some() {
            config.theme = self.theme.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Cli {
        Cli {
            service: None,
            location: None,
            subscription: None,
            endpoint_url: None,
            banner: false,
            no_banner: false,
            watch: false,
            macro_name: None,
            theme: None,
        }
    }

    #[test]
    fn watch_flag_overlays_config() {
        let mut cfg = Config::default();
        Cli { watch: true, ..empty() }.apply_to(&mut cfg);
        assert_eq!(cfg.watch, Some(true));
        // Absent flag leaves a config-file `watch = false` untouched.
        let mut cfg = Config { watch: Some(false), ..Config::default() };
        empty().apply_to(&mut cfg);
        assert_eq!(cfg.watch, Some(false));
    }

    #[test]
    fn cli_overrides_config_where_set() {
        let mut cfg = Config {
            default_service: Some("storage".into()),
            default_location: Some("eastus".into()),
            ..Config::default()
        };
        let cli = Cli {
            service: Some("vm".into()),
            no_banner: true,
            ..empty()
        };
        cli.apply_to(&mut cfg);
        assert_eq!(cfg.default_service.as_deref(), Some("vm")); // overridden
        assert_eq!(cfg.default_location.as_deref(), Some("eastus")); // untouched
        assert_eq!(cfg.show_banner, Some(false));
    }

    #[test]
    fn banner_flags_resolve() {
        assert_eq!(empty().banner_pref(), None);
        assert_eq!(Cli { banner: true, ..empty() }.banner_pref(), Some(true));
        assert_eq!(Cli { no_banner: true, ..empty() }.banner_pref(), Some(false));
    }
}
