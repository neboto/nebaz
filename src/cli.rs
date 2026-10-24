// ported from neboto-tui src/cli.rs @ d483900 (the subcommands from
// neboto-tui src/cli.rs @ 08fcd0c)
//! Command-line argument parsing. Every switch is optional and **overrides the
//! config file** (`~/.config/nebaz/config.toml` etc.) for this run only — so you
//! can jump straight to a service/location/subscription without editing config.

use crate::config::Config;
use clap::{Parser, Subcommand, ValueEnum};

/// nebaz — a read-only Azure resource browser TUI.
///
/// With no arguments it honours your config file (or shows the welcome splash).
/// Flags below override the config for this run, e.g. `nebaz -s vm -r westeurope`.
/// With a subcommand it runs once and prints instead of opening the TUI:
/// the same read-only calls, for scripts and agents.
#[derive(Debug, Parser)]
#[command(name = "nebaz", version, about, long_about = None)]
pub struct Cli {
    /// Run once and print instead of opening the TUI.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Output format for subcommands (default json).
    #[arg(short = 'o', long, value_enum, global = true, value_name = "FORMAT")]
    pub output: Option<OutputFormat>,

    /// Service to open on startup (prefix/alias, e.g. vm, storage, aks, @kv).
    #[arg(short = 's', long, value_name = "SERVICE")]
    pub service: Option<String>,

    /// Location filter to start with (e.g. westeurope, eastus; default all).
    #[arg(short = 'r', long, global = true, value_name = "LOCATION")]
    pub location: Option<String>,

    /// Subscription to browse, by id or display name (default: the Azure
    /// CLI's current account).
    #[arg(short = 'p', long, global = true, value_name = "SUBSCRIPTION")]
    pub subscription: Option<String>,

    /// ARM base URL for a sovereign cloud (default https://management.azure.com).
    #[arg(long, global = true, value_name = "URL")]
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

    /// Show each key as it's pressed, and what it did, in a corner box
    /// (for screen recordings and demos; typed text is never shown).
    #[arg(long)]
    pub show_keys: bool,
    /// Skip this run's once-a-day check for a newer nebaz release (config
    /// `update_check = false` turns it off for good).
    #[arg(long)]
    pub no_update_check: bool,

    /// Browse a made-up, offline Azure tenant (`contoso-prod`, `contoso-dev`)
    /// with problems planted to find: no `az`, no login, no network. Works
    /// with the subcommands too (`nebaz --demo ls vm`).
    #[arg(long, global = true)]
    pub demo: bool,
}

/// The one-shot subcommands. Each makes the same read-only calls the TUI
/// makes and prints the result; nothing here can change a subscription.
/// A new headless form is a new variant here and a new arm in
/// `headless::run`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List every service: its prefix, name, and sub-tabs with their
    /// routing prefixes.
    Services,
    /// List one sub-tab, subscription-wide, filtered like the TUI's search.
    #[command(visible_alias = "list")]
    Ls(LsArgs),
    /// Show resources' full detail: every detail-pane section, lazy ones
    /// fetched.
    Get(GetArgs),
    /// What changed recently, subscription-wide (`@changes`), newest
    /// first: Activity Log changes, deployments, health transitions.
    Changes(ChangesArgs),
    /// Security findings (`@audit`): loads the lists the checks read, runs
    /// them, prints the findings and what could not be checked. Exits 3 on
    /// a finding at or above `--fail-on`.
    Audit(AuditArgs),
}

#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    /// Lowest severity that makes the exit code 3: critical, high, medium,
    /// low, info, or never (exit 0 whenever the audit ran).
    #[arg(long, value_name = "SEVERITY", default_value = "low")]
    pub fail_on: String,
}

#[derive(Debug, clap::Args)]
pub struct ChangesArgs {
    /// How far back: 15m, 1h, 6h, 24h or 7d (also spelled 1d, 60m, 1w).
    #[arg(long, value_name = "WINDOW", default_value = "1h")]
    pub since: String,

    /// One source only: activity, deployments or health (default all).
    #[arg(long, value_name = "SOURCE")]
    pub source: Option<String>,

    /// Filter like the TUI search (fuzzy text, `rg:NAME`), e.g. 'rg:prod'.
    #[arg(short = 'f', long, value_name = "QUERY")]
    pub filter: Option<String>,

    /// Drop noise: changes made by managed identities and Azure itself.
    #[arg(long)]
    pub hide_noise: bool,

    /// Print at most N rows.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

#[derive(Debug, clap::Args)]
pub struct LsArgs {
    /// What to list: a prefix (vm, @nsg, rg, …; `nebaz services` lists
    /// them) or service/sub-tab (vnet/subnets, aca/jobs).
    #[arg(value_name = "PREFIX")]
    pub target: String,

    /// Filter like the TUI search: fuzzy text plus exact `rg:NAME` and
    /// `tag:key[=value]` terms, e.g. 'web rg:prod tag:env=prod'.
    #[arg(short = 'f', long, value_name = "QUERY")]
    pub filter: Option<String>,

    /// Only rows in this state, as the state column shows it (any case),
    /// e.g. running.
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,

    /// Drop noise rows (subscriptions that are not Enabled, `@changes`
    /// made by managed identities and Azure itself), the TUI's `a`.
    #[arg(long)]
    pub hide_noise: bool,

    /// Print at most N rows (across every subscription with
    /// --subscriptions).
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,

    /// List in several subscriptions at once, every row tagged with its
    /// subscription: ids or display names, comma-separated
    /// (`--subscriptions Prod,Dev`).
    #[arg(long, value_name = "LIST", value_delimiter = ',', conflicts_with = "all_configured")]
    pub subscriptions: Option<Vec<String>>,

    /// List in every subscription of config `subscriptions`, as
    /// --subscriptions would.
    #[arg(long)]
    pub all_configured: bool,
}

#[derive(Debug, clap::Args)]
pub struct GetArgs {
    /// ARM ids (`/subscriptions/…`), directory ids (`graph:/…`), or exact
    /// names with --in. Up to 50.
    #[arg(value_name = "ID", required = true, num_args = 1..)]
    pub ids: Vec<String>,

    /// Where to look names up: a prefix or service/sub-tab, as `ls` takes.
    /// Ids route themselves and ignore it.
    #[arg(long = "in", value_name = "PREFIX")]
    pub within: Option<String>,

    /// Only this detail section (repeatable, any case), e.g. --section
    /// access. Only its data is fetched.
    #[arg(long = "section", value_name = "NAME")]
    pub sections: Vec<String>,

    /// Seconds to wait for lazily-loaded sections; a section still loading
    /// after that prints as not loaded (null).
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    pub wait: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// One JSON document carrying `"schema": "nebaz/v1"`.
    Json,
    /// Markdown: a table for lists, a document for `get`.
    Md,
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
        if self.show_keys {
            config.show_keys = Some(true);
        }
        if self.no_update_check {
            config.update_check = Some(false);
        }
        // Demo mode is offline: the made-up tenant, and no release check.
        if self.demo {
            config.auth = Some("demo".to_string());
            config.update_check = Some(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Cli {
        Cli {
            command: None,
            output: None,
            service: None,
            location: None,
            subscription: None,
            endpoint_url: None,
            banner: false,
            no_banner: false,
            watch: false,
            macro_name: None,
            theme: None,
            show_keys: false,
            no_update_check: false,
            demo: false,
        }
    }

    #[test]
    fn show_keys_flag_overlays_config() {
        let mut cfg = Config::default();
        Cli { show_keys: true, ..empty() }.apply_to(&mut cfg);
        assert_eq!(cfg.show_keys, Some(true));
        // Absent flag leaves a config-file `show_keys = false` untouched.
        let mut cfg = Config { show_keys: Some(false), ..Config::default() };
        empty().apply_to(&mut cfg);
        assert_eq!(cfg.show_keys, Some(false));
    }

    #[test]
    fn no_update_check_flag_overlays_config() {
        let mut cfg = Config::default();
        Cli { no_update_check: true, ..empty() }.apply_to(&mut cfg);
        assert_eq!(cfg.update_check, Some(false));
        let mut cfg = Config::default();
        empty().apply_to(&mut cfg);
        assert_eq!(cfg.update_check, None, "absent flag: on by default");
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
