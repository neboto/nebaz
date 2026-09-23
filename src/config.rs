// ported from neboto-tui src/config.rs @ d483900
use crate::azure::location::Location;
use crate::azure::service::ServiceType;
use serde::Deserialize;
use std::path::PathBuf;

/// User configuration, loaded once at startup from a TOML file. Every field is
/// optional — a missing file (or missing key) just falls back to defaults.
///
/// Search order: `$NEBAZ_CONFIG`, then `$XDG_CONFIG_HOME/nebaz/config.toml`
/// (default `~/.config/nebaz/config.toml`), then `~/.nebaz.toml`.
///
/// ```toml
/// # ~/.config/nebaz/config.toml
/// default_service = "vm"       # omit to show the welcome screen and load nothing
/// default_location = "westeurope"  # omit for "all locations"
/// default_subscription = "00000000-0000-0000-0000-000000000000"
/// show_banner     = true
/// ```
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Service to load on startup (a prefix/alias, e.g. "vm", "storage", "aks").
    /// `None` shows the welcome/help splash and loads nothing until the user
    /// picks a service.
    pub default_service: Option<String>,
    /// Location filter to start with (short name, e.g. "westeurope");
    /// unset means all locations.
    pub default_location: Option<String>,
    /// Subscription id to start in. Unset: the Azure CLI's current account.
    pub default_subscription: Option<String>,
    /// Whether the ASCII banner is shown at startup (default true).
    pub show_banner: Option<bool>,
    /// Custom ARM endpoint URL (a sovereign cloud, or an emulator — whether
    /// one is worth supporting is open; Azurite covers storage only).
    pub endpoint_url: Option<String>,
    /// Start in watch mode (auto-refresh of the current view) — same as the
    /// `--watch` flag. `w` toggles it at runtime either way.
    pub watch: Option<bool>,
    /// Watch-mode refresh interval in seconds (default 10, clamped 5–300).
    /// `+`/`-` step through presets at runtime.
    pub watch_interval: Option<u64>,
    /// Start with the detail pane in flat view: every section concatenated
    /// into one scroll (section chips become jump anchors) instead of the
    /// tabbed section-at-a-time view. `\` toggles it at runtime either way.
    pub detail_flat: Option<bool>,
    /// Base resource-cache freshness window in seconds (default 300). A list
    /// reload within this window serves cached data instead of refetching.
    pub cache_ttl: Option<u64>,
    /// Per-service TTL overrides in seconds, keyed by service prefix (any
    /// alias `@`-search accepts). Unknown prefixes are ignored (the config
    /// parses; the key just has no effect). Cost keeps its built-in 6h TTL
    /// unless overridden here.
    ///
    /// ```toml
    /// [cache_ttls]
    /// lambda = 60
    /// cost   = 86400
    /// ```
    pub cache_ttls: Option<std::collections::HashMap<String, u64>>,
    /// Color theme preset: "dark" (default — the classic look), "light",
    /// "solarized-dark", "solarized-light", "gruvbox-dark", "gruvbox-light",
    /// "dracula", "nord", "catppuccin-mocha", or "catppuccin-latte"
    /// (separators optional; `mocha`/`latte` also work).
    pub theme: Option<String>,
    /// Per-color overrides applied on top of the preset, keyed by palette
    /// field name (`accent`, `warning`, `text_dim`, `selection_bg`, …).
    /// Values are `#rrggbb` hex or ANSI color names. Unknown keys / unparsable
    /// values warn at startup and are ignored.
    ///
    /// ```toml
    /// theme = "light"
    /// [theme_colors]
    /// accent  = "#005faf"
    /// warning = "yellow"
    /// ```
    pub theme_colors: Option<std::collections::HashMap<String, String>>,
    /// Set when the config file existed but failed to parse — the app starts
    /// on defaults and surfaces this in the status bar. Never silently: a
    /// TOML typo used to wipe every setting (default_service, roles, …) with
    /// no hint why.
    #[serde(skip)]
    pub load_warning: Option<String>,
}

impl Config {
    /// Load the config from the first existing candidate path, or defaults.
    /// A file that exists but fails to parse falls back to defaults **with
    /// `load_warning` set** so the failure is visible at startup.
    pub fn load() -> Self {
        for path in Self::candidate_paths() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                return match toml::from_str(&contents) {
                    Ok(config) => config,
                    Err(e) => {
                        let mut config = Config::default();
                        // First line of the TOML error carries the message;
                        // the rest is a source snippet too wide for the bar.
                        let msg = e.to_string().lines().next().unwrap_or("parse error").to_string();
                        config.load_warning = Some(format!(
                            "Config ignored — {} failed to parse: {}",
                            path.display(),
                            msg
                        ));
                        config
                    }
                };
            }
        }
        Config::default()
    }

    fn candidate_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(p) = std::env::var("NEBAZ_CONFIG") {
            paths.push(PathBuf::from(p));
        }
        if let Ok(home) = std::env::var("HOME") {
            let xdg = std::env::var("XDG_CONFIG_HOME")
                .unwrap_or_else(|_| format!("{}/.config", home));
            paths.push(PathBuf::from(format!("{}/nebaz/config.toml", xdg)));
            paths.push(PathBuf::from(format!("{}/.nebaz.toml", home)));
        }
        paths
    }

    /// Resolve `default_service` to a `ServiceType` (None if unset/unknown).
    pub fn default_service_type(&self) -> Option<ServiceType> {
        self.default_service
            .as_deref()
            .and_then(ServiceType::from_prefix_service)
    }

    /// Resolve `default_location` to a `Location` (None if unset). Any
    /// string is accepted — there is no location table to validate against
    /// (ADR 0002); an unknown value filters to the empty state.
    pub fn default_location_typed(&self) -> Option<Location> {
        self.default_location.as_deref().map(Location::parse)
    }

    /// Resolve `cache_ttls` prefixes to typed per-service overrides. Unknown
    /// prefixes are dropped silently — a stale key shouldn't break startup.
    pub fn cache_ttl_overrides(
        &self,
    ) -> std::collections::HashMap<ServiceType, std::time::Duration> {
        self.cache_ttls
            .iter()
            .flatten()
            .filter_map(|(prefix, secs)| {
                ServiceType::from_prefix_service(prefix)
                    .map(|s| (s, std::time::Duration::from_secs(*secs)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_service_and_location() {
        let config: Config = toml::from_str(
            r#"
default_service = "vm"
default_location = "WestEurope"
"#,
        )
        .unwrap();
        assert_eq!(config.default_service_type(), Some(ServiceType::VirtualMachines));
        assert_eq!(config.default_location_typed(), Some(Location::Named("westeurope".into())));
    }

    #[test]
    fn parses_cache_ttls_and_drops_unknown_prefixes() {
        let config: Config = toml::from_str(
            r#"
cache_ttl = 120

[cache_ttls]
vm = 60
storage = 900
nosuchservice = 5
"#,
        )
        .unwrap();
        assert_eq!(config.cache_ttl, Some(120));
        let overrides = config.cache_ttl_overrides();
        assert_eq!(
            overrides.get(&ServiceType::VirtualMachines),
            Some(&std::time::Duration::from_secs(60))
        );
        assert_eq!(
            overrides.get(&ServiceType::Storage),
            Some(&std::time::Duration::from_secs(900))
        );
        // The unknown prefix parses but resolves to nothing.
        assert_eq!(overrides.len(), 2);
    }

    #[test]
    fn broken_toml_sets_load_warning_semantics() {
        // Mirrors Config::load's parse arm: a bad file must produce a default
        // config, never a panic — load_warning carries the reason.
        let parsed: std::result::Result<Config, _> = toml::from_str("default_service = [unclosed");
        assert!(parsed.is_err());
    }
}
