// ported from neboto-tui src/aws/region.rs @ d483900
//! The `R` slot. In Azure a location is a **client-side filter** over
//! subscription-wide lists (no ARM list endpoint filters by location), so
//! `Location::All` is a first-class value and the default.
//!
//! `Location` is a string, not a compiled table (ADR 0002): the picker is
//! fed from `GET /subscriptions/{id}/locations` merged with the distinct
//! locations of the current list, so any ARM short name is a valid value
//! and a location with zero rows in this service is still pickable. An
//! unknown `-r` value simply filters to the "N in other locations" empty
//! state.

/// A location filter value: everything, or one ARM short name (`eastus`).
/// Short names are stored lowercased so equality is by ARM's own spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Location {
    /// No filter — the ordinary state, not a special one.
    #[default]
    All,
    /// One ARM location short name, lowercased.
    Named(String),
}

/// The short name reserved for the no-filter value in config, flags,
/// macros and bookmarks.
pub const ALL: &str = "all";

/// What the `All` value displays as.
pub const ALL_DISPLAY: &str = "All locations";

impl Location {
    /// Parse any user-supplied spelling. `"all"` (any case) and the empty
    /// string are the no-filter value; anything else is taken verbatim as
    /// a short name — there is no table to validate against.
    pub fn parse(s: &str) -> Location {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case(ALL) {
            Location::All
        } else {
            Location::Named(s.to_lowercase())
        }
    }

    /// The ARM short name (`eastus`); `"all"` for the no-filter value.
    pub fn as_str(&self) -> &str {
        match self {
            Location::All => ALL,
            Location::Named(s) => s,
        }
    }

    /// Whether a resource's own `location` passes this filter. `All`
    /// passes everything; a resource with no location of its own
    /// (subscription rows, child resources) is never filtered out.
    pub fn admits(&self, resource_location: Option<&str>) -> bool {
        match (self, resource_location) {
            (Location::All, _) => true,
            (_, None) => true,
            (Location::Named(loc), Some(l)) => l.eq_ignore_ascii_case(loc),
        }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// One entry of `GET /subscriptions/{id}/locations` — what the picker
/// shows next to a short name. Fetched once per subscription and held in
/// the LazyStore, so it resets with a subscription switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationInfo {
    /// ARM short name, as the endpoint spells it (`eastus`).
    pub name: String,
    /// `East US`.
    pub display_name: String,
    /// `(US) East US`, when the endpoint gives one.
    pub regional_display_name: Option<String>,
    /// `Physical` / `Logical`; the picker dims logical (geo) entries.
    pub region_type: Option<String>,
}

impl LocationInfo {
    /// Parse one element of the endpoint's `value` array.
    pub fn from_json(v: &serde_json::Value) -> Option<LocationInfo> {
        let name = v.get("name")?.as_str()?.to_string();
        let display_name = v
            .get("displayName")
            .and_then(|d| d.as_str())
            .unwrap_or(&name)
            .to_string();
        Some(LocationInfo {
            name,
            display_name,
            regional_display_name: v
                .get("regionalDisplayName")
                .and_then(|d| d.as_str())
                .map(str::to_string),
            region_type: v
                .pointer("/metadata/regionType")
                .and_then(|d| d.as_str())
                .map(str::to_string),
        })
    }
}

/// One row of the `R` picker: the endpoint's entry (when the list has
/// landed) merged with how many rows of the current list carry that
/// location. Built by `App::location_rows`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRow {
    pub location: Location,
    pub display_name: String,
    /// Rows in the current list with this location (`All`: every row).
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::{Location, LocationInfo};

    #[test]
    fn all_admits_everything_and_a_location_admits_itself_or_nothing() {
        let eastus = Location::parse("EastUS");
        assert!(Location::All.admits(Some("eastus")));
        assert!(eastus.admits(Some("EastUS")));
        assert!(!eastus.admits(Some("westus")));
        // Child / subscription-level rows carry no location: never filtered.
        assert!(eastus.admits(None));
    }

    #[test]
    fn parse_accepts_any_short_name_and_reserves_all() {
        assert_eq!(Location::parse("all"), Location::All);
        assert_eq!(Location::parse("ALL"), Location::All);
        assert_eq!(Location::parse(""), Location::All);
        assert_eq!(Location::parse(" WestEurope "), Location::Named("westeurope".into()));
        // A region Azure adds tomorrow is just as valid as one it has today.
        assert_eq!(Location::parse("newzealandnorth").as_str(), "newzealandnorth");
        assert_eq!(Location::default(), Location::All);
    }

    #[test]
    fn short_names_round_trip() {
        for s in ["all", "eastus", "westeurope"] {
            assert_eq!(Location::parse(s).as_str(), s);
        }
    }

    #[test]
    fn location_info_parses_the_arm_shape() {
        let v = serde_json::json!({
            "id": "/subscriptions/0/locations/eastus",
            "name": "eastus",
            "displayName": "East US",
            "regionalDisplayName": "(US) East US",
            "metadata": { "regionType": "Physical", "regionCategory": "Recommended" }
        });
        let info = LocationInfo::from_json(&v).unwrap();
        assert_eq!(info.name, "eastus");
        assert_eq!(info.display_name, "East US");
        assert_eq!(info.regional_display_name.as_deref(), Some("(US) East US"));
        assert_eq!(info.region_type.as_deref(), Some("Physical"));
        assert!(LocationInfo::from_json(&serde_json::json!({})).is_none());
    }
}
