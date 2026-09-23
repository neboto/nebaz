// ported from neboto-tui src/aws/region.rs @ d483900
//! The `R` slot. In Azure a location is a **client-side filter** over
//! subscription-wide lists (no ARM list endpoint filters by location), so
//! `Location::All` is a first-class value and the default.
//!
//! The list below is static, like neboto's region table. Azure's real list
//! is per-subscription (`GET /subscriptions/{id}/locations`, ~60 entries,
//! with display names and paired regions) — whether the picker is fed from
//! that endpoint instead of a compiled table is ticket 04's call; the
//! macro shape survives either way.

/// Define locations with their metadata in a single place.
macro_rules! define_locations {
    (
        $(
            $(#[$vmeta:meta])*
            $variant:ident => $id:expr => $name:expr
        ),* $(,)?
    ) => {
        /// Azure locations the filter offers. The first entry is the default.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub enum Location {
            $(
                $(#[$vmeta])*
                $variant,
            )*
        }

        impl Location {
            pub fn all() -> Vec<Location> {
                vec![
                    $(
                        Location::$variant,
                    )*
                ]
            }

            /// The ARM short name (`eastus`); `"all"` for the no-filter value.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Location::$variant => $id,
                    )*
                }
            }

            pub fn display_name(&self) -> &'static str {
                match self {
                    $(
                        Location::$variant => $name,
                    )*
                }
            }

            pub fn from_str(s: &str) -> Option<Location> {
                let s = s.to_lowercase();
                match s.as_str() {
                    $(
                        $id => Some(Location::$variant),
                    )*
                    _ => None,
                }
            }
        }
    };
}

define_locations! {
    #[default]
    All => "all" => "All locations",
    EastUs => "eastus" => "East US",
    EastUs2 => "eastus2" => "East US 2",
    CentralUs => "centralus" => "Central US",
    WestUs => "westus" => "West US",
    WestUs2 => "westus2" => "West US 2",
    WestUs3 => "westus3" => "West US 3",
    CanadaCentral => "canadacentral" => "Canada Central",
    BrazilSouth => "brazilsouth" => "Brazil South",
    NorthEurope => "northeurope" => "North Europe",
    WestEurope => "westeurope" => "West Europe",
    UkSouth => "uksouth" => "UK South",
    FranceCentral => "francecentral" => "France Central",
    GermanyWestCentral => "germanywestcentral" => "Germany West Central",
    SwedenCentral => "swedencentral" => "Sweden Central",
    SwitzerlandNorth => "switzerlandnorth" => "Switzerland North",
    UaeNorth => "uaenorth" => "UAE North",
    SouthAfricaNorth => "southafricanorth" => "South Africa North",
    CentralIndia => "centralindia" => "Central India",
    SoutheastAsia => "southeastasia" => "Southeast Asia",
    EastAsia => "eastasia" => "East Asia",
    JapanEast => "japaneast" => "Japan East",
    KoreaCentral => "koreacentral" => "Korea Central",
    AustraliaEast => "australiaeast" => "Australia East",
}

impl Location {
    /// Whether a resource's own `location` passes this filter. `All`
    /// passes everything; a resource with no location of its own
    /// (subscription rows, child resources) is never filtered out.
    pub fn admits(&self, resource_location: Option<&str>) -> bool {
        match (self, resource_location) {
            (Location::All, _) => true,
            (_, None) => true,
            (loc, Some(l)) => l.eq_ignore_ascii_case(loc.as_str()),
        }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Location;

    #[test]
    fn all_admits_everything_and_a_location_admits_itself_or_nothing() {
        assert!(Location::All.admits(Some("eastus")));
        assert!(Location::EastUs.admits(Some("EastUS")));
        assert!(!Location::EastUs.admits(Some("westus")));
        // Child / subscription-level rows carry no location: never filtered.
        assert!(Location::EastUs.admits(None));
    }

    #[test]
    fn short_names_round_trip() {
        for l in Location::all() {
            assert_eq!(Location::from_str(l.as_str()), Some(l));
        }
    }
}
