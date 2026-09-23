// ported from neboto-tui src/search/query_parser.rs @ d483900
use crate::azure::service::ServiceType;

/// Represents a parsed search query with optional service prefix
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedQuery {
    /// The service to switch to, if detected in the query
    pub service: Option<ServiceType>,
    /// The search text after removing the service prefix
    pub search_text: String,
    /// Whether this query represents a service switch
    pub is_service_switch: bool,
}

/// Parse a query string for service prefix patterns like @vm, @vnet, etc.
///
/// Supported patterns:
/// - `@vm` - Switch to Virtual Machines, empty search
/// - `@vm web` - Switch to Virtual Machines, search "web"
/// - `@vnet subnet` - Switch to Virtual Network, search "subnet"
/// - `web` - No switch, search "web" in current service
///
/// # Examples
///
/// ```
/// let parsed = parse_query("@vm web-server");
/// assert_eq!(parsed.service, Some(ServiceType::VirtualMachines));
/// assert_eq!(parsed.search_text, "web-server");
/// assert!(parsed.is_service_switch);
/// ```
/// `@all <text>` → the cross-service search text: fuzzy-match every service
/// with a warm cache entry instead of switching to one. Checked before
/// `parse_query` (which would reject `all` as an unknown service prefix).
/// `@allx` is NOT an @all query — the prefix must end the token.
pub fn parse_all_query(query: &str) -> Option<&str> {
    let rest = query.trim_start().strip_prefix("@all")?;
    if rest.is_empty() {
        Some("")
    } else if rest.starts_with(char::is_whitespace) {
        Some(rest.trim())
    } else {
        None
    }
}

pub fn parse_query(query: &str) -> ParsedQuery {
    let trimmed = query.trim();

    // Empty query - no service switch, empty search
    if trimmed.is_empty() {
        return ParsedQuery {
            service: None,
            search_text: String::new(),
            is_service_switch: false,
        };
    }

    // Check for @ prefix pattern
    if trimmed.starts_with('@') {
        return parse_at_prefix(trimmed);
    }

    // Check for colon pattern (vm:, vnet:, etc.) — but ONLY when the text before
    // the first colon is a *known* service prefix. Otherwise the colon is just
    // part of the search text (e.g. a pasted `key:value` tag or a URL, or an id/value
    // dropped in by a jump), which should fuzzy-search literally rather than be
    // mistaken for an "invalid service prefix".
    if let Some(colon_pos) = trimmed.find(':') {
        if ServiceType::from_prefix(&trimmed[..colon_pos]).is_some() {
            return parse_colon_prefix(trimmed, colon_pos);
        }
    }

    // No prefix detected - regular search in current service
    ParsedQuery {
        service: None,
        search_text: trimmed.to_string(),
        is_service_switch: false,
    }
}

/// Parse @ prefix pattern like @vm, @vnet
fn parse_at_prefix(query: &str) -> ParsedQuery {
    // Remove the @ symbol
    let without_at = &query[1..];

    // Find the end of the service name (space or end of string)
    let split_pos = without_at
        .find(char::is_whitespace)
        .unwrap_or(without_at.len());

    let service_str = &without_at[..split_pos];
    let remaining = without_at[split_pos..].trim();

    // Try to map to ServiceType
    let service = ServiceType::from_prefix(service_str);

    ParsedQuery {
        service,
        search_text: remaining.to_string(),
        is_service_switch: true,
    }
}

/// An exact tag filter extracted from a search query: `tag:key` (key present,
/// any value) or `tag:key=value` (exact value). Comparisons are
/// case-insensitive — friendlier at a terminal than case-sensitive tag values.
#[derive(Debug, Clone, PartialEq)]
pub struct TagFilter {
    pub key: String,
    pub value: Option<String>,
}

impl TagFilter {
    /// Whether a resource's tag map satisfies this filter.
    pub fn matches(&self, tags: &std::collections::HashMap<String, String>) -> bool {
        tags.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case(&self.key)
                && self
                    .value
                    .as_ref()
                    .is_none_or(|want| v.eq_ignore_ascii_case(want))
        })
    }
}

/// Split `tag:key[=value]` terms out of a search string, returning the exact
/// filters and the remaining text (re-joined) for fuzzy matching. A bare
/// `tag:` with no key stays literal search text.
pub fn split_tag_filters(text: &str) -> (Vec<TagFilter>, String) {
    let mut filters = Vec::new();
    let mut rest: Vec<&str> = Vec::new();
    for term in text.split_whitespace() {
        match term.strip_prefix("tag:") {
            Some(spec) if !spec.is_empty() => {
                let (key, value) = match spec.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => (spec.to_string(), None),
                };
                filters.push(TagFilter { key, value });
            }
            _ => rest.push(term),
        }
    }
    (filters, rest.join(" "))
}

/// Parse colon prefix pattern like vm:, vnet:
fn parse_colon_prefix(query: &str, colon_pos: usize) -> ParsedQuery {
    let service_str = &query[..colon_pos];
    let remaining = query[colon_pos + 1..].trim();

    // Try to map to ServiceType
    let service = ServiceType::from_prefix(service_str);

    ParsedQuery {
        service,
        search_text: remaining.to_string(),
        is_service_switch: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_query_requires_the_exact_prefix() {
        assert_eq!(parse_all_query("@all"), Some(""));
        assert_eq!(parse_all_query("@all "), Some(""));
        assert_eq!(parse_all_query("@all api prod"), Some("api prod"));
        assert_eq!(parse_all_query("  @all x"), Some("x"));
        assert_eq!(parse_all_query("@allx"), None); // prefix must end the token
        assert_eq!(parse_all_query("@vm all"), None);
        assert_eq!(parse_all_query("all"), None);
    }

    #[test]
    fn empty_and_plain_queries_do_not_switch() {
        let parsed = parse_query("");
        assert_eq!(parsed.service, None);
        assert!(!parsed.is_service_switch);
        let parsed = parse_query("web-server");
        assert_eq!(parsed.service, None);
        assert_eq!(parsed.search_text, "web-server");
        assert!(!parsed.is_service_switch);
    }

    #[test]
    fn at_prefix_switches_and_keeps_the_rest() {
        let parsed = parse_query("@vm web");
        assert_eq!(parsed.service, Some(ServiceType::VirtualMachines));
        assert_eq!(parsed.search_text, "web");
        assert!(parsed.is_service_switch);
        let parsed = parse_query("@vnet");
        assert_eq!(parsed.service, Some(ServiceType::Network));
        assert_eq!(parsed.search_text, "");
        // Unknown prefix: a switch with no target, so the app can say so.
        let parsed = parse_query("@ec2 web");
        assert_eq!(parsed.service, None);
        assert!(parsed.is_service_switch);
    }

    #[test]
    fn colon_prefix_only_fires_for_known_services() {
        let parsed = parse_query("kv:prod");
        assert_eq!(parsed.service, Some(ServiceType::KeyVault));
        assert_eq!(parsed.search_text, "prod");
        // A resource id contains colons? No — but a URL does; it must stay literal.
        let parsed = parse_query("https://portal.azure.com");
        assert_eq!(parsed.service, None);
        assert_eq!(parsed.search_text, "https://portal.azure.com");
        assert!(!parsed.is_service_switch);
    }

    #[test]
    fn tag_filters_split_out_and_match_case_insensitively() {
        let (filters, rest) = split_tag_filters("web tag:env=Prod tag:owner tag:");
        assert_eq!(rest, "web tag:");
        assert_eq!(filters.len(), 2);
        let mut tags = std::collections::HashMap::new();
        tags.insert("Env".to_string(), "prod".to_string());
        tags.insert("Owner".to_string(), "x".to_string());
        assert!(filters[0].matches(&tags));
        assert!(filters[1].matches(&tags));
        tags.insert("Env".to_string(), "dev".to_string());
        assert!(!filters[0].matches(&tags));
    }
}
