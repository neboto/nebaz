//! Responses computed per request instead of stored. None yet: metric
//! series over the asked-for `timespan` belong here (a stored body would
//! show a flat line or the wrong window).

/// A computed body for this request, with a name for the trace.
pub fn respond(_path: &str, _query: &str, _now: i64) -> Option<(&'static str, String)> {
    None
}
