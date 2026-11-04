//! The Azure WAF metrics view (`m` on an Application Gateway with WAF, a
//! Front Door Standard / Premium profile, or a WAF policy attached to
//! one; #153, neboto-tui#294 / #296 / #297): the requests by action, a
//! block rate, and per-rule tables, all from Azure Monitor platform
//! metrics split by dimension. The state and the drawing are
//! `ui::widgets::metrics_waf`; the keys and the task are `app::metrics`.
//!
//! Every call is the same control-plane `GET` the plain metrics view makes
//! (`{id}/providers/Microsoft.Insights/metrics`, `Reader`), with a
//! `$filter` that splits one metric by dimension (`Action eq '*'`), a
//! `top` and an `orderby`. Names and dimensions are from Microsoft Learn,
//! "Supported metrics for Microsoft.Network/applicationgateways" and
//! "Microsoft.Cdn/profiles":
//!
//! | Product | Metric | Dimensions |
//! |---|---|---|
//! | App Gateway | `AzwafTotalRequests` | `Action`, `PolicyName`, … |
//! | App Gateway | `AzwafSecRule` | `Action`, `RuleGroupID`, `RuleID`, `RuleSetName`, `PolicyName`, … |
//! | App Gateway | `AzwafCustomRule` | `Action`, `CustomRuleID`, `PolicyName`, … |
//! | App Gateway | `AzwafBotProtection` | `Action`, `Category`, `PolicyName`, … |
//! | Front Door | `WebApplicationFirewallRequestCount` | `Action`, `RuleName`, `PolicyName` |
//!
//! **Block rate** (neboto's rule): blocked ÷ the requests that end, so
//! `Block ÷ (Allow + Block + Other)`, with a log / count / detect action
//! left out of the denominator (the request went on and was decided
//! elsewhere), and 0% for a minute with no requests ([`classify_action`]
//! is the one place an action's word becomes a kind).

use crate::azure::metrics::{iso_utc, short_error, Aggregation, MetricWindow};
use serde_json::Value;
use std::future::Future;

/// Series asked for per call (`top`). The API default is 10; a rule
/// table is rule × action, so a few dozen rules need more.
pub const RULE_TOP: u32 = 60;
/// The action split has a handful of values.
pub const ACTION_TOP: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafProduct {
    AppGateway,
    FrontDoor,
}

impl WafProduct {
    /// The product whose WAF metrics this ARM id has: an Application
    /// Gateway, or a `Microsoft.Cdn/profiles` profile (nebaz lists only
    /// Front Door Standard / Premium there). Classic Front Door
    /// (`Microsoft.Network/frontDoors`) is not covered.
    pub fn from_id(id: &str) -> Option<Self> {
        let (ns, chain) = crate::azure::resource::arm_type_chain(id)?;
        match (ns.as_str(), chain.iter().map(String::as_str).collect::<Vec<_>>().as_slice()) {
            ("microsoft.network", ["applicationgateways"]) => Some(Self::AppGateway),
            ("microsoft.cdn", ["profiles"]) => Some(Self::FrontDoor),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AppGateway => "App Gateway",
            Self::FrontDoor => "Front Door",
        }
    }
}

// ── Actions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Allow,
    Block,
    /// Log, count, detect, anomaly score: the request went on.
    Log,
    /// Anything else that ends a request (CAPTCHA, JS challenge, redirect)
    /// or that the API names in a way this does not know.
    Other,
}

/// An `Action` dimension value as a kind (case-insensitive, by stem, so
/// `Block` / `Blocked` / `Detected` / `AnomalyScoring` all land).
pub fn classify_action(action: &str) -> ActionKind {
    let a = action.to_ascii_lowercase();
    if a.contains("block") || a.contains("deny") || a.contains("denied") {
        ActionKind::Block
    } else if a.contains("allow") || a == "pass" {
        ActionKind::Allow
    } else if ["log", "count", "detect", "match", "anomaly", "monitor"].iter().any(|s| a.contains(s)) {
        ActionKind::Log
    } else {
        ActionKind::Other
    }
}

/// One action's requests over the window.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionLine {
    pub action: String,
    pub kind: ActionKind,
    pub points: Vec<(i64, f64)>,
    pub total: f64,
}

// ── The calls ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Actions,
    Managed,
    Custom,
    Bot,
    /// Front Door: managed and custom rules share one dimension.
    Rules,
}

/// One split call: a metric, the dimensions it splits by (`required`
/// ones, then `optional` ones a gateway or profile on an older shape may
/// not have, dropped on a retry), the dimension names its rows are keyed
/// by.
#[derive(Debug, Clone, Copy)]
pub struct SplitSpec {
    pub role: Role,
    pub title: &'static str,
    pub metric: &'static str,
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
    /// Dimension holding the rule's identity, and its group and set.
    pub rule_dim: &'static str,
    pub group_dim: &'static str,
    pub set_dim: &'static str,
    pub top: u32,
}

const fn spec(
    role: Role,
    title: &'static str,
    metric: &'static str,
    required: &'static [&'static str],
    optional: &'static [&'static str],
    keys: (&'static str, &'static str, &'static str),
    top: u32,
) -> SplitSpec {
    SplitSpec { role, title, metric, required, optional, rule_dim: keys.0, group_dim: keys.1, set_dim: keys.2, top }
}

const AGW_CALLS: &[SplitSpec] = &[
    spec(Role::Actions, "Requests by action", "AzwafTotalRequests", &["Action"], &[], ("", "", ""), ACTION_TOP),
    spec(
        Role::Managed,
        "Managed rules",
        "AzwafSecRule",
        &["Action", "RuleID"],
        &["RuleGroupID", "RuleSetName", "PolicyName"],
        ("RuleID", "RuleGroupID", "RuleSetName"),
        RULE_TOP,
    ),
    spec(
        Role::Custom,
        "Custom rules",
        "AzwafCustomRule",
        &["Action", "CustomRuleID"],
        &["PolicyName"],
        ("CustomRuleID", "", ""),
        RULE_TOP,
    ),
    spec(
        Role::Bot,
        "Bot protection",
        "AzwafBotProtection",
        &["Action", "Category"],
        &["PolicyName"],
        ("Category", "", ""),
        RULE_TOP,
    ),
];

const AFD_CALLS: &[SplitSpec] = &[
    spec(
        Role::Actions,
        "Requests by action",
        "WebApplicationFirewallRequestCount",
        &["Action"],
        &[],
        ("", "", ""),
        ACTION_TOP,
    ),
    spec(
        Role::Rules,
        "Rules",
        "WebApplicationFirewallRequestCount",
        &["Action", "RuleName"],
        &["PolicyName"],
        ("RuleName", "", ""),
        RULE_TOP,
    ),
];

pub fn waf_calls(product: WafProduct) -> &'static [SplitSpec] {
    match product {
        WafProduct::AppGateway => AGW_CALLS,
        WafProduct::FrontDoor => AFD_CALLS,
    }
}

/// `'` doubled, as OData quotes a literal.
fn odata_quote(v: &str) -> String {
    v.replace('\'', "''")
}

/// The `$filter`: every split dimension as `Dim eq '*'`, then the pinned
/// policy.
pub fn split_filter(dims: &[&str], policy: Option<&str>) -> String {
    let mut parts: Vec<String> = dims.iter().map(|d| format!("{d} eq '*'")).collect();
    if let Some(p) = policy {
        parts.push(format!("PolicyName eq '{}'", odata_quote(p)));
    }
    parts.join(" and ")
}

/// The query pairs of one split call (`api-version` is added by the
/// constructor): the one metric summed, split by `dims`, the biggest
/// `top` series by total first.
pub fn split_query(
    metric: &str,
    dims: &[&str],
    policy: Option<&str>,
    top: u32,
    ordered: bool,
    window: MetricWindow,
    end: i64,
) -> Vec<(&'static str, String)> {
    let mut q = vec![
        ("metricnames", metric.to_string()),
        ("timespan", format!("{}/{}", iso_utc(end - window.secs()), iso_utc(end))),
        ("interval", window.interval().to_string()),
        ("aggregation", Aggregation::Total.as_param().to_string()),
        ("AutoAdjustTimegrain", "true".to_string()),
        ("$filter", split_filter(dims, policy)),
        ("top", top.to_string()),
    ];
    if ordered {
        q.push(("orderby", "total desc".to_string()));
    }
    q
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// One time series of a split response: its dimension values (names
/// lowercased, the API lowercases them) and its points.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitSeries {
    pub dims: Vec<(String, String)>,
    pub points: Vec<(i64, f64)>,
}

impl SplitSeries {
    pub fn dim(&self, name: &str) -> &str {
        self.dims.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).unwrap_or("")
    }

    pub fn total(&self) -> f64 {
        self.points.iter().map(|p| p.1).sum()
    }
}

/// The `timeseries` of the named metric in a split response. A
/// per-metric error is `Err`.
pub fn parse_split(body: &Value, metric: &str) -> Result<Vec<SplitSeries>, String> {
    let Some(v) = body
        .get("value")
        .and_then(Value::as_array)
        .and_then(|vs| {
            vs.iter().find(|v| v.pointer("/name/value").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(metric)))
        })
    else {
        return Err("not in the response".into());
    };
    let code = v.get("errorCode").and_then(Value::as_str).unwrap_or("Success");
    if !code.eq_ignore_ascii_case("Success") {
        return Err(match v.get("errorMessage").and_then(Value::as_str) {
            Some(m) => format!("{code}: {m}"),
            None => code.to_string(),
        });
    }
    let series = v.get("timeseries").and_then(Value::as_array).cloned().unwrap_or_default();
    Ok(series
        .iter()
        .map(|s| {
            let dims = s
                .get("metadatavalues")
                .and_then(Value::as_array)
                .map(|ms| {
                    ms.iter()
                        .filter_map(|m| {
                            Some((m.pointer("/name/value")?.as_str()?.to_lowercase(), m.get("value")?.as_str()?.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let points = s
                .get("data")
                .and_then(Value::as_array)
                .map(|data| {
                    data.iter()
                        .filter_map(|p| {
                            let t = crate::azure::metrics::parse_iso_utc(p.get("timeStamp")?.as_str()?)?;
                            Some((t, p.get("total")?.as_f64()?))
                        })
                        .collect()
                })
                .unwrap_or_default();
            SplitSeries { dims, points }
        })
        .collect())
}

fn kind_order(k: ActionKind) -> u8 {
    match k {
        ActionKind::Allow => 0,
        ActionKind::Block => 1,
        ActionKind::Log => 2,
        ActionKind::Other => 3,
    }
}

/// Series merged per action (a series per policy, say, adds up), ordered
/// allow, block, log, other and by total within a kind.
pub fn merge_by_action(series: &[SplitSeries]) -> Vec<ActionLine> {
    let mut lines: Vec<ActionLine> = Vec::new();
    for s in series {
        let action = s.dim("action").to_string();
        let line = match lines.iter().position(|l| l.action.eq_ignore_ascii_case(&action)) {
            Some(i) => &mut lines[i],
            None => {
                lines.push(ActionLine { kind: classify_action(&action), action, points: Vec::new(), total: 0.0 });
                lines.last_mut().expect("just pushed")
            }
        };
        for &(t, v) in &s.points {
            match line.points.iter_mut().find(|p| p.0 == t) {
                Some(p) => p.1 += v,
                None => line.points.push((t, v)),
            }
        }
        line.total += s.total();
    }
    for l in &mut lines {
        l.points.sort_by_key(|p| p.0);
    }
    lines.sort_by(|a, b| {
        kind_order(a.kind).cmp(&kind_order(b.kind)).then(b.total.partial_cmp(&a.total).unwrap_or(std::cmp::Ordering::Equal))
    });
    lines
}

/// The rate of a pair of sums: blocked over what ended, 0 when nothing did.
fn rate(block: f64, ended: f64) -> f64 {
    if ended > 0.0 {
        100.0 * block / ended
    } else {
        0.0
    }
}

/// The block rate over the window, in percent: `Block ÷ (Allow + Block +
/// Other)`; log / count left out; 0 with no traffic.
pub fn block_rate_total(lines: &[ActionLine]) -> f64 {
    let sum = |k: ActionKind| lines.iter().filter(|l| l.kind == k).map(|l| l.total).sum::<f64>();
    let block = sum(ActionKind::Block);
    rate(block, sum(ActionKind::Allow) + block + sum(ActionKind::Other))
}

/// The block rate per time point: the same rule on each timestamp that
/// any action has, 0 where nothing ended.
pub fn block_rate_points(lines: &[ActionLine]) -> Vec<(i64, f64)> {
    let mut times: Vec<i64> = lines.iter().flat_map(|l| l.points.iter().map(|p| p.0)).collect();
    times.sort_unstable();
    times.dedup();
    times
        .into_iter()
        .map(|t| {
            let at = |k: ActionKind| {
                lines.iter().filter(|l| l.kind == k).flat_map(|l| l.points.iter()).filter(|p| p.0 == t).map(|p| p.1).sum::<f64>()
            };
            let block = at(ActionKind::Block);
            (t, rate(block, at(ActionKind::Allow) + block + at(ActionKind::Other)))
        })
        .collect()
}

/// One rule of a table: its identity, its totals over the window and its
/// actions over time (what `⏎` charts).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleRow {
    pub rule: String,
    pub group: String,
    pub set: String,
    pub policy: String,
    pub total: f64,
    pub blocked: f64,
    pub actions: Vec<ActionLine>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleTable {
    pub role: Role,
    pub title: &'static str,
    pub rows: Vec<RuleRow>,
    /// Series the call returned; at `top` there may be more.
    pub series: usize,
    pub top: u32,
    pub error: Option<String>,
}

impl RuleTable {
    /// The call returned as many series as it asked for, so more may exist.
    pub fn capped(&self) -> bool {
        self.series >= self.top as usize
    }

    /// "+N more not shown" is not knowable; this says what is.
    pub fn cap_note(&self) -> Option<String> {
        self.capped().then(|| format!("top {} series by total; more may not be shown", self.top))
    }

    /// Whether a column has anything to show (empty columns are hidden).
    pub fn has_group(&self) -> bool {
        self.rows.iter().any(|r| !r.group.is_empty())
    }
    pub fn has_set(&self) -> bool {
        self.rows.iter().any(|r| !r.set.is_empty())
    }
    /// The policy column: only when the rows span more than one policy.
    pub fn has_policy(&self) -> bool {
        let mut seen: Vec<&str> = Vec::new();
        for r in self.rows.iter().filter(|r| !r.policy.is_empty()) {
            if !seen.contains(&r.policy.as_str()) {
                seen.push(&r.policy);
            }
        }
        seen.len() > 1
    }
    pub fn has_blocked(&self) -> bool {
        self.rows.iter().any(|r| r.blocked > 0.0)
    }
}

/// Series grouped into rule rows by (set, group, rule, policy), biggest
/// total first.
pub fn rule_rows(series: &[SplitSeries], s: &SplitSpec) -> Vec<RuleRow> {
    let mut rows: Vec<RuleRow> = Vec::new();
    for sr in series {
        let key = |d: &str| if d.is_empty() { String::new() } else { sr.dim(d).to_string() };
        let (rule, group, set, policy) = (key(s.rule_dim), key(s.group_dim), key(s.set_dim), sr.dim("policyname").to_string());
        let i = match rows.iter().position(|r| r.rule == rule && r.group == group && r.set == set && r.policy == policy) {
            Some(i) => i,
            None => {
                rows.push(RuleRow { rule, group, set, policy, total: 0.0, blocked: 0.0, actions: Vec::new() });
                rows.len() - 1
            }
        };
        let merged = merge_by_action(std::slice::from_ref(sr));
        let row = &mut rows[i];
        row.total += sr.total();
        for l in merged {
            if l.kind == ActionKind::Block {
                row.blocked += l.total;
            }
            match row.actions.iter_mut().find(|a| a.action.eq_ignore_ascii_case(&l.action)) {
                Some(a) => {
                    a.total += l.total;
                    for (t, v) in l.points {
                        match a.points.iter_mut().find(|p| p.0 == t) {
                            Some(p) => p.1 += v,
                            None => a.points.push((t, v)),
                        }
                    }
                    a.points.sort_by_key(|p| p.0);
                }
                None => row.actions.push(l),
            }
        }
    }
    rows.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap_or(std::cmp::Ordering::Equal).then(a.rule.cmp(&b.rule)));
    rows
}

/// Everything the WAF view shows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WafData {
    pub end: i64,
    pub actions: Vec<ActionLine>,
    pub actions_error: Option<String>,
    pub tables: Vec<RuleTable>,
}

impl WafData {
    pub fn requests(&self) -> f64 {
        self.actions.iter().map(|a| a.total).sum()
    }

    pub fn block_rate(&self) -> f64 {
        block_rate_total(&self.actions)
    }

    /// Text for the `e` editor and a `y` copy.
    pub fn as_text(&self) -> String {
        let mut out = String::new();
        for a in &self.actions {
            out.push_str(&format!("{}: {}\n", a.action, a.total));
        }
        out.push_str(&format!("Block rate: {:.1}%\n", self.block_rate()));
        for t in &self.tables {
            out.push_str(&format!("\n{}\n", t.title));
            for r in &t.rows {
                let loc = [&r.set, &r.group, &r.rule].iter().filter(|s| !s.is_empty()).map(|s| s.as_str()).collect::<Vec<_>>().join(" / ");
                out.push_str(&format!("  {loc}  {}  blocked {}\n", r.total, r.blocked));
            }
        }
        out
    }
}

// ── The fetch ───────────────────────────────────────────────────────────

/// All of the product's split calls, in order. `fetch` takes the query
/// pairs of one call. A call that fails with its optional dimensions
/// and the `orderby` is retried once with only the required dimensions
/// and no `orderby` (an older shape without `RuleSetName`, say); a call
/// that still fails is a line on its table, never fatal, except the
/// action call which is `actions_error`. The bot call failing is
/// dropped: most gateways have no bot metrics.
pub async fn fetch_waf<F, Fut>(product: WafProduct, policy: Option<&str>, window: MetricWindow, end: i64, fetch: F) -> WafData
where
    F: Fn(Vec<(&'static str, String)>) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let mut data = WafData { end, ..Default::default() };
    for s in waf_calls(product) {
        let mut dims: Vec<&str> = s.required.to_vec();
        // The policy is pinned, not split, when the view is one policy's.
        dims.extend(s.optional.iter().filter(|d| !(policy.is_some() && d.eq_ignore_ascii_case("PolicyName"))));
        let first = fetch(split_query(s.metric, &dims, policy, s.top, true, window, end)).await;
        let result = match first.and_then(|b| parse_split(&b, s.metric)) {
            Ok(v) => Ok(v),
            Err(e) if !short_error(&e).starts_with("no access") => {
                match fetch(split_query(s.metric, s.required, policy, s.top, false, window, end)).await {
                    Ok(b) => parse_split(&b, s.metric),
                    Err(_) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        match (s.role, result) {
            (Role::Actions, Ok(series)) => data.actions = merge_by_action(&series),
            (Role::Actions, Err(e)) => data.actions_error = Some(short_error(&e)),
            (Role::Bot, Err(e)) if !short_error(&e).starts_with("no access") => {}
            (_, Ok(series)) => data.tables.push(RuleTable {
                role: s.role,
                title: s.title,
                rows: rule_rows(&series, s),
                series: series.len(),
                top: s.top,
                error: None,
            }),
            (_, Err(e)) => data.tables.push(RuleTable {
                role: s.role,
                title: s.title,
                rows: Vec::new(),
                series: 0,
                top: s.top,
                error: Some(short_error(&e)),
            }),
        }
    }
    // A table with nothing in it and nothing wrong is not shown.
    data.tables.retain(|t| t.error.is_some() || !t.rows.is_empty());
    data
}

// ── A policy's resources ────────────────────────────────────────────────

/// Where a WAF policy's `m` goes: the resources it is attached to, as
/// top-level ARM ids (deduplicated, in the order the policy lists them),
/// and what it is attached to that has no WAF view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyTargets {
    pub targets: Vec<String>,
    /// Attachments with no WAF view (classic Front Door, Application
    /// Gateway for Containers), as written in the policy.
    pub skipped: Vec<String>,
}

/// The gateways / profiles a policy's association ids sit under: a
/// gateway, one of its listeners or path rules, or a Front Door profile's
/// security policy.
pub fn policy_targets(associations: &[String]) -> PolicyTargets {
    let mut out = PolicyTargets::default();
    for a in associations {
        let top = crate::azure::services::edge::top_level_of(a).unwrap_or_else(|| a.clone());
        if WafProduct::from_id(&top).is_some() {
            if !out.targets.iter().any(|t| t.eq_ignore_ascii_case(&top)) {
                out.targets.push(top);
            }
        } else if !out.skipped.iter().any(|t| t.eq_ignore_ascii_case(a)) {
            out.skipped.push(a.clone());
        }
    }
    out
}

/// `agw-1` from a policy id, the `PolicyName` dimension's value.
pub fn policy_name(id: &str) -> String {
    id.trim_end_matches('/').rsplit('/').next().unwrap_or(id).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AGW: &str = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw-1";
    const AFD: &str = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Cdn/profiles/afd-1";

    fn line(action: &str, points: &[(i64, f64)]) -> ActionLine {
        ActionLine {
            action: action.into(),
            kind: classify_action(action),
            points: points.to_vec(),
            total: points.iter().map(|p| p.1).sum(),
        }
    }

    #[test]
    fn the_product_follows_the_arm_type() {
        assert_eq!(WafProduct::from_id(AGW), Some(WafProduct::AppGateway));
        assert_eq!(WafProduct::from_id(AFD), Some(WafProduct::FrontDoor));
        assert_eq!(WafProduct::from_id(&format!("{AGW}/httpListeners/l")), None);
        assert_eq!(WafProduct::from_id("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Network/frontDoors/fd"), None);
    }

    #[test]
    fn actions_become_kinds_by_their_stem() {
        use ActionKind::*;
        for (a, k) in [
            ("Allow", Allow),
            ("Allowed", Allow),
            ("Block", Block),
            ("Blocked", Block),
            ("Log", Log),
            ("Detected", Log),
            ("Matched", Log),
            ("AnomalyScoring", Log),
            ("JSChallenge", Other),
            ("CAPTCHA", Other),
            ("Redirect", Other),
        ] {
            assert_eq!(classify_action(a), k, "{a}");
        }
    }

    #[test]
    fn the_split_query_names_the_metric_the_dimensions_the_policy_and_the_top() {
        let end = crate::azure::metrics::parse_iso_utc("2026-10-23T12:00:00Z").unwrap();
        let q = split_query("AzwafSecRule", &["Action", "RuleID"], Some("o'brien"), 60, true, MetricWindow::SixHours, end);
        assert_eq!(
            q,
            vec![
                ("metricnames", "AzwafSecRule".to_string()),
                ("timespan", "2026-10-23T06:00:00Z/2026-10-23T12:00:00Z".to_string()),
                ("interval", "PT5M".to_string()),
                ("aggregation", "Total".to_string()),
                ("AutoAdjustTimegrain", "true".to_string()),
                ("$filter", "Action eq '*' and RuleID eq '*' and PolicyName eq 'o''brien'".to_string()),
                ("top", "60".to_string()),
                ("orderby", "total desc".to_string()),
            ]
        );
        let plain = split_query("m", &["Action"], None, 20, false, MetricWindow::OneHour, end);
        assert!(plain.iter().all(|(k, _)| *k != "orderby"));
        assert_eq!(split_filter(&["Action"], None), "Action eq '*'");
    }

    /// The documented response shape: a series per dimension combination,
    /// dimension names lowercased by the API.
    fn rule_body() -> Value {
        let ts = |action: &str, rule: &str, group: &str, set: &str, pts: &[f64]| {
            json!({
                "metadatavalues": [
                    {"name": {"value": "action", "localizedValue": "Action"}, "value": action},
                    {"name": {"value": "ruleid", "localizedValue": "RuleID"}, "value": rule},
                    {"name": {"value": "rulegroupid", "localizedValue": "RuleGroupID"}, "value": group},
                    {"name": {"value": "rulesetname", "localizedValue": "RuleSetName"}, "value": set}
                ],
                "data": pts.iter().enumerate().map(|(i, v)| json!({"timeStamp": format!("2026-10-23T11:0{i}:00Z"), "total": v})).collect::<Vec<_>>()
            })
        };
        json!({"value": [{
            "name": {"value": "AzwafSecRule"}, "unit": "Count", "errorCode": "Success",
            "timeseries": [
                ts("Blocked", "942100", "REQUEST-942-APPLICATION-ATTACK-SQLI", "OWASP_3.2", &[2.0, 3.0]),
                ts("Matched", "942100", "REQUEST-942-APPLICATION-ATTACK-SQLI", "OWASP_3.2", &[1.0, 0.0]),
                ts("Blocked", "920350", "REQUEST-920-PROTOCOL-ENFORCEMENT", "OWASP_3.2", &[1.0, 1.0]),
                ts("Matched", "941100", "REQUEST-941-APPLICATION-ATTACK-XSS", "OWASP_3.2", &[20.0, 10.0]),
            ]
        }]})
    }

    #[test]
    fn a_dimensioned_response_parses_into_per_rule_rows_with_totals() {
        let series = parse_split(&rule_body(), "AzwafSecRule").unwrap();
        assert_eq!(series.len(), 4);
        assert_eq!(series[0].dim("RuleID"), "942100", "dimension names match case-insensitively");
        let rows = rule_rows(&series, &AGW_CALLS[1]);
        assert_eq!(rows.iter().map(|r| r.rule.as_str()).collect::<Vec<_>>(), ["941100", "942100", "920350"], "biggest first");
        let sqli = &rows[1];
        assert_eq!((sqli.total, sqli.blocked), (6.0, 5.0), "two actions of one rule fold into one row");
        assert_eq!(sqli.group, "REQUEST-942-APPLICATION-ATTACK-SQLI");
        assert_eq!(sqli.set, "OWASP_3.2");
        assert_eq!(sqli.actions.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), ["Blocked", "Matched"]);
        assert_eq!(rows[0].blocked, 0.0);
        // A per-metric error and a missing metric.
        let err = json!({"value": [{"name": {"value": "AzwafSecRule"}, "errorCode": "BadRequest", "errorMessage": "no such dimension"}]});
        assert_eq!(parse_split(&err, "AzwafSecRule").unwrap_err(), "BadRequest: no such dimension");
        assert_eq!(parse_split(&json!({"value": []}), "x").unwrap_err(), "not in the response");
    }

    #[test]
    fn empty_columns_are_hidden() {
        let series = parse_split(&rule_body(), "AzwafSecRule").unwrap();
        let t = |rows| RuleTable { role: Role::Managed, title: "t", rows, series: 4, top: 60, error: None };
        let managed = t(rule_rows(&series, &AGW_CALLS[1]));
        assert!(managed.has_group() && managed.has_set() && managed.has_blocked());
        assert!(!managed.has_policy(), "one policy (none named) is not a column");
        // A custom-rule shaped table has no group or set.
        let custom = t(rule_rows(&series, &AGW_CALLS[2]));
        assert!(!custom.has_group() && !custom.has_set());
        assert!(!t(vec![]).has_blocked());
        assert!(!managed.capped() && managed.cap_note().is_none());
        let capped = RuleTable { series: 60, ..managed };
        assert!(capped.cap_note().unwrap().contains("top 60"));
    }

    #[test]
    fn block_rate_counts_blocked_over_what_ended_and_leaves_log_out() {
        let lines = vec![
            line("Allowed", &[(60, 90.0), (120, 0.0)]),
            line("Blocked", &[(60, 10.0), (120, 5.0)]),
            line("Matched", &[(60, 1000.0), (120, 0.0)]),
            line("JSChallenge", &[(60, 0.0), (120, 5.0)]),
        ];
        // 15 blocked of 90 + 15 + 5 that ended; the 1000 logged do not count.
        assert!((block_rate_total(&lines) - 100.0 * 15.0 / 110.0).abs() < 1e-9);
        let pts = block_rate_points(&lines);
        assert_eq!(pts.len(), 2);
        assert!((pts[0].1 - 10.0).abs() < 1e-9, "10 of 100");
        assert!((pts[1].1 - 50.0).abs() < 1e-9, "5 of 5 + 5");
    }

    #[test]
    fn block_rate_is_zero_with_no_traffic_and_with_only_logged_traffic() {
        assert_eq!(block_rate_total(&[]), 0.0);
        assert!(block_rate_points(&[]).is_empty());
        let logged = vec![line("Matched", &[(60, 40.0)])];
        assert_eq!(block_rate_total(&logged), 0.0);
        assert_eq!(block_rate_points(&logged), vec![(60, 0.0)]);
        let quiet = vec![line("Allowed", &[(60, 0.0)]), line("Blocked", &[(60, 0.0)])];
        assert_eq!(block_rate_total(&quiet), 0.0);
    }

    #[test]
    fn actions_merge_across_series_and_order_by_kind() {
        let s = |action: &str, policy: &str, pts: &[(i64, f64)]| SplitSeries {
            dims: vec![("action".into(), action.into()), ("policyname".into(), policy.into())],
            points: pts.to_vec(),
        };
        let lines = merge_by_action(&[
            s("Matched", "p1", &[(60, 5.0)]),
            s("Blocked", "p1", &[(60, 1.0)]),
            s("Allowed", "p1", &[(60, 7.0)]),
            s("Allowed", "p2", &[(60, 3.0), (120, 1.0)]),
        ]);
        assert_eq!(lines.iter().map(|l| l.action.as_str()).collect::<Vec<_>>(), ["Allowed", "Blocked", "Matched"]);
        assert_eq!(lines[0].points, vec![(60, 10.0), (120, 1.0)]);
        assert_eq!(lines[0].total, 11.0);
    }

    #[test]
    fn a_policy_resolves_to_its_gateways_and_profiles() {
        let base = "/subscriptions/0000/resourceGroups/rg/providers";
        let t = policy_targets(&[
            format!("{base}/Microsoft.Network/applicationGateways/agw-1"),
            format!("{base}/Microsoft.Network/applicationGateways/AGW-1/httpListeners/l1"),
            format!("{base}/Microsoft.Network/applicationGateways/agw-2/urlPathMaps/m/pathRules/r"),
            format!("{base}/Microsoft.Cdn/profiles/afd-1/securityPolicies/sp-1"),
            format!("{base}/Microsoft.Network/frontDoors/classic/frontendEndpoints/fe"),
        ]);
        assert_eq!(
            t.targets,
            [
                format!("{base}/Microsoft.Network/applicationGateways/agw-1"),
                format!("{base}/Microsoft.Network/applicationGateways/agw-2"),
                format!("{base}/Microsoft.Cdn/profiles/afd-1"),
            ],
            "listeners and path rules fold into their gateway, case-insensitively"
        );
        assert_eq!(t.skipped, [format!("{base}/Microsoft.Network/frontDoors/classic/frontendEndpoints/fe")]);
        assert_eq!(policy_targets(&[]), PolicyTargets::default());
        assert_eq!(policy_name(&format!("{base}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/wafp-1")), "wafp-1");
    }

    fn actions_body() -> Value {
        let ts = |action: &str, v: f64| {
            json!({"metadatavalues": [{"name": {"value": "action"}, "value": action}],
                   "data": [{"timeStamp": "2026-10-23T11:00:00Z", "total": v}]})
        };
        json!({"value": [{"name": {"value": "AzwafTotalRequests"}, "errorCode": "Success",
            "timeseries": [ts("Allowed", 90.0), ts("Blocked", 10.0)]}]})
    }

    #[tokio::test]
    async fn the_fetch_splits_each_metric_retries_without_optional_dimensions_and_drops_a_missing_bot_metric() {
        use std::sync::Mutex;
        let calls: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
        let fetch = |q: Vec<(&'static str, String)>| {
            let get = |k: &str| q.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()).unwrap_or_default();
            let (metric, filter, ordered) = (get("metricnames"), get("$filter"), get("orderby") == "total desc");
            calls.lock().unwrap().push((metric.clone(), filter.clone()));
            async move {
                match metric.as_str() {
                    "AzwafTotalRequests" => Ok(actions_body()),
                    // The optional dimensions are refused: the retry has none.
                    "AzwafSecRule" if filter.contains("RuleSetName") || ordered => Err("400 BadRequest: invalid dimension".to_string()),
                    "AzwafSecRule" => Ok(rule_body()),
                    "AzwafCustomRule" => Ok(json!({"value": [{"name": {"value": "AzwafCustomRule"}, "timeseries": [], "errorCode": "Success"}]})),
                    _ => Err("400 BadRequest: metric not found".to_string()),
                }
            }
        };
        let data = fetch_waf(WafProduct::AppGateway, Some("wafp-1"), MetricWindow::OneHour, 0, fetch).await;
        let calls = calls.lock().unwrap().clone();
        assert_eq!(calls[0], ("AzwafTotalRequests".into(), "Action eq '*' and PolicyName eq 'wafp-1'".into()));
        assert_eq!(calls[1].1, "Action eq '*' and RuleID eq '*' and RuleGroupID eq '*' and RuleSetName eq '*' and PolicyName eq 'wafp-1'");
        assert_eq!(calls[2].1, "Action eq '*' and RuleID eq '*' and PolicyName eq 'wafp-1'", "the retry keeps only the required dimensions");
        assert_eq!(data.actions.len(), 2);
        assert!((data.block_rate() - 10.0).abs() < 1e-9);
        assert_eq!(data.tables.len(), 1, "empty custom table and missing bot metric are not shown: {:?}", data.tables.iter().map(|t| t.title).collect::<Vec<_>>());
        assert_eq!(data.tables[0].role, Role::Managed);
        assert_eq!(data.tables[0].rows.len(), 3);
        assert!(data.as_text().contains("Block rate: 10.0%"));

        // A 403 on a rule table is shown, not swallowed.
        let denied = |_q: Vec<(&'static str, String)>| async { Err::<Value, _>("403 Forbidden AuthorizationFailed".to_string()) };
        let data = fetch_waf(WafProduct::FrontDoor, None, MetricWindow::OneHour, 0, denied).await;
        assert!(data.actions_error.as_deref().unwrap().starts_with("no access"));
        assert!(data.tables.iter().all(|t| t.error.as_deref().is_some_and(|e| e.starts_with("no access"))));
    }
}
