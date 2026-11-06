//! Budgets (#203, SERVICES.md rule 42): the Governance tab's Budgets
//! sub-tab, the subscription's `Microsoft.Consumption/budgets`. A budget
//! carries its own current spend and forecast, so the list is the whole
//! read: amount, time grain and period, spend and forecast against the
//! amount, the notification thresholds with their contacts, the filter.
//! Actual cost and usage stay out: the Cost Management query API is a
//! `POST`.
//!
//! A budget is a governance row (`is_governance_id`): no Access section.

use crate::azure::resource::{name_of_id, shell_quote, subscription_id_of, Resource, ResourceState};
use crate::azure::services::{arm_row, json, overview_rows, related_lines, ArmBase};
use serde_json::Value;

pub const BUDGETS_API_VERSION: &str = "2024-08-01";
pub const BUDGETS_PATH: &str = "/providers/Microsoft.Consumption/budgets";

crate::sections! {
    pub enum BudgetDetailSection,
    pub static BUDGET_SECTIONS = [
        Overview "Overview",
        Budget "Budget",
        Notifications "Notifications",
        Filter "Filter",
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
    ]
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub enabled: bool,
    pub operator: String,
    pub threshold: f64,
    /// `Actual` or `Forecasted`.
    pub kind: String,
    pub emails: Vec<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BudgetRow {
    pub base: ArmBase,
    pub amount: Option<f64>,
    pub category: Option<String>,
    pub time_grain: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub spend: Option<f64>,
    pub forecast: Option<f64>,
    pub unit: Option<String>,
    pub notifications: Vec<Notification>,
    /// `(field, operator, values)`, flattened from `and` / `not` / single.
    pub filters: Vec<(String, String, Vec<String>)>,
}

fn num_at(v: &Value, ptr: &str) -> Option<f64> {
    v.pointer(ptr).and_then(Value::as_f64)
}

/// One `dimensions` / `tags` clause, or every clause of an `and`.
fn filter_clauses(f: &Value, negated: bool, out: &mut Vec<(String, String, Vec<String>)>) {
    for (key, field) in [("dimensions", ""), ("tags", "tag ")] {
        if let Some(c) = f.get(key).filter(|c| !c.is_null()) {
            let op = json::text(c, "/operator");
            let op = if negated { format!("not {}", op) } else { op };
            out.push((format!("{}{}", field, json::text(c, "/name")), op, json::strings_at(c, "/values")));
        }
    }
    for c in json::arr(f, "/and") {
        filter_clauses(&c, negated, out);
    }
    if let Some(n) = f.get("not").filter(|n| !n.is_null()) {
        filter_clauses(n, !negated, out);
    }
}

impl BudgetRow {
    pub fn from_json(raw: &Value, tenant: Option<&str>) -> Option<BudgetRow> {
        // The list writes the id without its leading slash.
        let mut v = raw.clone();
        if let Some(id) = json::str_at(&v, "/id").filter(|i| !i.starts_with('/')) {
            v["id"] = Value::String(format!("/{}", id));
        }
        let v = &v;
        let base = ArmBase::from_json(v, tenant)?;
        let p = |f: &str| format!("/properties/{}", f);
        let notifications = v
            .pointer(&p("notifications"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(_, n)| Notification {
                        enabled: json::bool_at(n, "/enabled").unwrap_or(false),
                        operator: json::text(n, "/operator"),
                        threshold: num_at(n, "/threshold").unwrap_or(0.0),
                        kind: json::str_at(n, "/thresholdType").unwrap_or_else(|| "Actual".into()),
                        emails: json::strings_at(n, "/contactEmails"),
                        roles: json::strings_at(n, "/contactRoles"),
                        groups: json::strings_at(n, "/contactGroups"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut filters = Vec::new();
        if let Some(f) = v.pointer(&p("filter")) {
            filter_clauses(f, false, &mut filters);
        }
        Some(BudgetRow {
            amount: num_at(v, &p("amount")),
            category: json::str_at(v, &p("category")),
            time_grain: json::str_at(v, &p("timeGrain")),
            start: json::str_at(v, &p("timePeriod/startDate")),
            end: json::str_at(v, &p("timePeriod/endDate")),
            spend: num_at(v, &p("currentSpend/amount")),
            forecast: num_at(v, &p("forecastSpend/amount")),
            unit: json::str_at(v, &p("currentSpend/unit")).or_else(|| json::str_at(v, &p("forecastSpend/unit"))),
            notifications,
            filters,
            base,
        })
    }

    fn pct(&self, of: Option<f64>) -> Option<f64> {
        let amount = self.amount.filter(|a| *a > 0.0)?;
        Some(of? / amount * 100.0)
    }

    fn money(&self, n: Option<f64>) -> String {
        match n {
            Some(n) => format!("{:.2} {}", n, self.unit.as_deref().unwrap_or("")).trim_end().to_string(),
            None => "-".into(),
        }
    }

    /// Spent past the amount, then forecast past it, else within; no spend
    /// on the body (the caller may not read cost) is no state.
    fn ladder(&self) -> (ResourceState, String) {
        match (self.pct(self.spend), self.pct(self.forecast)) {
            (Some(s), _) if s >= 100.0 => (ResourceState::Unavailable, "over budget".into()),
            (Some(_), Some(f)) if f >= 100.0 => (ResourceState::Pending, "forecast over".into()),
            (Some(_), _) => (ResourceState::Available, "within".into()),
            (None, _) => (ResourceState::stateless(), String::new()),
        }
    }

    /// Whether a notification's threshold is already crossed, by the spend
    /// (actual) or the forecast (forecasted) it compares.
    fn crossed(&self, n: &Notification) -> Option<bool> {
        let pct = if n.kind.eq_ignore_ascii_case("Forecasted") { self.pct(self.forecast) } else { self.pct(self.spend) }?;
        Some(if n.operator.eq_ignore_ascii_case("GreaterThan") { pct > n.threshold } else { pct >= n.threshold })
    }

    fn budget_rows(&self) -> Vec<(String, String)> {
        let pct = |p: Option<f64>| p.map(|p| format!(" ({:.0}%)", p)).unwrap_or_default();
        let spend_pct = self.pct(self.spend);
        let forecast_pct = self.pct(self.forecast);
        let warn = |p: Option<f64>| if p.is_some_and(|p| p >= 100.0) { "⚠ " } else { "" };
        vec![
            ("Amount".into(), self.money(self.amount)),
            ("Spent".into(), format!("{}{}{}", warn(spend_pct), self.money(self.spend), pct(spend_pct))),
            ("Forecast".into(), format!("{}{}{}", warn(forecast_pct), self.money(self.forecast), pct(forecast_pct))),
            ("Time grain".into(), json::opt(self.time_grain.clone())),
            ("Period".into(), format!("{} → {}", json::time(self.start.clone()), json::time(self.end.clone()))),
            ("Category".into(), json::opt(self.category.clone())),
        ]
    }

    fn notification_rows(&self) -> Vec<(String, String)> {
        if self.notifications.is_empty() {
            return vec![(String::new(), "No notifications: the budget alerts nobody".into())];
        }
        let mut lines = Vec::new();
        let mut ns: Vec<&Notification> = self.notifications.iter().collect();
        ns.sort_by(|a, b| a.threshold.total_cmp(&b.threshold));
        for n in ns {
            let op = if n.operator.eq_ignore_ascii_case("GreaterThan") { ">" } else { "≥" };
            let status = match (n.enabled, self.crossed(n)) {
                (false, _) => "off".to_string(),
                (true, Some(true)) => "⚠ crossed".to_string(),
                (true, Some(false)) => "not reached".to_string(),
                (true, None) => "on".to_string(),
            };
            if !lines.is_empty() {
                lines.push((String::new(), String::new()));
            }
            lines.push((format!("{} {} {}%", n.kind.to_lowercase(), op, n.threshold), status));
            if !n.emails.is_empty() {
                lines.push(("  Emails".into(), json::join(&n.emails)));
            }
            if !n.roles.is_empty() {
                lines.push(("  Roles".into(), json::join(&n.roles)));
            }
            for g in &n.groups {
                lines.push((format!("  Action group · {}", name_of_id(g)), g.clone()));
            }
        }
        lines
    }

    fn filter_rows(&self) -> Vec<(String, String)> {
        if self.filters.is_empty() {
            return vec![(String::new(), "No filter: the whole subscription's cost".into())];
        }
        self.filters
            .iter()
            .map(|(field, op, values)| (format!("{} {}", field, op.to_lowercase()), json::join(values)))
            .collect()
    }

    /// The resource groups and resources a filter names, and the action
    /// groups notifications send to.
    fn filter_ids(&self) -> Vec<(String, String)> {
        let sub = subscription_id_of(&self.base.id).unwrap_or_default();
        let mut v = Vec::new();
        for (field, op, values) in &self.filters {
            if op.starts_with("not") {
                continue;
            }
            for value in values {
                if field.eq_ignore_ascii_case("ResourceGroupName") {
                    v.push((format!("Resource group {}", value), format!("{}/resourceGroups/{}", sub, value)));
                } else if field.eq_ignore_ascii_case("ResourceId") && json::arm_id(Some(value.clone())).is_some() {
                    v.push((format!("Resource {}", name_of_id(value)), value.clone()));
                }
            }
        }
        v
    }
}

impl Resource for BudgetRow {
    arm_row!("Budget");
    fn filter_location(&self) -> Option<&str> {
        None
    }
    fn state(&self) -> ResourceState {
        self.ladder().0
    }
    fn state_label(&self) -> String {
        self.ladder().1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&BUDGET_SECTIONS)
    }
    /// `16400.00 of 20000.00 EUR · monthly · 82%`.
    fn list_summary(&self) -> Option<String> {
        let amount = self.amount?;
        let mut s = match self.spend {
            Some(spent) => format!("{:.2} of {:.2} {}", spent, amount, self.unit.as_deref().unwrap_or("")),
            None => format!("{:.2} {}", amount, self.unit.as_deref().unwrap_or("")),
        };
        s = s.trim_end().to_string();
        if let Some(g) = &self.time_grain {
            s.push_str(&format!(" · {}", g.to_lowercase()));
        }
        if let Some(p) = self.pct(self.spend) {
            s.push_str(&format!(" · {:.0}%", p));
        }
        Some(s)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Amount".into(), self.money(self.amount)),
            ("Time grain".into(), json::opt(self.time_grain.clone())),
            ("Notifications".into(), self.notifications.len().to_string()),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        if let Some(sub) = subscription_id_of(&self.base.id) {
            v.push(("Subscription".into(), sub));
        }
        v.extend(self.filter_ids());
        for g in self.notifications.iter().flat_map(|n| &n.groups) {
            if !v.iter().any(|(_, id)| id.eq_ignore_ascii_case(g)) {
                v.push((format!("Action group {}", name_of_id(g)), g.clone()));
            }
        }
        v
    }
    fn cli_command(&self) -> Option<String> {
        // `az consumption budget show` takes the name (no `--ids`), and
        // the subscription from the context.
        Some(format!(
            "az consumption budget show --budget-name {} --subscription {}",
            shell_quote(&self.base.name),
            shell_quote(crate::azure::resource::subscription_of(&self.base.id).unwrap_or("-"))
        ))
    }
}

/// Body lines for one section of a budget; `None` for another type.
pub fn budget_section_lines(r: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<BudgetRow>()?;
    use BudgetDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Budget => x.budget_rows(),
        S::Notifications => x.notification_rows(),
        S::Filter => x.filter_rows(),
        S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => related_lines(x.related()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn budget(spend: f64, forecast: f64) -> BudgetRow {
        BudgetRow::from_json(
            &json!({
                "id": "subscriptions/0000/providers/Microsoft.Consumption/budgets/monthly",
                "name": "monthly", "type": "Microsoft.Consumption/budgets",
                "properties": {
                    "amount": 2000, "category": "Cost", "timeGrain": "Monthly",
                    "timePeriod": {"startDate": "2026-01-01T00:00:00Z", "endDate": "2027-12-31T00:00:00Z"},
                    "currentSpend": {"amount": spend, "unit": "EUR"},
                    "forecastSpend": {"amount": forecast, "unit": "EUR"},
                    "notifications": {
                        "Actual_GreaterThan_80_Percent": {"enabled": true, "operator": "GreaterThan", "threshold": 80,
                            "thresholdType": "Actual", "contactEmails": ["finops@contoso.example"], "contactRoles": ["Owner"],
                            "contactGroups": ["/subscriptions/0000/resourceGroups/rg-ops/providers/microsoft.insights/actionGroups/ag-finops"]},
                        "Forecasted_GreaterThanOrEqualTo_100_Percent": {"enabled": true, "operator": "GreaterThanOrEqualTo",
                            "threshold": 100, "thresholdType": "Forecasted", "contactEmails": ["finops@contoso.example"]}
                    },
                    "filter": {"and": [
                        {"dimensions": {"name": "ResourceGroupName", "operator": "In", "values": ["rg-orders"]}},
                        {"tags": {"name": "team", "operator": "In", "values": ["orders"]}}
                    ]}
                }
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn section_labels() {
        let labels: Vec<&str> = BUDGET_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Budget", "Notifications", "Filter", "Activity", "Related"]);
    }

    #[test]
    fn the_id_gets_its_slash_and_the_command_takes_the_name() {
        let b = budget(1640.0, 2130.0);
        assert_eq!(b.base.id, "/subscriptions/0000/providers/Microsoft.Consumption/budgets/monthly");
        assert_eq!(b.cli_command().as_deref(), Some("az consumption budget show --budget-name monthly --subscription 0000"));
        assert!(crate::azure::services::governance::is_governance_id(&b.base.id), "no Access section");
    }

    #[test]
    fn spend_and_forecast_against_the_amount() {
        let b = budget(1640.0, 2130.0);
        assert_eq!((b.state(), b.state_label()), (ResourceState::Pending, "forecast over".to_string()));
        assert_eq!(b.list_summary().as_deref(), Some("1640.00 of 2000.00 EUR · monthly · 82%"));
        let rows = b.budget_rows();
        assert!(rows.iter().any(|(k, v)| k == "Forecast" && v == "⚠ 2130.00 EUR (106%)"));
        assert_eq!(budget(2100.0, 2300.0).state(), ResourceState::Unavailable);
        assert_eq!(budget(500.0, 900.0).state_label(), "within");
    }

    #[test]
    fn notifications_say_which_threshold_is_crossed() {
        let lines = budget(1640.0, 2130.0).notification_rows();
        assert_eq!(lines[0], ("actual > 80%".to_string(), "⚠ crossed".to_string()));
        assert!(lines.iter().any(|(k, v)| k == "forecasted ≥ 100%" && v == "⚠ crossed"));
        assert!(lines.iter().any(|(k, _)| k == "  Action group · ag-finops"));
        let calm = budget(500.0, 900.0).notification_rows();
        assert_eq!(calm[0].1, "not reached");
    }

    #[test]
    fn the_filter_names_its_resource_groups_in_related() {
        let b = budget(1640.0, 2130.0);
        let f = b.filter_rows();
        assert_eq!(f, vec![
            ("ResourceGroupName in".to_string(), "rg-orders".to_string()),
            ("tag team in".to_string(), "orders".to_string()),
        ]);
        let related = b.related();
        assert!(related.iter().any(|(l, id)| l == "Resource group rg-orders" && id == "/subscriptions/0000/resourceGroups/rg-orders"));
        assert!(related.iter().any(|(l, _)| l == "Action group ag-finops"));
    }
}
