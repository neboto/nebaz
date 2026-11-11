// ported from neboto-tui src/open.rs @ b15c04f
//! `nebaz open` and `--bookmark`: start the TUI at a resource, the public
//! way in to what `--at` does for a `|` split (neboto-tui#334).
//!
//! `open`'s arguments are the stable contract (pinned in
//! `src/headless/contract.json`); the `NavLocation` they build is not. A
//! place is resolved here, before the TUI takes the screen, as far as it
//! can be without a fetch (the sub-tab an id routes to, the chart window),
//! so a typo exits with a message instead of opening a blank pane. The
//! rest (the row, the section, the metric) resolves once the list streams
//! in (`App::land_pending_place`).

use crate::app::{is_arm_id, NavLocation};
use crate::azure::metrics::{MetricQuery, MetricWindow};
use crate::azure::resource::{name_of_id, subscription_of};
use crate::azure::service::JumpView;
use crate::cli::OpenArgs;
use crate::split::Place;

/// A chart window as `--charts` spells it: the labels the charts' own
/// window row shows (`1h`, `6h`, `24h`, `7d`, `30d`).
pub fn parse_window(s: &str) -> Result<MetricWindow, String> {
    let want = s.trim().to_ascii_lowercase();
    let want = match want.as_str() {
        "1d" => "24h",
        "1w" => "7d",
        other => other,
    };
    MetricWindow::ALL
        .into_iter()
        .find(|w| w.label() == want)
        .ok_or_else(|| format!("--charts: unknown window {s:?}: 1h, 6h, 24h, 7d or 30d"))
}

/// What a startup place asks for beyond the place itself: checked once the
/// row resolves, so a wrong section or metric says so in the status bar
/// instead of landing somewhere else.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OpenRequest {
    /// The section name as given (any case); matched against the
    /// resource's own sections once it is selected.
    pub section: Option<String>,
    /// `--charts` or `--metric` was asked for.
    pub charts: bool,
    /// The chart row the cursor goes to (`match_metric`).
    pub metric: Option<String>,
    /// `--full`: the detail pane (or the charts) takes the whole width.
    pub full: bool,
    /// The target is an exact name (`--in`), not an id: the row is looked
    /// up by name once the list has loaded.
    pub by_name: bool,
}

/// `nebaz open …` → the place to start at, plus what to check once there.
pub fn plan(args: &OpenArgs) -> Result<(Place, OpenRequest), String> {
    let target = args.target.trim();
    if target.is_empty() {
        return Err("open: give an ARM id, or a name with --in".into());
    }
    let within = args
        .within
        .as_deref()
        .map(|p| crate::headless::resolve_list(p).map_err(|f| f.message().to_string()))
        .transpose()?;
    // An id routes itself and ignores --in, as `get` does.
    let (view, by_name) = if is_arm_id(target) {
        let view = JumpView::landing_for_arm_id(target)
            .ok_or_else(|| format!("open: {target}: not a type nebaz lists (nor a top-level resource in a group)"))?;
        (view, false)
    } else {
        let view = within.ok_or_else(|| {
            format!(
                "open: {target:?} is not an ARM id (/subscriptions/…) or a directory id (graph:/…); \
                 pass --in PREFIX to open it by name"
            )
        })?;
        (view, true)
    };
    if view.service().is_virtual() {
        return Err(format!("open: {} has no resources of its own to open", view.label()));
    }
    let chart_window = args.charts.as_deref().map(parse_window).transpose()?;
    let name = if by_name { target } else { name_of_id(target) };
    let loc = NavLocation {
        service: view.service(),
        view: Some(view),
        subscription: subscription_of(target).map(str::to_string),
        query: String::new(),
        selected_id: Some(target.to_string()),
        label: format!("{} · {}", view.label(), name),
        details_focused: true,
        // Matched (any case) once the resource is selected; the restore
        // path wants the exact label.
        detail_section: None,
    };
    let req = OpenRequest {
        section: args.section.clone(),
        charts: args.charts.is_some() || args.metric.is_some(),
        metric: args.metric.clone(),
        full: args.full,
        by_name,
    };
    Ok((Place { loc, chart_window }, req))
}

/// `--bookmark NAME`: the saved bookmark NAME picks. Matched against each
/// bookmark's label (`Virtual machines · vm-web-1`) and the id it holds,
/// any case: an exact label or id first, then a label containing NAME,
/// which must be the only one, or the candidates are listed.
pub fn pick_bookmark<'a>(bookmarks: &'a [NavLocation], name: &str) -> Result<&'a NavLocation, String> {
    let want = name.trim().to_lowercase();
    if want.is_empty() {
        return Err("--bookmark: give part of a bookmark's name".into());
    }
    let exact = |b: &&NavLocation| {
        b.label.to_lowercase() == want || b.selected_id.as_deref().is_some_and(|id| id.to_lowercase() == want)
    };
    if let Some(b) = bookmarks.iter().find(exact) {
        return Ok(b);
    }
    let hits: Vec<&NavLocation> = bookmarks.iter().filter(|b| b.label.to_lowercase().contains(&want)).collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] if bookmarks.is_empty() => Err("--bookmark: no bookmarks saved yet (B in the TUI saves one)".into()),
        [] => Err(format!("--bookmark: none match {name:?}:{}", labels(bookmarks.iter()))),
        many => Err(format!("--bookmark: {name:?} matches {}:{}", many.len(), labels(many.iter().copied()))),
    }
}

fn labels<'a>(it: impl Iterator<Item = &'a NavLocation>) -> String {
    let all: Vec<&str> = it.map(|b| b.label.as_str()).collect();
    const SHOW: usize = 8;
    let mut s: String = all.iter().take(SHOW).map(|l| format!("\n  {l}")).collect();
    if all.len() > SHOW {
        s.push_str(&format!("\n  … {} more", all.len() - SHOW));
    }
    s
}

/// The chart row `wanted` names: a row's label or Azure Monitor metric
/// name (any case), else the one label it starts; or the message listing
/// them.
pub fn match_metric(queries: &[MetricQuery], wanted: &str) -> Result<usize, String> {
    let w = wanted.trim().to_lowercase();
    if let Some(i) = queries.iter().position(|q| q.label.to_lowercase() == w || q.name.to_lowercase() == w) {
        return Ok(i);
    }
    let starts: Vec<usize> =
        (0..queries.len()).filter(|&i| queries[i].label.to_lowercase().starts_with(&w)).collect();
    if let [i] = starts.as_slice() {
        return Ok(*i);
    }
    let rows: Vec<String> = queries
        .iter()
        .map(|q| if q.name == q.label { q.label.clone() } else { format!("{} ({})", q.label, q.name) })
        .collect();
    let what = if starts.len() > 1 { "matches more than one" } else { "isn't charted" };
    Err(format!("open: metric {wanted:?} {what}: {}", rows.join(", ")))
}

/// The index of the section `wanted` names (any case), or the message
/// listing the real ones.
pub fn match_section(labels: &[&str], wanted: &str) -> Result<usize, String> {
    labels
        .iter()
        .position(|l| l.eq_ignore_ascii_case(wanted.trim()))
        .ok_or_else(|| format!("open: no section {wanted:?}: sections are {}", labels.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::metrics::Aggregation;
    use crate::azure::service::ServiceType;

    const VM: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-web-1";

    fn args(target: &str) -> OpenArgs {
        OpenArgs { target: target.to_string(), within: None, section: None, charts: None, metric: None, full: false }
    }

    #[test]
    fn an_arm_id_finds_its_sub_tab_and_subscription() {
        let (place, req) = plan(&args(VM)).unwrap();
        assert_eq!(place.loc.service, ServiceType::VirtualMachines);
        assert_eq!(place.loc.view, Some(JumpView::VirtualMachines));
        assert_eq!(place.loc.subscription.as_deref(), Some("11111111-1111-1111-1111-111111111111"));
        assert_eq!(place.loc.selected_id.as_deref(), Some(VM));
        assert!(place.loc.details_focused);
        assert_eq!(place.chart_window, None);
        assert_eq!(req, OpenRequest::default());
    }

    #[test]
    fn a_name_needs_in_and_is_looked_up_there() {
        let err = plan(&args("vm-web-1")).unwrap_err();
        assert!(err.contains("--in PREFIX"), "{err}");
        let mut a = args("vm-web-1");
        a.within = Some("vm".into());
        let (place, req) = plan(&a).unwrap();
        assert_eq!(place.loc.view, Some(JumpView::VirtualMachines));
        assert_eq!(place.loc.selected_id.as_deref(), Some("vm-web-1"));
        assert_eq!(place.loc.subscription, None, "a name is looked up in the current subscription");
        assert!(req.by_name);
        // An id routes itself and ignores --in.
        let mut a = args(VM);
        a.within = Some("storage".into());
        assert_eq!(plan(&a).unwrap().0.loc.view, Some(JumpView::VirtualMachines));
    }

    #[test]
    fn unknown_service_and_window_are_errors() {
        let mut a = args("x");
        a.within = Some("nope".into());
        assert!(plan(&a).is_err());
        let mut a = args(VM);
        a.charts = Some("2h".into());
        assert!(plan(&a).unwrap_err().contains("1h, 6h"));
        a.charts = Some("7D".into());
        let (place, req) = plan(&a).unwrap();
        assert_eq!(place.chart_window, Some(MetricWindow::SevenDays));
        assert!(req.charts);
        assert_eq!(parse_window("1d"), Ok(MetricWindow::OneDay));
    }

    #[test]
    fn metric_implies_the_charts_at_their_default_window() {
        let mut a = args(VM);
        a.metric = Some("cpu".into());
        let (place, req) = plan(&a).unwrap();
        assert_eq!(place.chart_window, None);
        assert!(req.charts);
        assert_eq!(req.metric.as_deref(), Some("cpu"));
    }

    #[test]
    fn virtual_services_have_nothing_to_open() {
        let mut a = args("x");
        a.within = Some("audit".into());
        assert!(plan(&a).unwrap_err().contains("no resources of its own"));
    }

    fn queries(rows: &[(&str, &str)]) -> Vec<MetricQuery> {
        rows.iter()
            .map(|(label, name)| MetricQuery {
                name: name.to_string(),
                label: label.to_string(),
                aggregation: Aggregation::Average,
            })
            .collect()
    }

    #[test]
    fn metric_matching() {
        let q = queries(&[("CPU", "Percentage CPU"), ("Network in", "Network In Total"), ("Network out", "Network Out Total")]);
        assert_eq!(match_metric(&q, "cpu"), Ok(0));
        assert_eq!(match_metric(&q, "network out total"), Ok(2));
        assert_eq!(match_metric(&q, "network i"), Ok(1));
        let err = match_metric(&q, "net").unwrap_err();
        assert!(err.contains("more than one") && err.contains("Network in (Network In Total)"), "{err}");
        assert!(match_metric(&q, "disk").unwrap_err().contains("isn't charted"));
    }

    fn bm(label: &str, id: &str) -> NavLocation {
        let mut a = args(id);
        a.within = Some("vm".into());
        let mut loc = plan(&a).unwrap().0.loc;
        loc.label = label.into();
        loc
    }

    #[test]
    fn bookmark_matching() {
        let bms = vec![bm("VMs · web-3", "i-1"), bm("VMs · web-30", "i-2"), bm("VMs · db-9", "i-3")];
        assert_eq!(pick_bookmark(&bms, "db").unwrap().selected_id.as_deref(), Some("i-3"));
        assert_eq!(pick_bookmark(&bms, "I-2").unwrap().selected_id.as_deref(), Some("i-2"));
        assert_eq!(pick_bookmark(&bms, "vms · web-3").unwrap().selected_id.as_deref(), Some("i-1"));
        assert!(pick_bookmark(&bms, "web").unwrap_err().contains("matches 2"));
        assert!(pick_bookmark(&bms, "zzz").unwrap_err().contains("none match"));
        assert!(pick_bookmark(&[], "x").unwrap_err().contains("no bookmarks"));
    }

    #[test]
    fn section_names_match_any_case() {
        let labels = ["Overview", "Network"];
        assert_eq!(match_section(&labels, "network"), Ok(1));
        assert!(match_section(&labels, "nope").unwrap_err().contains("Overview, Network"));
    }
}
