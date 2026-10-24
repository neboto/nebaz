// ported from neboto-tui src/audit.rs @ 693449a (the check / finding /
// coverage-note machinery; every check is rewritten for ARM)
//! `@audit` (#60): a virtual service whose rows are security findings
//! computed from data nebaz **already holds** — the list cache and the
//! lazy store — with zero API calls (ADR 0007).
//!
//! Every check is a pure function over an [`AuditInput`]: cached rows
//! (downcast to their typed row, or their raw ARM JSON), warm lazy
//! sections, the subscription and a clock value passed in. A check never
//! fetches, so the read-only guarantee holds by construction and each one
//! is a unit test over fixtures (`checks.rs`). A check whose inputs are not
//! cached emits a "not checked — load @x" row instead of passing, so "no
//! findings" never reads as "didn't look".
//!
//! The headless boundary (#44): [`sources`] says which lists to load,
//! [`load_source`] loads one exactly as the TUI's list does, and [`run`]
//! turns an input into rows. Nothing here touches the `App`.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::azure::resource::{portal_url_for, resource_group_of, state_ladder, Resource, ResourceState};
use crate::azure::service::{AzureService, JumpView, ServiceType};
use crate::event::Event;
use crate::lazy::LazyStore;

mod checks;
pub use checks::{privileged_user_ids, CHECKS};

/// How many resources `r` fetches one per-resource lazy section for (SQL
/// firewall rules, site configs) and how many privileged principals it
/// resolves: a bound on the GETs one key press can cause. The rest stay
/// "not checked" until their own section is opened.
pub const AUDIT_LAZY_MAX: usize = 50;

/// How bad a finding is. Ordered worst first, so a sort puts critical on
/// top.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    /// Not a weakness on its own: a configuration worth knowing about
    /// (an external Container Apps environment in a Power Platform VNet).
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// The coarse state the list colours and `z` sorts by: critical and
    /// high are red (critical sorts first), medium and low amber, info dim.
    pub fn bucket(self) -> ResourceState {
        match self {
            Severity::Critical => ResourceState::Unavailable,
            Severity::High => ResourceState::Stopped,
            Severity::Medium => ResourceState::Pending,
            Severity::Low => ResourceState::Creating,
            Severity::Info => ResourceState::stateless(),
        }
    }

    /// Parse a `--fail-on` value (`nebaz audit`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "med" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }
}

/// One built-in check.
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    /// Why it matters: the risk, in a sentence or three.
    pub why: &'static str,
    /// What to change, as text. Never a command nebaz could run: the
    /// audit only ever reads.
    pub fix: &'static str,
    /// The lists it reads. Every slot must be cached for the check to run;
    /// any one view in a slot is enough (a subnet is in the VNets list and
    /// in the Subnets list). `r` loads each slot's first view.
    pub sources: &'static [&'static [JumpView]],
    pub(crate) run: fn(&'static Check, &AuditInput, &mut Vec<AuditFinding>),
}

/// Every list a check reads, one view per slot, de-duplicated, in check
/// order: what `r` in `@audit` (and a headless audit) loads.
pub fn sources() -> Vec<JumpView> {
    let mut out: Vec<JumpView> = Vec::new();
    for check in CHECKS.iter() {
        for slot in check.sources {
            if slot.iter().any(|v| out.contains(v)) {
                continue;
            }
            out.push(slot[0]);
        }
    }
    out
}

/// What the checks read. Built by the app from its cache and lazy store,
/// by a test from fixtures.
pub struct AuditInput<'a> {
    lists: HashMap<JumpView, &'a [Box<dyn Resource>]>,
    /// Views `r` is loading right now: their checks read "loading…".
    loading: Vec<JumpView>,
    /// Warm lazy sections (SQL firewall rules, site configs, role
    /// assignments). `None`: no lazy data at all.
    lazy: Option<&'a LazyStore>,
    /// The subscription id (no `/subscriptions/` prefix).
    subscription: String,
    /// Unix seconds, for credential expiry. A field, not a clock read, so
    /// checks stay pure.
    now: i64,
}

impl<'a> AuditInput<'a> {
    pub fn new(subscription: &str, now: i64) -> Self {
        Self {
            lists: HashMap::new(),
            loading: Vec::new(),
            lazy: None,
            subscription: subscription.to_string(),
            now,
        }
    }

    pub fn add(&mut self, view: JumpView, list: &'a [Box<dyn Resource>]) {
        self.lists.insert(view, list);
    }

    pub fn set_loading(&mut self, loading: &[JumpView]) {
        self.loading = loading.to_vec();
    }

    pub fn set_lazy(&mut self, lazy: &'a LazyStore) {
        self.lazy = Some(lazy);
    }

    fn has_slot(&self, slot: &[JumpView]) -> bool {
        slot.iter().any(|v| self.lists.contains_key(v))
    }

    /// Every cached row of type `T` in `view`'s list.
    pub(crate) fn of<T: 'static>(&self, view: JumpView) -> impl Iterator<Item = &'a T> + '_ {
        self.lists
            .get(&view)
            .into_iter()
            .flat_map(|l| l.iter())
            .filter_map(|r| r.as_any().downcast_ref::<T>())
    }

    pub(crate) fn lazy(&self) -> Option<&'a LazyStore> {
        self.lazy
    }

    /// `/subscriptions/{id}`: the key the subscription's Access list is
    /// stored under.
    pub(crate) fn subscription_scope(&self) -> String {
        format!("/subscriptions/{}", self.subscription)
    }

    pub(crate) fn now(&self) -> i64 {
        self.now
    }
}

/// Run every check: findings worst first, then the coverage notes. One
/// "no findings" row when every check that ran was clean.
pub fn run(input: &AuditInput) -> Vec<AuditFinding> {
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    let mut ran = 0;
    for check in CHECKS.iter() {
        let missing: Vec<&[JumpView]> = check.sources.iter().copied().filter(|s| !input.has_slot(s)).collect();
        if missing.is_empty() {
            ran += 1;
            (check.run)(check, input, &mut rows);
        } else {
            let loading = missing.iter().all(|s| s.iter().any(|v| input.loading.contains(v)));
            notes.push(AuditFinding::not_checked(check, &missing, loading));
        }
    }
    // A check reports a gap in its own input (lazy data not loaded) as a
    // note beside its findings.
    let (gaps, mut findings): (Vec<_>, Vec<_>) = rows.into_iter().partition(|f: &AuditFinding| f.kind != RowKind::Finding);
    // A check that ran but could only note a gap did not run clean.
    let gapped: std::collections::HashSet<&str> = gaps.iter().map(|g| g.check_id).collect();
    let ran = ran - gapped.len();
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.check_id.cmp(b.check_id))
            .then_with(|| a.resource_name.to_lowercase().cmp(&b.resource_name.to_lowercase()))
    });
    if findings.is_empty() && ran > 0 {
        findings.push(AuditFinding::all_clear(ran));
    }
    findings.extend(gaps);
    findings.extend(notes);
    findings
}

/// The `@`-prefix and label a source is named by in a note
/// (`@vnet NSGs`).
pub fn source_name(view: JumpView) -> String {
    let service = view.service();
    if service.views().len() > 1 {
        format!("{} {}", service.prefix(), view.label())
    } else {
        service.prefix().to_string()
    }
}

/// One loaded source: its rows and any phase warnings, or the error.
pub type SourceLoad = std::result::Result<(Vec<Box<dyn Resource>>, Vec<String>), String>;

/// Load one source list the way the TUI's list load does — the provider's
/// own stream, so a list `r` caches here is the list the tab would have
/// shown — and collect it: the rows and any phase warnings, or the error.
pub async fn load_source(provider: Arc<dyn AzureService>, view: JumpView) -> SourceLoad {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let result = provider.list_resources_streaming(view, tx, view.service()).await;
    let mut rows: Vec<Box<dyn Resource>> = Vec::new();
    let mut warnings = Vec::new();
    let mut error = None;
    while let Ok(ev) = rx.try_recv() {
        match ev {
            Event::ResourcesLoaded { resources, .. } => rows = resources,
            Event::ResourcesPartiallyLoaded { resources, .. } => rows.extend(resources),
            Event::ResourceLoadWarning { warning, .. } => warnings.push(warning),
            Event::ResourceLoadError { error: e, .. } => error = Some(e),
            _ => {}
        }
    }
    if let Some(e) = error {
        return Err(e);
    }
    result.map_err(|e| e.to_string())?;
    Ok((rows, warnings))
}

// ── Finding rows ──────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    Finding,
    /// A check that couldn't run, or ran on part of its input.
    NotChecked,
    /// Every check that ran came back clean.
    AllClear,
}

#[derive(Clone, Debug)]
pub struct AuditFinding {
    pub kind: RowKind,
    pub severity: Severity,
    pub check_id: &'static str,
    pub check_title: &'static str,
    pub why: &'static str,
    pub fix: &'static str,
    /// The resource it is about: an ARM id (or a directory row's
    /// `graph:/…` id), so Enter routes through `jump_to_arm_id`. Empty on
    /// a note.
    pub resource_id: String,
    pub resource_name: String,
    /// The resource's location, so `R` narrows findings as it narrows
    /// lists. `None` passes every filter.
    pub location: Option<String>,
    /// What was found, one line: the list's second column.
    pub reason: String,
    /// The fields and values that show it.
    pub evidence: Vec<String>,
    /// The resource's own tags, so `t:env=prod` narrows findings.
    pub tags: HashMap<String, String>,
    row_id: String,
}

impl AuditFinding {
    /// A finding about a cached row.
    pub(crate) fn about(check: &'static Check, severity: Severity, r: &dyn Resource, reason: impl Into<String>) -> Self {
        Self::at(check, severity, r.id(), r.name(), r.location(), r.tags().clone(), reason)
    }

    /// A finding about an id that has no cached row (the subscription
    /// itself, for an Access finding).
    pub(crate) fn at(
        check: &'static Check,
        severity: Severity,
        id: &str,
        name: &str,
        location: Option<&str>,
        tags: HashMap<String, String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            kind: RowKind::Finding,
            severity,
            check_id: check.id,
            check_title: check.title,
            why: check.why,
            fix: check.fix,
            resource_id: id.to_string(),
            resource_name: name.to_string(),
            location: location.filter(|l| !l.is_empty()).map(str::to_string),
            reason: reason.into(),
            evidence: Vec::new(),
            tags,
            row_id: format!("audit:{}:{}", check.id, id.to_lowercase()),
        }
    }

    pub(crate) fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    fn not_checked(check: &'static Check, missing: &[&[JumpView]], loading: bool) -> Self {
        let names: Vec<String> = missing.iter().map(|s| source_name(s[0])).collect();
        let names = names.join(" and ");
        if loading {
            return Self::note(
                check,
                "loading…".to_string(),
                format!("{names} is loading; this check runs when it lands."),
            );
        }
        Self::note(
            check,
            format!("not checked — load {names}"),
            format!("{names} isn't cached, so this check didn't run. Press r here to load it in the background (or open {names})."),
        )
    }

    /// A gap in a check's own input (lazy data not loaded, or a read that
    /// failed): a dim note beside its findings.
    pub(crate) fn note(check: &'static Check, list_note: String, reason: String) -> Self {
        Self {
            kind: RowKind::NotChecked,
            severity: Severity::Info,
            check_id: check.id,
            check_title: check.title,
            why: check.why,
            fix: "",
            resource_id: String::new(),
            resource_name: check.title.to_string(),
            location: None,
            evidence: vec![list_note],
            reason,
            tags: HashMap::new(),
            row_id: format!("audit-note:{}", check.id),
        }
    }

    fn all_clear(ran: usize) -> Self {
        Self {
            kind: RowKind::AllClear,
            severity: Severity::Info,
            check_id: "all-clear",
            check_title: "No findings",
            why: "",
            fix: "",
            resource_id: String::new(),
            resource_name: format!("✓ no findings — {} check{} ran clean", ran, if ran == 1 { "" } else { "s" }),
            location: None,
            reason: String::new(),
            evidence: Vec::new(),
            tags: HashMap::new(),
            row_id: "audit:all-clear".to_string(),
        }
    }

    pub fn is_finding(&self) -> bool {
        self.kind == RowKind::Finding
    }

    /// The list's second column: the finding, or a note's short status.
    pub(crate) fn list_note(&self) -> String {
        match self.kind {
            RowKind::Finding => self.reason.clone(),
            RowKind::NotChecked => self.evidence.first().cloned().unwrap_or_default(),
            RowKind::AllClear => String::new(),
        }
    }
}

impl Resource for AuditFinding {
    /// A compound key (`audit:{check}:{resource}`), never an ARM id: the
    /// resource is `resource_id`.
    fn id(&self) -> &str {
        &self.row_id
    }

    fn name(&self) -> &str {
        &self.resource_name
    }

    fn resource_type(&self) -> &str {
        match self.kind {
            RowKind::Finding => self.check_title,
            RowKind::NotChecked => "Not checked",
            RowKind::AllClear => "Summary",
        }
    }

    /// Severity is the state, through the ladder: `F` filters on the
    /// word, `z` sorts critical first. Notes are stateless.
    fn state(&self) -> ResourceState {
        self.ladder().0
    }

    fn state_label(&self) -> String {
        self.ladder().1
    }

    fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }

    fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    fn resource_group(&self) -> Option<&str> {
        resource_group_of(&self.resource_id)
    }

    fn list_summary(&self) -> Option<String> {
        Some(self.list_note())
    }

    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.check_id,
            self.check_title,
            self.resource_id,
            self.resource_name,
            self.reason,
            self.state_label(),
        )
    }

    fn details(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        let para = |rows: &mut Vec<(String, String)>, title: &str, text: &str| {
            if text.is_empty() {
                return;
            }
            rows.push((String::new(), String::new()));
            rows.push((title.to_string(), String::new()));
            for line in wrap(text, 72) {
                rows.push((String::new(), line));
            }
        };
        match self.kind {
            RowKind::Finding => {
                rows.push(("Check".into(), format!("{} ({})", self.check_title, self.check_id)));
                rows.push(("Severity".into(), self.severity.label().into()));
                // The jump row: ⏎ opens the resource in its own tab.
                rows.push(("Resource".into(), self.resource_id.clone()));
                rows.push(("Finding".into(), self.reason.clone()));
                if !self.evidence.is_empty() {
                    rows.push((String::new(), String::new()));
                    rows.push(("Evidence".into(), String::new()));
                    for e in &self.evidence {
                        rows.push((String::new(), e.clone()));
                    }
                }
                para(&mut rows, "Why it matters", self.why);
                para(&mut rows, "Remediation", self.fix);
                rows.push((String::new(), String::new()));
                rows.push((
                    String::new(),
                    "· read from what nebaz already loaded; nebaz never changes anything".into(),
                ));
            }
            RowKind::NotChecked => {
                rows.push(("Check".into(), format!("{} ({})", self.check_title, self.check_id)));
                rows.push(("Status".into(), self.list_note()));
                rows.push((String::new(), String::new()));
                for line in wrap(&self.reason, 72) {
                    rows.push((String::new(), line));
                }
                para(&mut rows, "What it checks", self.why);
            }
            RowKind::AllClear => {
                rows.push(("Result".into(), self.resource_name.clone()));
                rows.push((String::new(), String::new()));
                rows.push((
                    String::new(),
                    "· clean over what is cached; the rows below say which checks didn't run".into(),
                ));
            }
        }
        rows
    }

    fn portal_url(&self) -> Option<String> {
        portal_url_for(&self.resource_id, None)
    }

    fn clone_box(&self) -> Box<dyn Resource> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AuditFinding {
    fn ladder(&self) -> (ResourceState, String) {
        match self.kind {
            RowKind::Finding => state_ladder(None, Some((self.severity.bucket(), self.severity.label()))),
            RowKind::AllClear => state_ladder(None, Some((ResourceState::Available, "clean"))),
            RowKind::NotChecked => state_ladder(None, None),
        }
    }
}

/// Greedy word wrap for the prose paragraphs.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

// ── The provider slot ─────────────────────────────────────────────────

/// `AzureClients::service(Audit)`: the service map is total, so the
/// virtual service has a provider. It is never asked for a list
/// (`load_service_resources` computes the rows), and a finding cannot be
/// refetched.
pub struct AuditService;

#[async_trait::async_trait]
impl AzureService for AuditService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Audit
    }

    fn name(&self) -> &str {
        "Audit"
    }

    async fn list_resources(&self, _view: JumpView) -> crate::error::Result<Vec<Box<dyn Resource>>> {
        Ok(Vec::new())
    }

    async fn get_resource_details(&self, _id: &str) -> crate::error::Result<Box<dyn Resource>> {
        Err(crate::error::Error::Azure("an audit finding is computed, not fetched: press r to re-audit".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_worst_first_and_parses() {
        assert!(Severity::Critical < Severity::High && Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low && Severity::Low < Severity::Info);
        assert_eq!(Severity::parse("MED"), Some(Severity::Medium));
        assert_eq!(Severity::parse("bogus"), None);
    }

    #[test]
    fn every_check_id_is_unique_and_every_source_slot_is_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for c in CHECKS.iter() {
            assert!(seen.insert(c.id), "duplicate check id {}", c.id);
            assert!(!c.why.is_empty() && !c.fix.is_empty(), "{}: why and fix are required", c.id);
            for slot in c.sources {
                assert!(!slot.is_empty(), "{}: empty source slot", c.id);
                for v in *slot {
                    assert!(!v.service().is_virtual(), "{}: reads a virtual list", c.id);
                }
            }
        }
    }

    #[test]
    fn sources_are_one_view_per_slot_without_repeats() {
        let s = sources();
        let mut dedup = s.clone();
        dedup.dedup();
        assert_eq!(s.len(), dedup.len());
        assert!(s.contains(&JumpView::NetworkSecurityGroups));
        assert!(s.contains(&JumpView::VirtualNetworks), "subnets come from the VNets list");
        assert!(!s.contains(&JumpView::Subnets), "the VNets list already covers the Subnets slot");
    }

    #[test]
    fn an_empty_input_runs_nothing_and_says_so_per_check() {
        let input = AuditInput::new("sub", 0);
        let rows = run(&input);
        assert!(rows.iter().all(|r| r.kind == RowKind::NotChecked || r.check_id == "sub-privileged-guest-or-sp"));
        let nsg = rows.iter().find(|r| r.check_id == "nsg-open-internet").unwrap();
        assert_eq!(nsg.list_note(), "not checked — load @vnet NSGs");
        assert_eq!(nsg.state_label(), "", "a note is stateless");
        assert!(nsg.id().starts_with("audit-note:"));
    }

    #[test]
    fn a_loading_source_reads_loading() {
        let mut input = AuditInput::new("sub", 0);
        input.set_loading(&[JumpView::StorageAccounts]);
        let rows = run(&input);
        let st = rows.iter().find(|r| r.check_id == "storage-https-only").unwrap();
        assert_eq!(st.list_note(), "loading…");
    }

    #[test]
    fn wrap_keeps_words_whole() {
        assert_eq!(wrap("aa bb cc", 5), vec!["aa bb", "cc"]);
        assert!(wrap("", 5).is_empty());
    }
}
