// ported from neboto-tui src/aws/resource.rs @ d483900
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceState {
    Running,
    Stopped,
    Pending,
    Terminated,
    Available,
    Unavailable,
    Creating,
    Deleting,
    Unknown(String),
}

impl ResourceState {
    /// The state of a resource kind that has **no lifecycle state** — a
    /// resource group, a subnet, a key vault. Renders as a dim `○` with a
    /// blank label, so the wide list column stays empty and the `F` filter
    /// offers nothing. Use this instead of a constant `Available`: a column
    /// of green "available" on rows that can't be anything else reads as a
    /// state and is just noise.
    pub fn stateless() -> Self {
        ResourceState::Unknown(String::new())
    }
}

impl std::fmt::Display for ResourceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceState::Running => write!(f, "running"),
            ResourceState::Stopped => write!(f, "stopped"),
            ResourceState::Pending => write!(f, "pending"),
            ResourceState::Terminated => write!(f, "terminated"),
            ResourceState::Available => write!(f, "available"),
            ResourceState::Unavailable => write!(f, "unavailable"),
            ResourceState::Creating => write!(f, "creating"),
            ResourceState::Deleting => write!(f, "deleting"),
            ResourceState::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// The `state_label()` for a type whose `state()` is a mapping of a native
/// status string: the native word, lowercased (so the `F` chips read
/// `deallocated` / `succeeded` / `provisioning`, not the coarse bucket's
/// `stopped`). An empty native status falls back to the coarse word so the
/// column never goes blank.
pub fn native_state_label(native: &str, fallback: impl FnOnce() -> ResourceState) -> String {
    let native = native.trim();
    if native.is_empty() {
        fallback().to_string()
    } else {
        native.to_lowercase()
    }
}

/// One row in any list pane. `id()` is the full ARM resource id
/// (`/subscriptions/…/providers/…`) for every ARM-backed type — it is the
/// universal jump key, the portal deep-link source, and the cache/lazy key.
///
/// Compared with neboto's trait, four AWS-shaped methods are gone
/// (`console_url(region)`, `trail_lookup_keys`, `security_group_ids`,
/// `references`) and two Azure-shaped ones are added (`location`,
/// `resource_group`). The final shape is ticket 04's decision; see the
/// sizing report on ticket 02 for the reasoning behind each.
pub trait Resource: Send + Sync + Debug {
    /// Unique identifier — the ARM resource id wherever one exists.
    fn id(&self) -> &str;

    /// Display name
    fn name(&self) -> &str;

    /// Resource type (e.g., "Virtual Machine", "Storage Account")
    fn resource_type(&self) -> &str;

    /// Current state (running, stopped, etc.)
    fn state(&self) -> ResourceState;

    /// The word shown wherever `state()` renders as text — the wide list
    /// column, the `F` filter chips, exports. `state()` is a *coarse*
    /// colour/sort bucket, so nearly every type maps its own status onto it
    /// (a VM's `PowerState/deallocated` → Stopped); the label must say the
    /// resource's **own** word, never the bucket's. Override on every type
    /// whose mapping changes the word (`native_state_label` covers the common
    /// status-string case); the default is only right when the enum word IS
    /// the native one. The dot colour always comes from `state()` itself.
    fn state_label(&self) -> String {
        self.state().to_string()
    }

    /// The split pane's section table, when this type has one — the single
    /// source of truth its section wiring derives from (`src/sections.rs`).
    /// `None` (the default) renders the flat `details()` view.
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        None
    }

    /// Tags
    fn tags(&self) -> &HashMap<String, String>;

    /// The resource's own `location` (short form, `eastus`), when it has
    /// one. `None` for subscriptions, resource-group-level rows and child
    /// resources (subnets, containers, agent pools), which inherit their
    /// parent's and are **never** filtered out by the `R` slot. The
    /// location filter keys on this, never on the resource group's location.
    fn location(&self) -> Option<&str> {
        None
    }

    /// The resource group this resource lives in, parsed from the ARM id.
    /// `None` for subscription-level rows. Drives the resource-group filter
    /// chip on every list.
    fn resource_group(&self) -> Option<&str> {
        resource_group_of(self.id())
    }

    /// Searchable text (for fuzzy search)
    fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.id(),
            self.name(),
            self.resource_type(),
            self.resource_group().unwrap_or(""),
            self.tags()
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    /// Details for display pane (key-value pairs)
    fn details(&self) -> Vec<(String, String)>;

    /// Whether this resource is "noise" — a low-signal, everything-is-fine row
    /// that the list pane hides by default so problems stand out. Toggled
    /// with `a`. Default: not noise.
    fn is_noise(&self) -> bool {
        false
    }

    /// Clone as boxed trait object
    fn clone_box(&self) -> Box<dyn Resource>;

    fn as_any(&self) -> &dyn Any;

    /// The resource's **raw ARM JSON**, when the API hands us one verbatim.
    /// `e` opens it in `$EDITOR` in preference to the detail-snapshot JSON.
    fn raw_content(&self) -> Option<String> {
        None
    }

    /// The Entra tenant this resource's subscription belongs to, when the
    /// provider knows it. Only used to qualify the portal link.
    fn tenant_id(&self) -> Option<&str> {
        None
    }

    /// The Azure portal page for this resource. Every ARM id has one, so
    /// unlike neboto's `console_url(region)` this needs no region argument
    /// and defaults from `id()` (tenant-qualified when `tenant_id()` is
    /// known); override only for rows with no ARM id.
    fn portal_url(&self) -> Option<String> {
        portal_url_for(self.id(), self.tenant_id())
    }

    /// The `az` CLI command that fetches this resource, complete: `C`
    /// copies it verbatim. Use `--ids <ARM id>` wherever `az` supports it
    /// and **never** append `--subscription` to such a command (the id
    /// carries the subscription); only commands without `--ids`
    /// (`az account show`, `az group show -n`) carry `--subscription`
    /// themselves. **Read commands only**: never a mutation, and never one
    /// that reveals a secret value (Key Vault maps to `az keyvault secret
    /// list`, never `secret show`). Quote values with [`shell_quote`].
    fn cli_command(&self) -> Option<String> {
        None
    }
}

/// The portal deep link for an ARM id: `#@{tenant}/resource{id}` when the
/// tenant is known, else `#@/resource{id}` (the portal then picks the
/// signed-in directory). `None` for anything that is not an ARM id.
pub fn portal_url_for(id: &str, tenant: Option<&str>) -> Option<String> {
    if !id.starts_with("/subscriptions/") {
        return None;
    }
    Some(format!(
        "https://portal.azure.com/#@{}/resource{}",
        tenant.unwrap_or(""),
        id
    ))
}

/// The `resourceGroups/{name}` segment of an ARM id, case-insensitively.
pub fn resource_group_of(id: &str) -> Option<&str> {
    let mut parts = id.split('/').filter(|p| !p.is_empty());
    while let Some(p) = parts.next() {
        if p.eq_ignore_ascii_case("resourceGroups") {
            return parts.next();
        }
    }
    None
}

// Enable cloning of Box<dyn Resource>
impl Clone for Box<dyn Resource> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Single-quote a value for a copied shell command when it contains anything
/// beyond the characters safe in every POSIX shell; identifiers (ARM ids,
/// most names) pass through untouched so commands stay readable.
pub fn shell_quote(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./:=@,+".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::{native_state_label, portal_url_for, resource_group_of, shell_quote, ResourceState};

    #[test]
    fn portal_url_is_tenant_qualified_when_the_tenant_is_known() {
        let id = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1";
        assert_eq!(
            portal_url_for(id, Some("t-1")).as_deref(),
            Some("https://portal.azure.com/#@t-1/resource/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1")
        );
        assert_eq!(
            portal_url_for(id, None).as_deref(),
            Some("https://portal.azure.com/#@/resource/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1")
        );
        assert_eq!(portal_url_for("not-an-arm-id", None), None);
    }

    #[test]
    fn native_state_label_prefers_the_resource_word_over_the_bucket() {
        assert_eq!(
            native_state_label("PowerState/deallocated", || ResourceState::Stopped),
            "powerstate/deallocated"
        );
        assert_eq!(native_state_label(" Succeeded ", || ResourceState::Available), "succeeded");
        assert_eq!(native_state_label("", || ResourceState::Pending), "pending");
    }

    #[test]
    fn resource_group_is_parsed_from_the_arm_id_case_insensitively() {
        let id = "/subscriptions/0000/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm1";
        assert_eq!(resource_group_of(id), Some("rg-prod"));
        assert_eq!(resource_group_of("/subscriptions/0000/RESOURCEGROUPS/x"), Some("x"));
        assert_eq!(resource_group_of("/subscriptions/0000"), None);
    }

    #[test]
    fn shell_quote_passes_identifiers_and_quotes_the_rest() {
        assert_eq!(
            shell_quote("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"),
            "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
        );
        assert_eq!(shell_quote("my name"), "'my name'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}
