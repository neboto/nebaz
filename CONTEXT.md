# nebaz

A read-only Azure resource browser TUI, the sibling of neboto (the AWS one).
This glossary is the canonical language for the project's own concepts —
architecture and per-service detail live in CLAUDE.md and `docs/adr/`, not
here. The detail-loading, section, export and macro vocabulary is inherited
from neboto's glossary and kept word-for-word where the concept is unchanged.

## Language

### Scoping

**Subscription**:
The unit an Azure list call is scoped to, and the one thing the app is
"pointed at" at any moment (the `P` slot). Every list is fetched per
subscription.
_Avoid_: profile, account (neboto words with no Azure meaning)

**Location**:
An Azure region name as ARM spells it (`westeurope`). In nebaz a location is
a **filter** over rows already fetched for the subscription, never a scope a
call is made in; "all locations" is the ordinary state, not a special one.
_Avoid_: region (even though the picker key stays `R`)

**Resource group**:
The folder an ARM resource lives in, readable from its ARM id. A filter, not
a scope: it narrows a list the same way a search term does.
_Avoid_: RG as a "slot", group (bare)

**Tenant scope**:
The scope of a list that has no subscription in its path — only the
subscription list itself. Such lists belong to the tenant, so switching
subscription does not invalidate them.
_Avoid_: global (neboto's word for us-east-1-pinned services)

**Tenant**:
The Entra directory a subscription belongs to. One login may span several;
a token is minted for exactly one, so the tenant is what a credential is
scoped to. There is no tenant picker: choosing a subscription chooses its
tenant.
_Avoid_: directory, Azure AD

**Credential source**:
Where tokens come from — the Azure CLI's login in the first release, a
service principal or managed identity later. Chosen explicitly in config,
never guessed from the environment.
_Avoid_: credential chain (implies auto-detection)

**Auth error**:
The single, app-wide condition that tokens cannot be obtained, shown as one
status-bar line with the fix. It replaces per-service load errors while it
holds and clears on the next successful token.
_Avoid_: per-service auth failure

### Resources

**ARM id**:
The full `/subscriptions/…/providers/…` path of a resource. It is the
universal key: the row's identity, the portal deep link, the cache and lazy
key, and the argument of the copied `az` command.
_Avoid_: resource URI, resource path, resource name (when the path is meant)

**Service**:
One tab in the tab strip and one list provider behind it — a grouping nebaz
chooses (Virtual Machines, Storage, Network…), not an Azure concept.
_Avoid_: provider (see Resource provider), namespace

**Resource provider**:
An ARM namespace such as `Microsoft.Compute`. Several resource providers may
feed one service, and this word is reserved for the Azure meaning.
_Avoid_: provider (bare, for a service's implementation)

**Sub-tab**:
A list-pane view within a service — the rows of one resource type. Every
sub-tab is fed by one subscription-wide list or flattened from one.
_Avoid_: tab (that word belongs to the service strip), section (the detail pane)

**Embedded child**:
A resource type whose rows arrive inside its parent's list (subnets inside
virtual networks, node pools inside clusters). It costs no extra call, so it
gets its own sub-tab and appears as a section on the parent as well.
_Avoid_: nested resource, flattened resource

**Lazy child**:
A resource type that can only be listed per parent (blob containers per
storage account, secret and key names per vault). It costs one call per
parent, so it is a lazy section on the parent and never a sub-tab.
_Avoid_: child list, per-resource list

**Node pool**:
An AKS cluster's group of identically-sized nodes. The API calls it an agent
pool; the portal and this project say node pool.
_Avoid_: agent pool

**Routing prefix**:
An `@word` typed in search that selects a service *and* a sub-tab (`@disk`
lands on the Disks sub-tab of Virtual Machines). A plain service prefix
(`@vm`) lands on the service's first sub-tab.
_Avoid_: alias (for the sub-tab-selecting form)

### Detail loading

**Lazy section**:
A detail-pane section whose data is not fetched until the user first views it.
_Avoid_: on-demand section, deferred section

**Lazy**:
The three-state outcome of a lazy fetch — still loading, loaded with a value,
or failed with a message. Every lazy fetch resolves to exactly one of these.
_Avoid_: per-service `*State` enums, LoadState

**LazyMap**:
A keyed collection of Lazy outcomes for one detail concern (e.g. containers
by storage-account ARM id). Triggering a key that is already present is a
no-op, so a section can be triggered from many places safely.
_Avoid_: state map, state HashMap

**LazyStore**:
The single owner of every LazyMap. It is replaced wholesale whenever the
subscription changes, so no lazy data can survive a switch — reset is by
construction, not by convention. A location change never touches it.
_Avoid_: subscription-scoped state (as a scattered convention)

**List cache**:
The store of fetched lists, one entry per service, subscription and sub-tab.
It outlives a subscription switch, so switching back is instant, and a
location change never touches it because location is a filter.
_Avoid_: resource cache (ambiguous with the LazyStore)

**Epoch**:
The LazyStore's generation stamp. A fetch that completes under an older epoch
is dropped, never applied — stale in-flight results cannot poison a fresh
store.
_Avoid_: generation (that word belongs to the list-load stream guard)

**Apply-closure event**:
The one event through which every lazy fetch delivers its result back into
the app, replacing per-fetch `*Loaded` event variants.
_Avoid_: `*Loaded` events (for lazy sections)

### Detail sections

**Section descriptor**:
A resource type's single source of truth for its detail-pane sections — the
ordered list of section definitions the pane cycles through. Everything that
consumes section order (digit keys, Tab cycling, reset, the snapshot, the tab
bar, flat view) derives from it, so order agreement holds by construction.
_Avoid_: section list, section table (when meaning the per-type declaration)

**Section definition**:
One entry in a section descriptor — a label plus an optional on-enter hook.
_Avoid_: tab

**On-enter hook**:
A section definition's optional trigger, fired whenever the section becomes
active. It points at a lazy trigger, whose LazyMap idempotence makes repeated
firing safe.
_Avoid_: section trigger dispatch (as a per-consumer re-encoding)

**Section index**:
The app's single cursor into the selected resource's section descriptor —
which section is active. There is one index, not one enum field per type.
_Avoid_: `*DetailSection` field

### Selection & export

**Visual selection**:
A contiguous, positional anchor-to-cursor range — over body lines in the
detail pane, over rows in the list pane. Because it is positional, anything
that changes what the positions mean (sort, filter, query edit, sub-tab
switch, reload, refresh swap, drill-in) cancels it rather than remapping it.
_Avoid_: marks, marked set, highlight

**Selection-aware verb**:
A copy/export key that operates on the visual selection when one is active
and falls back to its single-target or whole-list meaning when none is.
_Avoid_: multi-select action

**Deep export**:
An export carrying a resource's full detail — every section, including lazy
ones. A deep export is only honest when its lazy data is loaded; it never
silently exports unloaded sections.
_Avoid_: full export, detail export

**Shallow export**:
An export of list-row fields only — one row per resource, no sections
fetched. Costs zero Azure calls, so it is never capped.
_Avoid_: inventory export, list export

**Press-again export**:
The two-step deep export of not-yet-loaded data: the first press fires the
lazy triggers and says so; pressing again once they land exports complete
data. The selection survives the first press by definition.

### Macros

**Step**:
One replayable unit of a macro, recording the *meaning* of a navigation action
rather than the key that produced it — the row's ARM id, the whole search
query, the section's name.
_Avoid_: keystroke, recorded key

**Checkpoint**:
A step derived by **diffing app state** after the fact rather than from the
key pressed — the subscription, location, or service. Keys typed inside a
picker are filter text and reproduce nothing, so the *outcome* is what gets
recorded.
_Avoid_: modal replay, recording the picker keys

**Quiescence**:
The condition a macro player waits for before injecting its next step —
nothing loading, no pending jump, no subscription switch in flight, plus a
short settle. Modals are deliberately *not* part of it.
_Avoid_: sleep, delay, timeout

**Collapsing**:
Folding a run of steps that describe the same journey into the one that
describes its destination — a run of `j`/`k` becomes a single select-by-id.
_Avoid_: deduplication
