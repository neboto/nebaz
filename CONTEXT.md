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
A row whose location is `global` (private DNS zones and other non-regional
types) passes every location filter: it is in every location, not none. So
does a row whose location is not an Azure region at all (a Power Platform
enterprise policy's geography, `unitedstates`): `Resource::filter_location`
is `None` for it, while the geography still shows on the row.
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

**Cross-cache search**:
`@* <text>`: one search over every list of the subscription with a warm
cache entry, never a fetch. Not a routing prefix, and not All resources
(`@all`, one ARM list of the whole subscription).
_Avoid_: @all (neboto's spelling; here it is the All resources prefix)

**State ladder**:
The one rule that maps a row's Azure status onto the coarse colour bucket:
a provisioning state in transition or failed wins, else the type's runtime
state (power, attachment, primary status), else stateless. The label is
always the resource's own word, never the bucket's.
_Avoid_: per-type state tables that disagree on what `Succeeded` means

**Access section**:
The RBAC section every type carries just before Related: the role
assignments that apply at the row's ARM id, made there or inherited from a
resource group, subscription or management group. Principals are named
through Microsoft Graph when the account may read the directory, object ids
otherwise. An identity's **Can do** section is the
reverse: what its principal holds.
_Avoid_: permissions (that is `PERMISSIONS.md`, what nebaz itself needs), IAM

**Activity section**:
The section every type carries after Access: the last week of control-plane
operations on the row (who, what, when, whether it worked), from the
subscription's activity log. One entry per operation, not per event.
_Avoid_: audit log, logs (Log Analytics is Monitor's, and data plane)

**Directory row**:
A row from Microsoft Graph, not ARM: a service principal or an app
registration (Identity tab). It has no ARM id and keys on a synthetic id,
`graph:/servicePrincipals/{objectId}`, also answering to its app-id alias.
_Avoid_: enterprise app (the portal's word for a service principal), AAD

**All resources**:
The Subscriptions sub-tab listing every resource in the subscription from
the generic list, whatever its type (`→` marks a type with its own tab). It
is where a jump to a type nebaz does not browse yet lands.
_Avoid_: inventory, Resource Graph (a POST query nebaz does not use)

**Related section**:
The detail section every type carries listing the ARM ids the row points at
(its subscription and resource group first, then its own links); Enter on a
line jumps to that resource. It is the app's only jump mechanism besides
the network lens.
_Avoid_: references, referenced-by (the reverse lens, not in the first release)

**Network lens**:
The `N` view of the NSG rules that apply to a NIC, a subnet or an NSG (a
VM through its NICs), in Azure's evaluation order: subnet NSG then NIC NSG
inbound, the reverse outbound, priority order within each. **Computed**
from the NSGs' rules, never Azure's effective view. A rule is **shadowed**
when an earlier rule of the same NSG matches everything it matches.
_Avoid_: effective rules (Azure's POST-only view, which this is not)

**Read-only guarantee**:
The promise that nebaz never changes anything in Azure, and never fetches a
value that belongs to a data plane (a secret's value, a blob's body). It is
held by three layers that fail independently: the process refuses to send
anything but a read, the guard fails the build, and the granted role can
only read.
_Avoid_: read-only mode (it is not a mode; there is no other one)

**Guard**:
The test that fails the build when the source could break the read-only
guarantee: another request builder, a data-plane host, a mutating `az`
command outside the command catalogue, a destructive or secret-revealing
one anywhere, a non-read permission in the permissions doc.
_Avoid_: linter, allowlist script (neboto's name for its Python version)

**Command catalogue**:
The `az` commands `C` offers for a row (`src/azure/cli_actions.rs`), in
three **tiers**: **Inspect** (reads), **Connect** (opens a session or
configures a local tool, changes nothing in Azure) and **Change**
(start / stop / restart / scale). Copied to the clipboard, never run; the
one file the guard lets spell a Connect or Change verb (ADR 0005).
_Avoid_: actions (nebaz performs none), CLI actions

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

**DNS topology**:
One lazy fetch per subscription that gathers every DNS link no list body
carries: resolver endpoints, and the VNet links of forwarding rulesets, DNS
security policies and private DNS zones. Several sections and the VNet and
subnet Related sections read the same entry.
_Avoid_: DNS graph, DNS map

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
and falls back to its single-target or whole-list meaning when none is
(list pane: `y`/`c` copy a Markdown table, `X` deep-exports, `Ctrl-X`
shallow-exports the selected rows).
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

**Export wait**:
How a deep export gets its lazy data: the press **arms** the export, fires
every section's on-enter hook, and the main loop writes the files once no
section reads `Loading…` (at once when all are warm), or after two minutes
with the still-loading sections marked not loaded. `Esc` cancels. The rows
are held by id, so the wait outlives a positional selection.
_Avoid_: press-again export (what it replaced)

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
