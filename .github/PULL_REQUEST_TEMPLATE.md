## What

<!-- one or two sentences: what changes and why -->

## Tested against

<!-- a live tenant (which services) / the fake-az pty smoke run / unit tests only -->

## Checklist

- [ ] `cargo test` and `cargo clippy` pass with no new warnings
- [ ] The read-only guard (`cargo test --test readonly_guard`) passes — **no writes, no data-plane hosts, no mutating `az` commands** (allowlist additions explained above)
- [ ] New/changed ARM calls are in `PERMISSIONS.md` (action) and the catalog call table (path + api-version)
- [ ] New service or sub-tab: registered in `AzureClients::service()`, section descriptor written, `README.md` build lines updated
- [ ] Visual change: screenshot or recording attached; colors go through `theme.rs`
- [ ] `README.md` / `docs/` / `CONTEXT.md` updated if behaviour or vocabulary changed
