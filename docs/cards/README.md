# Info cards

What `i` shows: one card per sub-tab (or per group of sub-tabs that are
the same idea), built into the binary from this folder by `src/cards.rs`.
Every sub-tab has one; a new sub-tab fails `every_sub_tab_has_a_card`
until it is added to a card there.

A card is short. Four parts, in this order:

1. `# Title`, then two or three sentences: what the service is.
2. `## Key ideas`: a few bullets, `**term**: what it means`.
3. `## In nebaz`: what the tab shows, what its states mean, what is never
   read and why, which `@audit` checks look at it. Take it from
   `docs/SERVICES.md`; that file stays the reference.
4. `## Learn more`: `- Label: https://learn.microsoft.com/…` lines. The
   card numbers them; `1`–`9` copy one. Microsoft Learn is the authority
   for anything about Azure itself; keep the prose here short so it can't
   drift far.

Only that much Markdown: `#`, `##`, `- ` bullets, `**bold**`, paragraphs.
