//! Info cards (`i`): a short page per sub-tab on what the service is, its
//! key ideas, what nebaz shows of it and where Microsoft Learn explains
//! the rest. The text is Markdown in `docs/cards/` (its README is the
//! format), built into the binary; this module maps sub-tabs to cards and
//! parses the small Markdown subset into [`Block`]s. The popup is
//! `src/ui/widgets/info_card.rs`. A card is text only: its links are
//! copied, never fetched.

use crate::azure::service::JumpView;

pub struct Card {
    /// The sub-tabs the card is about (several when they are one idea).
    pub views: &'static [JumpView],
    pub source: &'static str,
}

pub static CARDS: &[Card] = &[
    Card { views: &[JumpView::VirtualNetworks], source: include_str!("../docs/cards/vnets.md") },
    Card { views: &[JumpView::ArcMachines], source: include_str!("../docs/cards/arc-servers.md") },
    Card { views: &[JumpView::AutomationAccounts], source: include_str!("../docs/cards/automation-accounts.md") },
];

/// The card for a sub-tab, if one is written.
pub fn for_view(view: JumpView) -> Option<&'static Card> {
    CARDS.iter().find(|c| c.views.contains(&view))
}

/// One piece of a card, in reading order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Title(String),
    Heading(String),
    Paragraph(String),
    Bullet(String),
    /// A `- Label: https://…` line, numbered in the card's order.
    Link { n: usize, label: String, url: String },
}

impl Card {
    /// The card as blocks. A paragraph's lines join with spaces; a bullet
    /// whose text is `Label: https://…` is a link.
    pub fn blocks(&self) -> Vec<Block> {
        let mut out = Vec::new();
        let mut para: Vec<&str> = Vec::new();
        let mut links = 0;
        let flush = |para: &mut Vec<&str>, out: &mut Vec<Block>| {
            if !para.is_empty() {
                out.push(Block::Paragraph(para.join(" ")));
                para.clear();
            }
        };
        for line in self.source.lines().map(str::trim_end) {
            if line.trim().is_empty() {
                flush(&mut para, &mut out);
            } else if let Some(t) = line.strip_prefix("## ") {
                flush(&mut para, &mut out);
                out.push(Block::Heading(t.trim().to_string()));
            } else if let Some(t) = line.strip_prefix("# ") {
                flush(&mut para, &mut out);
                out.push(Block::Title(t.trim().to_string()));
            } else if let Some(t) = line.strip_prefix("- ") {
                flush(&mut para, &mut out);
                match t.split_once(": https://") {
                    Some((label, rest)) => {
                        links += 1;
                        out.push(Block::Link { n: links, label: label.trim().to_string(), url: format!("https://{}", rest.trim()) });
                    }
                    None => out.push(Block::Bullet(t.trim().to_string())),
                }
            } else {
                para.push(line.trim());
            }
        }
        flush(&mut para, &mut out);
        out
    }

    /// The URL of link `n` (1-based).
    pub fn link(&self, n: usize) -> Option<String> {
        self.blocks().into_iter().find_map(|b| match b {
            Block::Link { n: k, url, .. } if k == n => Some(url),
            _ => None,
        })
    }
}

/// `text` as words, each a run of `(bold, piece)` segments: `**` toggles
/// emphasis without breaking a word, so `**Peering**:` stays one word.
pub fn styled_words(text: &str) -> Vec<Vec<(bool, String)>> {
    let mut words = Vec::new();
    let mut word: Vec<(bool, String)> = Vec::new();
    let mut bold = false;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("**") {
            bold = !bold;
            rest = after;
            continue;
        }
        rest = &rest[c.len_utf8()..];
        if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        match word.last_mut() {
            Some((b, piece)) if *b == bold => piece.push(c),
            _ => word.push((bold, c.to_string())),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azure::service::ServiceType;

    #[test]
    fn every_card_has_a_title_the_three_parts_and_learn_links() {
        for card in CARDS {
            let blocks = card.blocks();
            assert!(matches!(blocks.first(), Some(Block::Title(_))), "{:?}: starts with a # title", card.views);
            let headings: Vec<&str> = blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Heading(h) => Some(h.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(headings, ["Key ideas", "In nebaz", "Learn more"], "{:?}", card.views);
            let links: Vec<&str> = blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Link { url, .. } => Some(url.as_str()),
                    _ => None,
                })
                .collect();
            assert!(!links.is_empty() && links.len() <= 9, "{:?}: 1 to 9 links (keys 1–9 copy them)", card.views);
            assert!(
                links.iter().all(|u| u.starts_with("https://learn.microsoft.com/")),
                "{:?}: links go to Microsoft Learn",
                card.views
            );
        }
    }

    #[test]
    fn no_sub_tab_has_two_cards() {
        let mut seen = Vec::new();
        for view in CARDS.iter().flat_map(|c| c.views) {
            assert!(!seen.contains(view), "{view:?} has two cards");
            seen.push(*view);
        }
    }

    /// Not a gate yet: the prototype has three cards. Prints which
    /// sub-tabs still have none (`cargo test cards -- --nocapture`).
    #[test]
    fn sub_tabs_without_a_card_are_listed() {
        let missing: Vec<&str> = ServiceType::all()
            .iter()
            .flat_map(|s| s.views().iter())
            .filter(|v| for_view(**v).is_none())
            .map(|v| v.as_str())
            .collect();
        println!("{} sub-tabs without a card: {}", missing.len(), missing.join(", "));
        assert!(for_view(JumpView::VirtualNetworks).is_some());
    }

    #[test]
    fn a_card_parses_into_blocks_and_numbers_its_links() {
        let card = Card {
            views: &[],
            source: "# T\n\nOne line\nand the next.\n\n## Key ideas\n\n- **A**: b\n\n## Learn more\n\n- Overview: https://learn.microsoft.com/x\n- More: https://learn.microsoft.com/y\n",
        };
        assert_eq!(
            card.blocks(),
            [
                Block::Title("T".into()),
                Block::Paragraph("One line and the next.".into()),
                Block::Heading("Key ideas".into()),
                Block::Bullet("**A**: b".into()),
                Block::Heading("Learn more".into()),
                Block::Link { n: 1, label: "Overview".into(), url: "https://learn.microsoft.com/x".into() },
                Block::Link { n: 2, label: "More".into(), url: "https://learn.microsoft.com/y".into() },
            ]
        );
        assert_eq!(card.link(2).as_deref(), Some("https://learn.microsoft.com/y"));
        assert_eq!(card.link(3), None);
        assert_eq!(
            styled_words("**Peering**: joins"),
            [vec![(true, "Peering".to_string()), (false, ":".to_string())], vec![(false, "joins".to_string())]]
        );
    }
}
