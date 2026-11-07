//! The info card popup (`i`, `src/cards.rs`): the sub-tab's card, word
//! wrapped to the popup, scrollable, its Learn links numbered for `1`–`9`.

use crate::app::App;
use crate::cards::{self, Block};
use crate::ui::theme;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};
use unicode_width::UnicodeWidthStr;

/// Wide enough for a comfortable line, narrow enough to read.
const MAX_WIDTH: u16 = 88;

/// Greedy word wrap: `first` prefixes the first line, `rest` the others
/// (a bullet's hanging indent). Bold segments keep their emphasis.
fn wrap(text: &str, width: usize, first: &str, rest: &str, base: Style) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut spans: Vec<Span<'static>> = vec![Span::styled(first.to_string(), base)];
    let mut used = first.width();
    let mut empty = true;
    for word in cards::styled_words(text).into_iter().flat_map(|w| split_long(w, width.saturating_sub(rest.width()).max(8))) {
        let w: usize = word.iter().map(|(_, s)| s.width()).sum();
        if !empty && used + 1 + w > width {
            lines.push(Line::from(std::mem::take(&mut spans)));
            spans.push(Span::styled(rest.to_string(), base));
            used = rest.width();
            empty = true;
        }
        if !empty {
            spans.push(Span::styled(" ", base));
            used += 1;
        }
        for (bold, piece) in word {
            let style = if bold { base.fg(theme::text_primary()).add_modifier(Modifier::BOLD) } else { base };
            spans.push(Span::styled(piece, style));
        }
        used += w;
        empty = false;
    }
    lines.push(Line::from(spans));
    lines
}

/// A word wider than `max` (a URL) cut into `max`-wide pieces, each its
/// own word, so it wraps instead of running past the edge.
fn split_long(word: Vec<(bool, String)>, max: usize) -> Vec<Vec<(bool, String)>> {
    if word.iter().map(|(_, s)| s.width()).sum::<usize>() <= max {
        return vec![word];
    }
    let mut out: Vec<Vec<(bool, String)>> = vec![Vec::new()];
    let mut used = 0;
    for (bold, piece) in word {
        for c in piece.chars() {
            let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
            if used + cw > max {
                out.push(Vec::new());
                used = 0;
            }
            let cur = out.last_mut().expect("never empty");
            match cur.last_mut() {
                Some((b, s)) if *b == bold => s.push(c),
                _ => cur.push((bold, c.to_string())),
            }
            used += cw;
        }
    }
    out
}

/// The card's lines at `width` columns.
pub fn card_lines(card: &cards::Card, width: usize) -> Vec<Line<'static>> {
    let body = Style::default().fg(theme::text_primary());
    let dim = Style::default().fg(theme::text_dim());
    let mut out: Vec<Line<'static>> = Vec::new();
    for block in card.blocks() {
        match block {
            Block::Title(t) => out.push(Line::from(Span::styled(
                t,
                Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD),
            ))),
            Block::Heading(h) => {
                out.push(Line::raw(""));
                out.push(Line::from(Span::styled(h, Style::default().fg(theme::heading()).add_modifier(Modifier::BOLD))));
            }
            Block::Paragraph(p) => {
                out.push(Line::raw(""));
                out.extend(wrap(&p, width, "", "", body));
            }
            Block::Bullet(b) => out.extend(wrap(&b, width, "• ", "  ", body)),
            Block::Link { n, label, url } => {
                out.push(Line::from(vec![
                    Span::styled(format!("{} ", n), Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
                    Span::styled(label, body),
                ]));
                out.extend(wrap(&url, width, "  ", "  ", dim));
            }
        }
    }
    out
}

pub fn render_info_card(app: &App, frame: &mut Frame) {
    let Some(state) = &app.info_card else { return };
    let Some(card) = cards::for_view(state.view) else { return };
    let size = frame.area();
    let width = MAX_WIDTH.min(size.width.saturating_sub(4)).max(30);
    let text_w = width.saturating_sub(2 + 4) as usize; // borders + margins
    let lines = card_lines(card, text_w);
    let max_h = (size.height * 85 / 100).max(10);
    let height = (lines.len() as u16 + 2).min(max_h);
    let area = Rect {
        x: size.x + size.width.saturating_sub(width) / 2,
        y: size.y + size.height.saturating_sub(height) / 2,
        width: width.min(size.width),
        height: height.min(size.height),
    };
    let viewport = height.saturating_sub(2);
    let max_scroll = (lines.len() as u16).saturating_sub(viewport);
    app.info_max_scroll.set(max_scroll);
    let offset = state.scroll.min(max_scroll);

    frame.render_widget(Clear, area);
    app.mouse.popup.borrow_mut().record_area(area);
    let links = card.blocks().iter().filter(|b| matches!(b, Block::Link { .. })).count();
    let keys = match links {
        0 => String::new(),
        1 => "1 copy the link · ".into(),
        n => format!("1–{} copy a link · ", n),
    };
    let scroll = if max_scroll > 0 { "↑/↓ scroll · " } else { "" };
    let mut block = theme::popup_block(&format!("About · {}", state.view.label())).title_bottom(
        Line::from(Span::styled(format!(" {}{}Esc close ", scroll, keys), Style::default().fg(theme::text_dim()))).centered(),
    );
    if max_scroll > 0 {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" {}–{}/{} ", offset + 1, (offset + viewport).min(lines.len() as u16), lines.len()),
                Style::default().fg(theme::text_dim()),
            ))
            .right_aligned(),
        );
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let body = Rect { x: inner.x + 2, width: inner.width.saturating_sub(4), ..inner };
    frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), body);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[Line]) -> Vec<String> {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect()
    }

    #[test]
    fn bullets_wrap_with_a_hanging_indent_and_keep_bold_words_whole() {
        let lines = wrap("**Peering**: joins two VNets over the backbone", 20, "• ", "  ", Style::default());
        assert_eq!(text(&lines), ["• Peering: joins two", "  VNets over the", "  backbone"]);
        assert!(lines[0].spans.iter().any(|s| s.content == "Peering" && s.style.add_modifier.contains(Modifier::BOLD)));
    }

    #[test]
    fn a_url_too_long_for_the_line_wraps_whole() {
        let url = "https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview";
        let lines = wrap(url, 30, "  ", "  ", Style::default());
        let rows = text(&lines);
        assert!(rows.iter().all(|r| r.width() <= 30), "{rows:?}");
        assert_eq!(rows.iter().map(|r| r.trim_start()).collect::<String>(), url);
    }

    #[test]
    fn every_card_fits_a_narrow_popup_without_a_line_past_the_edge() {
        for card in cards::CARDS {
            for line in card_lines(card, 40) {
                let w: usize = line.spans.iter().map(|s| s.content.width()).sum();
                let joined: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                assert!(w <= 40, "{:?}: {joined:?}", card.views);
            }
        }
    }
}
