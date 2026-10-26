// ported from neboto-tui src/ui/widgets/service_tabs.rs @ d483900
use crate::app::{App, ClickAction};
use crate::azure::service::ServiceType;
use crossterm::event::KeyCode;
use crate::ui::theme;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// `" name "` chip width in columns.
fn chip_width(label: &str) -> u16 {
    label.chars().count() as u16 + 2
}

/// `" │ "` separator between chips.
const SEP: u16 = 3;
/// `"‹ "` / `" ›"` overflow markers.
const MARKER_W: u16 = 2;

/// Service strip showing only visited services (loaded at least once this
/// session), plus the right-side badges (endpoint / subscription / hint).
/// The badges are **never dropped**: they degrade field-by-field (hint →
/// subscription name → subscription id) and the chip
/// strip scrolls a window around the active chip with `‹`/`›` markers, like
/// the sub-tab bars. Switch via S modal, @prefix search, or chip click.
pub fn render_service_tabs(app: &App, area: Rect, frame: &mut Frame) {
    // ── Right side: badge parts in priority order ─────────────────────────
    // Demo mode (#45) takes the endpoint badge's slot and style: it is the
    // one thing a screenshot must never be mistaken for.
    let endpoint_text = match app.azure_clients.current_endpoint() {
        _ if app.azure_clients.is_demo() => " DEMO · made-up data ".to_string(),
        Some(ep) => {
            // Strip the scheme for a compact `⚙ localhost:4566` badge.
            let host = ep
                .strip_prefix("http://")
                .or_else(|| ep.strip_prefix("https://"))
                .unwrap_or(ep);
            format!(" ⚙ {} ", host.trim_end_matches('/'))
        }
        None => String::new(),
    };
    // Subscription badge: `⦿ name (id)` degrading to `⦿ id` — every row on
    // screen belongs to this subscription, so it is always visible.
    let sub_id = app
        .azure_clients
        .current_subscription()
        .map(str::to_string)
        .or_else(|| app.subscription_id.clone());
    let (sub_full, sub_short) = match (&app.subscription_name, &sub_id) {
        (Some(name), Some(id)) => (format!(" ⦿ {} ({}) ", name, id), format!(" ⦿ {} ", id)),
        (None, Some(id)) => (format!(" ⦿ {} ", id), format!(" ⦿ {} ", id)),
        (Some(name), None) => (format!(" ⦿ {} ", name), format!(" ⦿ {} ", name)),
        (None, None) => (String::new(), String::new()),
    };
    let hint_text = " S: services  @: prefix ";
    // A newer release (`update_check.rs`): dim, so it reads as news rather
    // than a warning; the first badge to go when the strip is narrow.
    let update_text = match &app.update_available {
        Some(v) => format!(" ↑ v{} ", v),
        None => String::new(),
    };
    let update_style = Style::default().fg(theme::text_dim());

    let endpoint_style = Style::default()
        .fg(theme::chip_fg())
        .bg(theme::warning())
        .add_modifier(Modifier::BOLD);
    let sub_style = Style::default()
        .fg(crate::ui::theme::text_primary())
        .add_modifier(Modifier::BOLD);
    let hint_style = Style::default().fg(theme::text_dim());

    // Candidate badge sets, widest first. The last (endpoint + short
    // subscription) is the floor — identity info survives any terminal width.
    let build = |update: bool, hint: bool, sub_long: bool| {
        let mut parts: Vec<(String, Style)> = Vec::new();
        if update && !update_text.is_empty() {
            parts.push((update_text.clone(), update_style));
        }
        if !endpoint_text.is_empty() {
            parts.push((endpoint_text.clone(), endpoint_style));
        }
        let sub = if sub_long { &sub_full } else { &sub_short };
        if !sub.is_empty() {
            parts.push((sub.clone(), sub_style));
        }
        if hint {
            parts.push((hint_text.to_string(), hint_style));
        }
        parts
    };
    let candidates = [
        build(true, true, true),
        build(false, true, true),
        build(false, false, true),
        build(false, false, false),
    ];
    let parts_width = |parts: &[(String, Style)]| -> u16 {
        parts
            .iter()
            .map(|(t, _)| t.chars().count() as u16)
            .sum()
    };

    // ── Left side: brand prefix + visited-service chips ───────────────────
    let visible: Vec<ServiceType> = ServiceType::all()
        .iter()
        .copied()
        .filter(|s| app.visited_services.contains(s) || app.current_service == Some(*s))
        .collect();
    // Chip labels, built once so every width computation (reservation,
    // windowing, render, click regions) agrees.
    let labels: Vec<String> = visible
        .iter()
        .map(|s| s.short_name().to_string())
        .collect();
    let active_idx = visible
        .iter()
        .position(|s| app.current_service == Some(*s))
        .unwrap_or(0);

    let prefix_w: u16 = 1 + if app.banner_visible { 0 } else { 8 }; // " " + "nebaz │ "

    // Pick the widest badge set that leaves the chips enough room: every
    // chip, or, for a set without the hint and the update news (the first
    // badges to go, before any chip hides), the active chip and both
    // markers, with the chips scrolling.
    let full_chips: u16 = labels
        .iter()
        .enumerate()
        .map(|(i, l)| chip_width(l) + if i > 0 { SEP } else { 0 })
        .sum();
    let min_left = prefix_w
        + MARKER_W * 2
        + labels
            .get(active_idx)
            .map(|l| chip_width(l))
            .unwrap_or(0);
    const FIRST_WITHOUT_HINT: usize = 2;
    let right_parts = candidates
        .iter()
        .enumerate()
        .find(|(i, p)| {
            parts_width(p) + prefix_w + full_chips <= area.width
                || (*i >= FIRST_WITHOUT_HINT && parts_width(p) + min_left <= area.width)
        })
        .map(|(_, p)| p)
        .unwrap_or(&candidates[candidates.len() - 1]);
    let right_width = parts_width(right_parts);
    let left_avail = area.width.saturating_sub(right_width);

    // Window the chips into the space left of the badges.
    let (lo, hi) = if visible.is_empty() {
        (0usize, 0usize)
    } else if prefix_w + full_chips <= left_avail {
        (0, visible.len() - 1)
    } else {
        visible_window(&labels, active_idx, left_avail.saturating_sub(prefix_w))
    };
    let left_marker = lo > 0;
    let right_marker = !visible.is_empty() && hi + 1 < visible.len();

    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    if !app.banner_visible {
        spans.push(Span::styled(
            "nebaz",
            Style::default()
                .fg(theme::brand())
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(" │ ", Style::default().fg(theme::text_dim())));
    }
    let mut chip_x = area.x + prefix_w;

    // The `‹` / `›` markers switch to the service just off that edge.
    if left_marker {
        spans.push(Span::styled("‹ ", Style::default().fg(theme::text_dim())));
        app.push_click_region(
            Rect { x: chip_x, y: area.y, width: MARKER_W, height: 1 },
            ClickAction::Service(visible[lo - 1]),
        );
        chip_x += MARKER_W;
    }

    for (slot, i) in (lo..=hi).enumerate() {
        let Some(service) = visible.get(i) else { break };
        let Some(label) = labels.get(i) else { break };
        if slot > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(theme::text_dim())));
            chip_x += SEP;
        }

        let chip_w = chip_width(label);
        app.push_click_region(
            Rect {
                x: chip_x,
                y: area.y,
                width: chip_w,
                height: 1,
            },
            ClickAction::Service(*service),
        );
        chip_x += chip_w;

        let is_active = app.current_service == Some(*service);
        if is_active {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default()
                    .fg(theme::chip_fg())
                    .bg(theme::brand())
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default().fg(crate::ui::theme::text_muted()),
            ));
        }
    }

    if right_marker {
        spans.push(Span::styled(" ›", Style::default().fg(theme::text_dim())));
        app.push_click_region(
            Rect { x: chip_x, y: area.y, width: MARKER_W, height: 1 },
            ClickAction::Service(visible[hi + 1]),
        );
    }

    // ── Compose: left chips, pad, badges (always rendered) ────────────────
    let left_width = Line::from(spans.clone()).width() as u16;
    let pad = area.width.saturating_sub(left_width + right_width);
    if pad > 0 {
        spans.push(Span::raw(" ".repeat(pad as usize)));
    }
    // A badge opens what it names: the subscription badge the `P` picker,
    // the hint the `S` picker. (The endpoint badge has no key.)
    let mut badge_x = area.x + left_width + pad;
    for (text, style) in right_parts {
        let w = text.chars().count() as u16;
        let key = if text == hint_text {
            Some('S')
        } else if !sub_full.is_empty() && (*text == sub_full || *text == sub_short) {
            Some('P')
        } else {
            None
        };
        if let Some(k) = key {
            let right = (area.x + area.width).min(badge_x + w);
            if right > badge_x {
                app.push_click_region(
                    Rect { x: badge_x, y: area.y, width: right - badge_x, height: 1 },
                    ClickAction::Press(KeyCode::Char(k)),
                );
            }
        }
        badge_x += w;
        spans.push(Span::styled(text.clone(), *style));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Pick the inclusive chip range `[lo, hi]` to show when the strip overflows:
/// always include the active chip, then grow outward (right first, then left)
/// while it fits. A marker's two columns are reserved only on a side that
/// still hides a chip, so a window that reaches an edge spends that space
/// on a chip.
fn visible_window(labels: &[String], active: usize, width: u16) -> (usize, usize) {
    let n = labels.len();
    // Columns for the chips `lo..=hi`, their separators and the markers the
    // window needs.
    let cost = |lo: usize, hi: usize, chips: u16| -> u16 {
        chips + if lo > 0 { MARKER_W } else { 0 } + if hi + 1 < n { MARKER_W } else { 0 }
    };

    let mut lo = active;
    let mut hi = active;
    let mut used = chip_width(&labels[active]);

    loop {
        let mut grew = false;
        if hi + 1 < n {
            let need = used + SEP + chip_width(&labels[hi + 1]);
            if cost(lo, hi + 1, need) <= width {
                hi += 1;
                used = need;
                grew = true;
            }
        }
        if lo > 0 {
            let need = used + SEP + chip_width(&labels[lo - 1]);
            if cost(lo - 1, hi, need) <= width {
                lo -= 1;
                used = need;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_window_at_the_edge_spends_the_unused_marker_on_a_chip() {
        let l = labels(&["VNet", "ACA", "Changes", "Audit"]);
        // "‹ " + " Changes " + " │ " + " Audit " = 2 + 9 + 3 + 7 = 21: no
        // right marker is needed with Audit last.
        assert_eq!(visible_window(&l, 3, 21), (2, 3));
        assert_eq!(visible_window(&l, 3, 20), (3, 3));
        // From the left edge the same holds for the left marker.
        assert_eq!(visible_window(&l, 0, 6 + 3 + 5 + 2), (0, 1));
    }

    #[test]
    fn everything_fits_without_markers() {
        let l = labels(&["VNet", "Audit"]);
        assert_eq!(visible_window(&l, 1, 6 + 3 + 7), (0, 1));
    }
}
