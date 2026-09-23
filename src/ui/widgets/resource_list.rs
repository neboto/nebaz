// ported from neboto-tui src/ui/widgets/resource_list.rs @ d483900
use crate::app::App;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        block::{Position, Title},
        List, ListItem, Paragraph,
    },
    Frame,
};

/// The dim second column: the id when it adds to the name (for ARM rows the
/// full `/subscriptions/…` id, which the wide layout bounds to a third of the
/// pane), blank otherwise.
fn id_cell(resource: &dyn crate::azure::resource::Resource) -> String {
    if resource.id() != resource.name() {
        resource.id().to_string()
    } else {
        String::new()
    }
}

/// Floor for the name column, not a ceiling: it's what the name gets on a
/// cramped list. On a wide one the name grows into whatever the id and state
/// columns don't need — a fixed cap truncated long names (deep OU paths,
/// nested stack names) with the rest of the row sitting empty.
const NAME_MIN: usize = 40;
/// Below this the id column isn't worth rendering; it's dropped and the name
/// takes the space (the id is always in the detail pane anyway).
const MIN_ID_COL: usize = 8;
/// The id column never takes more than a `1/ID_COL_SHARE` slice of a wide
/// list. Ids that are ARNs would otherwise crowd out the name, which is the
/// column people actually read.
const ID_COL_SHARE: usize = 3;

/// Split a wide list row into `(name, id, state)` column widths.
///
/// `*_nat` are the natural (widest-content) widths over the whole filtered
/// set, `state_nat` already capped by the caller. `lead` covers any leading
/// badges. Ordering matters: the id is bounded to its share **first** so the
/// name can claim everything else, then the id is re-derived from what the
/// name actually left — otherwise a long-id service and a long-name service
/// each starve the other.
fn column_widths(
    inner_width: usize,
    lead: usize,
    name_nat: usize,
    id_nat: usize,
    state_nat: usize,
) -> (usize, usize, usize) {
    let id_w = id_nat.min((inner_width / ID_COL_SHARE).max(MIN_ID_COL));
    let gutters = 2 + lead + 2 + 2 + state_nat;
    let name_avail = inner_width.saturating_sub(gutters + id_w);
    // `NAME_MIN` is a floor the name may claim back from the id column, but it
    // can't exceed the pane: a wide badge plus a long state word can leave
    // less than 40 columns even on a "wide" list, and padding past that pushes
    // the right-aligned state off the row.
    let name_ceiling = inner_width.saturating_sub(gutters);
    let name_w = name_nat.min(name_avail.max(NAME_MIN).min(name_ceiling));

    let id_avail = inner_width.saturating_sub(2 + lead + name_w + 2 + 2 + state_nat);
    let id_w = if id_avail < MIN_ID_COL {
        0
    } else {
        id_w.min(id_avail)
    };
    (name_w, id_w, state_nat)
}

pub fn render_resource_list(app: &App, area: Rect, frame: &mut Frame) {
    // Record geometry so mouse clicks/scroll can hit-test this pane.
    app.record_list_geometry(area);

    let focused = !app.details_focused;

    let title = if app.all_search_mode {
        "All services (cached)".to_string()
    } else {
        match app.current_service {
            Some(service) => service.description().to_string(),
            None => "Resources".to_string(),
        }
    };

    // Count / progress indicator shown in the bottom-right corner of the border
    let show_loading = app.show_loading_indicator();
    let corner_text = if show_loading {
        let count = match &app.loading_progress {
            Some(progress) => match progress.total_count {
                Some(total) => format!("{}/{}", progress.loaded_count, total),
                None => format!("{}", progress.loaded_count),
            },
            None => String::new(),
        };
        // Include the per-phase message ("Loading policies…") so multi-batch
        // loads don't look stalled when watching the list instead of the
        // status bar. Truncated so it can't swallow the border.
        let phase = app
            .loading_progress
            .as_ref()
            .and_then(|p| p.status_message.as_deref())
            .map(|m| {
                let m = m.trim_end_matches(['.', '…']);
                // The corner already says "loading" — drop a redundant prefix.
                let m = m.strip_prefix("Loading ").unwrap_or(m);
                let short: String = m.chars().take(32).collect();
                if short.len() < m.len() {
                    format!(" · {short}…")
                } else {
                    format!(" · {short}")
                }
            })
            .unwrap_or_default();
        format!(
            " {} loading {}{} ",
            theme::spinner(app.tick_count),
            count,
            phase
        )
    } else {
        let hidden_note = if app.hide_noise && app.hidden_noise_count > 0 {
            format!(" ({} hidden)", app.hidden_noise_count)
        } else {
            String::new()
        };
        // Filter chip: show the active search term so it's clear the count is
        // filtered (and by what) without looking at the search bar.
        let filter_note = if !app.search_query.is_empty() {
            format!("/{} · ", app.search_query)
        } else {
            String::new()
        };
        // Sort / state-filter chips (`z` / `F`) — only when active, so the
        // corner explains any non-default ordering or a thinned-out list.
        let sort_note = app
            .list_sort
            .label()
            .map(|l| format!("z sort: {} · ", l))
            .unwrap_or_default();
        let state_note = app
            .list_state_filter
            .as_deref()
            .map(|s| format!("F state: {} · ", s))
            .unwrap_or_default();
        format!(
            " {}{}{}{} of {}{} ",
            sort_note,
            state_note,
            filter_note,
            app.filtered_resources.len(),
            app.current_view_total(),
            hidden_note
        )
    };

    let corner_style = if show_loading {
        Style::default().fg(theme::warning())
    } else {
        Style::default().fg(theme::text_dim())
    };

    let block = theme::pane_block(&title, focused).title(
        Title::from(Span::styled(corner_text, corner_style))
            .position(Position::Bottom)
            .alignment(Alignment::Right),
    );

    // Empty states: centered message with a contextual hint
    if app.filtered_resources.is_empty() {
        let (message, hint) = if show_loading {
            (
                format!("{} Loading resources…", theme::spinner(app.tick_count)),
                String::new(),
            )
        } else if app.all_search_mode {
            // @all searches warm cache entries only — an empty result set
            // needs to say whether nothing matched or nothing is cached yet.
            if app.resources.is_empty() {
                (
                    "Nothing cached to search".to_string(),
                    "@all searches services already visited this session".to_string(),
                )
            } else {
                (
                    format!("No matches for “{}”", app.search_query),
                    "searching cached services only · Esc clear".to_string(),
                )
            }
        } else if app.resources.is_empty() {
            (
                "No resources found".to_string(),
                "r refresh · R change location filter · P switch subscription".to_string(),
            )
        } else if app.search_query.is_empty() {
            // `a` is a global toggle that survives service and sub-tab
            // switches, so a tab whose rows are *all* noise reads as empty
            // long after the keypress. This has to be checked FIRST: every
            // per-tab arm below would otherwise misattribute it to a
            // permission gap the user doesn't have.
            if app.hide_noise && app.hidden_noise_count > 0 {
                (
                    format!("{} row(s) hidden by the noise filter", app.hidden_noise_count),
                    "a show all".to_string(),
                )
            }
            // A location filter that excluded everything is the likeliest
            // "empty but loaded" case in Azure — every list is
            // subscription-wide and the `R` slot thins it client-side.
            else if app.location_hidden_count > 0 && app.list_state_filter.is_none() {
                (
                    format!("No resources in {}", app.location_label()),
                    format!(
                        "{} in other locations · R change location filter",
                        app.location_hidden_count
                    ),
                )
            } else {
                // A state filter (or noise filter) thinned the view to nothing.
                let subject = app
                    .list_state_filter
                    .as_deref()
                    .map(|s| format!("No resources in state “{}”", s))
                    .unwrap_or_else(|| "No resources in view".to_string());
                (subject, "F cycle state filter · a show all".to_string())
            }
        } else {
            let hint = if app.search_query.contains("tag:") {
                "Esc clear search".to_string()
            } else {
                "Esc clear search · tag:key=value filters by tag".to_string()
            };
            (format!("No matches for “{}”", app.search_query), hint)
        };

        let inner_height = area.height.saturating_sub(2);
        let top_pad = (inner_height.saturating_sub(2) / 2) as usize;
        let mut lines = vec![Line::raw(""); top_pad];
        lines.push(Line::styled(message, Style::default().fg(crate::ui::theme::text_muted())));
        if !hint.is_empty() {
            lines.push(Line::styled(hint, Style::default().fg(theme::text_dim())));
        }

        let paragraph = Paragraph::new(lines)
            .block(block)
            .alignment(Alignment::Center);

        frame.render_widget(paragraph, area);
        return;
    }

    // Width available for text inside borders, minus the highlight symbol
    let inner_width = area.width.saturating_sub(4) as usize;
    const STATE_CAP: usize = 24;

    // Wide-terminal columns (U16): with enough width, pad names to a shared
    // column, align ids, and right-align the state word in its state color.
    // Below the threshold the compact "name  dim-id" layout stands. Column
    // widths come from the whole filtered set (not just visible rows) so the
    // layout doesn't shift while scrolling.
    const WIDE_MIN_INNER: usize = 70;
    let wide = inner_width >= WIDE_MIN_INNER;
    // @all rows lead with a 6-col service badge; budget the wide columns for it.
    let badge_w: usize = if app.all_search_mode { 6 } else { 0 };
    let pol_badge_w: usize = 0;
    let (name_col, id_col, state_col) = if wide {
        let mut name_w = 0usize;
        let mut id_w = 0usize;
        let mut state_w = 0usize;
        for &idx in &app.filtered_resources {
            let r = &app.resources[idx];
            name_w = name_w.max(r.name().chars().count());
            id_w = id_w.max(id_cell(r.as_ref()).chars().count());
            state_w = state_w.max(r.state_label().chars().count());
        }
        column_widths(
            inner_width,
            badge_w + pol_badge_w,
            name_w,
            id_w,
            state_w.min(STATE_CAP),
        )
    } else {
        (0, 0, 0)
    };

    // Pad-or-truncate to exactly `w` display chars (truncation gets an `…`).
    let fit = |s: &str, w: usize| -> String {
        let n = s.chars().count();
        if n <= w {
            format!("{}{}", s, " ".repeat(w - n))
        } else {
            let cut: String = s.chars().take(w.saturating_sub(1)).collect();
            format!("{}…", cut)
        }
    };

    // Rows inside the list visual selection (`V` / `Ctrl-A` / drag) render on
    // the selection bar style, like the detail body's visual mode; every span
    // is restyled so per-state colors can't clash with the bar.
    fn visual_item(line: Line<'_>) -> ListItem<'_> {
        let sel = theme::selection_style(true);
        let spans: Vec<Span> = line
            .spans
            .into_iter()
            .map(|s| Span::styled(s.content, sel))
            .collect();
        ListItem::new(Line::from(spans)).style(sel)
    }

    let items: Vec<ListItem> = app
        .filtered_resources
        .iter()
        .enumerate()
        .map(|(pos, &resource_idx)| {
            let in_visual = app.list_row_in_selection(pos);
            let resource = &app.resources[resource_idx];
            let (indicator, state_color) = theme::state_indicator(&resource.state());

            let name = resource.name();

            let name_style = Style::default();
            let indicator_color = state_color;

            let mut spans = vec![Span::styled(
                format!("{} ", indicator),
                Style::default().fg(indicator_color),
            )];

            // @all cross-service rows lead with their owning service so
            // results from sixty services stay tellable-apart.
            if app.all_search_mode {
                let label = app
                    .all_search_sources
                    .get(resource_idx)
                    .map(|s| s.short_name())
                    .unwrap_or("");
                spans.push(Span::styled(
                    format!("{:<6}", label),
                    Style::default().fg(theme::brand()),
                ));
            }

            if wide {
                // Columns: name │ id (dim) │ state right-aligned.
                spans.push(Span::styled(format!("{}  ", fit(name, name_col)), name_style));
                if id_col > 0 {
                    let cell = id_cell(resource.as_ref());
                    spans.push(Span::styled(
                        format!("{}  ", fit(&cell, id_col)),
                        Style::default().fg(theme::text_dim()),
                    ));
                }
                let mut state_text = resource.state_label();
                if state_text.chars().count() > STATE_CAP {
                    state_text = fit(&state_text, STATE_CAP);
                }
                let used =
                    2 + badge_w + pol_badge_w + name_col + 2 + if id_col > 0 { id_col + 2 } else { 0 };
                let right = inner_width.saturating_sub(used).max(state_col);
                spans.push(Span::styled(
                    format!("{:>right$}", state_text, right = right),
                    Style::default().fg(indicator_color),
                ));
                let line = Line::from(spans);
                return if in_visual {
                    visual_item(line)
                } else {
                    ListItem::new(line)
                };
            }

            spans.push(Span::styled(name.to_string(), name_style));

            {
                // Show the id cell dimmed after the name when it adds
                // information and there is room for at least part of it
                let cell = id_cell(resource.as_ref());
                let used = 2 + name.chars().count();
                if !cell.is_empty() && inner_width > used + 4 {
                    spans.push(Span::styled(
                        format!("  {}", cell),
                        Style::default().fg(theme::text_dim()),
                    ));
                }
            }

            let line = Line::from(spans);
            if in_visual {
                visual_item(line)
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(theme::selection_style(focused))
        .highlight_symbol(if focused { "▌ " } else { "  " })
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

    // Stateful rendering enables automatic scrolling (ListState in RefCell)
    frame.render_stateful_widget(list, area, &mut app.resource_list_state.borrow_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full-screen list must not truncate a long name at the old fixed 40
    /// columns while the rest of the row sits empty — the regression that deep
    /// OU paths ("Root/Workloads/NonProd/…") surfaced.
    #[test]
    fn wide_list_gives_long_names_the_leftover_width() {
        let (name, id, _state) = column_widths(200, 0, 120, 16, 10);
        assert_eq!(name, 120, "name should get its natural width");
        assert_eq!(id, 16, "a short id keeps its natural width");
    }

    /// ...but the id column can't grow without bound either: an ARN-shaped id
    /// must stay inside its share so the name keeps the majority.
    #[test]
    fn long_ids_are_bounded_to_their_share() {
        let (name, id, _state) = column_widths(200, 0, 120, 100, 10);
        assert_eq!(id, 200 / ID_COL_SHARE);
        assert!(name > id, "name must outweigh a bounded id column: {name} vs {id}");
    }

    /// Narrow lists keep the old behavior: the name gets NAME_MIN and the id
    /// takes what's left.
    #[test]
    fn narrow_list_holds_the_name_floor() {
        let (name, _id, _state) = column_widths(70, 0, 120, 20, 10);
        assert_eq!(name, NAME_MIN);
    }

    /// When a wide badge and a long state word leave too little for both, the
    /// id column is dropped rather than rendered as an unreadable sliver.
    #[test]
    fn id_column_drops_when_squeezed() {
        let (_name, id, _state) = column_widths(70, 10, 200, 20, 24);
        assert_eq!(id, 0);
    }

    /// The name floor must yield to the pane: 40 columns don't fit alongside a
    /// wide badge and a long state word, and padding past the pane pushes the
    /// right-aligned state off the row.
    #[test]
    fn name_floor_yields_to_a_cramped_pane() {
        let (name, id, state) = column_widths(70, 10, 200, 20, 24);
        assert!(name < NAME_MIN, "floor should have been clamped: {name}");
        assert!(2 + 10 + name + 2 + if id > 0 { id + 2 } else { 0 } + state <= 70);
    }

    /// Content narrower than the pane is padded to content width, never
    /// stretched — short names must not push the state column off-screen.
    #[test]
    fn short_content_does_not_stretch() {
        let (name, id, _state) = column_widths(200, 0, 12, 8, 10);
        assert_eq!(name, 12);
        assert_eq!(id, 8);
    }

    /// Every column plus its gutters has to fit inside the pane, or the
    /// right-aligned state word wraps.
    #[test]
    fn columns_fit_within_the_pane() {
        for inner in [70usize, 90, 120, 200, 400] {
            for lead in [0usize, 6, 10] {
                for state in [0usize, 10, 24] {
                    for (name_nat, id_nat) in [(120, 100), (12, 8), (200, 200), (40, 60)] {
                        let (name, id, state_w) =
                            column_widths(inner, lead, name_nat, id_nat, state);
                        let used =
                            2 + lead + name + 2 + if id > 0 { id + 2 } else { 0 } + state_w;
                        assert!(
                            used <= inner,
                            "inner={inner} lead={lead} state={state} \
                             name_nat={name_nat} id_nat={id_nat} → used {used}"
                        );
                    }
                }
            }
        }
    }
}
