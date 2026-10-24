// ported from neboto-tui src/ui/widgets/splash.rs @ d483900
use crate::ui::theme;
use crate::ui::widgets::banner::BANNER_ART;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Dashboard-style entries: (shortcut, label). Shortcut is shown right-aligned,
/// label left-aligned, the whole block horizontally centered (LazyVim style).
const MENU: [(&str, &str); 7] = [
    ("@vm", "Load a service by prefix (try @storage, @vnet, @kv, @aks)"),
    ("S", "Open the service picker"),
    ("R", "Filter by location"),
    ("P", "Switch subscription"),
    ("/", "Search within a service"),
    ("?", "Full keybinding help"),
    ("q", "Quit"),
];

const MENU_W: u16 = 60;

/// Welcome / getting-started dashboard shown in the main content area when no
/// service is loaded yet. A centered logo over a left-aligned menu block —
/// loads nothing until the user picks a service (`@prefix` or `S`).
pub fn render_splash(area: Rect, frame: &mut Frame) {
    let logo_h = BANNER_ART.len() as u16; // 6
    let menu_h = MENU.len() as u16; // 7
    // The menu is the point of the screen; the logo, then the footer tip,
    // go first when the terminal is short (#103).
    let core_h = 1 + 1 + menu_h; // subtitle + gap + menu
    let show_logo = area.height >= logo_h + core_h + 2;
    let show_footer = area.height >= core_h + 2;
    let logo_h = if show_logo { logo_h } else { 0 };
    let total_h = logo_h + core_h + if show_footer { 2 } else { 0 };
    let top = area.y + area.height.saturating_sub(total_h) / 2;
    // Every block is clipped to the frame area, so nothing is written
    // outside the buffer however small the terminal is.
    let render = |frame: &mut Frame, widget: Paragraph, rect: Rect| {
        let rect = rect.intersection(area);
        if !rect.is_empty() {
            frame.render_widget(widget, rect);
        }
    };

    // ── Logo (centered across the full width) ──
    let logo_lines: Vec<Line> = BANNER_ART
        .iter()
        .map(|row| Line::from(Span::styled(*row, Style::default().fg(theme::brand()))))
        .collect();
    if show_logo {
        render(
            frame,
            Paragraph::new(logo_lines).alignment(Alignment::Center),
            Rect { x: area.x, y: top, width: area.width, height: logo_h },
        );
    }

    // ── Subtitle (centered) ──
    render(
        frame,
        Paragraph::new(Line::from(Span::styled(
            "Nothing loaded — pick a service to begin",
            Style::default()
                .fg(theme::text_dim())
                .add_modifier(Modifier::ITALIC),
        )))
        .alignment(Alignment::Center),
        Rect { x: area.x, y: top.saturating_add(logo_h), width: area.width, height: 1 },
    );

    // ── Menu (centered block; label left, shortcut right) ──
    let menu_x = area.x + area.width.saturating_sub(MENU_W) / 2;
    let menu_y = top.saturating_add(logo_h + 2);
    let menu_lines: Vec<Line> = MENU
        .iter()
        .map(|(key, label)| {
            let used = 2 + label.chars().count() + key.chars().count();
            let pad = (MENU_W as usize).saturating_sub(used);
            Line::from(vec![
                Span::styled(format!("  {}", label), Style::default().fg(crate::ui::theme::text_muted())),
                Span::raw(" ".repeat(pad)),
                Span::styled(
                    key.to_string(),
                    Style::default()
                        .fg(theme::brand())
                        .add_modifier(Modifier::BOLD),
                ),
            ])
        })
        .collect();
    render(
        frame,
        Paragraph::new(menu_lines).alignment(Alignment::Left),
        Rect { x: menu_x, y: menu_y, width: MENU_W, height: menu_h },
    );

    // ── Footer tip (centered) ──
    if !show_footer {
        return;
    }
    render(
        frame,
        Paragraph::new(Line::from(Span::styled(
            "Tip: set default_service in ~/.config/nebaz/config.toml to skip this screen",
            Style::default()
                .fg(theme::text_dim())
                .add_modifier(Modifier::ITALIC),
        )))
        .alignment(Alignment::Center),
        Rect { x: area.x, y: menu_y.saturating_add(menu_h + 1), width: area.width, height: 1 },
    );
}
