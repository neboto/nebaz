// ported from neboto-tui src/main.rs @ d483900 (run loop and status bar; the
// per-service sub-tab routing and lens overlays are not carried over)
mod app;
mod azure;
mod bookmarks;
mod cli;
mod config;
mod editor;
mod error;
mod event;
mod export;
mod lazy;
mod macros;
mod search;
mod sections;
mod tui;
mod ui;

use app::App;
use error::Result;
use event::{handle_terminal_events, handle_tick_events, EventHandler};
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use std::time::Duration;
use tui::Tui;
use ui::layout::AppLayout;
use ui::theme;
use ui::widgets::{
    banner, details_pane, help_overlay, jump_list, location_selector, macro_picker,
    message_log, resource_list, search_bar, service_selector, service_tabs, splash,
    subscription_selector, subtab_bar,
};

fn main() -> Result<()> {
    // Parse CLI args before the runtime so `--help`/`--version` exit immediately.
    let cli = <cli::Cli as clap::Parser>::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(run(cli))
}

async fn run(cli: cli::Cli) -> Result<()> {
    let mut app = App::new(cli).await?;
    app.arm_startup_macro();

    let mut tui = Some(Tui::new()?);
    let mut event_handler = EventHandler::new();
    let mut event_tx = event_handler.sender();

    spawn_input_tasks(&event_tx);

    // Trigger initial resource load — only if a startup service is set.
    if app.current_service.is_some() && !app.macro_supersedes_startup_load() {
        app.load_service_resources();
    }
    app.spawn_subscription_info_fetch(&event_tx);
    App::trigger_locations(&mut app, &event_tx);

    while app.running {
        if app.should_load_resources() {
            app.load_resources_async(&event_tx);
        }

        // `$EDITOR` needs the TUI fully torn down so the child owns the TTY.
        if app.editor_requested {
            app.editor_requested = false;
            let saved_selected_resource_id = app.get_selected_resource_id();
            if let Some(mut current_tui) = tui.take() {
                if let Err(e) = current_tui.restore() {
                    app.error_message = Some(format!("Failed to restore terminal: {}", e));
                    tui = Some(current_tui);
                } else {
                    drop(event_handler);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    drop(current_tui);

                    if let Err(e) = app.open_in_editor() {
                        app.error_message = Some(e.to_string());
                    }

                    // Clear stdin so the editor's trailing keys don't land here.
                    use crossterm::event::{poll, read};
                    for _ in 0..10 {
                        while poll(Duration::from_millis(0)).unwrap_or(false) {
                            let _ = read();
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }

                    tui = match Tui::new() {
                        Ok(mut t) => {
                            let _ = t.terminal().clear();
                            let _ = t.terminal().hide_cursor();
                            Some(t)
                        }
                        Err(_) => break,
                    };

                    // The event channel was torn down mid-stream: a load in
                    // flight will never complete, so reset and re-serve.
                    app.loading = false;
                    app.loading_started = false;
                    app.loading_progress = None;
                    app.loading_complete = false;
                    app.watch_staging = None;
                    app.search_active = false;

                    event_handler = EventHandler::new();
                    event_tx = event_handler.sender();
                    while poll(Duration::from_millis(0)).unwrap_or(false) {
                        let _ = read();
                    }
                    spawn_input_tasks(&event_tx);

                    app.load_service_resources();
                    if let Some(id) = &saved_selected_resource_id {
                        app.restore_selection_by_id(id);
                    }
                }
            }
        }

        // Macro recording / playback, before the draw so the chips are current.
        app.macro_tick(&event_tx);

        if let Some(ref mut t) = tui {
            t.terminal().draw(|frame| render_app(&app, frame))?;
        }

        // Search filtering runs after the draw so the typed char shows first.
        app.process_pending_search();
        app.record_message_history();
        app.clear_expired_success_message();

        if let Some(event) = event_handler.next().await {
            app.handle_event(event, &event_tx).await?;
        }
    }

    if let Some(mut t) = tui {
        t.restore()?;
    }
    Ok(())
}

fn spawn_input_tasks(event_tx: &tokio::sync::mpsc::UnboundedSender<event::Event>) {
    let term_event_tx = event_tx.clone();
    tokio::spawn(async move {
        handle_terminal_events(term_event_tx).await;
    });
    let tick_event_tx = event_tx.clone();
    tokio::spawn(async move {
        handle_tick_events(tick_event_tx, Duration::from_millis(250)).await;
    });
}

/// Render one full frame — everything the main loop draws, factored out of
/// the draw closure so harness tests can render to a `TestBackend`.
fn render_app(app: &App, frame: &mut ratatui::Frame) {
    // A service with more than one sub-tab gets the sub-tab row.
    let sub_tabs = app.sub_tab_chips();
    let show_sub_tabs = !sub_tabs.is_empty();
    // Hide the top banner on the welcome splash — it has its own logo.
    let show_banner = app.banner_visible && app.current_service.is_some();
    let layout = AppLayout::new(frame.size(), show_banner, show_sub_tabs, app.layout_mode);

    if let Some(banner_area) = layout.banner_area {
        banner::render_banner(banner_area, frame);
    }
    service_tabs::render_service_tabs(app, layout.tabs_area, frame);
    search_bar::render_search_bar(app, layout.search_area, frame);
    if let Some(area) = layout.sub_tabs_area {
        subtab_bar::render_subtab_bar(app, area, frame, &sub_tabs);
    }

    if app.current_service.is_none() {
        let rl = layout.resource_list_area;
        let d = layout.details_area;
        let content = ratatui::layout::Rect {
            x: rl.x,
            y: rl.y,
            width: (d.x + d.width).saturating_sub(rl.x),
            height: rl.height,
        };
        splash::render_splash(content, frame);
    } else {
        resource_list::render_resource_list(app, layout.resource_list_area, frame);
        details_pane::render_details_pane(app, layout.details_area, frame);
    }

    render_status_bar(app, layout.status_area, frame);

    // Overlays, in stacking order.
    search_bar::render_service_completions(app, layout.search_area, frame);
    if app.help_visible {
        help_overlay::render_help_overlay(app, frame);
    }
    if app.location_selector.visible {
        location_selector::render_location_selector(
            &app.location_selector,
            &app.current_location,
            frame,
        );
    }
    if app.subscription_selector.visible {
        subscription_selector::render_subscription_selector(
            &app.subscription_selector,
            app.azure_clients.current_subscription(),
            frame,
        );
    }
    if app.service_selector.visible {
        service_selector::render_service_selector(
            &app.service_selector,
            app.current_service,
            frame,
        );
    }
    if app.jump_list_visible {
        jump_list::render_jump_list(app, frame);
    }
    if app.bookmarks_visible {
        jump_list::render_bookmarks(app, frame);
    }
    if app.message_history_visible {
        message_log::render_message_log(app, frame);
    }
    if app.macro_picker_visible {
        macro_picker::render_macro_picker(app, frame);
    }
}

/// Trim a `theme::hint_line` to `max_width` cells on a `  ·  ` boundary, so
/// a narrow terminal drops whole trailing hints instead of clipping one
/// mid-word against the location label.
fn fit_hint_line(mut line: Line<'static>, max_width: usize) -> Line<'static> {
    if line.width() <= max_width {
        return line;
    }
    let mut width = 0usize;
    let mut keep = 0usize;
    for (i, span) in line.spans.iter().enumerate() {
        if span.content == "  ·  " {
            if width <= max_width {
                keep = i;
            } else {
                break;
            }
        }
        width += span.width();
    }
    if keep > 0 {
        line.spans.truncate(keep);
    }
    line
}

fn render_status_bar(app: &App, area: ratatui::layout::Rect, frame: &mut ratatui::Frame) {
    // Left segment: transient message (error/success/loading) or contextual key hints
    let mut left_is_hints = false;
    let left: Line = if let Some(error) = &app.error_message {
        Line::from(vec![
            Span::styled(
                " ✗ ",
                Style::default()
                    .fg(theme::error())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(error.clone(), Style::default().fg(theme::error())),
        ])
    } else if let Some(progress) = &app.deep_export_progress {
        Line::from(vec![
            Span::styled(
                format!(" {} ", theme::spinner(app.tick_count)),
                Style::default().fg(theme::accent()),
            ),
            Span::styled(progress.clone(), Style::default().fg(theme::accent())),
        ])
    } else if let Some(success) = &app.success_message {
        Line::from(vec![
            Span::styled(
                " ✓ ",
                Style::default()
                    .fg(theme::success())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(success.clone(), Style::default().fg(theme::success())),
        ])
    } else if app.show_loading_indicator() {
        let service_name = app
            .current_service
            .map(|s| s.name().to_string())
            .unwrap_or_else(|| "resources".to_string());
        let detail = match &app.loading_progress {
            Some(progress) => {
                let count = match progress.total_count {
                    Some(total) => format!(" {}/{}", progress.loaded_count, total),
                    None => format!(" {}", progress.loaded_count),
                };
                match &progress.status_message {
                    Some(msg) => format!("{} — {}", count, msg),
                    None => count,
                }
            }
            None => String::new(),
        };
        Line::from(Span::styled(
            format!(
                " {} Loading {}{}…",
                theme::spinner(app.tick_count),
                service_name,
                detail
            ),
            Style::default().fg(theme::warning()),
        ))
    } else {
        left_is_hints = true;
        let mut line = if app.search_active {
            theme::hint_line(&[("⏎", "confirm"), ("Esc", "cancel"), ("@service", "switch")])
        } else if app.details_focused {
            theme::hint_line(&[
                ("j/k", "scroll"),
                ("y", "copy"),
                ("e", "editor"),
                ("r", "refresh"),
                ("Esc", "back"),
                ("?", "help"),
            ])
        } else {
            let mut hints: Vec<(&str, &str)> = vec![
                ("j/k", "move"),
                ("/", "search"),
                ("⏎", "details"),
                ("y", "copy id"),
            ];
            if app.noise_in_view {
                hints.push(("a", if app.hide_noise { "show all" } else { "hide noise" }));
            }
            hints.push(("'", "bookmarks"));
            hints.extend_from_slice(&[("?", "help"), ("q", "quit")]);
            theme::hint_line(&hints)
        };
        line.spans.insert(0, Span::raw(" "));
        line
    };

    // Right segment: recording/playback chips, watch chip, data age, location,
    // resource count — always visible.
    let mut right_spans = Vec::new();
    if let Some(rec) = &app.macro_recorder {
        right_spans.push(Span::styled(
            format!("● REC {} steps  ", rec.steps.len()),
            Style::default()
                .fg(theme::error())
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(p) = &app.macro_player {
        right_spans.push(Span::styled(
            format!(
                "▶ {} {}/{}  ",
                p.name,
                (p.index + 1).min(p.steps.len()),
                p.steps.len()
            ),
            Style::default().fg(theme::brand()),
        ));
    }
    if app.watch.enabled {
        let icon = if app.watch_refresh_active() {
            theme::spinner(app.tick_count).to_string()
        } else {
            "⟳".to_string()
        };
        right_spans.push(Span::styled(
            format!("{} watch {}s  ", icon, app.watch.interval.as_secs()),
            Style::default().fg(theme::success()),
        ));
    }
    if let Some(age) = app.current_data_age() {
        let secs = age.as_secs();
        let label = if secs >= 3600 {
            format!("⟳ {}h ago  ", secs / 3600)
        } else {
            format!("⟳ {}m ago  ", secs / 60)
        };
        right_spans.push(Span::styled(label, Style::default().fg(theme::text_dim())));
    }
    right_spans.push(Span::styled(
        app.location_label(),
        Style::default().fg(theme::brand()),
    ));
    right_spans.push(Span::styled(
        format!(
            "  {}/{} ",
            app.filtered_resources.len(),
            app.resources.len()
        ),
        Style::default().fg(theme::text_dim()),
    ));
    let right = Line::from(right_spans);

    let right_width = right.width() as u16;
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(right_width)])
        .split(area);

    let left = if left_is_hints {
        fit_hint_line(left, chunks[0].width.saturating_sub(1) as usize)
    } else {
        left
    };
    frame.render_widget(Paragraph::new(left), chunks[0]);
    frame.render_widget(Paragraph::new(right).alignment(Alignment::Right), chunks[1]);
}
