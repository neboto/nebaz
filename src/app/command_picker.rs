// ported from neboto-tui src/app.rs @ 343ef65 (`copy_cli_command`, `copy_cli_row`, `handle_cli_picker_key`; adapted: no batching or role gate, a `/` filter)
//! The `C` command picker (#47) on `App`: build the rows for the selected
//! resource, copy one, and the picker's keys. The catalogue is
//! `azure::cli_actions`; the drawing is `ui::widgets::command_picker`.
//! Nothing here runs a command: a row goes to the clipboard, nowhere else.

use super::App;
use crate::azure::arm::DEFAULT_ENDPOINT;
use crate::azure::cli_actions::{actions_for, CliAction, CliTier};
use crate::ui::widgets::command_picker::CommandPickerState;
use crossterm::event::{KeyCode, KeyEvent};

impl App {
    /// `C`: the selected row's commands. One command copies straight away
    /// (what `C` always did); more open the picker on the read command.
    pub(super) fn open_command_picker(&mut self) {
        let Some(r) = self.get_selected_resource() else {
            self.error_message = Some("No resource selected".into());
            return;
        };
        let actions = actions_for(r);
        let subject = format!("{} · {}", r.name(), r.resource_type());
        match actions.len() {
            0 => self.error_message = Some("No CLI command for this resource".into()),
            1 => {
                let a = actions.into_iter().next().expect("one action");
                self.copy_cli_action(&a);
            }
            _ => {
                let caution = self.cloud_caution();
                self.command_picker = Some(CommandPickerState::new(subject, actions, caution));
            }
        }
    }

    /// A non-public ARM endpoint: the copied command runs against whatever
    /// cloud the CLI is set to, which may not be the one nebaz reads.
    fn cloud_caution(&self) -> Option<String> {
        let endpoint = self.azure_clients.endpoint().trim_end_matches('/');
        (!endpoint.eq_ignore_ascii_case(DEFAULT_ENDPOINT)).then(|| {
            format!(
                "nebaz reads {}: check `az cloud show` names that cloud before you paste",
                endpoint
            )
        })
    }

    /// Copy one command. The toast names the command chain, and says so
    /// when it changes Azure.
    fn copy_cli_action(&mut self, a: &CliAction) {
        let what = match a.tier {
            CliTier::Change => format!("`{}` (changes Azure; not run)", a.label),
            _ => format!("`{}`", a.label),
        };
        let command = a.command.clone();
        self.copy_to_clipboard(&command, &what);
    }

    pub(super) fn handle_command_picker_key(&mut self, key: KeyEvent) {
        let Some(p) = self.command_picker.as_mut() else {
            return;
        };
        let pick: Option<CliAction> = if p.filtering {
            match key.code {
                KeyCode::Esc => {
                    p.clear_filter();
                    None
                }
                KeyCode::Down => {
                    p.next();
                    None
                }
                KeyCode::Up => {
                    p.prev();
                    None
                }
                KeyCode::Backspace => {
                    p.pop_char();
                    None
                }
                KeyCode::Enter => p.selected_action().cloned(),
                KeyCode::Char(c) => {
                    p.push_char(c);
                    None
                }
                _ => None,
            }
        } else {
            match key.code {
                KeyCode::Esc if !p.query.is_empty() => {
                    p.clear_filter();
                    None
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('C') => {
                    self.command_picker = None;
                    return;
                }
                KeyCode::Char('/') => {
                    p.filtering = true;
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    p.next();
                    None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    p.prev();
                    None
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    p.first();
                    None
                }
                KeyCode::End | KeyCode::Char('G') => {
                    p.last();
                    None
                }
                KeyCode::Enter | KeyCode::Char('y') => p.selected_action().cloned(),
                KeyCode::Char(c @ '1'..='9') => p.nth(c as usize - '1' as usize).cloned(),
                _ => None,
            }
        };
        if let Some(a) = pick {
            self.command_picker = None;
            self.copy_cli_action(&a);
        }
    }
}
