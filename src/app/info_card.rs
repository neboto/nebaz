//! The info card (`i`, `src/cards.rs`): open it for the current sub-tab,
//! scroll it, copy one of its links. A modal like `?`: it owns the keys
//! while open.

use super::App;
use crate::azure::service::JumpView;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub struct InfoCardState {
    pub view: JumpView,
    pub scroll: u16,
}

impl App {
    /// Gate for `i`: the current sub-tab has a card.
    pub fn supports_info_card(&self) -> bool {
        self.current_service.is_some_and(|s| !s.is_virtual()) && crate::cards::for_view(self.current_view).is_some()
    }

    pub(super) fn open_info_card(&mut self) {
        if self.current_service.is_none() {
            return;
        }
        if crate::cards::for_view(self.current_view).is_some() {
            self.info_card = Some(InfoCardState { view: self.current_view, scroll: 0 });
        } else {
            self.toast(format!("No info card for {} yet", self.current_view.label()));
        }
    }

    pub(super) fn handle_info_card_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let max = self.info_max_scroll.get();
        let Some(state) = self.info_card.as_mut() else { return };
        match key.code {
            KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('q') => self.info_card = None,
            KeyCode::Down | KeyCode::Char('j') => state.scroll = (state.scroll + 1).min(max),
            KeyCode::Up | KeyCode::Char('k') => state.scroll = state.scroll.saturating_sub(1),
            KeyCode::Char('d') if ctrl => state.scroll = (state.scroll + 10).min(max),
            KeyCode::Char('u') if ctrl => state.scroll = state.scroll.saturating_sub(10),
            KeyCode::PageDown | KeyCode::Char(' ') => state.scroll = (state.scroll + 10).min(max),
            KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(10),
            KeyCode::Home | KeyCode::Char('g') => state.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => state.scroll = max,
            KeyCode::Char(c @ '1'..='9') => {
                let n = c.to_digit(10).unwrap_or(0) as usize;
                let url = crate::cards::for_view(state.view).and_then(|card| card.link(n));
                match url {
                    Some(url) => self.copy_to_clipboard(&url, "the link"),
                    None => self.toast(format!("No link {}", n)),
                }
            }
            _ => {}
        }
    }
}
