//! The info card (`i`, `src/cards.rs`): open it for the current sub-tab,
//! move over its blocks, select and copy them, copy one of its links. A
//! modal like `?`: it owns the keys while open. The keys are the detail
//! pane's: `j`/`k` move, `V` selects, `Ctrl-A` selects all, `y` copies.

use super::App;
use crate::azure::service::JumpView;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::cell::Cell;

pub struct InfoCardState {
    pub view: JumpView,
    /// The block under the cursor (a paragraph, a bullet, a link).
    pub cursor: usize,
    /// Where `V` started a selection.
    pub anchor: Option<usize>,
    /// The first line on screen; the draw keeps the cursor in view.
    pub scroll: Cell<u16>,
}

impl InfoCardState {
    /// The selected blocks, or the cursor's alone.
    pub fn range(&self) -> (usize, usize) {
        let a = self.anchor.unwrap_or(self.cursor);
        (a.min(self.cursor), a.max(self.cursor))
    }
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
        match crate::cards::for_view(self.current_view) {
            Some(card) => {
                self.info_block_count.set(card.blocks().len());
                self.info_card =
                    Some(InfoCardState { view: self.current_view, cursor: 0, anchor: None, scroll: Cell::new(0) });
            }
            None => self.toast(format!("No info card for {} yet", self.current_view.label())),
        }
    }

    pub(super) fn handle_info_card_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let last = self.info_block_count.get().saturating_sub(1);
        let Some(state) = self.info_card.as_mut() else { return };
        let step = |c: usize, d: isize| (c as isize + d).clamp(0, last as isize) as usize;
        match key.code {
            KeyCode::Esc if state.anchor.is_some() => state.anchor = None,
            KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('q') => self.info_card = None,
            KeyCode::Down | KeyCode::Char('j') => state.cursor = step(state.cursor, 1),
            KeyCode::Up | KeyCode::Char('k') => state.cursor = step(state.cursor, -1),
            KeyCode::Char('d') if ctrl => state.cursor = step(state.cursor, 5),
            KeyCode::Char('u') if ctrl => state.cursor = step(state.cursor, -5),
            KeyCode::PageDown | KeyCode::Char(' ') => state.cursor = step(state.cursor, 5),
            KeyCode::PageUp => state.cursor = step(state.cursor, -5),
            KeyCode::Home | KeyCode::Char('g') => state.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => state.cursor = last,
            KeyCode::Char('a') if ctrl => {
                state.anchor = Some(0);
                state.cursor = last;
            }
            KeyCode::Char('V') | KeyCode::Char('v') => {
                state.anchor = if state.anchor.is_some() { None } else { Some(state.cursor) };
            }
            KeyCode::Char('y') => {
                let (lo, hi) = state.range();
                let whole = lo == 0 && hi == last;
                let what = if whole { "the card" } else if lo == hi { "the line" } else { "the selection" };
                state.anchor = None;
                let text = crate::cards::for_view(state.view).map(|c| c.text_of(lo, hi));
                if let Some(text) = text {
                    self.copy_to_clipboard(&text, what);
                }
            }
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
