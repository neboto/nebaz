//! The network access lens (`N`, #50) on `App`: what it starts from, the
//! warm rows it reuses, the one fetch task, and its keys. The evaluation is
//! `azure::nsg_eval`; the drawing is `ui::widgets::network_lens`.

use super::{App, LayoutMode, PAGE_STEP};
use crate::azure::nsg_eval::{resolve, Known, Seed};
use crate::azure::resource::Resource;
use crate::azure::service::{JumpView, ServiceType};
use crate::azure::services::compute::NicRow;
use crate::azure::services::network::{NsgRow, SubnetRow, VnetRow, NETWORK_API_VERSION};
use crate::event::Event;
use crate::lazy::LazyApply;
use crate::ui::widgets::network_lens::NetworkLensState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

/// What the lens starts from for a row: an NSG itself, a NIC, a subnet;
/// for anything else the NICs its Related section lists (a VM, a private
/// endpoint), else the subnets it lists (an AKS node pool, an app's VNet
/// integration, a Power Platform policy, a VNet's every subnet).
pub fn lens_seed(r: &dyn Resource) -> Seed {
    let any = r.as_any();
    if any.downcast_ref::<NsgRow>().is_some() {
        return Seed { nsg: Some(r.id().to_string()), ..Default::default() };
    }
    if any.downcast_ref::<NicRow>().is_some() {
        return Seed { nics: vec![r.id().to_string()], ..Default::default() };
    }
    if any.downcast_ref::<SubnetRow>().is_some() {
        return Seed { subnets: vec![r.id().to_string()], ..Default::default() };
    }
    // An application gateway's own subnet is what its NSG guards (the
    // GatewayManager ports); its backend NICs are the backends' business.
    if let Some(g) = any.downcast_ref::<crate::azure::services::edge::AppGatewayRow>() {
        return Seed { subnets: g.subnet_ids.clone(), ..Default::default() };
    }
    let mut seed = Seed::default();
    for (_, id) in r.related() {
        let list = match JumpView::for_arm_id(&id) {
            Some(JumpView::Nics) => &mut seed.nics,
            Some(JumpView::Subnets) => &mut seed.subnets,
            _ => continue,
        };
        if !list.iter().any(|x| x.eq_ignore_ascii_case(&id)) {
            list.push(id);
        }
    }
    // A NIC brings its own subnet; listing both would show it twice.
    if !seed.nics.is_empty() {
        seed.subnets.clear();
    }
    seed
}

impl App {
    /// Whether `N` has anything to show for the selected row.
    pub fn supports_network_lens(&self) -> bool {
        self.get_selected_resource().is_some_and(|r| !lens_seed(r).is_empty())
    }

    pub(super) fn open_network_lens(&mut self, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(r) = self.get_selected_resource() else {
            self.error_message = Some("No resource selected".into());
            return;
        };
        let seed = lens_seed(r);
        if seed.is_empty() {
            self.error_message = Some(format!("No NIC, subnet or NSG on this {}", r.resource_type()));
            return;
        }
        let title = format!("{} · {}", r.resource_type(), r.name());
        // The direction toggle is sticky across opens.
        let direction = self.network_lens.as_ref().map(|s| s.direction).unwrap_or_default();
        self.refs_lens = None;
        self.network_lens = Some(NetworkLensState::open(title, seed.clone(), direction));
        self.details_focused = true;
        let known = self.lens_known();
        self.fetch_network_lens(seed, known, event_tx);
    }

    /// NICs, subnets and NSGs already loaded: the warm NICs, VNets,
    /// Subnets and NSGs lists of the current subscription, and the
    /// on-screen list.
    fn lens_known(&self) -> Known {
        let mut known = Known::default();
        let mut take = |r: &dyn Resource| {
            let any = r.as_any();
            if let Some(n) = any.downcast_ref::<NicRow>() {
                known.add_nic(n);
            } else if let Some(s) = any.downcast_ref::<SubnetRow>() {
                known.add_subnet(s);
            } else if let Some(v) = any.downcast_ref::<VnetRow>() {
                for s in &v.subnets {
                    known.add_subnet(s);
                }
            } else if let Some(g) = any.downcast_ref::<NsgRow>() {
                known.add_nsg(g);
            }
        };
        let sub = self.subscription_key();
        for (service, view) in [
            (ServiceType::VirtualMachines, JumpView::Nics),
            (ServiceType::Network, JumpView::VirtualNetworks),
            (ServiceType::Network, JumpView::Subnets),
            (ServiceType::Network, JumpView::NetworkSecurityGroups),
        ] {
            if let Some(list) = self.cache.get_ref(&service, &sub, Some(view.as_str())) {
                for r in list {
                    take(r.as_ref());
                }
            }
        }
        for r in &self.resources {
            take(r.as_ref());
        }
        known
    }

    /// One task: resolve the seed (warm rows first, a GET each for the
    /// rest) and deliver through the apply-closure event, stamped with the
    /// lazy epoch (a subscription switch drops it) and the lens generation
    /// (a reopen or `r` supersedes it).
    fn fetch_network_lens(&mut self, seed: Seed, known: Known, event_tx: &mpsc::UnboundedSender<Event>) {
        self.network_lens_generation += 1;
        let generation = self.network_lens_generation;
        let arm = match seed.any_id().map(|id| self.azure_clients.arm_for_path(id)) {
            Some(Ok(arm)) => arm,
            other => {
                if let Some(st) = self.network_lens.as_mut() {
                    st.loading = false;
                    st.error = Some(match other {
                        Some(Err(e)) => e,
                        _ => "nothing to read".into(),
                    });
                }
                return;
            }
        };
        let epoch = self.lazy.epoch();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let fetch = move |path: String| {
                let arm = arm.clone();
                async move { arm.get(&path, NETWORK_API_VERSION).await.map_err(|e| e.to_string()) }
            };
            let resolved = resolve(seed, known, fetch).await;
            let apply: Box<dyn FnOnce(&mut App) + Send> = Box::new(move |app: &mut App| {
                if app.network_lens_generation != generation {
                    return;
                }
                if let Some(st) = app.network_lens.as_mut() {
                    st.set_resolved(resolved);
                }
            });
            let _ = tx.send(Event::Lazy(LazyApply { epoch, apply }));
        });
    }

    fn close_network_lens(&mut self) {
        self.network_lens = None;
        if self.layout_mode == LayoutMode::DetailsOnly {
            self.layout_mode = LayoutMode::Split;
        }
    }

    /// Keys while the lens owns the detail pane.
    pub(super) fn handle_network_lens_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(st) = self.network_lens.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('N') | KeyCode::Char('h') | KeyCode::Left => {
                self.close_network_lens()
            }
            KeyCode::Char('j') | KeyCode::Down => st.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => st.move_by(-1),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => st.move_by(PAGE_STEP as isize),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => st.move_by(-(PAGE_STEP as isize)),
            KeyCode::PageDown => st.move_by(2 * PAGE_STEP as isize),
            KeyCode::PageUp => st.move_by(-2 * (PAGE_STEP as isize)),
            KeyCode::Char('g') | KeyCode::Home => st.goto_top(),
            KeyCode::Char('G') | KeyCode::End => st.goto_bottom(),
            KeyCode::Char('t') => st.cycle_direction(),
            // Refetch everything: rules may have changed since the cache.
            KeyCode::Char('r') => {
                let seed = st.seed.clone();
                st.loading = true;
                st.error = None;
                self.fetch_network_lens(seed, Known::default(), event_tx);
            }
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => self.redraw_requested = true,
            // Go to the line's NSG (or subnet / NIC); Ctrl-O comes back.
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if let Some(id) = st.selected_line().and_then(|l| l.jump.clone()) {
                    self.close_network_lens();
                    self.jump_to_arm_id(&id, event_tx);
                }
            }
            KeyCode::Char('e') => self.editor_requested = true,
            KeyCode::Char('y') => {
                if let Some(text) = st.selected_line().map(|l| l.copy_text()) {
                    self.copy_to_clipboard(&text, "rule");
                }
            }
            KeyCode::Char('Z') => {
                self.layout_mode = match self.layout_mode {
                    LayoutMode::DetailsOnly => LayoutMode::Split,
                    _ => LayoutMode::DetailsOnly,
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg/providers";

    #[test]
    fn the_seed_follows_nics_first_then_subnets() {
        let vm = crate::azure::services::compute::VmRow::from_json(
            &serde_json::json!({
                "id": format!("{}/Microsoft.Compute/virtualMachines/vm-1", RG), "name": "vm-1", "location": "westeurope",
                "properties": {"networkProfile": {"networkInterfaces": [
                    {"id": format!("{}/Microsoft.Network/networkInterfaces/vm-1-nic", RG), "properties": {"primary": true}}
                ]}}
            }),
            None,
        )
        .unwrap();
        let seed = lens_seed(&vm);
        assert_eq!(seed.nics, vec![format!("{}/Microsoft.Network/networkInterfaces/vm-1-nic", RG)]);
        assert!(seed.subnets.is_empty() && seed.nsg.is_none());

        let nsg = NsgRow::from_json(
            &serde_json::json!({"id": format!("{}/Microsoft.Network/networkSecurityGroups/g", RG), "name": "g", "location": "x"}),
            None,
        )
        .unwrap();
        assert_eq!(lens_seed(&nsg).nsg.as_deref(), Some(nsg.base.id.as_str()));

        let vnet = VnetRow::from_json(
            &serde_json::json!({"id": format!("{}/Microsoft.Network/virtualNetworks/v", RG), "name": "v", "location": "x",
                "properties": {"subnets": [{"id": format!("{}/Microsoft.Network/virtualNetworks/v/subnets/a", RG), "name": "a"}]}}),
            None,
        )
        .unwrap();
        assert_eq!(lens_seed(&vnet.subnets[0]).subnets.len(), 1);
        assert_eq!(lens_seed(&vnet).subnets.len(), 1);

        // An application gateway seeds on its own subnet, not its backend NICs.
        let agw = crate::azure::services::edge::AppGatewayRow::from_json(
            &serde_json::json!({"id": format!("{}/Microsoft.Network/applicationGateways/agw", RG), "name": "agw", "location": "x",
                "properties": {
                    "gatewayIPConfigurations": [{"name": "gw", "properties": {"subnet": {"id": format!("{}/Microsoft.Network/virtualNetworks/v/subnets/agw", RG)}}}],
                    "backendAddressPools": [{"name": "p", "properties": {"backendIPConfigurations": [
                        {"id": format!("{}/Microsoft.Network/networkInterfaces/nic-1/ipConfigurations/ipconfig1", RG)}]}}]}}),
            None,
        )
        .unwrap();
        let seed = lens_seed(&agw);
        assert_eq!(seed.subnets, vec![format!("{}/Microsoft.Network/virtualNetworks/v/subnets/agw", RG)]);
        assert!(seed.nics.is_empty());
    }
}
