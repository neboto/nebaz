//! The glue for the Virtual WAN tab (#158): the section dispatch, the
//! three lazy reads per hub (its VNet connections, its route tables, its
//! routing intent) and the hooks that load a sibling list a section
//! matches in (a WAN's hubs, a VPN site's gateway connections). The rows
//! and renderers are `src/azure/services/virtual_wan.rs`.

use super::App;
use crate::azure::resource::Resource;
use crate::azure::service::JumpView;
use crate::azure::services::virtual_wan::{hub_child_path, virtual_wan_section_lines, VwanContext, VWAN_API_VERSION};
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The Virtual WAN arm of `section_lines_for`; `None` for another type.
    pub(crate) fn virtual_wan_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let id = resource.id();
        let cx = VwanContext {
            hubs: self.section_list(JumpView::VirtualHubs),
            vpn_gateways: self.section_list(JumpView::VwanVpnGateways),
            hub_connections: self.lazy.vwan_hub_connections.get(id),
            route_tables: self.lazy.vwan_route_tables.get(id),
            routing_intent: self.lazy.vwan_routing_intent.get(id),
        };
        virtual_wan_section_lines(resource, idx, &cx)
    }

    /// On-enter hook for a hub's Connections: one list per hub.
    pub fn trigger_hub_connections(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.vwan_hub_connections,
            event_tx,
            |c, id| c.list_fetch(&hub_child_path(id, "hubVirtualNetworkConnections"), VWAN_API_VERSION),
        );
    }

    /// On-enter hook for a hub's Routing: its route tables and its routing
    /// intent, one list each. Never the effective routes (a POST).
    pub fn trigger_hub_routing(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.vwan_route_tables,
            event_tx,
            |c, id| c.list_fetch(&hub_child_path(id, "hubRouteTables"), VWAN_API_VERSION),
        );
        app.trigger_selected(
            |s| &mut s.vwan_routing_intent,
            event_tx,
            |c, id| c.list_fetch(&hub_child_path(id, "routingIntent"), VWAN_API_VERSION),
        );
    }

    /// On-enter hook for a WAN's Hubs.
    pub fn trigger_vwan_hubs(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::VirtualHubs, event_tx);
    }

    /// On-enter hook for a VPN site's Connections: the VPN gateways list
    /// holds every site connection.
    pub fn trigger_vwan_vpn_gateways(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_section_list(JumpView::VwanVpnGateways, event_tx);
    }
}
