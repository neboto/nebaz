//! The glue for #143's network types: the subscription's flow logs (one
//! lazy read, `SERVICES.md` rule 30) behind the VNet and NSG Flow logs
//! sections and the audit, and the section dispatch of Private Link
//! services (Edge) and Traffic Manager profiles (DNS), which read the warm
//! load balancers and private endpoints. The rows and renderers are
//! `src/azure/services/{flow_logs,private_link,traffic_manager}.rs`.

use super::App;
use crate::azure::resource::{subscription_id_of, subscription_of, Resource};
use crate::azure::service::JumpView;
use crate::azure::services::flow_logs::{fetch_flow_logs, nsg_flow_log_rows, vnet_flow_log_rows, FlowLogs};
use crate::azure::services::network::{NsgDetailSection, NsgRow, VnetDetailSection, VnetRow};
use crate::azure::services::private_link::{
    private_link_service_section_lines, PrivateLinkServiceDetailSection, PrivateLinkServiceRow,
};
use crate::azure::services::traffic_manager::{traffic_manager_section_lines, TrafficManagerDetailSection, TrafficManagerRow};
use crate::event::Event;
use crate::lazy::Lazy;
use tokio::sync::mpsc;

impl App {
    /// The loaded (or loading) flow logs of an ARM id's subscription.
    pub(crate) fn flow_logs_for(&self, id: &str) -> Option<&Lazy<FlowLogs>> {
        subscription_id_of(id).and_then(|k| self.lazy.flow_logs.get(&k))
    }

    /// A warm list of an ARM id's subscription (never a call).
    fn warm_list(&self, id: &str, view: JumpView) -> Option<&[Box<dyn Resource>]> {
        let sub = subscription_of(id)?;
        self.cache.get_ref(&view.service(), sub, Some(view.as_str()))
    }

    /// The #143 arms of `section_lines_for`: a VNet's or NSG's Flow logs
    /// section, a Private Link service, a Traffic Manager profile; `None`
    /// for anything else (a VNet's or NSG's other sections included).
    pub(crate) fn flow_log_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let any = resource.as_any();
        if let Some(r) = any.downcast_ref::<VnetRow>() {
            if VnetDetailSection::from_index(idx) == VnetDetailSection::FlowLogs {
                let nics = self.warm_list(r.id(), JumpView::Nics);
                return Some(vnet_flow_log_rows(r, self.flow_logs_for(r.id()), nics));
            }
            return None;
        }
        if let Some(r) = any.downcast_ref::<NsgRow>() {
            if NsgDetailSection::from_index(idx) == NsgDetailSection::FlowLogs {
                return Some(nsg_flow_log_rows(r, self.flow_logs_for(r.id())));
            }
            return None;
        }
        if let Some(r) = any.downcast_ref::<PrivateLinkServiceRow>() {
            return Some(private_link_service_section_lines(
                r,
                PrivateLinkServiceDetailSection::from_index(idx),
                self.warm_list(r.id(), JumpView::LoadBalancers),
                self.warm_list(r.id(), JumpView::PrivateEndpoints),
            ));
        }
        if let Some(r) = any.downcast_ref::<TrafficManagerRow>() {
            return Some(traffic_manager_section_lines(r, TrafficManagerDetailSection::from_index(idx)));
        }
        None
    }

    /// Start the flow-logs read of one subscription (`/subscriptions/{id}`)
    /// unless it is loaded or in flight: the on-enter hook and `r` in
    /// `@audit` both come here.
    pub(crate) fn trigger_flow_logs_for(&mut self, key: String, event_tx: &mpsc::UnboundedSender<Event>) {
        if self.lazy.flow_logs.contains(&key) {
            return;
        }
        let arm = self
            .azure_clients
            .arm_for_subscription(subscription_of(&key).unwrap_or_default())
            .map_err(|e| e.to_string());
        let sub = key.clone();
        self.trigger_lazy(|s| &mut s.flow_logs, key, event_tx, move || async move { fetch_flow_logs(arm?, sub).await });
    }

    /// On-enter hook for a VNet's or NSG's Flow logs: the selected row's
    /// subscription's flow logs, once per subscription per session.
    pub fn trigger_flow_logs(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        let Some(key) = app.get_selected_resource_id().and_then(|id| subscription_id_of(&id)) else {
            return;
        };
        app.trigger_flow_logs_for(key, event_tx);
    }
}
