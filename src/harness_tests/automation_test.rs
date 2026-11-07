//! Automation (#202): Runbooks fires the runbooks with the job schedules
//! and jobs their lines draw on, and once the worker read lands a hybrid
//! worker's machine is a Related jump to its VM.

use super::mocks::{arm_id, Mock};
use super::*;
use crate::azure::services::automation::{AutomationAccountRow, WorkerGroups};
use crate::lazy::Lazy;
use serde_json::json;

#[tokio::test]
async fn runbooks_fire_their_three_reads_and_a_worker_jumps_to_its_vm() {
    let mut h = Harness::new().await;
    let account_id = arm_id("Microsoft.Automation/automationAccounts/aa-1");
    let vm_id = arm_id("Microsoft.Compute/virtualMachines/vm-hw");
    let account = AutomationAccountRow::from_json(
        &json!({"id": account_id, "name": "aa-1", "location": "westeurope", "properties": {"state": "Ok"}}),
        None,
    )
    .unwrap();
    h.install(Mock { view: JumpView::AutomationAccounts, label: "AutomationAccountRow", resource: Box::new(account) }).await;

    h.press(KeyCode::Enter).await;
    let at = |h: &Harness, label: &str| h.section_labels().iter().position(|l| *l == label).unwrap();
    let runbooks = at(&h, "Runbooks");
    h.press(KeyCode::Char(crate::sections::key_for(runbooks).unwrap())).await;
    for (what, lazy) in [
        ("runbooks", h.app.lazy.aa_runbooks.get(&account_id)),
        ("job schedules", h.app.lazy.aa_job_schedules.get(&account_id)),
        ("jobs", h.app.lazy.aa_jobs.get(&account_id)),
    ] {
        assert!(matches!(lazy, Some(Lazy::Loading)), "{what} fired");
    }

    let workers = WorkerGroups {
        groups: vec![(
            json!({"name": "hwg"}),
            Ok(vec![json!({"properties": {"workerName": "vm-hw", "vmResourceId": vm_id}})]),
        )],
        skipped: 0,
    };
    h.app.lazy.aa_workers.apply(account_id.clone(), Ok(workers));
    let related = at(&h, "Related");
    h.press(KeyCode::Char(crate::sections::key_for(related).unwrap())).await;
    assert!(matches!(h.app.lazy.aa_linked_workspace.get(&account_id), Some(Lazy::Loading)), "the workspace read fired");
    assert!(h.app.get_detail_lines().iter().any(|(l, v)| l == "Hybrid worker vm-hw" && *v == vm_id));
    h.cursor_to_value(&vm_id).await;
    h.press(KeyCode::Enter).await;
    assert_eq!(h.app.current_service, Some(ServiceType::VirtualMachines));
    assert_eq!(h.app.current_view, JumpView::VirtualMachines);
}
