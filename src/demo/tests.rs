use super::fixtures::{Fixture, AREAS};
use super::*;

const NOW: i64 = 1_790_000_000; // 2026-09-21T14:13:20Z

static TEST_AREA: &[Fixture] = &[
    Fixture {
        path: "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachines",
        when: &["statusOnly=true"],
        status: 200,
        file: "test/vms-status.json",
        body: r#"{"value": [{"id": "status"}]}"#,
    },
    Fixture {
        path: "/subscriptions/{{prod}}/providers/Microsoft.Compute/virtualMachines",
        when: &[],
        status: 200,
        file: "test/vms.json",
        body: r#"{"value": [{"id": "/subscriptions/{{prod}}/x", "t": "{{iso:now-15m}}"}]}"#,
    },
    Fixture {
        path: "/subscriptions/*/resourceGroups/*/providers/Microsoft.KeyVault/vaults/kv-gone",
        when: &[],
        status: 404,
        file: "test/gone.json",
        body: r#"{"error": {"code": "ResourceNotFound", "message": "gone"}}"#,
    },
];

fn ask(path: &str, query: &str) -> Reply {
    respond_from(&[TEST_AREA], path, query, NOW)
}

#[test]
fn paths_match_case_insensitively_with_wildcards_and_the_first_when_wins() {
    let vms = format!("/subscriptions/{PROD}/providers/microsoft.compute/VIRTUALMACHINES");
    assert_eq!(ask(&vms, "api-version=2024-07-01").source, Source::Fixture("test/vms.json"));
    assert_eq!(
        ask(&vms, "api-version=2024-07-01&statusOnly=true").source,
        Source::Fixture("test/vms-status.json")
    );
    // Another subscription's list is not prod's.
    let dev = format!("/subscriptions/{DEV}/providers/Microsoft.Compute/virtualMachines");
    assert_eq!(ask(&dev, "").source, Source::Empty);
    let gone = format!("/subscriptions/{PROD}/resourceGroups/rg-x/providers/Microsoft.KeyVault/vaults/kv-gone");
    let r = ask(&gone, "");
    assert_eq!((r.status, r.source), (404, Source::Fixture("test/gone.json")));
}

#[test]
fn bodies_render_ids_and_relative_times() {
    let vms = format!("/subscriptions/{PROD}/providers/Microsoft.Compute/virtualMachines");
    let body = ask(&vms, "").body;
    assert!(body.contains(&format!("/subscriptions/{PROD}/x")), "{body}");
    assert!(body.contains("2026-09-21T13:58:20Z"), "{body}");
    assert_eq!(render("{{iso:now+2d}} {{iso:now}} {{iso:bogus}}", NOW), "2026-09-23T14:13:20Z 2026-09-21T14:13:20Z {{iso:bogus}}");
}

#[test]
fn unmatched_collections_are_empty_and_single_resources_404() {
    for coll in [
        "/subscriptions",
        "/subscriptions/x/resourceGroups",
        "/subscriptions/x/locations",
        "/subscriptions/x/providers/Microsoft.Web/sites",
        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app/slots",
        "/subscriptions/x/providers/Microsoft.Insights/eventtypes/management/values",
        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app/providers/Microsoft.Insights/metrics",
        "/v1.0/servicePrincipals",
        "/v1.0/applications/abc/owners",
        "/v1.0/servicePrincipals(appId='00000000-0000-0000-0000-000000000000')/owners",
    ] {
        assert!(is_collection(coll), "{coll} is a collection");
        assert_eq!(ask(coll, "").source, Source::Empty, "{coll}");
    }
    for one in [
        "/subscriptions/x",
        "/subscriptions/x/resourceGroups/rg",
        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app/config/web",
        "/v1.0/servicePrincipals/abc",
        "/v1.0/servicePrincipals(appId='00000000-0000-0000-0000-000000000000')",
    ] {
        assert!(!is_collection(one), "{one} is one resource");
        let r = ask(one, "");
        assert_eq!((r.status, r.source), (404, Source::NotFound), "{one}");
    }
}

#[test]
fn every_fixture_is_valid_json_with_its_placeholders_filled() {
    for f in AREAS.iter().flat_map(|a| a.iter()) {
        assert!(f.path.starts_with('/') && !f.path.contains('?'), "{}: path {:?}", f.file, f.path);
        let body = render(f.body, NOW);
        assert!(!body.contains("{{"), "{}: an unfilled placeholder", f.file);
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&body) {
            panic!("{}: not JSON: {e}", f.file);
        }
    }
}

#[test]
fn every_fixture_file_on_disk_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/demo/fixtures");
    let registered: std::collections::HashSet<&str> = AREAS.iter().flat_map(|a| a.iter()).map(|f| f.file).collect();
    let mut stray = Vec::new();
    for area in std::fs::read_dir(&root).unwrap().flatten().filter(|e| e.path().is_dir()) {
        for file in std::fs::read_dir(area.path()).unwrap().flatten() {
            let rel = format!("{}/{}", area.file_name().to_string_lossy(), file.file_name().to_string_lossy());
            if !registered.contains(rel.as_str()) {
                stray.push(rel);
            }
        }
    }
    assert!(stray.is_empty(), "fixture files no fx! entry serves: {stray:?}");
}

#[test]
fn the_demo_subscriptions_share_one_tenant_and_prod_is_default() {
    let subs = subscriptions();
    assert!(subs.iter().all(|s| s.tenant_id == TENANT && s.is_enabled()));
    assert_eq!(subs.iter().find(|s| s.is_default).map(|s| s.name.as_str()), Some("contoso-prod"));
}

#[tokio::test]
async fn the_transport_answers_through_the_real_pipeline() {
    use crate::azure::arm::ArmClient;
    use crate::azure::auth::CredentialSource;
    let arm = ArmClient::new(CredentialSource::Demo, TENANT, crate::azure::arm::DEFAULT_ENDPOINT).unwrap();
    // No fixture: an empty list, not an error.
    let rows = arm
        .list(&format!("/subscriptions/{PROD}/providers/Microsoft.Nope/things"), "2020-01-01")
        .await
        .unwrap();
    assert!(rows.is_empty());
    // A single resource with no fixture is ARM's 404, read as one.
    let err = arm
        .get(&format!("/subscriptions/{PROD}/resourceGroups/rg/providers/Microsoft.Nope/things/x"), "2020-01-01")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("404") && err.contains("ResourceNotFound"), "{err}");
}
