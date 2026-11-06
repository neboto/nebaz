//! Azure Compute Gallery (#203, SERVICES.md rule 41): the Virtual
//! Machines tab's Galleries sub-tab, one subscription-wide list of
//! `Microsoft.Compute/galleries`. A gallery's image definitions and each
//! one's versions are per-gallery lists, so they are one lazy section,
//! **Images**: the definitions (`{gallery}/images`), then the versions of
//! each (`{image}/versions`, the first [`MAX_IMAGES`] images), read in one
//! fetch. A VM or scale set built from a gallery image names the gallery
//! in its Related; the gallery's Related names the warm VMs and scale sets
//! built from it.

use crate::azure::arm::ArmClient;
use crate::azure::resource::{name_of_id, scope_related, shell_quote, state_ladder, Resource, ResourceState};
use crate::azure::services::directory::iso_to_unix;
use crate::azure::services::{arm_row, error_rows, json, overview_rows, related_rows_with, tag_rows, ArmBase};
use serde_json::Value;
use std::sync::Arc;

/// Months old and the version every region serves (azure-rest-api-specs
/// `Compute/stable/2025-03-03`, checked 2026-11-07; 2026-03-03 landed in
/// September).
pub const GALLERY_API_VERSION: &str = "2025-03-03";
pub const GALLERIES_PATH: &str = "/providers/Microsoft.Compute/galleries";

/// Images whose versions one Images read lists; past it the section says
/// how many were left out.
pub const MAX_IMAGES: usize = 25;

crate::sections! {
    pub enum GalleryDetailSection,
    pub static GALLERY_SECTIONS = [
        Overview "Overview",
        Images "Images" => crate::app::App::trigger_gallery_images,
        Sharing "Sharing",
        Access "Access" => crate::app::App::trigger_access,
        Activity "Activity" => crate::app::App::trigger_activity,
        Related "Related",
        Tags "Tags",
    ]
}

#[derive(Debug, Clone)]
pub struct GalleryRow {
    pub base: ArmBase,
    pub description: Option<String>,
    pub unique_name: Option<String>,
    /// `Private`, `Groups` or `Community`.
    pub sharing: Option<String>,
    pub community_public_names: Vec<String>,
    pub community_eula: Option<String>,
    pub soft_delete: Option<bool>,
    pub identity_type: Option<String>,
}

impl GalleryRow {
    pub fn from_json(v: &Value, tenant: Option<&str>) -> Option<GalleryRow> {
        let mut base = ArmBase::from_json(v, tenant)?;
        // The list can return a display-name location (`West US`).
        base.location = base.location.replace(' ', "");
        let p = |f: &str| format!("/properties/{}", f);
        Some(GalleryRow {
            description: json::str_at(v, &p("description")).filter(|d| !d.is_empty()),
            unique_name: json::str_at(v, &p("identifier/uniqueName")),
            sharing: json::str_at(v, &p("sharingProfile/permissions")),
            community_public_names: json::strings_at(v, &p("sharingProfile/communityGalleryInfo/publicNames")),
            community_eula: json::str_at(v, &p("sharingProfile/communityGalleryInfo/eula")),
            soft_delete: json::bool_at(v, &p("softDeletePolicy/isSoftDeleteEnabled")),
            identity_type: json::str_at(v, "/identity/type"),
            base,
        })
    }

    fn sharing_rows(&self) -> Vec<(String, String)> {
        let mut lines = vec![(
            "Sharing".into(),
            match self.sharing.as_deref() {
                None | Some("Private") => "private (RBAC on the gallery)".into(),
                Some("Groups") => "direct shared with subscriptions or tenants".into(),
                Some("Community") => "⚠ community: every Azure user can use its images".into(),
                Some(other) => other.to_string(),
            },
        )];
        if !self.community_public_names.is_empty() {
            lines.push(("Public names".into(), json::join(&self.community_public_names)));
        }
        if let Some(eula) = &self.community_eula {
            lines.push(("EULA".into(), eula.clone()));
        }
        lines.push(("Soft delete".into(), json::yes_no(self.soft_delete)));
        lines.push(("Identity".into(), json::opt(self.identity_type.clone())));
        lines
    }
}

impl Resource for GalleryRow {
    arm_row!("Compute Gallery");
    fn state(&self) -> ResourceState {
        state_ladder(self.base.provisioning_state.as_deref(), None).0
    }
    fn state_label(&self) -> String {
        state_ladder(self.base.provisioning_state.as_deref(), None).1
    }
    fn detail_sections(&self) -> Option<&'static crate::sections::SectionDescriptor> {
        Some(&GALLERY_SECTIONS)
    }
    fn list_summary(&self) -> Option<String> {
        self.sharing.as_deref().filter(|s| *s != "Private").map(str::to_lowercase)
    }
    fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Name".into(), self.base.name.clone()),
            ("Id".into(), self.base.id.clone()),
            ("Location".into(), self.base.location.clone()),
            ("Resource group".into(), self.resource_group().unwrap_or("-").to_string()),
            ("Provisioning state".into(), json::opt(self.base.provisioning_state.clone())),
            ("Description".into(), json::opt(self.description.clone())),
            ("Unique name".into(), json::opt(self.unique_name.clone())),
        ]
    }
    fn related(&self) -> Vec<(String, String)> {
        scope_related(&self.base.id)
    }
    fn cli_command(&self) -> Option<String> {
        Some(format!("az sig show --ids {}", shell_quote(&self.base.id)))
    }
}

// ── Images and versions ───────────────────────────────────────────────

/// One Images read: each definition with its versions (or the error that
/// listing them returned), and how many definitions were not expanded.
#[derive(Debug, Clone, Default)]
pub struct GalleryImages {
    pub images: Vec<(Value, std::result::Result<Vec<Value>, String>)>,
    pub skipped: usize,
}

/// `{gallery}/images`, then `{image}/versions` for the first
/// [`MAX_IMAGES`]. A failed versions list stays on its image.
pub async fn fetch_gallery_images(
    arm: std::result::Result<Arc<ArmClient>, String>,
    gallery_id: String,
) -> std::result::Result<GalleryImages, String> {
    let arm = arm?;
    let images = arm
        .list(&format!("{}/images", gallery_id.trim_end_matches('/')), GALLERY_API_VERSION)
        .await
        .map_err(|e| e.to_string())?;
    let mut out = GalleryImages { skipped: images.len().saturating_sub(MAX_IMAGES), ..Default::default() };
    for (i, image) in images.into_iter().enumerate() {
        if i >= MAX_IMAGES {
            break;
        }
        let path = format!("{}/images/{}/versions", gallery_id.trim_end_matches('/'), json::text(&image, "/name"));
        let versions = arm.list(&path, GALLERY_API_VERSION).await.map_err(|e| e.to_string());
        out.images.push((image, versions));
    }
    Ok(out)
}

/// `true` when an ISO date is before `now` (Unix seconds).
fn is_past(date: &str, now: i64) -> bool {
    iso_to_unix(date).is_some_and(|t| t < now)
}

fn version_rows(v: &Value, now: i64) -> Vec<(String, String)> {
    let p = |f: &str| format!("/properties/{}", f);
    let pp = |f: &str| p(&format!("publishingProfile/{}", f));
    let regions: Vec<String> = json::arr(v, &pp("targetRegions"))
        .iter()
        .map(|r| {
            let n = json::int_at(r, "/regionalReplicaCount").map(|n| format!(" ×{}", n)).unwrap_or_default();
            format!("{}{}", json::text(r, "/name").replace(' ', "").to_lowercase(), n)
        })
        .collect();
    let mut head = vec![format!("published {}", json::time(json::str_at(v, &pp("publishedDate"))))];
    if let Some(eol) = json::str_at(v, &pp("endOfLifeDate")) {
        if is_past(&eol, now) {
            head.push(format!("⚠ end of life {}", json::time(Some(eol))));
        } else {
            head.push(format!("end of life {}", json::time(Some(eol))));
        }
    }
    if json::bool_at(v, &pp("excludeFromLatest")) == Some(true) {
        head.push("excluded from latest".into());
    }
    let mut lines = vec![
        (format!("  Version {}", json::text(v, "/name")), head.join(" · ")),
        ("    Regions".into(), json::join(&regions)),
    ];
    if let Some(st) = json::str_at(v, &pp("storageAccountType")) {
        lines.push(("    Storage".into(), st));
    }
    if let Some(ps) = json::str_at(v, &p("provisioningState")).filter(|s| !s.eq_ignore_ascii_case("succeeded")) {
        lines.push(("    Provisioning".into(), format!("⚠ {}", ps.to_lowercase())));
    }
    if json::bool_at(v, &p("safetyProfile/reportedForPolicyViolation")) == Some(true) {
        lines.push(("    Policy".into(), "⚠ reported for a policy violation".into()));
    }
    lines
}

fn image_rows(image: &Value, versions: &std::result::Result<Vec<Value>, String>, now: i64) -> Vec<(String, String)> {
    let p = |f: &str| format!("/properties/{}", f);
    let mut os = vec![json::text(image, &p("osType")), json::text(image, &p("osState")).to_lowercase()];
    if let Some(g) = json::str_at(image, &p("hyperVGeneration")) {
        os.push(format!("gen {}", g.trim_start_matches('V')));
    }
    if let Some(a) = json::str_at(image, &p("architecture")) {
        os.push(a);
    }
    let security = json::arr(image, &p("features"))
        .iter()
        .find(|f| json::str_at(f, "/name").as_deref() == Some("SecurityType"))
        .and_then(|f| json::str_at(f, "/value"));
    if let Some(s) = security {
        os.push(s);
    }
    let mut lines = vec![
        (String::new(), String::new()),
        (json::text(image, "/name"), os.join(" · ")),
        (
            "  Identifier".into(),
            format!(
                "{}:{}:{}",
                json::text(image, &p("identifier/publisher")),
                json::text(image, &p("identifier/offer")),
                json::text(image, &p("identifier/sku"))
            ),
        ),
    ];
    if let Some(eol) = json::str_at(image, &p("endOfLifeDate")) {
        let warn = if is_past(&eol, now) { "⚠ " } else { "" };
        lines.push(("  End of life".into(), format!("{}{}", warn, json::time(Some(eol)))));
    }
    match versions {
        Err(e) => lines.extend(error_rows(e).into_iter().map(|(k, v)| (format!("  {}", k), v))),
        Ok(vs) if vs.is_empty() => lines.push(("  Versions".into(), "none".into())),
        Ok(vs) => {
            // Newest first: published date, then the name.
            let mut vs: Vec<&Value> = vs.iter().collect();
            vs.sort_by_key(|v| {
                std::cmp::Reverse((
                    json::str_at(v, "/properties/publishingProfile/publishedDate"),
                    json::str_at(v, "/name"),
                ))
            });
            for v in vs {
                lines.extend(version_rows(v, now));
            }
        }
    }
    lines
}

/// The Images section: each definition, then its versions newest first.
/// `now` is Unix seconds, for the end-of-life marks.
pub fn images_rows(r: &GalleryRow, images: Option<&crate::lazy::Lazy<GalleryImages>>, now: i64) -> Vec<(String, String)> {
    use crate::lazy::Lazy;
    let loaded = match images {
        None | Some(Lazy::Loading) => return vec![("Images".into(), "Loading…".into())],
        Some(Lazy::Error(e)) => return error_rows(e),
        Some(Lazy::Loaded(l)) => l,
    };
    let mut lines = Vec::new();
    if loaded.images.is_empty() {
        lines.push((String::new(), "No image definitions".into()));
    }
    for (image, versions) in &loaded.images {
        lines.extend(image_rows(image, versions, now));
    }
    if loaded.skipped > 0 {
        lines.push((String::new(), String::new()));
        lines.push((String::new(), format!("{} more definitions not expanded (the first {} are)", loaded.skipped, MAX_IMAGES)));
    }
    lines.push((String::new(), String::new()));
    lines.push((
        "Read command".into(),
        format!(
            "az sig image-definition list --gallery-name {} -g {}",
            shell_quote(&r.base.name),
            shell_quote(r.resource_group().unwrap_or("-"))
        ),
    ));
    lines
}

// ── The VM side ───────────────────────────────────────────────────────

/// The gallery an image reference id is under (an image definition or a
/// version): `…/galleries/{g}`. `None` for a managed image or a
/// marketplace image.
pub fn gallery_of_image(image_id: &str) -> Option<String> {
    let lower = image_id.to_lowercase();
    let at = lower.find("/galleries/")? + "/galleries/".len();
    let end = image_id[at..].find('/').map(|i| at + i).unwrap_or(image_id.len());
    Some(image_id[..end].to_string())
}

/// A VM's or scale set's Related line for its image id: the gallery
/// (which lists the definition and versions), or the managed image.
pub fn image_related(image_id: &str) -> Vec<(String, String)> {
    match gallery_of_image(image_id) {
        Some(g) => {
            let parts: Vec<&str> = image_id.split('/').collect();
            let after = |key: &str| {
                parts
                    .iter()
                    .position(|p| p.eq_ignore_ascii_case(key))
                    .and_then(|i| parts.get(i + 1))
                    .copied()
            };
            let image = after("images").unwrap_or("-");
            let version = after("versions").map(|v| format!(" {}", v)).unwrap_or_default();
            vec![(format!("Gallery {} · image {}{}", name_of_id(&g), image, version), g)]
        }
        None => vec![(format!("Image {}", name_of_id(image_id)), image_id.to_string())],
    }
}

/// Body lines for one section of a gallery; `None` for another type.
/// `built` is the warm VMs and scale sets whose image is in this gallery.
pub fn gallery_section_lines(
    r: &dyn Resource,
    idx: usize,
    images: Option<&crate::lazy::Lazy<GalleryImages>>,
    built: Vec<(String, String)>,
    now: i64,
) -> Option<Vec<(String, String)>> {
    let x = r.as_any().downcast_ref::<GalleryRow>()?;
    use GalleryDetailSection as S;
    Some(match S::from_index(idx) {
        S::Overview => overview_rows(x),
        S::Images => images_rows(x, images, now),
        S::Sharing => x.sharing_rows(),
        S::Access | S::Activity => crate::azure::services::rendered_by_app(),
        S::Related => related_rows_with(x, built),
        S::Tags => tag_rows(x.tags()),
    })
}

pub fn rows(page: &[Value], tenant: Option<&str>) -> Vec<GalleryRow> {
    page.iter().filter_map(|v| GalleryRow::from_json(v, tenant)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lazy::Lazy;
    use serde_json::json;

    const RG: &str = "/subscriptions/0000/resourceGroups/rg-img";

    fn gallery_id() -> String {
        format!("{}/providers/Microsoft.Compute/galleries/gal_prod", RG)
    }

    fn gallery(sharing: &str) -> GalleryRow {
        GalleryRow::from_json(
            &json!({"id": gallery_id(), "name": "gal_prod", "location": "West Europe",
                "properties": {"provisioningState": "Succeeded", "description": "",
                    "identifier": {"uniqueName": "0000-GAL_PROD"},
                    "sharingProfile": {"permissions": sharing},
                    "softDeletePolicy": {"isSoftDeleteEnabled": true}}}),
            None,
        )
        .unwrap()
    }

    fn version(name: &str, published: &str, eol: Option<&str>) -> Value {
        let mut v = json!({"name": name, "properties": {"provisioningState": "Succeeded", "publishingProfile": {
            "publishedDate": published, "storageAccountType": "Standard_ZRS",
            "targetRegions": [{"name": "West Europe", "regionalReplicaCount": 2}, {"name": "North Europe", "regionalReplicaCount": 1}]}}});
        if let Some(e) = eol {
            v["properties"]["publishingProfile"]["endOfLifeDate"] = json!(e);
        }
        v
    }

    fn image() -> Value {
        json!({"name": "ubuntu-hardened", "properties": {"osType": "Linux", "osState": "Generalized", "hyperVGeneration": "V2",
            "architecture": "x64", "features": [{"name": "SecurityType", "value": "TrustedLaunch"}],
            "identifier": {"publisher": "contoso", "offer": "ubuntu", "sku": "24_04-hardened"}}})
    }

    #[test]
    fn section_labels_put_overview_first_related_second_to_last_tags_last() {
        let labels: Vec<&str> = GALLERY_SECTIONS.sections.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Overview", "Images", "Sharing", "Access", "Activity", "Related", "Tags"]);
    }

    #[test]
    fn a_gallery_reads_its_sharing_and_location() {
        let g = gallery("Private");
        assert_eq!(g.base.location, "westeurope");
        assert_eq!(g.list_summary(), None, "private is the default, no summary");
        assert_eq!(g.cli_command(), Some(format!("az sig show --ids {}", gallery_id())));
        let community = gallery("Community");
        assert_eq!(community.list_summary().as_deref(), Some("community"));
        assert!(community.sharing_rows()[0].1.starts_with("⚠ community"));
    }

    #[test]
    fn images_list_versions_newest_first_and_flag_end_of_life() {
        let g = gallery("Private");
        let loaded = GalleryImages {
            images: vec![
                (image(), Ok(vec![
                    version("1.0.0", "2026-01-10T00:00:00Z", Some("2026-06-30T00:00:00Z")),
                    version("1.1.0", "2026-05-02T00:00:00Z", Some("2027-05-01T00:00:00Z")),
                ])),
                (json!({"name": "win-base", "properties": {"osType": "Windows", "osState": "Generalized"}}), Err("403 AuthorizationFailed".into())),
            ],
            skipped: 3,
        };
        let now = iso_to_unix("2026-11-07T00:00:00Z").unwrap();
        let lines = images_rows(&g, Some(&Lazy::Loaded(loaded)), now);
        assert!(lines.iter().any(|(k, v)| k == "ubuntu-hardened" && v == "Linux · generalized · gen 2 · x64 · TrustedLaunch"));
        assert!(lines.iter().any(|(k, v)| k == "  Identifier" && v == "contoso:ubuntu:24_04-hardened"));
        let versions: Vec<&str> = lines.iter().filter(|(k, _)| k.starts_with("  Version")).map(|(k, _)| k.as_str()).collect();
        assert_eq!(versions, ["  Version 1.1.0", "  Version 1.0.0"]);
        let old = lines.iter().find(|(k, _)| k == "  Version 1.0.0").unwrap();
        assert!(old.1.contains("⚠ end of life 2026-06-30"), "{}", old.1);
        let new = lines.iter().find(|(k, _)| k == "  Version 1.1.0").unwrap();
        assert!(!new.1.contains('⚠'));
        assert!(lines.iter().any(|(k, v)| k == "    Regions" && v == "westeurope ×2, northeurope ×1"));
        assert!(lines.iter().any(|(_, v)| v.contains("403")), "a failed versions list stays on its image");
        assert!(lines.iter().any(|(_, v)| v == "3 more definitions not expanded (the first 25 are)"));
        assert_eq!(lines.last().unwrap().1, "az sig image-definition list --gallery-name gal_prod -g rg-img");
    }

    #[test]
    fn an_image_reference_names_its_gallery() {
        let version_id = format!("{}/images/ubuntu-hardened/versions/1.1.0", gallery_id());
        assert_eq!(gallery_of_image(&version_id), Some(gallery_id()));
        assert_eq!(image_related(&version_id), vec![("Gallery gal_prod · image ubuntu-hardened 1.1.0".to_string(), gallery_id())]);
        let managed = format!("{}/providers/Microsoft.Compute/images/golden", RG);
        assert_eq!(gallery_of_image(&managed), None);
        assert_eq!(image_related(&managed), vec![("Image golden".to_string(), managed.clone())]);
    }
}
