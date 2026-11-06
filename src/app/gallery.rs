//! The glue for Compute Gallery (#203, SERVICES.md rule 41): the section
//! dispatch, whose Related names the warm VMs and scale sets built from
//! the gallery's images, and the Images read. The rows and renderers are
//! `src/azure/services/gallery.rs`.

use super::App;
use crate::azure::resource::{name_of_id, Resource};
use crate::azure::service::JumpView;
use crate::azure::services::compute::VmRow;
use crate::azure::services::directory::now_unix;
use crate::azure::services::gallery::{fetch_gallery_images, gallery_of_image, gallery_section_lines, GalleryRow};
use crate::azure::services::scale_sets::ScaleSetRow;
use crate::event::Event;
use tokio::sync::mpsc;

impl App {
    /// The gallery arm of `section_lines_for`; `None` for another type.
    pub(crate) fn gallery_section_lines(&self, resource: &dyn Resource, idx: usize) -> Option<Vec<(String, String)>> {
        let gallery = resource.as_any().downcast_ref::<GalleryRow>()?;
        let mine = |image: &Option<String>| {
            image.as_deref().and_then(gallery_of_image).is_some_and(|g| g.eq_ignore_ascii_case(gallery.id()))
        };
        let mut built: Vec<(String, String)> = Vec::new();
        for r in self.warm_list(gallery.id(), JumpView::VirtualMachines).unwrap_or_default() {
            if let Some(vm) = r.as_any().downcast_ref::<VmRow>().filter(|vm| mine(&vm.image_id)) {
                built.push((format!("VM {} (built from it)", vm.base.name), vm.base.id.clone()));
            }
        }
        for r in self.warm_list(gallery.id(), JumpView::ScaleSets).unwrap_or_default() {
            if let Some(s) = r.as_any().downcast_ref::<ScaleSetRow>().filter(|s| mine(&s.image_id)) {
                built.push((format!("Scale set {} (built from it)", name_of_id(&s.base.id)), s.base.id.clone()));
            }
        }
        gallery_section_lines(resource, idx, self.lazy.gallery_images.get(gallery.id()), built, now_unix())
    }

    /// On-enter hook for a gallery's Images: the definitions, then each
    /// one's versions, in one read.
    pub fn trigger_gallery_images(app: &mut App, event_tx: &mpsc::UnboundedSender<Event>) {
        app.trigger_selected(
            |s| &mut s.gallery_images,
            event_tx,
            |c, id| fetch_gallery_images(c.arm_for_path(id), id.to_string()),
        );
    }
}
