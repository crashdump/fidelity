//! The image-catalog capability.

use crate::Observation;
use crate::fact::ImageCatalogState;

/// Reads executable file images and the dynamic-loader catalog.
pub trait ImageCatalog {
    /// Whether the loader accounts for each executable file image.
    fn image_catalog_state(&self) -> Observation<ImageCatalogState> {
        Observation::Unsupported {
            reason: "this platform offers no image-catalog reader",
        }
    }
}
