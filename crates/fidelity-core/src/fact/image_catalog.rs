//! The fact that the image-catalog capability reports.

use fidelity_types::BoundedText;

/// Whether the loader accounts for each executable file image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageCatalogState {
    /// The loader accounts for each executable file image.
    Accounted,

    /// An executable file image bypasses the loader catalog.
    Unregistered {
        /// How many image regions bypass the loader catalog.
        regions: u32,
        /// A bounded description of the regions.
        detail: BoundedText,
    },
}
