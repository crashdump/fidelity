//! The image-catalog capability on Linux.

use fidelity_core::{ImageCatalog, ImageCatalogState, Observation};
use fidelity_formats::procfs::maps;
use fidelity_types::BoundedText;

use crate::LinuxEnvironment;
use crate::sys;

impl ImageCatalog for LinuxEnvironment {
    fn image_catalog_state(&self) -> Observation<ImageCatalogState> {
        let text = match sys::maps::read() {
            Ok(text) => text,
            Err(detail) => return Observation::failed(detail),
        };
        let ranges = match sys::catalog::read() {
            Ok(ranges) => ranges,
            Err(detail) => return Observation::failed(detail),
        };
        let found = maps::outside_loader(&text, &ranges);
        if found.is_empty() {
            return Observation::Fact(ImageCatalogState::Accounted);
        }
        Observation::Fact(ImageCatalogState::Unregistered {
            regions: found.regions,
            detail: BoundedText::new(format!(
                "unregistered executable image: {} bytes, region count {}",
                found.bytes, found.regions
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{ImageCatalog, ImageCatalogState, Observation};

    use super::LinuxEnvironment;

    #[test]
    fn a_clean_process_accounts_for_each_executable_file_image() {
        assert_eq!(
            LinuxEnvironment::new().image_catalog_state(),
            Observation::Fact(ImageCatalogState::Accounted)
        );
    }
}
