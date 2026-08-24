//! The image-catalog capability on Windows.

use fidelity_core::{ImageCatalog, ImageCatalogState, Observation};
use fidelity_types::BoundedText;

use crate::WindowsEnvironment;
use crate::sys;

impl ImageCatalog for WindowsEnvironment {
    fn image_catalog_state(&self) -> Observation<ImageCatalogState> {
        let regions = match sys::memory::executable() {
            Ok(regions) => regions,
            Err(detail) => return Observation::failed(detail),
        };
        let module_bases = match sys::catalog::module_bases() {
            Ok(module_bases) => module_bases,
            Err(detail) => return Observation::failed(detail),
        };

        let mut count = 0_u32;
        let mut bytes = 0_u64;
        for region in regions.iter().filter(|region| region.image) {
            if module_bases.contains(&region.allocation_base) {
                continue;
            }
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(region.end.saturating_sub(region.start));
        }
        if count == 0 {
            return Observation::Fact(ImageCatalogState::Accounted);
        }
        Observation::Fact(ImageCatalogState::Unregistered {
            regions: count,
            detail: BoundedText::new(format!(
                "unregistered executable image: {bytes} bytes, region count {count}"
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{ImageCatalog, ImageCatalogState, Observation};

    use super::WindowsEnvironment;

    #[test]
    fn a_clean_process_accounts_for_each_executable_image() {
        assert_eq!(
            WindowsEnvironment::new().image_catalog_state(),
            Observation::Fact(ImageCatalogState::Accounted)
        );
    }
}
