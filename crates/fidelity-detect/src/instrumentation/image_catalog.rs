use fidelity_core::{ImageCatalog, ImageCatalogState, Observation};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// An executable file image bypasses the dynamic-loader catalog.
pub const IMAGE_CATALOG: Detector = Detector::new(
    12,
    "instrumentation.image_catalog",
    Category::Instrumentation,
);

/// Interprets the executable-image and loader comparison.
pub(crate) fn image_catalog(
    environment: &(impl ImageCatalog + ?Sized),
    now_unix_ms: u64,
) -> Outcome {
    match environment.image_catalog_state() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(ImageCatalogState::Accounted) => Outcome::Clean,
        Observation::Fact(ImageCatalogState::Unregistered { detail, .. }) => {
            Outcome::Finding(Finding::new(
                IMAGE_CATALOG,
                SignalStrength::Medium,
                Evidence::UnregisteredImage { detail },
                now_unix_ms,
            ))
        }
    }
}

fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        IMAGE_CATALOG,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{ImageCatalogState, Observation};
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{BoundedText, Evidence, Outcome, SignalStrength};

    use super::image_catalog;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn an_accounted_catalog_reports_clean() {
        let environment = FakeEnvironment::new()
            .with_image_catalog(Observation::Fact(ImageCatalogState::Accounted));
        assert_eq!(image_catalog(&environment, NOW), Outcome::Clean);
    }

    #[test]
    fn an_unregistered_image_reports_a_medium_finding() {
        let environment = FakeEnvironment::new().with_image_catalog(Observation::Fact(
            ImageCatalogState::Unregistered {
                regions: 1,
                detail: BoundedText::new("one executable image bypasses the loader catalog"),
            },
        ));
        let Outcome::Finding(finding) = image_catalog(&environment, NOW) else {
            panic!("an unregistered image must report a finding")
        };
        assert!(matches!(
            (finding.strength(), finding.evidence()),
            (SignalStrength::Medium, Evidence::UnregisteredImage { .. })
        ));
    }

    #[test]
    fn a_failed_catalog_read_reports_health() {
        let environment = FakeEnvironment::new()
            .with_image_catalog(Observation::failed("the loader catalog reached its bound"));
        let Outcome::Finding(finding) = image_catalog(&environment, NOW) else {
            panic!("a failed catalog read must report a finding")
        };
        assert!(finding.evidence().is_detector_health());
    }
}
