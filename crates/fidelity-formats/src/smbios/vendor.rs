//! The judgment on what the two firmware strings name.
//!
//! A maker of hardware writes its own name here. A virtual machine monitor
//! writes a name of its own, and the names it writes are published, so the rule
//! is a list of them rather than a guess about shape.
//!
//! The list fails open. A name that it does not hold reports no monitor, which
//! costs coverage and never costs a clean run. That is the same rule that the
//! Android system build follows, and the reason is the same: no survey covers
//! what every maker writes, and a clean control that reports is worse than one
//! that stays quiet.

/// The names that a virtual machine monitor writes, as a prefix of either
/// field.
///
/// The list comes from the `dmi_vendor_table` of systemd, at
/// <https://github.com/systemd/systemd/blob/main/src/basic/virt.c>, read on
/// 2026-08-18. That table is the one that a Linux system already trusts to
/// answer this question, and it is public, so a reader checks this list rather
/// than taking it on trust.
///
/// Two names of that table are absent here on purpose, because each one also
/// names real hardware:
///
/// - `Amazon EC2`, because a bare-metal instance reports it as well; and
/// - `Oracle Corporation`, because that company sells servers.
///
/// This project measured one entry itself. Both guests that
/// `tests/platform/vm/` builds report `QEMU` and `QEMU Virtual Machine`,
/// through the Linux kernel and through the Windows firmware table, and the
/// captured table in the fixtures holds it.
const MONITORS: [&str; 16] = [
    "Alibaba Cloud ECS",
    "Apple Virtualization",
    "BHYVE",
    "Bochs",
    "Google Compute Engine",
    "Hyper-V",
    "KVM",
    "KubeVirt",
    "OpenStack",
    "Parallels",
    "QEMU",
    "VMW",
    "VMware",
    "VirtualBox",
    "Xen",
    "innotek GmbH",
];

/// Reports which name states that a virtual machine monitor runs this system.
///
/// Takes the manufacturer and the product of the System Information structure,
/// which Linux writes as `sys_vendor` and `product_name`. Returns the whole
/// field that matched, and not the name inside it, so the finding quotes what
/// the firmware said rather than stating that something matched.
///
/// The match is a prefix, because a maker states more than its own name in
/// these fields. `VMware, Inc.` and `Parallels Software International Inc.`
/// are both real values that a whole-string rule would miss.
#[must_use]
pub fn names_a_monitor<'a>(manufacturer: &'a str, product: &'a str) -> Option<&'a str> {
    [manufacturer, product]
        .into_iter()
        .find(|field| MONITORS.iter().any(|name| field.starts_with(name)))
}

#[cfg(test)]
mod tests {
    use super::names_a_monitor;

    #[test]
    fn the_measured_guest_reports_its_monitor() {
        // What both guests of this project state, through two different
        // interfaces. See the captured table in the fixtures.
        assert_eq!(
            names_a_monitor("QEMU", "QEMU Virtual Machine"),
            Some("QEMU")
        );
    }

    #[test]
    fn a_maker_of_hardware_reports_no_monitor() {
        assert_eq!(names_a_monitor("LENOVO", "20QDS00R00"), None);
    }

    #[test]
    fn the_product_answers_when_the_manufacturer_does_not() {
        // Oracle writes its own name as the manufacturer, and that name also
        // belongs to a maker of servers, so only the product decides here.
        assert_eq!(
            names_a_monitor("Oracle Corporation", "VirtualBox"),
            Some("VirtualBox")
        );
    }

    #[test]
    fn a_name_that_states_more_than_itself_still_matches() {
        // The reason the rule takes a prefix. Both of these are real values.
        assert_eq!(
            names_a_monitor("VMware, Inc.", "VMware7,1"),
            Some("VMware, Inc.")
        );
        assert_eq!(
            names_a_monitor("Parallels Software International Inc.", "Parallels ARM"),
            Some("Parallels Software International Inc.")
        );
    }

    #[test]
    fn a_bare_metal_cloud_instance_reports_no_monitor() {
        // The reason `Amazon EC2` is absent from the list. A `metal` instance
        // states the same name and runs on the hardware, so the name proves
        // nothing either way.
        assert_eq!(names_a_monitor("Amazon EC2", "c6g.metal"), None);
    }

    #[test]
    fn a_name_that_only_holds_a_marker_reports_no_monitor() {
        // The match is a prefix and not a search. A maker whose name ends in
        // one of these must not report.
        assert_eq!(names_a_monitor("Advanced Xen", "Server"), None);
    }

    #[test]
    fn empty_fields_report_no_monitor() {
        assert_eq!(names_a_monitor("", ""), None);
    }
}
