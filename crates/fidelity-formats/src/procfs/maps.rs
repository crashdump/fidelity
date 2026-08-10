//! The reader for the process mapping table.
//!
//! The kernel writes `/proc/<pid>/maps` as one line for each mapping:
//!
//! ```text
//! ffffaa230000-ffffaa231000 r-xp 00000000 00:5f 1051114    /tmp/evil.so
//! ```
//!
//! The reader keeps the executable mappings and states where each one comes
//! from. It reaches no verdict: a detector does that, because what counts as
//! unexpected depends on the platform and on the host's own runtime.

/// Where the code in one executable mapping comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A file that still exists at the path the kernel reports.
    File(String),

    /// A file that no longer exists at the path the kernel reports.
    ///
    /// The kernel marks it `(deleted)`. Code that unlinks itself after it
    /// loads leaves this trace, and so does a package upgrade under a running
    /// process.
    Deleted(String),

    /// Memory with no file behind it.
    ///
    /// Manually mapped code looks like this, and so does every compiler that
    /// generates code at run time.
    Anonymous,

    /// Memory that the kernel named, such as a stack, a heap, or a run-time
    /// code cache.
    ///
    /// The name is the kernel's, in the form `[name]`, and it is not a path.
    Named(String),
}

/// One executable mapping of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// The first address of the mapping.
    pub start: u64,
    /// The address after the mapping.
    pub end: u64,
    /// Whether the mapping is writable as well as executable.
    pub writable: bool,
    /// Where the code comes from.
    pub origin: Origin,
}

impl Mapping {
    /// The size of the mapping, in bytes.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// The suffix that the kernel adds to a path whose file is gone.
const DELETED: &str = " (deleted)";

/// Reads every executable mapping out of the mapping text.
///
/// A line that the reader cannot understand is skipped rather than guessed at.
/// The caller compares the count with the line count when that matters.
#[must_use]
pub fn executable_mappings(text: &str) -> Vec<Mapping> {
    text.lines().filter_map(mapping).collect()
}

/// The directory that Android installs an application archive under.
const INSTALLED: &str = "/data/app/";

/// The suffix of an application archive.
const ARCHIVE: &str = ".apk";

/// The archive that one package runs from, out of the mapping text.
///
/// An application process maps many archives, and only one of them is its own.
/// Measured on Android 37 on 2026-08-10: a Chrome process maps 58 of them,
/// including resource overlays, the framework resources, and a second
/// installed archive that holds a shared library. A search for the first
/// archive, or for the first one under `/data/app/`, answers with the wrong
/// file, and a wrong archive gives a wrong identity with no error.
///
/// The rule is therefore exact rather than close. Android installs an archive
/// at `/data/app/<random>/<package>-<random>/<name>.apk`, so the directory
/// that names the package is what selects it. The archive file itself is not
/// always `base.apk`, so the name never takes part.
///
/// Returns `None` when no mapped archive names this package. That is the
/// fail-closed answer, and a system application reaches it, because Android
/// installs one outside `/data/app/` under a name of its own. The caller
/// reports that gap, and it never guesses.
#[must_use]
pub fn package_archive<'a>(text: &'a str, package: &str) -> Option<&'a str> {
    if package.is_empty() {
        return None;
    }

    text.lines().find_map(|line| {
        let path = path_of(line)?;
        if path.starts_with(INSTALLED) && path.ends_with(ARCHIVE) && names(path, package) {
            Some(path)
        } else {
            None
        }
    })
}

/// Reports whether one directory of a path is the package and its suffix.
///
/// Android writes `<package>-<random>`, so the comparison takes the whole
/// component. A prefix test alone would accept
/// `com.google.android.trichromelibrary_782700532` for the package
/// `com.google.android.trichromelibrary`, which is a different archive that
/// the same process maps.
fn names(path: &str, package: &str) -> bool {
    path.split('/')
        .any(|component| match component.strip_prefix(package) {
            Some(rest) => rest.starts_with('-'),
            None => false,
        })
}

/// The path of one mapping line, when a live file backs it.
fn path_of(line: &str) -> Option<&str> {
    // The path is the sixth field, and it may hold a space, so the reader
    // takes everything from where that field starts.
    let sixth = line.split_whitespace().nth(5)?;
    let at = line.find(sixth)?;
    let path = line[at..].trim_end();

    if path.is_empty() || path.starts_with('[') || path.ends_with(DELETED) {
        return None;
    }
    Some(path)
}

/// Reads one line, and keeps it only when the mapping is executable.
fn mapping(line: &str) -> Option<Mapping> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let permissions = fields.next()?;

    // The fourth column is the device and the fifth is the inode. The path is
    // everything after them, and it may hold a space.
    let _offset = fields.next()?;
    let _device = fields.next()?;
    let _inode = fields.next()?;

    if !permissions.contains('x') {
        return None;
    }

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;

    let rest = line
        .split_whitespace()
        .nth(5)
        .map_or("", |first| match line.find(first) {
            Some(at) => line[at..].trim_end(),
            None => "",
        });

    Some(Mapping {
        start,
        end,
        writable: permissions.contains('w'),
        origin: origin(rest),
    })
}

/// States where the code of one mapping comes from.
fn origin(path: &str) -> Origin {
    if path.is_empty() {
        return Origin::Anonymous;
    }
    if let Some(name) = path.strip_suffix(DELETED) {
        return Origin::Deleted(name.to_owned());
    }
    if path.starts_with('[') {
        return Origin::Named(path.to_owned());
    }
    Origin::File(path.to_owned())
}

/// What a scan found that no file accounts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Unaccounted {
    /// How many executable regions have no file behind them.
    pub regions: u32,
    /// How many bytes those regions cover.
    pub bytes: u64,
}

impl Unaccounted {
    /// Reports whether a file accounts for every executable region.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regions == 0
    }
}

/// Counts the executable regions that no file accounts for.
///
/// A region counts when it is anonymous, or when its file is gone. A region
/// that the kernel named does not count: a runtime names its code cache, and
/// treating that as injected would report every process that compiles code.
/// The rule lives here, and not in a probe crate, so one fixture tests it for
/// every platform that reads this format.
#[must_use]
pub fn unaccounted(text: &str) -> Unaccounted {
    let mut found = Unaccounted::default();
    for mapping in executable_mappings(text) {
        if !matches!(mapping.origin, Origin::Anonymous | Origin::Deleted(_)) {
            continue;
        }
        found.regions = found.regions.saturating_add(1);
        found.bytes = found.bytes.saturating_add(mapping.bytes());
    }
    found
}

/// The address range of every executable mapping, in address order.
///
/// The caller turns these into a snapshot. The reader keeps no judgement here:
/// a region that a runtime named is still a region, and a baseline compares
/// what exists rather than what it came from.
#[must_use]
pub fn executable_ranges(text: &str) -> Vec<(u64, u64)> {
    executable_mappings(text)
        .into_iter()
        .map(|mapping| (mapping.start, mapping.end))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Origin, executable_mappings, executable_ranges, unaccounted};

    /// A real mapping table, captured on Debian and ARM64 on 2026-08-09.
    const CLEAN: &str = include_str!("../fixtures/maps-clean.txt");

    /// The same program with a library preloaded into it.
    const PRELOADED: &str = include_str!("../fixtures/maps-preloaded.txt");

    /// The executable mappings of a real Android runtime process.
    ///
    /// Captured from `com.android.systemui` on API 37 and ARM64 on
    /// 2026-08-09. The process runs a just-in-time compiler, so it is the
    /// clean control that matters most.
    const ANDROID_RUNTIME: &str = include_str!("../fixtures/maps-android-runtime.txt");

    /// A second compiler, which names nothing.
    ///
    /// Captured from a warmed Node process on Debian and ARM64 on 2026-08-09.
    /// It is the counter-example to the fixture above, and it holds the one
    /// false positive that this rule accepts.
    const V8_RUNTIME: &str = include_str!("../fixtures/maps-v8-jit.txt");

    #[test]
    fn a_clean_process_holds_executable_mappings() {
        assert!(!executable_mappings(CLEAN).is_empty());
    }

    #[test]
    fn a_clean_process_maps_no_anonymous_and_no_deleted_code() {
        // The baseline that a detector depends on. Measured, not assumed: the
        // captured file also holds an executable `[vdso]`, which the kernel
        // supplies to every process. A named mapping is therefore normal, and
        // only anonymous or deleted code is worth a second look.
        let odd: Vec<_> = executable_mappings(CLEAN)
            .into_iter()
            .filter(|mapping| matches!(mapping.origin, Origin::Anonymous | Origin::Deleted(_)))
            .collect();
        assert!(odd.is_empty(), "the clean baseline holds {odd:?}");
    }

    #[test]
    fn the_kernel_supplies_one_named_executable_mapping() {
        // `[vdso]` is in the captured baseline. A detector that treated a
        // named mapping as injected would report every Linux process.
        let named = executable_mappings(CLEAN)
            .into_iter()
            .any(|mapping| matches!(mapping.origin, Origin::Named(name) if name == "[vdso]"));
        assert!(named, "the clean baseline must hold the kernel vDSO");
    }

    #[test]
    fn a_preloaded_library_reads_as_a_file_mapping() {
        let found = executable_mappings(PRELOADED).into_iter().any(
            |mapping| matches!(mapping.origin, Origin::File(path) if path.contains("evil.so")),
        );
        assert!(found, "the preloaded library must appear");
    }

    #[test]
    fn a_deleted_file_keeps_its_path_without_the_marker() {
        let text = "ffff0000-ffff1000 r-xp 00000000 00:5f 1 /tmp/gone.so (deleted)\n";
        let mapping = executable_mappings(text).pop();
        assert_eq!(
            mapping.map(|mapping| mapping.origin),
            Some(Origin::Deleted("/tmp/gone.so".to_owned()))
        );
    }

    #[test]
    fn memory_with_no_file_reads_as_anonymous() {
        let text = "ffff0000-ffff1000 r-xp 00000000 00:00 0 \n";
        let mapping = executable_mappings(text).pop();
        assert_eq!(
            mapping.map(|mapping| mapping.origin),
            Some(Origin::Anonymous)
        );
    }

    #[test]
    fn a_kernel_name_reads_as_named_and_not_as_a_path() {
        // The exact string that a device reported. A name is not a file, so a
        // detector must not read it as one.
        let text = "ffff0000-ffff1000 r-xs 00000000 00:01 1 [anon_shmem:dalvik-jit-code-cache]\n";
        let mapping = executable_mappings(text).pop();
        assert_eq!(
            mapping.map(|mapping| mapping.origin),
            Some(Origin::Named(
                "[anon_shmem:dalvik-jit-code-cache]".to_owned()
            ))
        );
    }

    /// The archive mappings of a real application process.
    ///
    /// Captured from a Chrome process on Android 37 and ARM64 on 2026-08-10.
    /// The 2746 lines that name no archive were dropped, because the reader
    /// inspects a path and nothing else. It maps 58 archives, and two of them
    /// sit under `/data/app/`, which is what makes it the fixture that matters.
    const ANDROID_APP: &str = include_str!("../fixtures/maps-android-app.txt");

    /// The package that the recorded process runs.
    const CHROME: &str = "com.android.chrome";

    #[test]
    fn the_reader_finds_the_archive_that_the_package_runs_from() {
        assert_eq!(
            super::package_archive(ANDROID_APP, CHROME),
            Some(
                "/data/app/~~4AXJAFr_niMUpWx2IdKD0A==/com.android.chrome-Wm_m5nTF4fFqzXEOHXXIgQ==/Chrome.apk"
            )
        );
    }

    #[test]
    fn a_second_installed_archive_never_answers_for_the_package() {
        // The recorded process maps two archives under `/data/app/`: its own,
        // and one that holds a shared library. A search for the first one
        // under that directory would answer with whichever the kernel listed
        // first, and a wrong archive gives a wrong identity with no error.
        let Some(found) = super::package_archive(ANDROID_APP, CHROME) else {
            panic!("the fixture maps the archive of its own package")
        };
        assert!(!found.contains("trichromelibrary"), "{found}");
    }

    #[test]
    fn an_archive_that_carries_a_version_in_its_name_reports_nothing() {
        // Android installs a static shared library as `<package>_<version>`,
        // and the recorded process maps one. The exact rule refuses it,
        // because the component is not the package and a separator. That is
        // the fail-closed direction: a gap, and never another package.
        let library = super::package_archive(ANDROID_APP, "com.google.android.trichromelibrary");
        assert_eq!(library, None);
    }

    #[test]
    fn a_package_that_the_process_does_not_run_reports_nothing() {
        assert_eq!(
            super::package_archive(ANDROID_APP, "com.example.absent"),
            None
        );
    }

    #[test]
    fn a_package_that_another_package_starts_with_never_matches() {
        // `com.android.chrome` is a prefix of nothing here, but a package that
        // is a prefix of a real one must still not match, because Android
        // writes the package and then a separator.
        assert_eq!(super::package_archive(ANDROID_APP, "com.android"), None);
    }

    #[test]
    fn a_system_archive_never_answers() {
        // A system application installs outside `/data/app/`, under a name of
        // its own, so the exact rule reports a gap rather than a guess.
        assert_eq!(
            super::package_archive(ANDROID_RUNTIME, "com.android.systemui"),
            None
        );
    }

    #[test]
    fn an_empty_package_reports_nothing() {
        assert_eq!(super::package_archive(ANDROID_APP, ""), None);
    }

    #[test]
    fn a_deleted_archive_never_answers() {
        // The bytes behind a deleted path are gone, so a reader that returned
        // it would send the caller to a file it cannot open.
        let text = "7f0 r--p 0 fe:02 1 /data/app/~~a/com.example.app-b/base.apk (deleted)\n";
        assert_eq!(super::package_archive(text, "com.example.app"), None);
    }

    #[test]
    fn a_read_only_archive_answers() {
        // An ordinary application maps its archive read-only, because the
        // resources are what it reads. A search that kept only executable
        // mappings would answer for a system application and not for this one.
        let text = "7f0-7f1 r--p 0 fe:02 1 /data/app/~~a/com.example.app-b/base.apk\n";
        assert_eq!(
            super::package_archive(text, "com.example.app"),
            Some("/data/app/~~a/com.example.app-b/base.apk")
        );
    }

    #[test]
    fn a_running_just_in_time_compiler_maps_no_anonymous_code() {
        // The measurement that makes the detector possible. A runtime that
        // generates code was the obvious source of false positives, and the
        // kernel names those regions instead of leaving them anonymous.
        let odd: Vec<_> = executable_mappings(ANDROID_RUNTIME)
            .into_iter()
            .filter(|mapping| matches!(mapping.origin, Origin::Anonymous | Origin::Deleted(_)))
            .collect();
        assert!(odd.is_empty(), "a real runtime process holds {odd:?}");
    }

    #[test]
    fn the_runtime_code_cache_reads_as_named() {
        let named = executable_mappings(ANDROID_RUNTIME)
            .into_iter()
            .any(|mapping| {
                matches!(mapping.origin, Origin::Named(name) if name.contains("jit-code-cache"))
            });
        assert!(named, "the captured runtime must hold its code cache");
    }

    #[test]
    fn a_mapping_that_cannot_execute_is_absent() {
        let text = "ffff0000-ffff1000 rw-p 00000000 00:00 0 \n";
        assert!(executable_mappings(text).is_empty());
    }

    #[test]
    fn a_writable_executable_mapping_reports_that_it_is_writable() {
        let text = "ffff0000-ffff1000 rwxp 00000000 00:00 0 \n";
        let mapping = executable_mappings(text).pop();
        assert_eq!(mapping.map(|mapping| mapping.writable), Some(true));
    }

    #[test]
    fn a_mapping_keeps_its_size() {
        let text = "ffff0000-ffff2000 r-xp 00000000 00:00 0 \n";
        let mapping = executable_mappings(text).pop();
        assert_eq!(mapping.map(|mapping| mapping.bytes()), Some(0x2000));
    }

    #[test]
    fn a_clean_process_accounts_for_all_of_its_code() {
        assert!(unaccounted(CLEAN).is_empty());
    }

    #[test]
    fn a_running_just_in_time_compiler_accounts_for_all_of_its_code() {
        assert!(unaccounted(ANDROID_RUNTIME).is_empty());
    }

    #[test]
    fn a_compiler_that_names_nothing_reads_as_unaccounted() {
        // The false positive, measured rather than predicted. Android names
        // its code caches and this runtime does not, so the rule reports a
        // process that did nothing wrong. The limit is real, and it is why
        // unaccounted code stays `Medium`. See
        // `docs/plan/04-detectors-and-platforms.md`.
        assert_eq!(unaccounted(V8_RUNTIME).regions, 1);
    }

    #[test]
    fn that_compiler_writes_and_executes_the_same_region() {
        // What makes it hard to separate from an injected agent: the region is
        // writable and executable, which is what an agent needs too.
        let odd = executable_mappings(V8_RUNTIME)
            .into_iter()
            .find(|mapping| matches!(mapping.origin, Origin::Anonymous));
        assert_eq!(odd.map(|mapping| mapping.writable), Some(true));
    }

    #[test]
    fn a_preloaded_library_still_accounts_for_its_code() {
        // A preloaded library is file backed, so this rule does not see it.
        // The coverage limit is deliberate, and the plan records it.
        assert!(unaccounted(PRELOADED).is_empty());
    }

    #[test]
    fn manually_mapped_code_counts_as_unaccounted() {
        let text = "ffff0000-ffff2000 r-xp 00000000 00:00 0 \n";
        assert_eq!(unaccounted(text).regions, 1);
    }

    #[test]
    fn manually_mapped_code_counts_its_bytes() {
        let text = "ffff0000-ffff2000 r-xp 00000000 00:00 0 \n";
        assert_eq!(unaccounted(text).bytes, 0x2000);
    }

    #[test]
    fn code_from_a_deleted_file_counts_as_unaccounted() {
        let text = "ffff0000-ffff1000 r-xp 0 00:5f 1 /tmp/gone.so (deleted)\n";
        assert_eq!(unaccounted(text).regions, 1);
    }

    #[test]
    fn a_named_runtime_region_never_counts() {
        let text = "ffff0000-ffff1000 r-xs 00000000 00:01 1 [anon_shmem:dalvik-jit-code-cache]\n";
        assert!(unaccounted(text).is_empty());
    }

    #[test]
    fn a_clean_process_reports_its_executable_ranges() {
        assert_eq!(
            executable_ranges(CLEAN).len(),
            executable_mappings(CLEAN).len()
        );
    }

    #[test]
    fn a_range_states_the_first_address_and_the_address_after_it() {
        let text = "ffff0000-ffff2000 r-xp 00000000 00:00 0 \n";
        assert_eq!(executable_ranges(text), vec![(0xffff_0000, 0xffff_2000)]);
    }

    #[test]
    fn a_line_that_the_reader_cannot_understand_is_skipped() {
        assert!(executable_mappings("nonsense\n\n").is_empty());
    }
}
