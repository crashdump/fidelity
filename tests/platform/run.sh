#!/bin/sh
# Runs the controls that this machine can reach, and writes the generated
# record that docs/plan/05-verification.md asks for.
#
#     tests/platform/run.sh [record path]
#
# The record is a tab-separated file, one row for each control, with four
# columns: system, control, result, detail. A result is one of
#
#     pass      the control ran here and gave the answer it must give
#     fail      the control ran here and gave another answer
#     skipped   this machine cannot reach the system, and the detail says why
#     manual    a person runs this control, and the detail says where the
#               result lives in tests/platform/README.md
#
# The skipped rows carry the weight. A record that lists only what passed reads
# as complete coverage, and no machine reaches every system that Fidelity
# supports. This one names what it could not run.
#
# The script leaves output for each control under target/platform/, and it
# exits non-zero when any control that ran gave a wrong answer.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECORD=${1:-$ROOT/tests/platform/record.tsv}
OUT=$ROOT/target/platform
FAILED=0

# Every target that a probe crate builds for. The cross-check is what proves
# that a change to a capability trait still compiles every platform.
#
# Every supported architecture of every platform is here, because the release
# gate in 05-verification.md asks that each one builds with its intended
# toolchain. Until 2026-08-18 the list held one x86_64 target, and a change that
# broke the others would have reached a release. macOS and iOS name one target
# each, because Apple Silicon is the only Apple hardware in scope.
#
# A build proves nothing. Every detector result that this machine produced came
# from ARM64, and the gaps table in README.md states that.
TARGETS="aarch64-apple-darwin aarch64-apple-ios aarch64-linux-android x86_64-linux-android aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu aarch64-pc-windows-msvc x86_64-pc-windows-msvc"

# Prints that list, one target for each line, and stops. The gate installs what
# it prints, so the workflow file holds no second copy. The three targets that
# arrived on 2026-08-18 reached the cross-check and never reached the gate, and
# `rustup` reports a missing target as a missing standard library, which names
# neither the target nor the toolchain that lacks it.
if [ "${1:-}" = "--targets" ]; then
    for target in $TARGETS; do
        echo "$target"
    done
    exit 0
fi

# A digest of the right shape, for the build rules that must refuse a value.
DIGEST=9f3a1c0e5b7d2846a09f3a1c0e5b7d2846a09f3a1c0e5b7d2846a09f3a1c0e5b

# Cargo adds this suffix to an example on Windows.
EXAMPLE_SUFFIX=''
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) EXAMPLE_SUFFIX=.exe ;;
esac

mkdir -p "$OUT"
# The markers that the timeout below writes. A run that a person stopped leaves
# them, and a stale one must not decide anything in the next run.
rm -f "$OUT"/.killed-* "$OUT"/.finished-*
: > "$RECORD"

# Writes one row, to the record and to the terminal.
note() {
    detail=$(printf '%s' "$4" | sed 's/[[:space:]]*$//')
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$detail" >> "$RECORD"
    printf '%-8s %-26s %-8s %s\n' "$1" "$2" "$3" "$detail"
}

# Prints the output that gave a failed row.
show_failure() {
    printf 'output for %s:\n' "$1"
    sed -n '1,240p' "$OUT/$1.out"
}

# What one control answered, in one line. A tab in it would break the record.
#
# A test run prints one summary for each binary, and the last one is the
# doc-test summary, which is empty for most crates. The count of every summary
# is the answer there, and the last line is the answer everywhere else.
#
# The record is checked in, so a detail must name no machine. The path of this
# workspace goes, and what remains reads the same on every machine.
answer() {
    file=$OUT/$1.out
    if grep -q '^test result:' "$file" 2>/dev/null; then
        awk '/^test result:/ { passed += $4; failed += $6 }
             END { printf "%d passed, %d failed", passed, failed }' "$file"
        return
    fi
    # A cost example prints one line for each read, and the last line alone
    # states almost nothing. The Windows column of 07-state-and-budgets.md was
    # absent for two days because this function kept that one line. Join every
    # read instead, so the record carries the whole measurement.
    if grep -q '^read  *each  *runs' "$file" 2>/dev/null; then
        awk 'seen { printf "%s%s %s", separator, $1, $2; separator = "; " }
             /^read  *each  *runs/ { seen = 1 }' "$file"
        return
    fi
    grep -v '^[[:space:]]*$' "$file" 2>/dev/null | tail -1 | tr -d '\t' |
        sed "s|$ROOT/||g" | cut -c1-160 | sed 's/[[:space:]]*$//'
}

# The longest one control may take. A control that hangs must fail and say so,
# and it must not stop the run. The Android instrumented control stalled once
# for 12 hours, and the harness reported nothing at all until a person looked.
# Measured on 2026-08-18: the slowest control that passes takes 41 s, so this
# limit leaves a wide margin over every control that works.
LIMIT=${FIDELITY_CONTROL_LIMIT:-900}

# The text that a killed control prints. Both callers below look for it.
KILLED="the harness killed this control, because it passed the $LIMIT second limit"

# Kills a process and every descendant of it.
#
# A control runs `cargo`, which runs a test binary, so a kill of the first one
# alone leaves the work running.
kill_tree() {
    for child in $(pgrep -P "$1" 2> /dev/null); do
        kill_tree "$child"
    done
    kill -9 "$1" 2> /dev/null
}

# Counts the controls, so each one owns a pair of marker files.
GUARDED=0

# Runs a command, and kills it when it passes the limit above.
#
# A base macOS carries no `timeout`, and a control that needs one from a
# package manager is a control that runs on one machine. So this is the
# portable form: the work runs in the background, a watchdog waits, and
# whichever finishes first decides. The watchdog writes a marker, because the
# status of a killed process does not say who killed it.
#
# The watchdog ends by itself, and nothing kills it. A kill wrote "Killed: 9"
# to the terminal for every control, because the shell reports a background job
# that a signal stopped, and a passing run then read as a failing one. So the
# watchdog polls a marker that this function writes when the work ends. The
# shell still writes that one line for a control that the watchdog killed,
# which is a true statement about a control that failed, and the line below
# follows it and names the limit.
#
# Each control owns its own two markers. A watchdog can outlive its control by
# up to one second, and a shared marker would let that one kill the next
# control, or report a limit that nothing passed.
guard() {
    GUARDED=$((GUARDED + 1))
    killed=$OUT/.killed-$GUARDED
    finished=$OUT/.finished-$GUARDED
    rm -f "$killed" "$finished"
    "$@" &
    work=$!
    (
        waited=0
        while [ "$waited" -lt "$LIMIT" ]; do
            sleep 1
            if [ -e "$finished" ]; then
                exit 0
            fi
            waited=$((waited + 1))
        done
        : > "$killed"
        kill_tree "$work"
    ) &
    wait "$work"
    status=$?
    : > "$finished"
    if [ -e "$killed" ]; then
        echo "$KILLED"
        return 124
    fi
    return "$status"
}

# Runs one control that must succeed.
#     run <system> <name> <command> [argument...]
run() {
    system=$1
    name=$2
    shift 2
    begin=$(date +%s)
    if guard "$@" > "$OUT/$name.out" 2>&1; then
        result=pass
    else
        result=fail
        FAILED=$((FAILED + 1))
    fi
    note "$system" "$name" "$result" "$(($(date +%s) - begin))s. $(answer "$name")"
    if [ "$result" = fail ]; then
        show_failure "$name"
    fi
}

# Runs one control that must fail, and that must say why.
#     refute <system> <name> <text it must print> <command> [argument...]
refute() {
    system=$1
    name=$2
    needle=$3
    shift 3
    begin=$(date +%s)
    if guard "$@" > "$OUT/$name.out" 2>&1; then
        note "$system" "$name" fail "the control succeeded, and it must not"
        show_failure "$name"
        FAILED=$((FAILED + 1))
    elif grep -qF "$KILLED" "$OUT/$name.out"; then
        # This one comes before the needle, because a control that never
        # finished refused nothing.
        note "$system" "$name" fail "$KILLED"
        show_failure "$name"
        FAILED=$((FAILED + 1))
    elif grep -qF "$needle" "$OUT/$name.out"; then
        note "$system" "$name" pass "$(($(date +%s) - begin))s. refused, and it said \"$needle\""
    else
        note "$system" "$name" fail "it failed for another reason than \"$needle\""
        show_failure "$name"
        FAILED=$((FAILED + 1))
    fi
}

skip() { note "$1" "$2" skipped "$3"; }
manual() { note "$1" "$2" manual "$3"; }

{
    printf '# generated by tests/platform/run.sh on %s, on %s\n' \
        "$(date -u '+%Y-%m-%d %H:%M UTC')" "$(uname -sm)"
    printf 'system\tcontrol\tresult\tdetail\n'
} >> "$RECORD"
printf '%-8s %-26s %-8s %s\n' system control result detail

# ---------------------------------------------------------------- the toolchain

# Rustdoc reports a broken link as a warning, so warnings fail this gate. The
# private-item pass also checks links inside platform seams.
rustdoc() {
    RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features \
        --document-private-items --no-deps --locked
}

# `--all-features` reaches the optional `serde` surface. A platform is never a
# feature, so this enables no platform code and hides no target behind a flag.
# Cargo gives equal example names one output path on Windows. The platform
# controls compile each example for its owner, so this row tests the libraries,
# the integration tests, and the documentation tests.
workspace_tests() {
    cargo test --workspace --all-features --lib --tests || return 1
    cargo test --workspace --all-features --doc
}
run host workspace-tests workspace_tests
run host package-contract "$ROOT/tests/package.sh"
run host workspace-lints cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run host fuzz-lints cargo clippy --manifest-path "$ROOT/fuzz/Cargo.toml" \
    --all-targets --locked -- -D warnings

# The default build is what a host gets, and it is the only build that resolves
# to no external crate. Every row above enables both features, so nothing lints
# the code that a feature removes. The `tracing` events expand to nothing when
# the feature is off, and that is exactly the arm this row compiles.
run host workspace-default-lints cargo clippy --workspace --all-targets --locked -- -D warnings

# The adapter and the fuzz targets have independent workspaces. One format row
# covers all three workspaces.
format() {
    cargo fmt --check || return 1
    cargo fmt --manifest-path \
        "$ROOT/bindings/tauri-plugin-fidelity/Cargo.toml" -- --check || return 1
    cargo fmt --manifest-path "$ROOT/fuzz/Cargo.toml" -- --check
}
run host workspace-format format
run host workspace-rustdoc rustdoc
for target in $TARGETS; do
    run host "cross-$target" cargo check --workspace --target "$target"
done

# ------------------------------------------------------------ guarded constants

guarded_unbound() {
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
        cargo run --quiet --example guarded -p fidelity | grep 'host: api.example.com'
}
run host guarded-unbound guarded_unbound

# This one binds the build to a team that did not sign the image, and then runs
# it, so it needs a host whose own target takes Apple material. Another host
# refuses the same value while it builds, which is a different answer, and
# `guarded-platform-without-identity` already covers that one by target.
if [ "$(uname -s)" = Darwin ]; then
    refute host guarded-no-signer 'IdentityBindingUnavailable' \
        env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 \
        cargo run --quiet --example guarded -p fidelity
else
    skip host guarded-no-signer "the build binds Apple material, and this machine does not run macOS"
fi
refute host guarded-unnamed-kind 'names no material kind' \
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=ABCDE12345 \
    cargo check --quiet -p fidelity
refute host guarded-wrong-platform 'reports android material' \
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 \
    cargo check --quiet -p fidelity --target aarch64-linux-android
refute host guarded-platform-without-identity 'no code identity at all' \
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 \
    cargo check --quiet -p fidelity --target aarch64-unknown-linux-gnu
# The two forms that `keytool -list -v` puts in front of a host. It separates
# every pair of digits with a colon, so the first pair reads as the kind, and it
# prints a SHA-1 digest one line above the SHA-256 one.
refute host guarded-keytool-colons 'the kind "9F"' \
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY="9F:3A:1C:0E:5B:7D:28:46" \
    cargo check --quiet -p fidelity --target aarch64-linux-android
refute host guarded-sha1-digest 'and this one has 40' \
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY="android:${DIGEST%????????????????????????}" \
    cargo check --quiet -p fidelity --target aarch64-linux-android

# The floor, which holds on every target: the artifact carries no guarded
# literal in the clear. The extraction control below states the ceiling, and
# this states the floor. A compiler that folded the expansion would put the
# literal straight into the binary, and nothing else here would notice.
plaintext() {
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
        cargo build --release --quiet --example guarded -p fidelity || return 1
    artifact=$ROOT/target/release/examples/guarded$EXAMPLE_SUFFIX

    # The example prints this label, so the scan must find it. A scan that
    # found nothing at all would otherwise pass this control by failing.
    grep -aqF 'host: ' "$artifact" || return 1

    for literal in api.example.com /v1/session/open; do
        if grep -aqF "$literal" "$artifact"; then
            echo "the artifact holds $literal in the clear"
            return 1
        fi
    done
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
        cargo build --release --quiet --example guarded-bytes -p fidelity || return 1
    byte_artifact=$ROOT/target/release/examples/guarded-bytes$EXAMPLE_SUFFIX
    if grep -aqF GuardedByteSpan2408 "$byte_artifact"; then
        echo "the byte artifact holds its literal in the clear"
        return 1
    fi
    echo "no guarded literal is in its artifact in the clear"
}
run host guarded-no-plaintext plaintext

# The extraction ceiling. The first must recover a constant, and the second
# must recover none, because a control that recovers with any input is
# measuring itself.
extract() {
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
        cargo build --release --quiet --example guarded -p fidelity || return 1
    cargo run --release --quiet --example extract -p fidelity-cipher -- \
        "$ROOT/target/release/examples/guarded$EXAMPLE_SUFFIX" \
        "$1" api.example.com /v1/session/open
}
case "$(uname -s):$(uname -m)" in
    MINGW*:x86_64 | MSYS*:x86_64 | CYGWIN*:x86_64)
        skip host extract-with-the-identity \
            "the x86_64 Windows compiler puts both ciphertexts in instruction immediates"
        skip host extract-with-another-identity \
            "the byte extractor does not reassemble x86_64 instruction immediates"
        ;;
    *)
        run host extract-with-the-identity extract ''
        refute host extract-with-another-identity 'stayed hidden' extract ABCDE12345
        ;;
esac

extract_bytes() {
    env FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
        cargo build --release --quiet --example guarded-bytes -p fidelity || return 1
    cargo run --release --quiet --example extract -p fidelity-cipher -- \
        "$ROOT/target/release/examples/guarded-bytes$EXAMPLE_SUFFIX" \
        "$1" hex:0047756172646564427974655370616e32343038ff
}
run host extract-bytes-with-the-identity extract_bytes ''
refute host extract-bytes-with-another-identity 'stayed hidden' \
    extract_bytes ABCDE12345

# `06-delivery.md` requires this one by name. The macro crate declares the seed
# with `rerun-if-env-changed`, and without that line Cargo reuses the previous
# expansion: the binary keeps the old key, and a host that rotated its seed
# ships the value it thought it had replaced. Nothing else reports that.
seeded() {
    env FIDELITY_BUILD_SEED="$1" FIDELITY_CODE_IDENTITY=none \
        cargo build --release --quiet --example guarded -p fidelity >&2 || return 1
    (shasum -a 256 2> /dev/null || sha256sum) < \
        "$ROOT/target/release/examples/guarded$EXAMPLE_SUFFIX" |
        cut -d' ' -f1
}
two_seeds() {
    one=$(seeded one-seed) || return 1
    another=$(seeded another-seed) || return 1
    printf 'one-seed     %s\nanother-seed %s\n' "$one" "$another"
    [ "$one" != "$another" ]
}
run host two-seeds-two-binaries two_seeds

# The `UiAbuse` pair. This category takes its input from the host, so both
# halves run anywhere and neither needs a platform. That is not a weaker
# control: no operating system answers this question, and
# `docs/plan/04-detectors-and-platforms.md` holds the measurement that decided
# it. What the pair proves is the whole contract: a runtime that no host
# reported to states the absence of a report, and one report denies at once.
interface_clean() {
    cargo run --quiet --example interface -p fidelity |
        grep 'ui_abuse.host_report: no scan reached it'
}
interface_overlay() {
    cargo run --quiet --example interface -p fidelity -- overlay |
        grep 'protected operation: denied'
}

run host interface-clean interface_clean
run host interface-overlay interface_overlay
SANITIZER_TARGET=$(rustc -vV | awk '/^host: / { print $2 }')
case "$SANITIZER_TARGET" in
    aarch64-apple-darwin | aarch64-unknown-linux-gnu | \
        x86_64-apple-darwin | x86_64-unknown-freebsd | \
        x86_64-unknown-linux-gnu)
        run host sanitizers "$ROOT/tests/platform/controls/run-sanitizers.sh"
        ;;
    *)
        skip host sanitizers "the Rust sanitizer tools do not support $SANITIZER_TARGET"
        ;;
esac

# `05-verification.md` puts the sanitizers on every change and Miri on a
# schedule. Miri walks seven crates and takes longer than the whole rest of this
# harness, so the default run records why it did not run rather than staying
# silent about it.
if [ "${FIDELITY_WITH_MIRI:-}" = 1 ]; then
    run host miri "$ROOT/tests/platform/controls/run-sanitizers.sh" just-miri
else
    skip host miri "05-verification.md schedules Miri, and it costs 4 minutes: FIDELITY_WITH_MIRI=1 tests/platform/run.sh"
fi

# ------------------------------------------------------- the minimum Rust version
#
# `06-delivery.md` makes the minimum version normative, and nothing checked it.
# A let-chain therefore made the claim false for months, and the workspace did
# not build on the version that it named. The version comes from the manifest
# here, so the check and the claim cannot drift apart again.
#
# It caught a second one on 2026-08-19. `#[derive(Default)]` on a struct that
# holds a raw pointer builds on a current compiler and fails on 1.85, because
# `Default` for a raw pointer arrived in 1.88. It broke the two Linux targets
# alone, so the host arm above passed and only the cross loop below reported it.
# That is the reason this control checks every target and not the host.
MSRV=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
if [ -n "$MSRV" ] && rustup run "$MSRV" rustc --version > /dev/null 2>&1; then
    msrv() {
        # `--all-features` reaches the optional `serde` surface, so a bump in
        # that crate cannot raise the floor without this row noticing. The
        # cross-checks below stay lean, because that surface is portable Rust
        # and holds no platform code.
        cargo "+$MSRV" check --workspace --all-targets --all-features || return 1
        for target in $TARGETS; do
            cargo "+$MSRV" check --workspace --target "$target" || return 1
        done
        rustup run "$MSRV" rustc --version
    }
    run host "msrv-$MSRV" msrv
else
    skip host "msrv-${MSRV:-unstated}" \
        "install it first: rustup toolchain install ${MSRV:-<version>}"
fi

# ------------------------------------------------------------------------ macOS

if [ "$(uname -s)" = Darwin ]; then
    # The runtime-baseline pair. The `late` example exits zero when the worker
    # catches a change, and non-zero when the deadline passes first, so the
    # clean control is the same binary with no agent in front of it. The clean
    # half costs its whole 40 second deadline, and that wait is the measurement.
    late() {
        cargo build --quiet --example late -p fidelity || return 1
        clang -dynamiclib -o "$OUT/delayed.dylib" "$ROOT/tests/platform/controls/delayed.c" || return 1
        env "$@" "$ROOT/target/debug/examples/late"
    }
    baseline_hostile() { late DYLD_INSERT_LIBRARIES="$OUT/delayed.dylib"; }
    baseline_clean() { late DYLD_INSERT_LIBRARIES=; }

    baseline_boundary_macos() {
        cargo build --quiet --example baseline-boundaries -p fidelity || return 1
        clang -dynamiclib -o "$OUT/baseline-boundaries.dylib" \
            "$ROOT/tests/platform/controls/baseline-boundaries.c" || return 1
        env FIDELITY_BASELINE_BOUNDARY="$1" \
            DYLD_INSERT_LIBRARIES="$OUT/baseline-boundaries.dylib" \
            "$ROOT/target/debug/examples/baseline-boundaries" "$1"
    }
    baseline_writable_macos() { baseline_boundary_macos writable; }
    baseline_limit_macos() { baseline_boundary_macos limit; }

    # The tracer set. `lldb -b` runs the whole program under a debugger, which
    # the initial scan finds, and `lldb -p` attaches to a process that already
    # runs, which only the worker finds.
    tracer_clean() {
        cargo build --quiet --example tracer -p fidelity || return 1
        "$ROOT/target/debug/examples/tracer" | grep 'tracer_present: clean'
    }
    tracer_at_start() {
        cargo build --quiet --example tracer -p fidelity || return 1
        lldb -b -o run -- "$ROOT/target/debug/examples/tracer" |
            grep 'protected operation: denied'
    }
    tracer_attaches() {
        cargo build --quiet --example attach -p fidelity || return 1
        "$ROOT/tests/platform/controls/trace-after-start.sh" \
            "$ROOT/target/debug/examples/attach" lldb -p
    }

    # The dispatch pair. The agent arrives with the image, so the loader maps
    # its code before `start()` reads the baseline, and only the table moves
    # afterwards. That is what separates this detector from the baseline.
    dispatch_hostile_macos() {
        clang -dynamiclib -o "$OUT/hook-macos.dylib" \
            "$ROOT/tests/platform/controls/hook-macos.c" || return 1
        cargo build --quiet --example redirect -p fidelity || return 1
        DYLD_INSERT_LIBRARIES="$OUT/hook-macos.dylib" \
            "$ROOT/target/debug/examples/redirect" | grep 'DispatchRedirected'
    }
    dispatch_clean_macos() {
        cargo build --quiet --example redirect -p fidelity || return 1
        "$ROOT/target/debug/examples/redirect"
    }

    local_agent_macos() {
        mode=$1
        cargo build --quiet --example local-agent --example local-agent-endpoint \
            -p fidelity || return 1
        "$ROOT/target/debug/examples/local-agent-endpoint" "$mode" > "$OUT/endpoint.out" &
        server=$!
        while ! grep -q ready "$OUT/endpoint.out"; do sleep 0.05; done
        "$ROOT/target/debug/examples/local-agent"
        status=$?
        wait "$server" || status=1
        return "$status"
    }
    local_agent_hostile_macos() { local_agent_macos frida | grep 'local_agent: Medium'; }
    local_agent_unrelated_macos() { local_agent_macos unrelated | grep 'local_agent: clean'; }

    # The resume promise. The plan makes a full scan the worker's first work
    # item after the machine continues a frozen process, and the mechanism is
    # the same on every system, so the development machine runs it too.
    resume_after_freeze() {
        cargo build --quiet --example resume -p fidelity || return 1
        "$ROOT/tests/platform/controls/resume-after-freeze.sh" \
            "$ROOT/target/debug/examples/resume"
    }

    # The region counts behind the runtime-baseline strength. `plugin-load.c`
    # includes `controls/regions.h` from the same directory.
    plugin() {
        printf 'int plugin_entry(void){return 7;}\n' > "$OUT/plug.c"
        clang -dynamiclib -o "$OUT/plugin.dylib" "$OUT/plug.c"
    }
    plugin_load() {
        plugin || return 1
        clang -I "$ROOT/tests/platform/controls" -o "$OUT/plugin-load" \
            "$ROOT/tests/platform/controls/plugin-load.c" || return 1
        counts=$("$OUT/plugin-load" "$OUT/plugin.dylib") || return 1
        printf '%s\n' "$counts"
        # A library that the dyld shared cache already holds adds no region,
        # and a plugin on disk adds one. Those two numbers decided the strength.
        printf '%s\n' "$counts" | grep -q 'shared-cache load:.*(+0)' || return 1
        printf '%s\n' "$counts" | grep -q 'plugin load.*(+1)' || return 1
    }

    # The clean control that decided the strength. A host loads one of its own
    # plugins after start, and the detector cannot tell it from an injection.
    # The same control loads a cached library, which adds no region and reports
    # nothing, and that pair is the whole argument.
    legitimate() {
        plugin || return 1
        clang -dynamiclib -o "$OUT/legitimate.dylib" \
            "$ROOT/tests/platform/controls/legitimate.c" || return 1
        cargo build --quiet --example late -p fidelity || return 1
        env DYLD_INSERT_LIBRARIES="$OUT/legitimate.dylib" FIDELITY_PLUGIN="$1" \
            "$ROOT/target/debug/examples/late"
    }
    legitimate_plugin() { legitimate "$OUT/plugin.dylib"; }
    legitimate_cached() { legitimate /usr/lib/libcurl.dylib; }

    # The image-identity set. Until 2026-08-18 macOS had no identity control
    # here at all, and its rows in README.md came from a person.
    #
    # Four of the five arms that 05-verification.md asks for run with no Apple
    # Developer account, because a code requirement may name a cdhash rather
    # than a signer. The linker gives every local build an ad-hoc signature, so
    # the image has a cdhash of its own to pin. The fifth arm needs a second
    # certificate of one team, and the gaps table in README.md states that.
    identity_example() {
        FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
            cargo build --quiet --example identity -p fidelity
    }
    # The designated requirement of the running image, as codesign prints it.
    own_requirement() {
        codesign -d -r- "$ROOT/target/debug/examples/identity" 2>&1 |
            sed -n 's/^# designated => //p'
    }
    identity_adhoc_macos() {
        identity_example || return 1
        FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
            "$ROOT/target/debug/examples/identity" |
            grep 'platform_trust: Medium'
    }
    identity_clean_macos() {
        identity_example || return 1
        requirement=$(own_requirement) || return 1
        [ -n "$requirement" ] || return 1
        FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
            "$ROOT/target/debug/examples/identity" "$requirement" |
            grep 'expected_identity: clean'
    }
    identity_pinned_other_macos() {
        identity_example || return 1
        FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
            "$ROOT/target/debug/examples/identity" \
            'anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"' |
            grep 'expected_identity: High'
    }
    # The repackage arm. A copy that another party re-signs keeps every byte of
    # the code and gets another cdhash, so the pinned requirement fails.
    #
    # The check that the two hashes differ is what makes this control real. An
    # earlier form appended bytes instead, `codesign` refused the broken Mach-O,
    # and the copy kept the original signature. It then reported clean against
    # its own pin, which reads exactly like a control that worked.
    identity_repackaged_macos() {
        identity_example || return 1
        requirement=$(own_requirement) || return 1
        [ -n "$requirement" ] || return 1
        cp "$ROOT/target/debug/examples/identity" "$OUT/repackaged" || return 1
        codesign -f -s - --identifier repackaged.by.another.party \
            "$OUT/repackaged" > /dev/null 2>&1 || return 1
        after=$(codesign -d -r- "$OUT/repackaged" 2>&1 |
            sed -n 's/^# designated => //p')
        if [ "$after" = "$requirement" ]; then
            echo "the copy kept the original cdhash, so this control proves nothing"
            return 1
        fi
        FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
            "$OUT/repackaged" "$requirement" | grep 'expected_identity: High'
    }

    # The machine-host pair. The clean half is this machine, and the hostile
    # half is a macOS guest, because only a kernel that runs under a monitor
    # reports the other answer. `tests/platform/vm/macos/` builds that guest, and
    # `vm.sh macos setup` states the one step that stays manual.
    machine_hardware_macos() {
        cargo build --quiet --example machine -p fidelity || return 1
        "$ROOT/target/debug/examples/machine" | grep 'machine_host: clean'
    }
    machine_current_guest_macos() {
        cargo build --quiet --example machine -p fidelity || return 1
        "$ROOT/target/debug/examples/machine" | grep 'machine_host: Medium'
    }
    # The guest runs the same binary that the clean half ran. Host and guest
    # take one target triple, so no build happens in the guest and the guest
    # needs no tool chain of its own.
    #
    # It needs no account either. `provision.sh` writes a launch daemon into
    # the guest disk, the daemon runs the control at boot and stops the guest,
    # and the answer comes back off the same disk. The setup assistant never
    # appears, so this control needs nobody to answer a window.
    MACOS_GUEST=$ROOT/target/vm/macos/image
    machine_guest_macos() {
        cargo build --quiet --example machine -p fidelity || return 1
        "$ROOT/tests/platform/vm/macos/provision.sh" "$MACOS_GUEST" \
            "$ROOT/target/debug/examples/machine" > /dev/null || return 1
        "$ROOT/target/vm/macos/guest" run "$MACOS_GUEST" > /dev/null 2>&1 || return 1
        "$ROOT/tests/platform/vm/macos/provision.sh" "$MACOS_GUEST" --read |
            grep 'machine_host: Medium'
    }

    run macOS cost-macos cargo run --release --quiet --example cost -p fidelity-probe-apple
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        skip macOS machine-hardware-macos \
            "the GitHub runner is a virtual machine, so it cannot prove the hardware arm"
        run macOS machine-guest-macos machine_current_guest_macos
    elif [ -f "$MACOS_GUEST/disk.img" ]; then
        run macOS machine-hardware-macos machine_hardware_macos
        run macOS machine-guest-macos machine_guest_macos
    else
        run macOS machine-hardware-macos machine_hardware_macos
        skip macOS machine-guest-macos \
            "no macOS guest image. Build one with: tests/platform/controls/vm.sh macos build"
    fi
    run macOS identity-adhoc-macos identity_adhoc_macos
    run macOS identity-clean-macos identity_clean_macos
    run macOS identity-repackaged-macos identity_repackaged_macos
    run macOS identity-pinned-other-macos identity_pinned_other_macos
    run macOS local-agent-hostile-macos local_agent_hostile_macos
    run macOS local-agent-unrelated-macos local_agent_unrelated_macos
    run macOS baseline-hostile baseline_hostile
    refute macOS baseline-clean 'no code arrived after start' baseline_clean
    run macOS baseline-writable-macos baseline_writable_macos
    run macOS baseline-limit-macos baseline_limit_macos
    run macOS tracer-clean tracer_clean
    run macOS tracer-at-start tracer_at_start
    run macOS tracer-attaches tracer_attaches
    run macOS resume-after-freeze resume_after_freeze
    run macOS dispatch-hostile-macos dispatch_hostile_macos
    refute macOS dispatch-clean-macos 'no dispatch target moved after start' \
        dispatch_clean_macos
    run macOS plugin-load plugin_load
    run macOS legitimate-plugin legitimate_plugin
    refute macOS legitimate-cached 'no code arrived after start' legitimate_cached
else
    for control in cost-macos machine-hardware-macos machine-guest-macos \
        identity-adhoc-macos identity-clean-macos \
        identity-repackaged-macos identity-pinned-other-macos \
        local-agent-hostile-macos local-agent-unrelated-macos \
        baseline-hostile baseline-clean \
        baseline-writable-macos baseline-limit-macos \
        tracer-clean tracer-at-start tracer-attaches resume-after-freeze \
        dispatch-hostile-macos dispatch-clean-macos \
        plugin-load legitimate-plugin legitimate-cached; do
        skip macOS "$control" "this machine does not run macOS"
    done
fi

# ------------------------------------------------- macOS runs on ARM64 alone
#
# No x86_64 macOS control runs here, and that is a scope decision. Apple
# Silicon runs an x86_64 build under Rosetta, so seven controls did run and
# pass on 2026-08-18. The supported-targets table in
# `docs/plan/04-detectors-and-platforms.md` now names ARM64 alone for macOS,
# because no Intel Mac is in scope, and a control that carries no promise is
# a control that nobody has to keep working.
# -------------------------------------------------------------------------- iOS

SIMULATOR=${FIDELITY_IOS_SIM:-}
if [ -z "$SIMULATOR" ]; then
    SIMULATOR=$(xcrun simctl list devices 2>/dev/null |
        awk '/Booted/ {print $(NF-1)}' | tr -d '()' | head -1)
fi
if [ -n "$SIMULATOR" ]; then
    ios() {
        env FIDELITY_IOS_SIM="$SIMULATOR" \
            CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER="$ROOT/tests/platform/controls/run-ios.sh" \
            cargo "$@" --target aarch64-apple-ios-sim
    }
    # Builds one example for the simulator, and prints where it landed.
    sim_build() {
        cargo build --quiet --example "$1" -p fidelity \
            --target aarch64-apple-ios-sim || return 1
        printf '%s\n' "$ROOT/target/aarch64-apple-ios-sim/debug/examples/$1"
    }

    # Runs one example inside the simulator.
    sim_run() {
        binary=$(sim_build "$1") || return 1
        shift
        xcrun simctl spawn "$SIMULATOR" "$binary" "$@"
    }

    # The identity pair. Cargo signs a local build ad hoc, and an ad-hoc
    # signature names no team, so a pinned team reports and an absent one
    # accepts. Apple refuses to launch a self-signed image that carries the
    # team entitlement, so the clean half of the positive route needs a
    # provisioned build. The gaps table in README.md states that.
    identity_clean_ios() { sim_run identity | grep 'protected operation: allowed'; }
    identity_pinned_team_ios() {
        sim_run identity ABCDE12345 | grep 'the running image names none'
    }

    # The simulator reports the host architecture instead of an iOS product.
    machine_simulator_ios() {
        sim_run machine | grep 'SimulatedEnvironment'
    }

    local_agent_hostile_ios() {
        sim_run local-agent frida | grep 'local_agent: Medium'
    }
    local_agent_unrelated_ios() {
        sim_run local-agent unrelated | grep 'local_agent: clean'
    }

    # The tracer set, in the same three shapes as macOS, Linux, and Windows.
    # `lldb` launches a simulator binary by itself, and the process it makes is
    # an ordinary process of this machine, so `lldb -p` reaches it as well.
    tracer_clean_ios() { sim_run tracer | grep 'tracer_present: clean'; }
    tracer_at_start_ios() {
        binary=$(sim_build tracer) || return 1
        lldb -b -o run -- "$binary" | grep 'protected operation: denied'
    }
    tracer_attaches_ios() {
        binary=$(sim_build attach) || return 1
        printf '#!/bin/sh\nexec xcrun simctl spawn %s %s\n' \
            "$SIMULATOR" "$binary" > "$OUT/ios-subject" || return 1
        chmod +x "$OUT/ios-subject" || return 1
        "$ROOT/tests/platform/controls/trace-after-start.sh" "$OUT/ios-subject" lldb -p
    }

    # The resume promise, on the first of the two systems that it names. The
    # simulator runs the subject as an ordinary process of this machine, so the
    # freeze reaches it from here. A device suspends an application itself, and
    # tests/platform/README.md holds that gap.
    resume_after_freeze_ios() {
        binary=$(sim_build resume) || return 1
        printf '#!/bin/sh\nexec xcrun simctl spawn %s %s\n' \
            "$SIMULATOR" "$binary" > "$OUT/ios-resume" || return 1
        chmod +x "$OUT/ios-resume" || return 1
        "$ROOT/tests/platform/controls/resume-after-freeze.sh" "$OUT/ios-resume"
    }

    # The dispatch pair, in the shape that the macOS section states. The
    # simulator passes a variable to the child under the `SIMCTL_CHILD_`
    # prefix alone, which the baseline pair below records.
    dispatch_ios_dylib() {
        sdk=$(xcrun --sdk iphonesimulator --show-sdk-path) || return 1
        clang -arch arm64 -isysroot "$sdk" -mios-simulator-version-min=26.0 \
            -dynamiclib -o "$OUT/hook-ios.dylib" \
            "$ROOT/tests/platform/controls/hook-macos.c"
    }
    dispatch_hostile_ios() {
        binary=$(sim_build redirect) || return 1
        dispatch_ios_dylib || return 1
        env SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$OUT/hook-ios.dylib" \
            xcrun simctl spawn "$SIMULATOR" "$binary" | grep 'DispatchRedirected'
    }
    dispatch_clean_ios() {
        binary=$(sim_build redirect) || return 1
        xcrun simctl spawn "$SIMULATOR" "$binary"
    }

    # The runtime-baseline pair. `simctl spawn` gives a variable to the child
    # under the `SIMCTL_CHILD_` prefix only. A plain `DYLD_INSERT_LIBRARIES`
    # reaches nothing, and the run then reports a clean result that measured no
    # agent at all, which reads exactly like a passing control. Measured on
    # 2026-08-18.
    late_ios() {
        sdk=$(xcrun --sdk iphonesimulator --show-sdk-path) || return 1
        clang -dynamiclib -target arm64-apple-ios17.0-simulator -isysroot "$sdk" \
            -o "$OUT/delayed-ios.dylib" "$ROOT/tests/platform/controls/delayed.c" || return 1
        binary=$(sim_build late) || return 1
        env "$@" xcrun simctl spawn "$SIMULATOR" "$binary"
    }
    baseline_hostile_ios() {
        late_ios SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$OUT/delayed-ios.dylib"
    }
    baseline_clean_ios() { late_ios SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=; }

    baseline_boundary_ios() {
        sdk=$(xcrun --sdk iphonesimulator --show-sdk-path) || return 1
        clang -dynamiclib -target arm64-apple-ios17.0-simulator -isysroot "$sdk" \
            -o "$OUT/baseline-boundaries-ios.dylib" \
            "$ROOT/tests/platform/controls/baseline-boundaries.c" || return 1
        binary=$(sim_build baseline-boundaries) || return 1
        env SIMCTL_CHILD_FIDELITY_BASELINE_BOUNDARY="$1" \
            SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$OUT/baseline-boundaries-ios.dylib" \
            xcrun simctl spawn "$SIMULATOR" "$binary" "$1"
    }
    baseline_writable_ios() { baseline_boundary_ios writable; }
    baseline_limit_ios() { baseline_boundary_ios limit; }

    run iOS ios-probe-tests ios test -p fidelity-probe-apple
    run iOS cost-ios ios run --release --quiet --example cost -p fidelity-probe-apple
    run iOS machine-simulator-ios machine_simulator_ios
    run iOS identity-clean-ios identity_clean_ios
    run iOS identity-pinned-team-ios identity_pinned_team_ios
    run iOS local-agent-hostile-ios local_agent_hostile_ios
    run iOS local-agent-unrelated-ios local_agent_unrelated_ios
    run iOS tracer-clean-ios tracer_clean_ios
    run iOS tracer-at-start-ios tracer_at_start_ios
    run iOS tracer-attaches-ios tracer_attaches_ios
    run iOS resume-after-freeze-ios resume_after_freeze_ios
    run iOS dispatch-hostile-ios dispatch_hostile_ios
    refute iOS dispatch-clean-ios 'no dispatch target moved after start' \
        dispatch_clean_ios
    run iOS baseline-hostile-ios baseline_hostile_ios
    refute iOS baseline-clean-ios 'no code arrived after start' baseline_clean_ios
    run iOS baseline-writable-ios baseline_writable_ios
    run iOS baseline-limit-ios baseline_limit_ios
else
    for control in ios-probe-tests cost-ios machine-simulator-ios \
        identity-clean-ios identity-pinned-team-ios \
        local-agent-hostile-ios local-agent-unrelated-ios \
        tracer-clean-ios tracer-at-start-ios tracer-attaches-ios \
        resume-after-freeze-ios dispatch-hostile-ios dispatch-clean-ios \
        baseline-hostile-ios baseline-clean-ios \
        baseline-writable-ios baseline-limit-ios; do
        skip iOS "$control" \
            "no simulator is booted: xcrun simctl boot \"iPhone 16 Pro\""
    done
fi

# ---------------------------------------------------------- physical iPhone

if [ -n "${FIDELITY_IOS_DEVICE:-}" ] && [ -n "${FIDELITY_IOS_TEAM:-}" ]; then
    run iOS identity-device-ios \
        "$ROOT/tests/platform/controls/run-ios-device.sh" identity
    run iOS machine-device-ios \
        "$ROOT/tests/platform/controls/run-ios-device.sh" machine
    run iOS cost-device-ios \
        "$ROOT/tests/platform/controls/run-ios-device.sh" cost
    run iOS local-agent-device-ios \
        "$ROOT/tests/platform/controls/run-ios-device.sh" local-agent
else
    skip iOS identity-device-ios \
        "set FIDELITY_IOS_DEVICE and FIDELITY_IOS_TEAM for a physical iPhone"
    skip iOS machine-device-ios \
        "set FIDELITY_IOS_DEVICE and FIDELITY_IOS_TEAM for a physical iPhone"
    skip iOS cost-device-ios \
        "set FIDELITY_IOS_DEVICE and FIDELITY_IOS_TEAM for a physical iPhone"
    skip iOS local-agent-device-ios \
        "set FIDELITY_IOS_DEVICE and FIDELITY_IOS_TEAM for a physical iPhone"
fi

# ------------------------------------------------------------------------ Linux

# The controls run in the guest that `controls/vm.sh` manages, and not in a
# container. A container shares the kernel of its host, so it has no filesystem
# of its own and fs-verity cannot be enabled there, and it needed
# `--cap-add=SYS_PTRACE` for the tracer controls. A guest owns its kernel and
# its disk, so both of those answers become real.
#
# The workspace arrives over 9p at /work, which is where the container mounted
# it, so a control reads one path either way. The build directory stays on the
# disk of the guest, because a build over a shared filesystem is far slower.
# Two machines reach these controls, and a machine that is already Linux is
# one of them. A guest is what a Mac needs, and it must not become what a Linux
# host needs as well: a runner that is Linux would otherwise skip every row it
# can answer natively.
#
# Both forms run the same command text, and only the place changes, so a
# control cannot drift between them.
LINUX_HOW=''
if [ "$(uname -s)" = Linux ]; then
    LINUX_HOW="on this machine"
    linux() {
        sh -c "cd $ROOT &&
            export FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
                   CARGO_TARGET_DIR=/var/tmp/target &&
            $*"
    }
elif "$ROOT/tests/platform/controls/vm.sh" linux status > /dev/null 2>&1; then
    LINUX_HOW="in the guest"
    linux() {
        "$ROOT/tests/platform/controls/vm.sh" linux run "cd /work &&
            . \$HOME/.cargo/env &&
            export FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
                   CARGO_TARGET_DIR=/var/tmp/target &&
            $*"
    }
fi

if [ -n "$LINUX_HOW" ]; then
    # The unaccounted-code pair. A loader that maps a library from a file must
    # not trip the detector, and an agent that maps anonymous executable memory
    # must. The guest holds `build-essential`, so it builds each agent itself.
    inject_clean() {
        linux 'cargo run --quiet --example inject -p fidelity' |
            grep 'unaccounted_code: clean'
    }
    inject_hostile() {
        linux 'cc -shared -fPIC -o /tmp/agent.so tests/platform/controls/agent.c &&
            LD_PRELOAD=/tmp/agent.so cargo run --quiet --example inject -p fidelity' |
            grep 'unaccounted_code: Medium'
    }
    image_catalog_clean_linux() {
        linux 'cargo run --quiet --example image-catalog -p fidelity' |
            grep 'image catalog: clean'
    }
    image_catalog_hostile_linux() {
        linux 'cc -shared -fPIC -o /tmp/catalog-map.so \
                tests/platform/controls/catalog-map.c -ldl &&
            LD_PRELOAD=/tmp/catalog-map.so \
                cargo run --quiet --example image-catalog -p fidelity' |
            grep 'image catalog: Medium'
    }
    local_agent_hostile_linux() {
        linux 'cargo build --quiet --example local-agent --example local-agent-endpoint \
                -p fidelity || exit 1
            /var/tmp/target/debug/examples/local-agent-endpoint frida \
                >/tmp/endpoint.out & server=$!
            while ! grep -q ready /tmp/endpoint.out; do sleep 1; done
            /var/tmp/target/debug/examples/local-agent
            status=$?
            wait $server || status=1
            exit $status' | grep 'local_agent: Medium'
    }
    local_agent_unrelated_linux() {
        linux 'cargo build --quiet --example local-agent --example local-agent-endpoint \
                -p fidelity || exit 1
            /var/tmp/target/debug/examples/local-agent-endpoint unrelated \
                >/tmp/endpoint.out & server=$!
            while ! grep -q ready /tmp/endpoint.out; do sleep 1; done
            /var/tmp/target/debug/examples/local-agent
            status=$?
            wait $server || status=1
            exit $status' | grep 'local_agent: clean'
    }
    linux_late() {
        linux "cc -shared -fPIC -o /tmp/delayed.so tests/platform/controls/delayed.c -lpthread &&
            cargo build --quiet --example late -p fidelity &&
            LD_PRELOAD=$1 /var/tmp/target/debug/examples/late"
    }
    baseline_hostile_linux() { linux_late /tmp/delayed.so; }
    baseline_clean_linux() { linux_late ''; }

    baseline_boundary_linux() {
        linux "cc -shared -fPIC -o /tmp/baseline-boundaries.so \
                tests/platform/controls/baseline-boundaries.c -lpthread &&
            cargo build --quiet --example baseline-boundaries -p fidelity &&
            FIDELITY_BASELINE_BOUNDARY=$1 LD_PRELOAD=/tmp/baseline-boundaries.so \
                /var/tmp/target/debug/examples/baseline-boundaries $1"
    }
    baseline_writable_linux() { baseline_boundary_linux writable; }
    baseline_limit_linux() { baseline_boundary_linux limit; }

    # The dispatch pair. `hook.c`, with its shared walk in `dispatch.h`,
    # rewrites one entry of the main image's dispatch table so a call reaches
    # another function that already exists. It maps no new executable region,
    # so the runtime baseline reports clean and only this detector reports it.
    # The inside form points `memcpy` at `memmove`, which answers every call
    # correctly, so the subject keeps running.
    hook_build='cc -O2 -shared -fPIC -o /tmp/hook.so tests/platform/controls/hook.c -lpthread -ldl'
    dispatch_hostile_linux() {
        linux "$hook_build &&
            cargo build --quiet --example redirect -p fidelity &&
            LD_PRELOAD=/tmp/hook.so FIDELITY_HOOK=inside \
                /var/tmp/target/debug/examples/redirect" |
            grep 'DispatchRedirected'
    }
    dispatch_clean_linux() {
        linux 'cargo build --quiet --example redirect -p fidelity &&
            /var/tmp/target/debug/examples/redirect'
    }

    # The tracer set. `attach.c` is the tracer, in both of its forms, and it
    # needs no capability grant in a guest.
    tracer_clean_linux() {
        linux 'cargo build --quiet --example tracer -p fidelity &&
            /var/tmp/target/debug/examples/tracer' | grep 'tracer_present: clean'
    }
    tracer_at_start_linux() {
        linux 'cc -o /tmp/attach tests/platform/controls/attach.c &&
            cargo build --quiet --example tracer -p fidelity &&
            /tmp/attach /var/tmp/target/debug/examples/tracer' |
            grep 'protected operation: denied'
    }
    tracer_attaches_linux() {
        linux 'cc -o /tmp/attach tests/platform/controls/attach.c &&
            cargo build --quiet --example attach -p fidelity &&
            sh tests/platform/controls/trace-after-start.sh \
                /var/tmp/target/debug/examples/attach /tmp/attach'
    }

    run Linux linux-probe-tests linux cargo test -p fidelity-probe-linux
    run Linux cost-linux linux cargo run --release --quiet --example cost -p fidelity-probe-linux
    run Linux inject-clean inject_clean
    run Linux inject-hostile inject_hostile
    run Linux image-catalog-clean-linux image_catalog_clean_linux
    run Linux image-catalog-hostile-linux image_catalog_hostile_linux
    run Linux local-agent-hostile-linux local_agent_hostile_linux
    run Linux local-agent-unrelated-linux local_agent_unrelated_linux
    run Linux dispatch-hostile-linux dispatch_hostile_linux
    refute Linux dispatch-clean-linux 'no dispatch target moved after start' dispatch_clean_linux
    run Linux baseline-hostile-linux baseline_hostile_linux
    refute Linux baseline-clean-linux 'no code arrived after start' baseline_clean_linux
    run Linux baseline-writable-linux baseline_writable_linux
    run Linux baseline-limit-linux baseline_limit_linux
    # The same region counts. Linux holds no shared cache, so a system library
    # and a plugin each add one mapping, and the legitimate load reports.
    PLUG='printf "int plugin_entry(void){return 7;}\n" > /tmp/plug.c &&
        cc -shared -fPIC -o /tmp/plug.so /tmp/plug.c'
    plugin_load_linux() {
        counts=$(linux "$PLUG &&
            cc -o /tmp/plugin-load tests/platform/controls/plugin-load-linux.c -ldl &&
            /tmp/plugin-load /tmp/plug.so") || return 1
        printf '%s\n' "$counts"
        [ "$(printf '%s\n' "$counts" | grep -c '(+1)')" -eq 2 ]
    }
    legitimate_plugin_linux() {
        linux "$PLUG &&
            cc -shared -fPIC -o /tmp/legitimate.so tests/platform/controls/legitimate.c -ldl -lpthread &&
            cargo build --quiet --example late -p fidelity &&
            LD_PRELOAD=/tmp/legitimate.so FIDELITY_PLUGIN=/tmp/plug.so \
                /var/tmp/target/debug/examples/late"
    }

    # The expected-identity pair. An appended byte leaves an ELF image
    # runnable and changes its content, so the repackaged copy is what a
    # repackaged artifact really is, and not a value that a test made up.
    identity_build='cargo build --quiet --example identity -p fidelity &&
        cp /var/tmp/target/debug/examples/identity /tmp/original &&
        chmod +x /tmp/original'
    identity_clean_linux() {
        linux "$identity_build &&
            /tmp/original \$(sha256sum /tmp/original | cut -d\" \" -f1)" |
            grep 'expected_identity: clean'
    }
    identity_repackaged_linux() {
        linux "$identity_build &&
            digest=\$(sha256sum /tmp/original | cut -d\" \" -f1) &&
            cp /tmp/original /tmp/repackaged &&
            printf '\\0' >> /tmp/repackaged &&
            chmod +x /tmp/repackaged &&
            /tmp/repackaged \$digest" |
            grep 'expected_identity: High'
    }

    # The platform-trust pair. fs-verity needs a filesystem block size equal to
    # the page size, and `mkfs.ext4` chooses 1024-byte blocks for an image this
    # small, so `-b 4096` is not optional: without it the enable fails with
    # EINVAL, which names nothing.
    # The teardown comes first, because a guest keeps its state between runs.
    # An earlier run leaves the image mounted on a loop device, and `mkfs`
    # against a mounted image then fails, so the second run of the day
    # reported `/tmp/verity.img is already mounted`. Measured on 2026-08-16.
    verity_linux() {
        linux 'sudo umount /mnt/verity 2> /dev/null || true;
            sudo losetup -j /tmp/verity.img | cut -d: -f1 |
                xargs -r -n1 sudo losetup -d 2> /dev/null || true;
            dd if=/dev/zero of=/tmp/verity.img bs=1M count=256 status=none &&
            sudo /sbin/mkfs.ext4 -q -b 4096 -O verity -F /tmp/verity.img &&
            sudo mkdir -p /mnt/verity &&
            sudo mount -o loop /tmp/verity.img /mnt/verity &&
            cargo build --quiet --example identity -p fidelity &&
            sudo cp /var/tmp/target/debug/examples/identity /mnt/verity/identity &&
            sudo fsverity enable /mnt/verity/identity &&
            cd /mnt/verity && ./identity' |
            grep 'platform_trust: clean'
    }

    run Linux identity-clean-linux identity_clean_linux
    machine_guest_linux() {
        linux 'cargo run --quiet --example machine -p fidelity' |
            grep 'machine_host: Medium'
    }
    machine_hardware_linux() {
        linux 'cargo run --quiet --example machine -p fidelity' |
            grep 'machine_host: clean'
    }
    # The masked-firmware control, which proves that a failed read reports its
    # health and never the hardware. A user and mount namespace holds a fresh
    # tmpfs over the firmware directory, and a file named `id` sits in it, so a
    # read of `/sys/class/dmi/id/sys_vendor` fails with `ENOTDIR` rather than
    # with an absent file. That is the container case that the fix guards: a
    # read error must report a `Low` health finding, and a walk that treated the
    # error as an absent firmware reported `clean`. The example lowers the
    # threshold, but the health finding sits on the machine-host detector, and
    # `machine_host: Low` is the line that only the fix produces.
    machine_masked_linux() {
        linux 'cargo build --quiet --example machine -p fidelity &&
            unshare -rm sh -c "
                mount -t tmpfs none /sys/class/dmi &&
                : > /sys/class/dmi/id &&
                /var/tmp/target/debug/examples/machine"' |
            grep 'machine_host: Low'
    }

    run Linux identity-repackaged-linux identity_repackaged_linux
    if linux 'sudo -n true && command -v fsverity' > /dev/null 2>&1; then
        run Linux verity-linux verity_linux
    else
        skip Linux verity-linux "no passwordless sudo, or no fsverity tool"
    fi

    run Linux tracer-clean-linux tracer_clean_linux
    run Linux tracer-at-start-linux tracer_at_start_linux
    run Linux tracer-attaches-linux tracer_attaches_linux
    run Linux plugin-load-linux plugin_load_linux
    run Linux legitimate-plugin-linux legitimate_plugin_linux
    # The machine-host pair. A guest must report a monitor. A verified physical
    # host must report the hardware. The flag makes the operator state the
    # precondition, because a native Linux runner can still be a guest.
    if [ "$LINUX_HOW" = "in the guest" ]; then
        skip Linux machine-hardware-linux "the project guest cannot prove the hardware arm"
        run Linux machine-guest-linux machine_guest_linux
    elif [ "${FIDELITY_PHYSICAL_HOST:-}" = 1 ]; then
        run Linux machine-hardware-linux machine_hardware_linux
        skip Linux machine-guest-linux "the physical host cannot prove the guest arm"
    else
        skip Linux machine-hardware-linux "set FIDELITY_PHYSICAL_HOST=1 on verified hardware"
        skip Linux machine-guest-linux "this machine runs Linux, and the harness cannot state \
whether it runs on the hardware or inside a monitor"
    fi
    # The masked-firmware control runs on the hardware and in a guest alike,
    # because a failed read reports the same health on either machine. It needs
    # an unprivileged user namespace to hold the mount, so it skips where one
    # is off.
    if linux 'unshare -rm true' > /dev/null 2>&1; then
        run Linux machine-masked-linux machine_masked_linux
    else
        skip Linux machine-masked-linux "no unprivileged user namespace, so no mount masks /sys"
    fi
else
    for control in linux-probe-tests cost-linux inject-clean inject-hostile \
        image-catalog-clean-linux image-catalog-hostile-linux \
        local-agent-hostile-linux local-agent-unrelated-linux \
        dispatch-hostile-linux dispatch-clean-linux \
        baseline-hostile-linux baseline-clean-linux \
        baseline-writable-linux baseline-limit-linux \
        identity-clean-linux identity-repackaged-linux verity-linux \
        tracer-clean-linux tracer-at-start-linux tracer-attaches-linux \
        plugin-load-linux legitimate-plugin-linux machine-hardware-linux machine-guest-linux \
        machine-masked-linux; do
        skip Linux "$control" "this machine runs no Linux, and no guest answers: \
tests/platform/controls/vm.sh linux start"
    done
fi

# ---------------------------------------------------------------------- Windows

# Windows offers no preload variable, so every hostile control here reaches the
# subject from outside. `controls/inject-windows.c` maps the memory and
# `controls/attach-windows.c` is the tracer, and each one takes a process
# identifier or a program, in the same two forms that `attach.c` takes on Linux.
#
# A Windows probe answers only on Windows, so a control here needs a Windows
# machine. The cross-check above still builds the crate from every machine.
#
# Two machines reach these controls. A Windows runner is one, and the guest
# that `controls/vm.sh` manages is the other. Both forms run the same command
# text, and only the place changes, so a control cannot drift between them.
# The Linux section above takes the same shape.
#
# The guest reads the workspace at C:\work, because Windows drives no 9p, so
# the copy travels once before the first control runs. The Linux guest mounts
# the workspace instead, and that is the only difference between the two.
#
# `controls/build-control.sh` compiles a control in either place. It picks the
# compiler, and it converts a path with `cygpath`, so this file names neither.
#
# Each command text stays in single quotes, so the shell that runs it expands
# `cygpath`. The guest expands in the guest, and a runner expands on the
# runner. Double quotes would expand on the Mac, which holds no `cygpath`.
WINDOWS=no
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) WINDOWS=yes ;;
esac

# A runner needs a compiler of its own. The guest gets one from the Packer
# build, so only the native form asks.
WINDOWS_CC=''
for candidate in cl clang gcc; do
    if command -v "$candidate" > /dev/null 2>&1; then
        WINDOWS_CC=$candidate
        break
    fi
done

WINDOWS_HOW=''
if [ "$WINDOWS" = yes ] && [ -n "$WINDOWS_CC" ]; then
    WINDOWS_HOW="on this machine"
    windows() {
        sh -c "cd $ROOT &&
            export FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none &&
            $*"
    }
elif "$ROOT/tests/platform/controls/vm.sh" windows status > /dev/null 2>&1; then
    WINDOWS_HOW="in the guest"
    "$ROOT/tests/platform/controls/vm.sh" windows push > /dev/null 2>&1 ||
        WINDOWS_HOW=''
    windows() {
        "$ROOT/tests/platform/controls/vm.sh" windows run "cd /c/work &&
            export FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none &&
            $*"
    }
fi

if [ -n "$WINDOWS_HOW" ]; then
    # The clean control for both memory detectors, and the boundary tests that
    # only this system can run.
    windows_probe_tests() {
        windows 'cargo test --quiet -p fidelity-probe-windows'
    }
    cost_windows() {
        windows 'cargo run --release --quiet --example cost \
            -p fidelity-probe-windows'
    }

    # The image-identity set. Every arm needs a signed subject, so
    # `controls/sign-windows.ps1` makes one certificate that the machine
    # anchors and one that it does not, and it signs a copy with each. The
    # host pins the SHA-256 of a certificate, and the detector compares that
    # against the certificate that signed the running image.
    #
    # The script writes to the root store of the machine, so these arms run in
    # the guest and nowhere else. A guest throws its overlay away, and a
    # runner would keep the anchor.
    SIGN='powershell -NoProfile -ExecutionPolicy Bypass \
        -File tests/platform/controls/sign-windows.ps1 \
        -Source "$(cygpath -w target/debug/examples/identity.exe)" \
        -OutDir "$(cygpath -w target/platform)"'
    identity_clean_windows() {
        windows "cargo build --quiet --example identity -p fidelity &&
            $SIGN &&
            target/platform/signed-trusted.exe \
                \"\$(cat target/platform/trusted-sha256.txt)\"" |
            grep 'protected operation: allowed'
    }
    # The image carries a signature that validates, and the host pinned
    # another signer. That is a repackage that kept a valid signature.
    identity_other_signer_windows() {
        windows "cargo build --quiet --example identity -p fidelity &&
            $SIGN &&
            target/platform/signed-trusted.exe \
                \"\$(cat target/platform/untrusted-sha256.txt)\"" |
            grep 'expected_identity: High'
    }
    # The image carries a signature that nothing anchors. Both tiers report,
    # and the platform-trust tier states that the signature did not validate,
    # which is the branch that neither other arm reaches.
    identity_untrusted_windows() {
        windows "cargo build --quiet --example identity -p fidelity &&
            $SIGN &&
            target/platform/signed-untrusted.exe \
                \"\$(cat target/platform/trusted-sha256.txt)\"" |
            grep 'did not validate'
    }

    guarded_windows() {
        windows 'export FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none
            cargo build --quiet --example guarded -p fidelity || exit 1
            powershell -NoProfile -ExecutionPolicy Bypass \
                -File tests/platform/controls/sign-windows.ps1 \
                -Source "$(cygpath -w target/debug/examples/guarded.exe)" \
                -OutDir "$(cygpath -w target/platform)" || exit 1
            digest=$(cat target/platform/trusted-sha256.txt)
            export FIDELITY_CODE_IDENTITY=windows:$digest
            cargo build --quiet --example guarded -p fidelity || exit 1
            powershell -NoProfile -ExecutionPolicy Bypass \
                -File tests/platform/controls/sign-guarded-windows.ps1 \
                -Source "$(cygpath -w target/debug/examples/guarded.exe)" \
                -OutDir "$(cygpath -w target/platform)" || exit 1
            target/platform/guarded-trusted.exe >target/platform/guarded-clean.out || exit 1
            grep -q "host: api.example.com" target/platform/guarded-clean.out || exit 1
            target/platform/guarded-untrusted.exe >target/platform/guarded-hostile.out || exit 1
            grep -q "host:" target/platform/guarded-hostile.out || exit 1
            if grep -q "api.example.com" target/platform/guarded-hostile.out; then exit 1; fi
            if target/debug/examples/guarded.exe >target/platform/guarded-unsigned.out 2>&1; then
                exit 1
            fi
            grep -q IdentityBindingUnavailable target/platform/guarded-unsigned.out'
    }

    inject_clean_windows() {
        windows 'cargo build --quiet --example inject -p fidelity &&
            target/debug/examples/inject.exe' |
            grep 'unaccounted_code: clean'
    }
    # The region is in place before the subject runs its first instruction,
    # which is what a preloaded library gives on Linux.
    inject_hostile_windows() {
        windows 'cargo build --quiet --example inject -p fidelity &&
            sh tests/platform/controls/build-control.sh inject-windows &&
            target/platform/inject-windows.exe \
                "$(cygpath -w target/debug/examples/inject.exe)"' |
            grep 'unaccounted_code: Medium'
    }

    image_catalog_clean_windows() {
        windows 'cargo build --quiet --example image-catalog -p fidelity &&
            target/debug/examples/image-catalog.exe' |
            grep 'image catalog: clean'
    }
    image_catalog_hostile_windows() {
        # build-control.sh compiles controls/catalog-map-windows.c.
        windows 'cargo build --quiet --example image-catalog -p fidelity &&
            sh tests/platform/controls/build-control.sh catalog-map-windows &&
            target/platform/catalog-map-windows.exe \
                "$(cygpath -w target/debug/examples/image-catalog.exe)"' |
            grep 'image catalog: Medium'
    }
    local_agent_hostile_windows() {
        windows 'cargo build --quiet --example local-agent --example local-agent-endpoint \
                -p fidelity || exit 1
            target/debug/examples/local-agent-endpoint.exe frida \
                >target/platform/endpoint.out & server=$!
            while ! grep -q ready target/platform/endpoint.out; do sleep 1; done
            target/debug/examples/local-agent.exe
            status=$?
            wait $server || status=1
            exit $status' | grep 'local_agent: Medium'
    }
    local_agent_unrelated_windows() {
        windows 'cargo build --quiet --example local-agent --example local-agent-endpoint \
                -p fidelity || exit 1
            target/debug/examples/local-agent-endpoint.exe unrelated \
                >target/platform/endpoint.out & server=$!
            while ! grep -q ready target/platform/endpoint.out; do sleep 1; done
            target/debug/examples/local-agent.exe
            status=$?
            wait $server || status=1
            exit $status' | grep 'local_agent: clean'
    }

    # The runtime-baseline pair. The hostile half maps into a process that
    # already captured its baseline, so only the worker can catch it.
    baseline_hostile_windows() {
        windows 'cargo build --quiet --example late -p fidelity &&
            sh tests/platform/controls/build-control.sh inject-windows &&
            sh tests/platform/controls/trace-after-start.sh \
                target/debug/examples/late.exe \
                target/platform/inject-windows.exe'
    }
    baseline_clean_windows() {
        windows 'cargo build --quiet --example late -p fidelity &&
            target/debug/examples/late.exe'
    }

    # `baseline-boundaries-windows.c` owns both Windows memory subjects.
    baseline_boundary_windows() {
        windows "cargo build --quiet --example baseline-boundaries -p fidelity &&
            sh tests/platform/controls/build-control.sh baseline-boundaries-windows &&
            target/platform/baseline-boundaries-windows.exe $1 \
                \"\$(cygpath -w target/debug/examples/baseline-boundaries.exe) $1\""
    }
    baseline_writable_windows() { baseline_boundary_windows writable; }
    baseline_limit_windows() { baseline_boundary_windows limit; }

    # The dispatch pair. `iat-hook-windows.c` redirects one import address table
    # entry of the subject after start, to an address that another entry already
    # holds. It maps no new region, so the runtime baseline reports clean and
    # only this detector reports it. The subject already runs, so only the
    # worker catches it, and `trace-after-start.sh` drives it.
    dispatch_hostile_windows() {
        windows 'cargo build --quiet --example redirect -p fidelity &&
            sh tests/platform/controls/build-control.sh iat-hook-windows &&
            sh tests/platform/controls/trace-after-start.sh \
                target/debug/examples/redirect.exe \
                target/platform/iat-hook-windows.exe'
    }
    dispatch_clean_windows() {
        windows 'cargo build --quiet --example redirect -p fidelity &&
            target/debug/examples/redirect.exe'
    }
    # The hidden-redirect control, which proves the terminator-gap fix.
    # `hidden-iat-hook-windows.c` zeros one startup-only import, which is a fake
    # terminator, and it redirects a later import in the same library, which
    # sits behind that zero. A walk of the address table stopped at the zero and
    # reported clean. The reader now counts the lookup table, so the redirect
    # stays in the snapshot and this detector reports it.
    dispatch_hidden_windows() {
        windows 'cargo build --quiet --example redirect -p fidelity &&
            sh tests/platform/controls/build-control.sh hidden-iat-hook-windows &&
            sh tests/platform/controls/trace-after-start.sh \
                target/debug/examples/redirect.exe \
                target/platform/hidden-iat-hook-windows.exe'
    }

    # The tracer set, in the same three shapes as macOS and Linux.
    tracer_clean_windows() {
        windows 'cargo build --quiet --example tracer -p fidelity &&
            target/debug/examples/tracer.exe' |
            grep 'tracer_present: clean'
    }
    tracer_at_start_windows() {
        windows 'cargo build --quiet --example tracer -p fidelity &&
            sh tests/platform/controls/build-control.sh attach-windows &&
            target/platform/attach-windows.exe \
                "$(cygpath -w target/debug/examples/tracer.exe)"' |
            grep 'protected operation: denied'
    }
    tracer_attaches_windows() {
        windows 'cargo build --quiet --example attach -p fidelity &&
            sh tests/platform/controls/build-control.sh attach-windows &&
            sh tests/platform/controls/trace-after-start.sh \
                target/debug/examples/attach.exe \
                target/platform/attach-windows.exe'
    }

    # The second architecture of Windows. An ARM64 Windows runs an x64 image
    # under its own emulation, so these four controls need no second machine.
    # The emulator generates code, and that is what makes them worth running:
    # `unaccounted_code` asks whether a file backs every executable region, and
    # a translator answers no. Measured on 2026-08-18.
    windows_x86() {
        windows "rustup target add x86_64-pc-windows-msvc > /dev/null 2>&1
            $*"
    }
    cost_windows_x86() {
        windows_x86 'cargo run --release --quiet --example cost \
            -p fidelity-probe-windows --target x86_64-pc-windows-msvc'
    }

    # A clean x64 process, which reports. The emulator maps about 1 MB of
    # executable memory with no file behind it, and the rule cannot separate
    # that from a manual mapper. This is the Windows half of the same limit
    # that a warmed Node process states on Linux.
    inject_emulated_x86() {
        windows_x86 'cargo build --quiet --example tracer -p fidelity \
            --target x86_64-pc-windows-msvc &&
            target/x86_64-pc-windows-msvc/debug/examples/tracer.exe' |
            grep 'unaccounted_code: Medium'
    }

    # The runtime baseline stays clean in the same process, because the
    # emulator maps its cache before `start()` reads the baseline and adds no
    # region afterwards. The two detectors answer differently here, and that
    # pair is the whole measurement.
    baseline_clean_x86_windows() {
        windows_x86 'cargo build --quiet --example late -p fidelity \
            --target x86_64-pc-windows-msvc &&
            target/x86_64-pc-windows-msvc/debug/examples/late.exe'
    }
    tracer_clean_x86_windows() {
        windows_x86 'cargo build --quiet --example tracer -p fidelity \
            --target x86_64-pc-windows-msvc &&
            target/x86_64-pc-windows-msvc/debug/examples/tracer.exe' |
            grep 'tracer_present: clean'
    }

    machine_guest_windows() {
        windows 'cargo run --quiet --example machine -p fidelity' |
            grep 'machine_host: Medium'
    }
    machine_hardware_windows() {
        windows 'cargo run --quiet --example machine -p fidelity' |
            grep 'machine_host: clean'
    }

    run Windows windows-probe-tests windows_probe_tests
    run Windows cost-windows cost_windows
    # The identity arms anchor a certificate on the machine that runs them, so
    # they take the guest and they skip everywhere else.
    if [ "$WINDOWS_HOW" = "in the guest" ]; then
        run Windows identity-clean-windows identity_clean_windows
        run Windows identity-other-signer-windows identity_other_signer_windows
        run Windows identity-untrusted-windows identity_untrusted_windows
        run Windows guarded-windows guarded_windows
    else
        for control in identity-clean-windows identity-other-signer-windows \
            identity-untrusted-windows; do
            skip Windows "$control" "this arm anchors a certificate on the machine, so it \
takes the guest: tests/platform/controls/vm.sh windows start"
        done
        skip Windows guarded-windows \
            "this arm anchors a certificate on the machine, so it takes the guest"
    fi
    run Windows inject-clean-windows inject_clean_windows
    run Windows inject-hostile-windows inject_hostile_windows
    run Windows image-catalog-clean-windows image_catalog_clean_windows
    run Windows image-catalog-hostile-windows image_catalog_hostile_windows
    run Windows local-agent-hostile-windows local_agent_hostile_windows
    run Windows local-agent-unrelated-windows local_agent_unrelated_windows
    run Windows dispatch-hostile-windows dispatch_hostile_windows
    run Windows dispatch-hidden-windows dispatch_hidden_windows
    refute Windows dispatch-clean-windows 'no dispatch target moved after start' \
        dispatch_clean_windows
    run Windows baseline-hostile-windows baseline_hostile_windows
    refute Windows baseline-clean-windows 'no code arrived after start' \
        baseline_clean_windows
    run Windows baseline-writable-windows baseline_writable_windows
    run Windows baseline-limit-windows baseline_limit_windows
    run Windows tracer-clean-windows tracer_clean_windows
    run Windows tracer-at-start-windows tracer_at_start_windows
    run Windows tracer-attaches-windows tracer_attaches_windows
    case "$(uname -m)" in
        arm64 | aarch64)
            run Windows cost-windows-x86 cost_windows_x86
            run Windows inject-emulated-x86 inject_emulated_x86
            refute Windows baseline-clean-x86-windows 'no code arrived after start' \
                baseline_clean_x86_windows
            run Windows tracer-clean-x86-windows tracer_clean_x86_windows
            ;;
        *)
            for control in cost-windows-x86 inject-emulated-x86 \
                baseline-clean-x86-windows tracer-clean-x86-windows; do
                skip Windows "$control" \
                    "this machine runs x86_64 directly, so it does not emulate x86_64"
            done
            ;;
    esac
    # The machine-host pair, in the shape that the Linux section states.
    if [ "$WINDOWS_HOW" = "in the guest" ]; then
        skip Windows machine-hardware-windows "the project guest cannot prove the hardware arm"
        run Windows machine-guest-windows machine_guest_windows
    elif [ "${FIDELITY_PHYSICAL_HOST:-}" = 1 ]; then
        run Windows machine-hardware-windows machine_hardware_windows
        skip Windows machine-guest-windows "the physical host cannot prove the guest arm"
    else
        skip Windows machine-hardware-windows "set FIDELITY_PHYSICAL_HOST=1 on verified hardware"
        skip Windows machine-guest-windows "this machine runs Windows, and the harness cannot \
state whether it runs on the hardware or inside a monitor"
    fi
else
    if [ "$WINDOWS" = yes ]; then
        WHY="no cl, clang, or gcc on the path, so no control compiles"
    else
        WHY="this machine runs no Windows, and no guest answers: \
tests/platform/controls/vm.sh windows start"
    fi
    for control in windows-probe-tests cost-windows \
        identity-clean-windows identity-other-signer-windows \
        identity-untrusted-windows \
        guarded-windows \
        inject-clean-windows inject-hostile-windows \
        image-catalog-clean-windows image-catalog-hostile-windows \
        local-agent-hostile-windows local-agent-unrelated-windows \
        dispatch-hostile-windows dispatch-hidden-windows dispatch-clean-windows \
        baseline-hostile-windows baseline-clean-windows \
        baseline-writable-windows baseline-limit-windows \
        tracer-clean-windows tracer-at-start-windows tracer-attaches-windows \
        cost-windows-x86 inject-emulated-x86 baseline-clean-x86-windows \
        tracer-clean-x86-windows machine-hardware-windows machine-guest-windows; do
        skip Windows "$control" "$WHY"
    done
fi

# ---------------------------------------------------------------------- Android

# Cargo links an Android binary with `cc`, which is the host compiler here. The
# attached target selects its Rust target and its NDK linker. The harness takes
# the newest installed NDK rather than a pinned path.
ANDROID_ABI=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
ANDROID_TARGET=''
ANDROID_CARGO_LINKER=''
ANDROID_CC=''
ANDROID_RUNNER=''
case "$ANDROID_ABI" in
    arm64-v8a)
        ANDROID_TARGET=aarch64-linux-android
        ANDROID_CARGO_LINKER=CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
        ANDROID_CC=CC_aarch64_linux_android
        ANDROID_RUNNER=CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER
        ;;
    x86_64)
        ANDROID_TARGET=x86_64-linux-android
        ANDROID_CARGO_LINKER=CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER
        ANDROID_CC=CC_x86_64_linux_android
        ANDROID_RUNNER=CARGO_TARGET_X86_64_LINUX_ANDROID_RUNNER
        ;;
esac

NDK_CC=''
if [ -n "$ANDROID_TARGET" ]; then
    NDK_CC=$(ls "${ANDROID_HOME:-}"/ndk/*/toolchains/llvm/prebuilt/*/bin/"$ANDROID_TARGET"*-clang \
        2>/dev/null | tail -1)
fi

# Every control that this section runs. Both skip arms below read this one
# list, because a control that a skip arm forgets leaves no row at all, and a
# record that never mentions it reads as complete coverage.
ANDROID_CONTROLS="android-probe-tests cost-android android-instrumented
    android-repackage tracer-clean-android tracer-at-start-android
    tracer-attaches-android resume-after-freeze-android
    baseline-clean-android baseline-hostile-android
    baseline-writable-android baseline-limit-android
    inject-clean-android inject-hostile-android
    image-catalog-clean-android image-catalog-hostile-android
    local-agent-hostile-android local-agent-unrelated-android
    dispatch-clean-android dispatch-hostile-android
    verified-boot-clean-android verified-boot-hostile-android
    machine-hardware-android machine-emulator-android"

if [ -z "$(adb devices 2>/dev/null | awk 'NR > 1 && $2 == "device" { print $1 }')" ]; then
    for control in $ANDROID_CONTROLS; do
        skip Android "$control" "no device answers adb"
    done
elif [ -z "$ANDROID_TARGET" ]; then
    for control in $ANDROID_CONTROLS; do
        skip Android "$control" "the device reports the unsupported ABI ${ANDROID_ABI:-none}"
    done
elif [ -z "$NDK_CC" ]; then
    for control in $ANDROID_CONTROLS; do
        skip Android "$control" "no $ANDROID_TARGET NDK linker under \$ANDROID_HOME/ndk"
    done
else
    android() {
        env "$ANDROID_CARGO_LINKER=$NDK_CC" \
            "$ANDROID_CC=$NDK_CC" \
            "$ANDROID_RUNNER=$ROOT/tests/platform/controls/run-android.sh" \
            cargo "$@" --target "$ANDROID_TARGET"
    }
    instrumented() {
        (cd "$ROOT/crates/probe/fidelity-probe-android/android" &&
            env FIDELITY_ANDROID_ABI="$ANDROID_ABI" FIDELITY_NDK_CC="$NDK_CC" ./gradlew "$@")
    }
    repackage() {
        instrumented assembleDebugAndroidTest > /dev/null 2>&1 || return 1
        (cd "$ROOT/crates/probe/fidelity-probe-android/android" &&
            "$ROOT/tests/platform/controls/repackage-android.sh")
    }
    # The detector controls. Until 2026-08-18 the coverage table claimed three
    # Android detectors that no control here reproduced, and its tracer row
    # named a physical device that this machine has never held. These run the
    # same examples and the same agents that Linux runs, because Android keeps
    # the Linux process filesystem and the Linux loader.
    #
    # Every control below pushes what it needs. A device name differs from the
    # source name where the two would collide: the Rust `attach` example is the
    # subject, and `attach.c` is the tracer that attaches to it.
    android_push() {
        adb push "$1" "/data/local/tmp/$2" > /dev/null 2>&1 &&
            adb shell chmod 755 "/data/local/tmp/$2"
    }
    android_example() {
        android build --quiet --example "$1" -p fidelity > /dev/null 2>&1 &&
            android_push "$ROOT/target/$ANDROID_TARGET/debug/examples/$1" "$2"
    }
    android_tracer_tool() {
        "$NDK_CC" -o "$OUT/attach-android" "$ROOT/tests/platform/controls/attach.c" &&
            android_push "$OUT/attach-android" attach-tool
    }
    # pthread is inside the Android libc, so neither agent needs `-lpthread`.
    android_agent() {
        "$NDK_CC" -shared -fPIC -o "$OUT/$1-android.so" \
            "$ROOT/tests/platform/controls/$1.c" &&
            android_push "$OUT/$1-android.so" "$1.so"
    }

    tracer_clean_android() {
        android_example tracer tracer &&
            adb shell /data/local/tmp/tracer | grep 'tracer_present: clean'
    }
    tracer_at_start_android() {
        android_example tracer tracer && android_tracer_tool &&
            adb shell '/data/local/tmp/attach-tool /data/local/tmp/tracer' |
            grep 'protected operation: denied'
    }
    tracer_attaches_android() {
        android_example attach subject && android_tracer_tool &&
            android_push "$ROOT/tests/platform/controls/trace-after-start.sh" \
                trace-after-start.sh &&
            # One line. `adb shell` passes a newline through, and the shell on
            # the device reads it as the end of the command, so a split here
            # runs the script with no argument and then runs the subject alone.
            adb shell 'sh /data/local/tmp/trace-after-start.sh /data/local/tmp/subject /data/local/tmp/attach-tool'
    }

    # The resume promise, on the second of the two systems that it names. The
    # script runs on the device, because the shell there owns the subject and
    # can freeze it. Android freezes a cached process with the cgroup freezer
    # rather than with a signal, and tests/platform/README.md holds the run that
    # measured the real mechanism and found the same answer.
    resume_after_freeze_android() {
        android_example resume resume &&
            android_push "$ROOT/tests/platform/controls/resume-after-freeze.sh" \
                resume-after-freeze.sh &&
            # One line, for the reason that the tracer control above states.
            adb shell 'sh /data/local/tmp/resume-after-freeze.sh /data/local/tmp/resume'
    }

    android_late() {
        android_example late late &&
            adb shell "cd /data/local/tmp && LD_PRELOAD=$1 ./late"
    }
    baseline_hostile_android() {
        android_agent delayed && android_late /data/local/tmp/delayed.so
    }
    baseline_clean_android() { android_late ''; }

    baseline_boundary_android() {
        android_example baseline-boundaries baseline-boundaries &&
            android_agent baseline-boundaries &&
            adb shell "FIDELITY_BASELINE_BOUNDARY=$1 \
                LD_PRELOAD=/data/local/tmp/baseline-boundaries.so \
                /data/local/tmp/baseline-boundaries $1"
    }
    baseline_writable_android() { baseline_boundary_android writable; }
    baseline_limit_android() { baseline_boundary_android limit; }

    inject_clean_android() {
        android_example inject inject &&
            adb shell /data/local/tmp/inject | grep 'unaccounted_code: clean'
    }
    inject_hostile_android() {
        android_example inject inject && android_agent agent &&
            adb shell 'LD_PRELOAD=/data/local/tmp/agent.so /data/local/tmp/inject' |
            grep 'unaccounted_code: Medium'
    }

    image_catalog_clean_android() {
        android_example image-catalog image-catalog &&
            adb shell /data/local/tmp/image-catalog | grep 'image catalog: clean'
    }
    image_catalog_hostile_android() {
        android_example image-catalog image-catalog &&
            "$NDK_CC" -shared -fPIC -o "$OUT/catalog-map-android.so" \
                "$ROOT/tests/platform/controls/catalog-map.c" -ldl &&
            android_push "$OUT/catalog-map-android.so" catalog-map.so &&
            adb shell 'LD_PRELOAD=/data/local/tmp/catalog-map.so \
                /data/local/tmp/image-catalog' | grep 'image catalog: Medium'
    }

    local_agent_android() {
        mode=$1
        android_example local-agent local-agent &&
            android_example local-agent-endpoint local-agent-endpoint &&
            adb shell "cd /data/local/tmp
                ./local-agent-endpoint $mode >endpoint.out & server=\$!
                while ! grep -q ready endpoint.out; do sleep 1; done
                ./local-agent
                status=\$?
                wait \$server || status=1
                exit \$status"
    }
    local_agent_hostile_android() {
        local_agent_android frida | grep 'local_agent: Medium'
    }
    local_agent_unrelated_android() {
        local_agent_android unrelated | grep 'local_agent: clean'
    }

    # The dispatch pair, in the shape that the Linux section states. `hook.c`
    # rewrites one entry of the dispatch table of the main image, and a shell
    # binary holds Fidelity in that image, so the probe reads the table that
    # the control rewrote.
    #
    # A shell binary cannot prove the rule that Android needs, because there
    # the main image and the library of the host are one image. The
    # instrumented test proves that one, inside a real application process.
    dispatch_hostile_android() {
        android_example redirect redirect && android_agent hook &&
            adb shell 'LD_PRELOAD=/data/local/tmp/hook.so FIDELITY_HOOK=inside /data/local/tmp/redirect' |
            grep 'DispatchRedirected'
    }
    dispatch_clean_android() {
        android_example redirect redirect && adb shell /data/local/tmp/redirect
    }

    verified_boot_clean_android() {
        android_example verified-boot verified-boot &&
            adb shell /data/local/tmp/verified-boot |
            grep 'device_compromise.verified_boot: clean'
    }
    verified_boot_hostile_android() {
        android_example verified-boot verified-boot &&
            adb shell /data/local/tmp/verified-boot |
            grep 'device_compromise.verified_boot: Medium, UnverifiedBoot'
    }

    # The machine-host pair. An emulator states itself in one of the same three
    # properties that the probe reads. A physical device needs an operator to
    # state the precondition, because an unknown virtual product can name an
    # unknown board and look like hardware.
    android_target_is_emulator() {
        boot=$(adb shell getprop ro.boot.qemu | tr -d '\r')
        characteristics=$(adb shell getprop ro.build.characteristics | tr -d '\r')
        board=$(adb shell getprop ro.hardware | tr -d '\r')
        if [ "$boot" = 1 ]; then
            return 0
        fi
        case ",$characteristics," in
            *,emulator,*) return 0 ;;
        esac
        case "$board" in
            goldfish | ranchu) return 0 ;;
        esac
        return 1
    }
    machine_emulator_android() {
        android_example machine machine &&
            adb shell /data/local/tmp/machine | grep 'machine_host: Medium'
    }
    machine_hardware_android() {
        android_example machine machine &&
            adb shell /data/local/tmp/machine | grep 'machine_host: clean'
    }

    run Android android-probe-tests android test -p fidelity-probe-android
    run Android cost-android android run --release --quiet --example cost -p fidelity-probe-android
    run Android android-instrumented instrumented connectedDebugAndroidTest
    run Android android-repackage repackage
    run Android tracer-clean-android tracer_clean_android
    run Android tracer-at-start-android tracer_at_start_android
    run Android tracer-attaches-android tracer_attaches_android
    run Android resume-after-freeze-android resume_after_freeze_android
    # The clean arm exits with a failure code by design, because the example
    # reports success when the worker finds the change. `refute` reads the
    # answer rather than the status, and Linux and iOS take the same route.
    refute Android baseline-clean-android 'no code arrived after start' baseline_clean_android
    run Android baseline-hostile-android baseline_hostile_android
    run Android baseline-writable-android baseline_writable_android
    run Android baseline-limit-android baseline_limit_android
    run Android inject-clean-android inject_clean_android
    run Android inject-hostile-android inject_hostile_android
    run Android image-catalog-clean-android image_catalog_clean_android
    run Android image-catalog-hostile-android image_catalog_hostile_android
    run Android local-agent-hostile-android local_agent_hostile_android
    run Android local-agent-unrelated-android local_agent_unrelated_android
    run Android dispatch-hostile-android dispatch_hostile_android
    refute Android dispatch-clean-android 'no dispatch target moved after start' \
        dispatch_clean_android
    case "${FIDELITY_ANDROID_VERIFIED_BOOT:-}" in
        clean)
            run Android verified-boot-clean-android verified_boot_clean_android
            skip Android verified-boot-hostile-android \
                "the locked device cannot prove the unlocked arm"
            ;;
        hostile)
            skip Android verified-boot-clean-android \
                "the unlocked device cannot prove the locked arm"
            run Android verified-boot-hostile-android verified_boot_hostile_android
            ;;
        *)
            skip Android verified-boot-clean-android \
                "set FIDELITY_ANDROID_VERIFIED_BOOT=clean on a verified locked device"
            skip Android verified-boot-hostile-android \
                "set FIDELITY_ANDROID_VERIFIED_BOOT=hostile on a verified unlocked device"
            ;;
    esac
    if [ "${FIDELITY_ANDROID_PHYSICAL:-}" = 1 ]; then
        run Android machine-hardware-android machine_hardware_android
        skip Android machine-emulator-android "the physical device cannot prove the emulator arm"
    elif android_target_is_emulator; then
        skip Android machine-hardware-android "the emulator cannot prove the hardware arm"
        run Android machine-emulator-android machine_emulator_android
    else
        skip Android machine-hardware-android \
            "set FIDELITY_ANDROID_PHYSICAL=1 after the operator verifies the device"
        skip Android machine-emulator-android "the device states no known emulator marker"
    fi
fi

# The image-identity mechanism. It signs a small archive and reads the
# certificate digest from the keystore and from a walk of the signing block, so
# it needs the build tools and no device at all. The two must agree, because
# the walk is the route the probe takes and the keystore is the truth.
if [ -d "${ANDROID_HOME:-}/build-tools" ] && \
    command -v python3 > /dev/null 2>&1 && \
    command -v zip > /dev/null 2>&1 && \
    command -v keytool > /dev/null 2>&1; then
    run Android android-identity-mechanism "$ROOT/tests/platform/controls/make-apk.sh"
else
    skip Android android-identity-mechanism \
        "no Android build tools, python3, zip, or keytool"
fi

# ------------------------------------------------------- what a person still runs

# Each one needs a debugger to attach, an agent to load, a judgment about a
# region count, or a second machine. None of them gives a pass or a fail on its
# own, so a person runs it and records what happened.
#
# The last one needs a second monitor, and a container runtime supplies it.
# `tests/platform/README.md` states the two commands and what they reported.
manual macOS controls/phases.m "the late legitimate loads table"
manual macOS controls/qos-drift.c "the worker quality of service note in 07-state-and-budgets.md"
manual iOS controls/entitle.c "the iOS identity rows, and the two recorded signatures"
manual Linux machine-paravirtual-linux "the second Linux arm of the machine-host row"

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf 'PASS: every control that this machine could run gave the answer it must give.\n'
else
    printf 'FAIL: %s control(s) gave a wrong answer. See %s/\n' "$FAILED" "$OUT"
fi
printf 'The record is %s. Its skipped rows are the work list.\n' "$RECORD"
exit "$FAILED"
