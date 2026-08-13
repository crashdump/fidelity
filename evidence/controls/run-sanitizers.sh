#!/bin/sh
# Runs the unsafe-wrapper test layer that `docs/plan/05-verification.md` names.
#
#   evidence/controls/run-sanitizers.sh            the two sanitizers
#   evidence/controls/run-sanitizers.sh miri       add Miri, which takes minutes
#   evidence/controls/run-sanitizers.sh just-miri  Miri alone, for a caller that
#                                                  already ran the sanitizers
#
# The three tools cover different ground, and none of them covers the others:
#
#   AddressSanitizer  every crate, including the probe `sys/` modules. This is
#                     what checks the packed Mach structures and the sysctl
#                     buffer handling, where a wrong offset reads out of bounds.
#   ThreadSanitizer   the same set. It matters most for the engine and the
#                     facade, because the worker, the state, and the latch run
#                     on separate threads.
#   Miri              the crates that forbid unsafe code. Miri cannot cross a
#                     foreign call, so it never reaches a probe crate.
#
# Doc-tests are excluded on purpose, and that is not a workaround for a defect
# in this workspace. Rustdoc links a doc-test without the sanitizer runtime, so
# every one of them fails on `___asan_handle_no_return`. `cargo test --workspace`
# runs them.
set -e

# `-Zbuild-std` needs an explicit target, and the sanitizers instrument the
# machine that runs them, so the default is the host that rustc reports. A
# fixed default would name one platform, and the control then builds the
# standard library for a machine it cannot run the tests on.
TARGET=${FIDELITY_SAN_TARGET:-$(rustc -vV | awk '/^host: / { print $2 }')}
SET="--lib --bins --tests"
ASKED=${1:-}

if [ "$ASKED" != "just-miri" ]; then
    echo "=== AddressSanitizer, whole workspace ==="
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --workspace \
        --target "$TARGET" -Zbuild-std $SET

    echo "=== ThreadSanitizer, whole workspace ==="
    RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --workspace \
        --target "$TARGET" -Zbuild-std $SET
fi

if [ "$ASKED" = "miri" ] || [ "$ASKED" = "just-miri" ]; then
    echo "=== Miri, the crates that forbid unsafe code ==="
    # Isolation off, because the worker stamps a finding with the wall clock and
    # `SystemTime::now` asks for a real-time clock that Miri refuses to supply.
    # The alternative is a test that never runs the worker, and the worker is
    # the part with threads in it.
    #
    # Three tests in `fidelity-cipher` are excluded by name. Two of them sweep
    # 100000 wrong keys and one hashes a long message, and an interpreter cannot
    # finish any of them. Excluding the whole crate would lose 28 tests that
    # take five seconds, so the exclusion is by name and not by crate.
    MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test \
        -p fidelity-formats -p fidelity-types -p fidelity-core \
        -p fidelity-detect -p fidelity-cipher -p fidelity-engine \
        -p fidelity-testkit -- \
        --skip every_wrong_key_gives_a_well_formed_value \
        --skip a_wrong_key_almost_never_returns_the_literal \
        --skip the_long_message_vector_matches
fi
