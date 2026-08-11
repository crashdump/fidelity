#!/bin/sh
# Runs one test binary inside a booted iOS simulator.
#
# Cargo calls this with the test binary and its arguments, so it has the shape
# that CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER expects:
#
#   export FIDELITY_IOS_SIM=<the UDID of a booted simulator>
#   export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER=$PWD/evidence/controls/run-ios.sh
#   cargo test -p fidelity-probe-apple --target aarch64-apple-ios-sim
set -e

if [ -z "$FIDELITY_IOS_SIM" ]; then
    echo "run-ios.sh: set FIDELITY_IOS_SIM to the UDID of a booted simulator" >&2
    echo "run-ios.sh: xcrun simctl list devices | grep Booted" >&2
    exit 2
fi

binary="$1"
shift
exec xcrun simctl spawn "$FIDELITY_IOS_SIM" "$binary" "$@"
