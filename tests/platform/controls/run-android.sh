#!/bin/sh
# Pushes one test binary to an Android device, and runs it there.
#
# Cargo calls this with the test binary and its arguments, so it has the shape
# that a Cargo Android target runner expects:
#
#   export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER=$PWD/tests/platform/controls/run-android.sh
#   cargo test -p fidelity-probe-android --target aarch64-linux-android
#
# Use the corresponding X86_64 names for an x86_64 target.
#
# It needs `adb` on the path, and one device attached.
set -e

binary="$1"
shift
name=$(basename "$binary")

adb push "$binary" "/data/local/tmp/$name" >/dev/null
adb shell chmod 755 "/data/local/tmp/$name"
exec adb shell "/data/local/tmp/$name" "$@"
