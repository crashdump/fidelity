#!/bin/sh
# Builds the tool that installs and runs the macOS guest.
#
# The tool is one Swift file against Virtualization.framework. The signature
# carries `com.apple.security.virtualization`, and an ad-hoc signature grants
# that on macOS, so this needs no certificate and anybody reproduces it.
#
# A tool with no entitlement compiles and runs, and then every framework call
# fails. The catalog reports "failed to load" and names no cause, so this
# script checks the signature rather than trusting that it landed.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
HERE=$ROOT/tests/platform/vm/macos
OUT=$ROOT/target/vm/macos
TOOL=$OUT/guest

mkdir -p "$OUT"

# A rebuild costs three seconds, and a stale tool costs an hour of confusion.
if [ -f "$TOOL" ] && [ "$TOOL" -nt "$HERE/guest.swift" ] &&
    [ "$TOOL" -nt "$HERE/virtualization.entitlements" ]; then
    echo "the guest tool is $TOOL"
    exit 0
fi

swiftc -O -o "$TOOL" "$HERE/guest.swift"
codesign -s - --force --entitlements "$HERE/virtualization.entitlements" "$TOOL" 2> /dev/null

codesign -d --entitlements - "$TOOL" 2>&1 | grep -q 'com.apple.security.virtualization' || {
    echo "the guest tool carries no virtualization entitlement, so it cannot run a guest" >&2
    exit 1
}
echo "the guest tool is $TOOL"
