#!/bin/sh
# Runs a provisioned Fidelity control on one physical iPhone.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
OUT=$ROOT/target/platform/ios-device
SPEC=$ROOT/tests/platform/controls/ios-device/project.yml
DEVICE=${FIDELITY_IOS_DEVICE:-}
TEAM=${FIDELITY_IOS_TEAM:-}
BUNDLE=io.splitsec.fidelity.control

if [ "$#" -ne 1 ]; then
    echo "run-ios-device.sh: state identity, machine, local-agent, cost, or machine-name" >&2
    exit 2
fi
control=$1
case "$control" in
    identity | machine | local-agent | cost | machine-name) ;;
    *)
        echo "run-ios-device.sh: the control does not know $control" >&2
        exit 2
        ;;
esac

if [ -z "$DEVICE" ] || [ -z "$TEAM" ]; then
    echo "run-ios-device.sh: set FIDELITY_IOS_DEVICE and FIDELITY_IOS_TEAM" >&2
    exit 2
fi
if ! command -v xcodegen > /dev/null 2>&1; then
    echo "run-ios-device.sh: install xcodegen to create the device project" >&2
    exit 2
fi

mkdir -p "$OUT"
xcodegen --quiet --spec "$SPEC" --project "$OUT" --project-root "$ROOT"

# Each control replaces the linked executable. A clean build makes Xcode sign
# the new executable every time.
FIDELITY_IOS_CONTROL_EXAMPLE=$control xcodebuild -quiet \
    -project "$OUT/FidelityDeviceControl.xcodeproj" \
    -scheme FidelityDeviceControl \
    -configuration Release \
    -destination "id=$DEVICE" \
    -derivedDataPath "$OUT/DerivedData" \
    -allowProvisioningUpdates \
    DEVELOPMENT_TEAM="$TEAM" \
    clean build

APP=$OUT/DerivedData/Build/Products/Release-iphoneos/FidelityDeviceControl.app
xcrun devicectl device install app --device "$DEVICE" "$APP"

if [ "$control" = cost ] || [ "$control" = machine-name ]; then
    xcrun devicectl device process launch --device "$DEVICE" --console \
        --terminate-existing "$BUNDLE"
    exit 0
fi

if [ "$control" = machine ]; then
    MACHINE=$OUT/machine-clean.out
    xcrun devicectl device process launch --device "$DEVICE" --console \
        --terminate-existing "$BUNDLE" > "$MACHINE"
    grep -q 'virtualization.machine_host: clean' "$MACHINE"
    grep -q 'protected operation: allowed' "$MACHINE"
    cat "$MACHINE"
    echo "PASS: the physical iOS device reports hardware and allows the operation."
    exit 0
fi

if [ "$control" = local-agent ]; then
    HOSTILE=$OUT/local-agent-hostile.out
    UNRELATED=$OUT/local-agent-unrelated.out
    xcrun devicectl device process launch --device "$DEVICE" --console \
        --terminate-existing "$BUNDLE" frida > "$HOSTILE"
    xcrun devicectl device process launch --device "$DEVICE" --console \
        --terminate-existing "$BUNDLE" unrelated > "$UNRELATED"
    grep -q 'instrumentation.local_agent: Medium' "$HOSTILE"
    grep -q 'protected operation: denied' "$HOSTILE"
    grep -q 'instrumentation.local_agent: clean' "$UNRELATED"
    grep -q 'protected operation: allowed' "$UNRELATED"
    cat "$HOSTILE"
    cat "$UNRELATED"
    echo "PASS: the iOS device separates a compatible endpoint from an unrelated service."
    exit 0
fi

CLEAN=$OUT/identity-clean.out
HOSTILE=$OUT/identity-hostile.out
xcrun devicectl device process launch --device "$DEVICE" --console \
    --terminate-existing "$BUNDLE" "$TEAM" > "$CLEAN"
xcrun devicectl device process launch --device "$DEVICE" --console \
    --terminate-existing "$BUNDLE" AAAAAAAAAA > "$HOSTILE"

grep -q 'integrity.expected_identity: clean' "$CLEAN"
grep -q 'protected operation: allowed' "$CLEAN"
grep -q 'UnexpectedIdentity' "$HOSTILE"
grep -q 'protected operation: denied' "$HOSTILE"

cat "$CLEAN"
cat "$HOSTILE"
echo "PASS: the provisioned image reports its team and refuses another team."
