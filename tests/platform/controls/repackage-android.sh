#!/bin/sh
# The repackage control for guarded constants, on Android.
#
# `guarded!()` binds its key to the signing certificate of the archive. This
# script signs the instrumented test archive with a second key, installs that
# copy, and reads the same guarded constant again. The value changes, and no
# error reports the change, which is the property that
# docs/plan/05-verification.md requires the extraction test to prove.
#
# Run it from the Android library project, with one device attached and the
# suite already green:
#
#     cd crates/probe/fidelity-probe-android/android
#     ./gradlew assembleDebugAndroidTest
#     ../../../../tests/platform/controls/repackage-android.sh
#
# It leaves the original archive installed, so the Gradle suite still runs
# afterwards.
set -eu

TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)
APK=build/outputs/apk/androidTest/debug/fidelity-probe-android-debug-androidTest.apk
WORK=$(mktemp -d)
PACKAGE=fidelity.probe.test
TEST=fidelity.probe.HarnessTest#a_guarded_constant_returns_its_literal_in_the_archive_that_the_build_named

trap 'rm -rf "$WORK"' EXIT

test -f "$APK" || { echo "build the test archive first: ./gradlew assembleDebugAndroidTest"; exit 1; }

# A second key, which no build ever named. Each run makes a new one, so the
# wrong value differs between runs and only the fact that it is wrong repeats.
keytool -genkeypair -keystore "$WORK/other.jks" -storepass secret -keypass secret \
    -alias other -keyalg RSA -keysize 2048 -validity 30 \
    -dname "CN=fidelity repackage control" 2>/dev/null

cp "$APK" "$WORK/repackaged.apk"
"$TOOLS/apksigner" sign --ks "$WORK/other.jks" --ks-pass pass:secret --key-pass pass:secret \
    --ks-key-alias other "$WORK/repackaged.apk"

read_prefix() {
    adb logcat -c
    adb shell am instrument -w -e class "$TEST" \
        "$PACKAGE/androidx.test.runner.AndroidJUnitRunner" > "$WORK/result.txt" 2>&1 || true
    adb logcat -d -s fidelity | sed -n 's/.*guarded prefix //p' | tail -1
}

echo "== the archive that the build named =="
adb install -r -t "$APK" > /dev/null
ORIGINAL=$(read_prefix)
echo "   guarded prefix: $ORIGINAL"

echo "== the same archive, signed by another key =="
adb uninstall "$PACKAGE" > /dev/null 2>&1 || true
adb install -t "$WORK/repackaged.apk" > /dev/null
REPACKAGED=$(read_prefix)
echo "   guarded prefix: $REPACKAGED"
grep -q "FAILURES" "$WORK/result.txt" && echo "   the test failed, which is the expected result here"

echo "== restoring the original archive =="
adb uninstall "$PACKAGE" > /dev/null 2>&1 || true
adb install -t "$APK" > /dev/null

test -n "$ORIGINAL" || { echo "FAIL: the original archive logged no prefix"; exit 1; }
test -n "$REPACKAGED" || { echo "FAIL: the repackaged archive logged no prefix"; exit 1; }
test "$ORIGINAL" = "6170692e" || { echo "FAIL: the original must read api., and it read $ORIGINAL"; exit 1; }
test "$ORIGINAL" != "$REPACKAGED" || { echo "FAIL: the repackaged archive read the same value"; exit 1; }

echo
echo "PASS: another signer gives another value, and nothing reported an error."
