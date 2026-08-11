#!/bin/sh
# The Android image-identity control.
#
# It builds a small archive, signs it with a throwaway key, and prints the
# certificate digest from two independent sources. The recorded archive that
# `fidelity-formats` tests against came from this script:
# `crates/fidelity-formats/src/fixtures/apk-signed-v2v3.apk`.
#
# Android, unlike Apple, lets a developer sign freely, so the positive control
# needs no account and no device. That is why the Android identity reader is
# proven against a real signature and the iOS one is not.
#
# Each run makes a fresh key, so each run prints a different digest. What the
# control proves is that the two sources agree, whatever the key. Confirmed
# twice on 2026-08-10 with build tools 36.0.0.
#
# The recorded fixture came from the first run, and its digest is the one that
# `crates/probe/fidelity-probe-android/src/identity.rs` asserts:
#   2B:16:C1:4D:5D:C3:8A:49:58:76:1A:F8:BB:7F:B9:25:D5:AE:EA:89:94:BA:BF:78:18:5B:B0:04:C2:D3:83:86
#
# The certificate length moves by a byte between keys, because DER encodes a
# serial number and a signature of its own size. Do not read 783 as a constant.
#
# The archive holds no AndroidManifest.xml, so `apksigner verify` refuses it
# and `apksigner sign` needs an explicit minimum version. Neither matters: the
# signing block is what this control produces, and it is complete.
set -eu

BUILD_TOOLS=${BUILD_TOOLS:-$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)}
WORK=${WORK:-$(mktemp -d)}
cd "$WORK"

printf 'fidelity test payload\n' > payload.txt
zip -q -X unsigned.apk payload.txt

keytool -genkeypair -keystore test.jks -storepass fidelity -keypass fidelity \
    -alias test -keyalg RSA -keysize 2048 -validity 365 \
    -dname "CN=fidelity test, O=none, C=US"

"$BUILD_TOOLS/zipalign" -f 4 unsigned.apk aligned.apk
"$BUILD_TOOLS/apksigner" sign --ks test.jks --ks-pass pass:fidelity \
    --key-pass pass:fidelity --ks-key-alias test --min-sdk-version 34 \
    --v2-signing-enabled true --v3-signing-enabled true \
    --out signed.apk aligned.apk

echo "archive: $WORK/signed.apk"

# Source A. What the keystore says the certificate is.
KEYSTORE=$(keytool -list -v -keystore test.jks -storepass fidelity 2>/dev/null |
    grep -i "SHA256:" | sed -n 's/.*SHA256: *//p' | head -1)

# Source B. What a walk of the signing block says it is, which is the route the
# probe takes, because a library cannot reach the package manager.
WALK=$(python3 - "$WORK/signed.apk" <<'PY'
import hashlib, struct, sys
d = open(sys.argv[1], 'rb').read()
end = d.rfind(b'PK\x05\x06')
directory = struct.unpack('<I', d[end + 16:end + 20])[0]
assert d[directory - 16:directory] == b'APK Sig Block 42'
size = struct.unpack('<Q', d[directory - 24:directory - 16])[0]
at = directory - 8 - size + 8
scheme = {}
while at < directory - 24:
    length = struct.unpack('<Q', d[at:at + 8])[0]
    scheme[struct.unpack('<I', d[at + 8:at + 12])[0]] = d[at + 12:at + 8 + length]
    at += 8 + length

def sequence(raw):
    out, i = [], 0
    while i < len(raw):
        n = struct.unpack('<I', raw[i:i + 4])[0]
        out.append(raw[i + 4:i + 4 + n])
        i += 4 + n
    return out

# Scheme v3 first, which is the block that carries a rotated key.
block = scheme.get(0xf05368c0) or scheme[0x7109871a]
signed_data = sequence(sequence(sequence(block)[0])[0])[0]
certificate = sequence(sequence(signed_data)[1])[0]
digest = hashlib.sha256(certificate).hexdigest().upper()
print('digest ' + ':'.join(digest[i:i + 2] for i in range(0, 64, 2)))
print('bytes %d' % len(certificate))
PY
)

BLOCK=$(printf '%s\n' "$WALK" | sed -n 's/^digest //p')
BYTES=$(printf '%s\n' "$WALK" | sed -n 's/^bytes //p')

echo "source A, the keystore          : $KEYSTORE"
echo "source B, the signing block walk: $BLOCK"
echo "certificate bytes               : $BYTES"

test -n "$KEYSTORE" || { echo "FAIL: the keystore reported no digest"; exit 1; }
test -n "$BLOCK" || { echo "FAIL: the signing block walk reported no digest"; exit 1; }
if [ "$KEYSTORE" != "$BLOCK" ]; then
    echo "FAIL: the two sources disagree, so the signing block walk is wrong"
    exit 1
fi

echo
echo "PASS: both sources report one certificate, and the walk needs no package manager."
