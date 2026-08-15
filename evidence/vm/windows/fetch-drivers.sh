#!/bin/sh
# Fetches the one Windows driver that the guest needs, and no more.
#
# The `virt` machine offers no network device that Windows 11 ARM64 drives with
# an inbox driver. Microsoft removed the inbox RNDIS driver that a USB network
# device needs, so a guest with one reports no adapter at all. The virtio
# network device answers, and the driver for it ships in the virtio-win
# project. The install-time answer file names this driver, so the guest has a
# network from the first boot rather than after a person installs one.
#
# The driver is a third-party binary, so it is not committed. This script
# fetches it, and the Packer build reads it from the same place.
#
#     evidence/vm/windows/fetch-drivers.sh
set -eu

# A pinned release, so a rebuild uses the same driver that the evidence names.
VERSION=0.1.285
ISO_URL=https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-$VERSION-1/virtio-win-$VERSION.iso

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
OUT=$ROOT/target/vm/windows/drivers/netkvm
CACHE=$ROOT/target/vm/windows/virtio-win-$VERSION.iso

if [ -f "$OUT/netkvm.inf" ] && [ -f "$OUT/netkvm.sys" ] && [ -f "$OUT/netkvm.cat" ]; then
    echo "the virtio drivers are already under $ROOT/target/vm/windows/drivers"
    exit 0
fi

mkdir -p "$(dirname "$CACHE")"

if [ ! -f "$CACHE" ]; then
    echo "fetching virtio-win $VERSION, which is about 750 MB"
    curl -fsSL -o "$CACHE" "$ISO_URL" || {
        echo "the virtio-win image did not download" >&2
        exit 1
    }
fi

mount=$(hdiutil attach -readonly -nobrowse "$CACHE" 2>/dev/null |
    awk '/\/Volumes\//{print $NF}' | head -1)
[ -n "$mount" ] || {
    echo "the virtio-win image did not mount" >&2
    exit 1
}

# Only the three files that install the driver. The image also holds debug
# symbols and helper programs that the guest does not need.
#
# NetKVM is the network driver, and it is the one the guest cannot boot a
# network without. viostor is the disk driver, kept beside it because a build
# that puts the system disk on the virtio bus needs it during setup, and a
# build that uses NVMe does not read it.
for driver in NetKVM viostor; do
    dest=$ROOT/target/vm/windows/drivers/$(printf '%s' "$driver" | tr 'A-Z' 'a-z')
    mkdir -p "$dest"
    for ext in inf sys cat; do
        name=$(printf '%s' "$driver" | tr 'A-Z' 'a-z')
        cp "$mount/$driver/w11/ARM64/$name.$ext" "$dest/$name.$ext"
    done
done
hdiutil detach "$mount" -quiet 2>/dev/null || true

echo "wrote the virtio drivers under $ROOT/target/vm/windows/drivers"
