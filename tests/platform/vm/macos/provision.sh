#!/bin/sh
# Runs one control inside the macOS guest, and needs nobody to answer a window.
#
#     provision.sh <bundle> <binary>   installs the control, to run at boot
#     provision.sh <bundle> --read     prints what the last boot wrote
#
# The setup assistant holds a fresh macOS guest, and Apple ships no answer file
# for it. A launch daemon runs before the assistant, so this writes one into the
# guest from outside, boots the guest, and reads the answer back. The guest
# needs no account, no network, and no SSH.
#
# Ownership is the whole trick. A launch daemon loads only when root owns its
# plist, and a file that this machine creates on the guest disk lands under the
# uid of the caller. A rename inside one volume keeps the inode, and a write
# that truncates keeps it too, so an existing root-owned plist becomes the new
# one and stays root-owned. Measured on 2026-08-18: inode and uid both survive.
#
# The guest disk is a raw image, and macOS mounts its APFS data volume with no
# privilege. The system volume is sealed, so nothing here touches it.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
BUNDLE=${1:?usage: provision.sh <bundle> <binary>}
BINARY=${2:?usage: provision.sh <bundle> <binary>}
DISK=$BUNDLE/disk.img
MOUNT=${FIDELITY_MACOS_MOUNT:-/tmp/fidelity-guest}
# The guest keeps the control and its answer here.
INSIDE=private/var/fidelity

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

[ -f "$DISK" ] || die "no guest disk at $DISK. Run: vm.sh macos build"
[ "$BINARY" = --read ] || [ -f "$BINARY" ] || die "no control binary at $BINARY"
pgrep -f "guest run $BUNDLE" > /dev/null 2>&1 &&
    die "the guest runs. Stop it first: vm.sh macos stop"

# ------------------------------------------------------------------ the mount

# The attach reports the partitions and the containers that APFS synthesizes
# from them, so the data volume sits on a disk number that the image itself
# never names. Every reported disk gets the question instead.
ATTACHED=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$DISK" |
    awk '{ print $1 }' | grep -o 'disk[0-9]*' | sort -u)
[ -n "$ATTACHED" ] || die "the guest disk did not attach"
DEVICE=$(printf '%s\n' "$ATTACHED" | head -1)
detach() { diskutil unmount "$MOUNT" > /dev/null 2>&1 || true
    for d in $ATTACHED; do hdiutil detach "$d" > /dev/null 2>&1 || true; done; }
trap detach EXIT

# The data volume is the writable one. The system volume is sealed, and the
# name is the same on every macOS install.
VOLUME=""
for d in $ATTACHED; do
    found=$(diskutil list "$d" 2> /dev/null |
        awk '$0 ~ /APFS Volume Data / { print $NF }' | tail -1)
    [ -n "$found" ] && VOLUME=$found && break
done
[ -n "$VOLUME" ] || die "the guest disk holds no data volume"
mkdir -p "$MOUNT"

# The volume mounts twice, and each mount answers a different question.
#
# With ownership enforced, a search finds which plist root owns. That search is
# the only reason for this first mount: `noowners` maps every file to the
# caller, so the same search there finds nothing at all.
diskutil mount -mountOptions owners -mountPoint "$MOUNT" "$VOLUME" > /dev/null ||
    die "the data volume did not mount"
DONOR_NAME=$(find "$MOUNT/Library/LaunchDaemons" -maxdepth 1 -name '*.plist' -user 0 \
    2> /dev/null | head -1)
DONOR_NAME=${DONOR_NAME##*/}
HAS_PLIST=$([ -f "$MOUNT/Library/LaunchDaemons/net.fidelity.control.plist" ] &&
    echo yes || echo no)
diskutil unmount "$MOUNT" > /dev/null 2>&1

# `noowners` is what grants write access here. It does not change what lands on
# the disk: an in-place write keeps the uid that the inode already carries.
diskutil mount -mountOptions noowners -mountPoint "$MOUNT" "$VOLUME" > /dev/null ||
    die "the data volume did not mount"

# ------------------------------------------------------------- the control

# The read arm stops here. The boot wrote its answer inside the guest, and
# this is the only way back out, because the guest holds no account and
# answers no network.
if [ "$BINARY" = --read ]; then
    [ -f "$MOUNT/$INSIDE/result.txt" ] ||
        die "the guest wrote no answer. Boot it once after provision.sh"
    cat "$MOUNT/$INSIDE/result.txt"
    exit 0
fi

mkdir -p "$MOUNT/$INSIDE"
cp "$BINARY" "$MOUNT/$INSIDE/control"
chmod 755 "$MOUNT/$INSIDE/control"
rm -f "$MOUNT/$INSIDE/result.txt"

cat > "$MOUNT/$INSIDE/run.sh" <<'EOF'
#!/bin/sh
# The guest runs this once, as root, before the setup assistant appears.
exec > /private/var/fidelity/result.txt 2>&1
# The daemon starts early, and the Security framework fills its caches once.
# The control reads a code identity at start, so give the system a moment.
sleep 20
echo "sw_vers"
sw_vers
echo "kern.hv_vmm_present=$(sysctl -n kern.hv_vmm_present 2>&1)"
echo "--- control ---"
/private/var/fidelity/control
echo "--- exit=$? ---"
sync
# The host waits for the guest to stop, and that is how it knows this finished.
shutdown -h now
EOF
chmod 755 "$MOUNT/$INSIDE/run.sh"

# ------------------------------------------------------------- the daemon

DAEMONS=$MOUNT/Library/LaunchDaemons
PLIST=$DAEMONS/net.fidelity.control.plist

if [ "$HAS_PLIST" = no ]; then
    # Take an inode that root already owns. A rename inside one volume keeps
    # the inode, so the plist below inherits root and needs no chown.
    [ -n "$DONOR_NAME" ] || die "the guest holds no root-owned plist to take"
    mv "$DAEMONS/$DONOR_NAME" "$PLIST"
    say "the daemon takes the inode of $DONOR_NAME"
fi

# A truncating write keeps the inode, so this stays root-owned.
cat > "$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>net.fidelity.control</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/sh</string>
		<string>/private/var/fidelity/run.sh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
EOF
chmod 644 "$PLIST"

detach
trap - EXIT
say "the guest holds the control at /$INSIDE"
