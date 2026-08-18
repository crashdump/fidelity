#!/bin/sh
# Builds the two files that the Packer build attaches but does not create:
# the answer disk, and a fresh firmware variable store.
#
#     tests/platform/vm/windows/make-answers.sh
#
# The answer disk is a small FAT volume on a USB device, and it carries four
# things: the answer file, the first-logon script, the virtio network driver,
# and the boot script for the firmware shell. Windows Setup reads the answer
# file from the root of any removable volume, so no drive letter is named.
#
# The disk keeps its partition table, and that is measured rather than
# assumed. A run with `-layout NONE` put the filesystem at the start of the
# disk with no table, and Windows Setup then listed the disk as 8 MB of
# unallocated space. It could not read the volume at all. The firmware reads
# either layout, so only Windows decides this one.
#
# The variable store starts blank on every build. A store that a failed build
# wrote could still hold a boot entry, and the first boot would then take a
# path that a fresh install never takes.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
HERE=$ROOT/tests/platform/vm/windows
OUT=$ROOT/target/vm/windows

"$HERE/fetch-drivers.sh"
"$ROOT/tests/platform/vm/make-key.sh"

work=$OUT/answers
rm -rf "$work" "$OUT/answers.dmg"
mkdir -p "$work/drivers"

cp "$HERE/autounattend.xml" "$work/autounattend.xml"
cp "$HERE/setup.ps1" "$work/setup.ps1"
cp "$HERE/install.cmd" "$work/install.cmd"
cp -R "$OUT/drivers/netkvm" "$work/drivers/netkvm"

# The firmware needs telling, and this is the file that tells it.
#
# EDK2 finds no boot option it likes for an installation image on a USB
# CD-ROM, so the first boot drops to the firmware shell. That shell runs
# `startup.nsh` from the answer disk, which the disk reaches by taking a boot
# index of its own. The script connects every device and refreshes the map,
# because at this moment the CD-ROM is not yet mapped, then it starts the
# loader from whichever filesystem holds it. Only the installation image
# holds `\efi\boot\bootaa64.efi`, so the loop finds one and no other.
cat > "$work/startup.nsh" <<'NSH'
connect -r
map -r
for %d run (0 9)
  if exist fs%d:\efi\boot\bootaa64.efi then
    echo booting fs%d:
    fs%d:\efi\boot\bootaa64.efi
  endif
endfor
NSH

hdiutil create -quiet -srcfolder "$work" -fs MS-DOS -volname ANSWERS \
    -format UDRW -ov "$OUT/answers" || {
    echo "the answer disk did not build" >&2
    exit 1
}

# A FAT volume holds no extended attribute, so macOS writes the attributes of
# each file into a second file that starts with `._`. One of those is
# `._netkvm.inf`, and `dism /add-driver /recurse` reads every `.inf` under the
# directory that it takes. Delete them on the volume, because the copy makes
# them and clearing the attributes first does not stop it.
mount=$(hdiutil attach -nobrowse "$OUT/answers.dmg" |
    awk '/\/Volumes\//{print $NF}' | head -1)
if [ -n "$mount" ]; then
    find "$mount" -name '._*' -delete 2> /dev/null || true
    hdiutil detach "$mount" -quiet 2> /dev/null || true
fi

cp "$ROOT/tests/platform/vm/efivars-template.fd" "$OUT/vars.fd"

echo "wrote $OUT/answers.dmg and a blank $OUT/vars.fd"
