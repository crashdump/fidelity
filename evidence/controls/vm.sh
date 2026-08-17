#!/bin/sh
# Manages the guests that the platform controls need.
#
#     vm.sh <guest> <command>
#
#     guest:    linux | windows
#     command:  build | start | stop | status | reset | run <cmd> | push | iso
#
# Why this exists. The controls for a platform have to run on that platform,
# and this machine runs one of the five. QEMU runs both guests with the
# hypervisor of this machine, so an ARM64 guest runs at the speed of the host.
#
# Packer builds each guest from the template under `evidence/vm/<guest>/`, and
# that build is the whole setup: the install, the account, the toolchain, and
# the access. `build` runs it. `start` boots a copy-on-write overlay on top of
# the built image, so a run never dirties the image, and `reset` throws the
# overlay away, so a pristine guest costs seconds rather than a rebuild.
#
# The Linux guest answers two things a container could not. A container shares
# the kernel of the machine that hosts it, so it has no filesystem of its own:
# fs-verity cannot be enabled there, and the platform-trust tier of the Linux
# identity capability has no way to report anything but a gap. A guest owns
# its disk, so that tier gets a real control. The container also needed
# `--cap-add=SYS_PTRACE` for the tracer controls, and a guest needs no such
# grant, so the control matches what a host really runs under.
#
# A guest is a virtual machine, so a `Virtualization` detector would report
# both of these. That category holds no code. Every capability that these
# guests exercise reads memory, a debug port, a mapping table, or a signature,
# and none of them changes under a hypervisor.
#
# A guest keeps its overlay outside the workspace, because a booted system
# writes gigabytes and no part of that belongs in a repository.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BASE=${FIDELITY_VM_DIR:-$HOME/.local/share/fidelity-vm}
FIRMWARE=/opt/homebrew/share/qemu/edk2-aarch64-code.fd

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------ the guest itself

# Each guest states its own port and size. Two guests can run at once, so the
# ports differ. The disk sizes live in the Packer templates, and the harness
# key is one file that both images accept.
setup() {
    GUEST=$1
    DIR=$BASE/$GUEST
    DISK=$DIR/disk.qcow2
    VARS=$DIR/vars.fd
    PIDFILE=$DIR/qemu.pid
    KEY=$ROOT/target/vm/id_ed25519
    GOLD=$ROOT/target/vm/$GUEST/image/disk.qcow2
    GOLD_VARS=$ROOT/target/vm/windows/vars.fd
    case $GUEST in
        linux)
            PORT=${FIDELITY_LINUX_PORT:-2223}
            MEMORY=${FIDELITY_LINUX_MEMORY:-4G}
            CORES=${FIDELITY_LINUX_CORES:-4}
            ;;
        windows)
            PORT=${FIDELITY_WINDOWS_PORT:-2222}
            MEMORY=${FIDELITY_WINDOWS_MEMORY:-8G}
            CORES=${FIDELITY_WINDOWS_CORES:-4}
            ;;
        *) die "usage: vm.sh <linux|windows> <command>" ;;
    esac
    USER_NAME=fidelity
}

ssh_to_guest() {
    ssh -p "$PORT" -i "$KEY" \
        -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5 \
        "$USER_NAME@127.0.0.1" "$@"
}

# ------------------------------------------------------- the Windows image

# The one download step that a person takes has a Microsoft reason rather
# than a project one.
#
# The download has four steps, and three of them answer a script. The page
# names the ARM64 product, and an interface returns the language list. The
# fourth, which turns a language into a link, refuses with
# `ErrorSettings.SentinelReject`, because Microsoft guards that endpoint
# against automation on purpose. Measured on 2026-08-13.
#
# Defeating that guard is not this project's business, and a control built on
# a guard that somebody works around breaks the week it changes. So this step
# reads what it can, states the exact build it expects, and asks once.
WINDOWS_ISO=${FIDELITY_WINDOWS_ISO:-$BASE/windows/windows.iso}

windows_iso() {
    if [ -f "$WINDOWS_ISO" ]; then
        say "the installation image is $WINDOWS_ISO"
        return 0
    fi
    mkdir -p "$DIR"
    cat <<EOF
No installation image at $WINDOWS_ISO

Windows 11 for ARM64 is about 5 GB, and Microsoft serves the final link only to
a browser. Take the image once:

  1. Open https://www.microsoft.com/software-download/windows11arm64
  2. Choose "Windows 11 (multi-edition ISO for Arm64)" and English.
  3. Move the file to $WINDOWS_ISO

The v1 floor is Windows 11 25H2, and that page served 25H2 on 2026-08-13, so
the current image satisfies it. Check the floor again before a release.

Every step after this one runs from this shell.
EOF
    return 1
}

# ------------------------------------------------------------------- commands

cmd_build() {
    command -v packer > /dev/null 2>&1 ||
        die "no packer. Install it with: brew install packer"
    if [ "$GUEST" = windows ]; then
        windows_iso || return 1
        "$ROOT/evidence/vm/windows/make-answers.sh" || return 1
    else
        "$ROOT/evidence/vm/make-key.sh" || return 1
    fi
    # The build deletes the image it replaces, and a running guest still
    # holds the old one open.
    cmd_stop > /dev/null 2>&1
    packer init "$ROOT/evidence/vm/$GUEST" || die "packer init failed"
    packer build -force "$ROOT/evidence/vm/$GUEST" ||
        die "the $GUEST image did not build"
    rm -f "$DISK" "$VARS"
    say "the $GUEST image is $GOLD"
}

# The overlay keeps every write of a run, and the image below it stays as the
# build left it. A rebuilt image orphans the overlay, so `cmd_build` removes
# it, and this makes a fresh one.
overlay() {
    # A new build makes an existing overlay stale, and a stale overlay boots
    # the system that the build replaced. That reads as a guest that installed
    # itself wrong, so throw the overlay away rather than boot the old disk.
    if [ -f "$DISK" ] && [ -f "$GOLD" ] && [ "$GOLD" -nt "$DISK" ]; then
        say "the $GUEST image is newer than the overlay, so the overlay goes"
        rm -f "$DISK"
    fi
    [ -f "$DISK" ] && return 0
    [ -f "$GOLD" ] || die "no $GUEST image. Run: vm.sh $GUEST build"
    mkdir -p "$DIR"
    qemu-img create -q -f qcow2 -b "$GOLD" -F qcow2 "$DISK" ||
        die "the overlay did not build"
    # The firmware variables carry the boot entry that the install wrote, so
    # a fresh overlay takes a fresh copy of the store the build produced.
    [ "$GUEST" = windows ] && cp "$GOLD_VARS" "$VARS"
    return 0
}

# The Linux guest takes virtio for everything, because a Linux kernel carries
# those drivers. The Windows guest takes an NVMe disk and a virtio network
# device: NVMe because Windows 11 ARM64 drives it out of the box, and virtio
# network because the image carries the driver that the build installed. The
# install-time findings live with `evidence/vm/windows/windows.pkr.hcl`.
#
# `ramfb` is the Windows display. The `virt` machine offers no framebuffer,
# and a guest without one shows nothing and reads like a hung boot.
qemu_run() {
    if [ "$GUEST" = linux ]; then
        qemu-system-aarch64 \
            -M virt,highmem=on -accel hvf -cpu host \
            -smp "$CORES" -m "$MEMORY" \
            -bios "$FIRMWARE" \
            -drive "file=$DISK,if=virtio,format=qcow2" \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::$PORT-:22" \
            -virtfs "local,path=$ROOT,mount_tag=workspace,security_model=mapped-xattr,id=workspace" \
            -monitor "unix:$DIR/monitor.sock,server,nowait" \
            "$@"
    else
        qemu-system-aarch64 \
            -M virt,highmem=on -accel hvf -cpu host \
            -smp "$CORES" -m "$MEMORY" \
            -drive "if=pflash,format=raw,readonly=on,file=$FIRMWARE" \
            -drive "if=pflash,format=raw,file=$VARS" \
            -drive "file=$DISK,if=none,id=boot,format=qcow2" \
            -device nvme,drive=boot,serial=fidelity,bootindex=1 \
            -device ramfb \
            -device qemu-xhci -device usb-kbd -device usb-tablet \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::$PORT-:22" \
            -monitor "unix:$DIR/monitor.sock,server,nowait" \
            "$@"
    fi
}

cmd_start() {
    overlay
    # A guest with a problem has to be watchable, and a guest with no screen
    # cannot be. `FIDELITY_VM_DISPLAY=1` gives it one.
    display=${FIDELITY_VM_DISPLAY:+default,show-cursor=on}
    display=${display:-none}
    if ssh_to_guest 'exit' > /dev/null 2>&1; then
        say "the $GUEST guest already answers on port $PORT"
        return 0
    fi
    rm -f "$DIR/monitor.sock"

    # `-daemonize` and a window cannot be combined on macOS. QEMU forks after
    # the Objective-C runtime has started for the Cocoa display, and macOS
    # refuses that fork and crashes the child. A guest with no window
    # daemonizes, and a guest with one runs in the background of this shell
    # instead, which needs no fork inside QEMU.
    if [ "$display" = none ]; then
        qemu_run -display none -daemonize -pidfile "$PIDFILE" ||
            die "the $GUEST guest did not start"
    else
        qemu_run -display "$display" &
        printf '%s\n' "$!" > "$PIDFILE"
    fi

    tries=0
    while [ "$tries" -lt 60 ]; do
        if ssh_to_guest 'exit' > /dev/null 2>&1; then
            say "the $GUEST guest answers on port $PORT"
            return 0
        fi
        tries=$((tries + 1))
        sleep 5
    done
    die "the $GUEST guest did not answer on port $PORT within five minutes"
}

cmd_stop() {
    # The search by disk path catches a guest whose pidfile is gone, and one
    # that a crash left behind. A survivor keeps the forwarded port, and the
    # next start then fails on it. The disk path names exactly one guest, so
    # the search finds that one and no other.
    pid=$(cat "$PIDFILE" 2> /dev/null)
    [ -n "${pid:-}" ] && kill "$pid" 2> /dev/null
    for stray in $(pgrep -f "qemu-system-aarch64.*$DISK" 2> /dev/null); do
        kill "$stray" 2> /dev/null
    done
    sleep 2
    for stray in $(pgrep -f "qemu-system-aarch64.*$DISK" 2> /dev/null); do
        kill -9 "$stray" 2> /dev/null
    done
    rm -f "$PIDFILE"
    say "the $GUEST guest is down"
}

cmd_status() {
    ssh_to_guest 'exit' > /dev/null 2>&1 ||
        die "the $GUEST guest does not answer on port $PORT"
    say "the $GUEST guest answers on port $PORT"
}

cmd_reset() {
    cmd_stop
    rm -f "$DISK" "$VARS"
    say "the next start boots a fresh $GUEST guest"
}

cmd_run() {
    [ "$#" -gt 0 ] || die "usage: vm.sh $GUEST run <command>"
    ssh_to_guest "$@"
}

# The Linux guest reads the workspace over 9p at /work, and Windows drives no
# 9p, so its copy travels once. The tree that travels is the files that git
# tracks plus the new files that it does not ignore, which is what a runner
# would check out. The build directory stays in the guest, so a second push
# rebuilds only what changed.
cmd_push() {
    [ "$GUEST" = windows ] ||
        die "push is for the Windows guest. The Linux guest mounts the workspace at /work"
    cmd_status > /dev/null || die "start the guest first"
    # `--no-xattrs` because macOS writes a `com.apple.provenance` attribute on
    # every file, and it travels as a `LIBARCHIVE.xattr` header. The tar in the
    # guest calls that header unknown, warns once for each file, and exits with
    # a failure status, so a push that landed still reads as a push that failed.
    # `-h` because `AGENTS.md` is a symbolic link to `CLAUDE.md`, and Windows
    # grants no right to create one. The guest takes the content of the file
    # instead of the link, which is what a build there reads anyway.
    (cd "$ROOT" && git ls-files -co --exclude-standard |
        tar -h --no-xattrs -cf - -T -) |
        ssh_to_guest 'mkdir -p /c/work &&
            tar --warning=no-timestamp -xf - -C /c/work' ||
        die "the push did not land"
    say "the workspace is at C:\\work in the guest"
}

[ "$#" -ge 1 ] || { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
setup "$1"
shift
[ -f "$FIRMWARE" ] || die "no ARM64 firmware at $FIRMWARE. Install it with: brew install qemu"

case "${1:-}" in
    build) cmd_build ;;
    iso)
        [ "$GUEST" = windows ] || die "only the Windows image is a manual download"
        windows_iso
        ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    reset) cmd_reset ;;
    push) cmd_push ;;
    run) shift; cmd_run "$@" ;;
    *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
