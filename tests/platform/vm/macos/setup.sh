#!/bin/sh
# Prepares a fresh macOS guest for the harness. Run this once, in the guest.
#
# The macOS setup assistant is the one step that no script replaces. It asks
# for a region, a keyboard, an account, and a set of choices, and Apple offers
# no answer file for it. So the guest boots with a window, a person answers it
# once, and this script does everything after that.
#
# This step is optional, and `provision.sh` beside it is the reason. A control
# that only has to run a binary and report needs no account at all: that script
# writes a launch daemon into the guest disk from outside, and the daemon runs
# before the assistant ever appears. Run this one only when a control needs a
# real session, SSH, or a window.
#
# The ownership trap is worth stating, because it looks like a wall. A file
# that the host creates on the guest disk lands under the uid of the host user,
# launchd loads a daemon only when root owns its plist, and a chown to root
# needs sudo. A rename inside one volume keeps the inode, and a truncating
# write keeps it too, so an existing root-owned plist becomes the new one and
# stays root-owned. Measured on 2026-08-18, and `provision.sh` does exactly it.
#
# `vm.sh macos setup` attaches the directory that holds this file, and macOS
# mounts it by itself, so the guest already has it:
#
#     sh "/Volumes/My Shared Files/setup.sh"
#
# After this, the guest answers SSH and the image is ready to become golden.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KEY=$HERE/id_ed25519.pub

[ -f "$KEY" ] || {
    echo "no public key at $KEY" >&2
    exit 1
}

echo "the harness key goes in"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
grep -qxF "$(cat "$KEY")" "$HOME/.ssh/authorized_keys" 2> /dev/null ||
    cat "$KEY" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

# Remote Login has two switches on a current macOS, and which one answers
# depends on the release. `systemsetup` needs Full Disk Access for the
# terminal that runs it, and a fresh guest grants none, so it can refuse.
# `launchctl` reaches the same daemon and needs no such grant, so it runs
# first and `systemsetup` is the fallback.
echo "remote login goes on"
sudo launchctl enable system/com.openssh.sshd 2> /dev/null || true
sudo launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist 2> /dev/null ||
    sudo systemsetup -setremotelogin on > /dev/null 2>&1 ||
    echo "turn Remote Login on by hand, in System Settings, General, Sharing" >&2

# A guest that sleeps stops answering, and the harness then reads a timeout as
# a failed control.
echo "sleep goes off"
sudo pmset -a sleep 0 displaysleep 0 disksleep 0 2> /dev/null || true

# The record names the guest, so the guest states what it is.
echo
sw_vers
echo
echo "kern.hv_vmm_present is $(sysctl -n kern.hv_vmm_present 2> /dev/null || echo unavailable)"
echo
echo "the guest is ready. Shut it down, then run: tests/platform/controls/vm.sh macos start"
