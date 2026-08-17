#!/bin/sh
# Makes the key that the harness uses to reach both guests.
#
# Each Packer template bakes the public half into its image, so a fresh build
# answers the harness with no password step. The private half stays on this
# machine, under `target/`, and the guests hold no secret, so the key is not
# committed and not shared.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
KEY=$ROOT/target/vm/id_ed25519

mkdir -p "$ROOT/target/vm"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY" -C fidelity-vm
echo "the guest key is $KEY"
