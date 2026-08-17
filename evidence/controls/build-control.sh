#!/bin/sh
# Builds one Windows control from `evidence/controls/<name>.c`.
#
#     build-control.sh <name>
#
# The script runs on any machine that is Windows under a POSIX shell: a
# runner under Git Bash, or the guest that `vm.sh` manages, whose login shell
# is the bash that Git carries. One script serves both, so the control cannot
# drift between them.
#
# Any of three compilers builds a control, and the script takes the first one
# it finds. A step that installed one would add a supply-chain dependency to
# the gate, and this project keeps that surface at zero.
#
# A native Windows program takes a native path. This shell reports
# `/c/work`, and `CreateProcess` cannot open that, so every path that
# reaches a compiler goes through `cygpath`, which ships with the shell.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=$ROOT/target/evidence
mkdir -p "$OUT"

[ "$#" -eq 1 ] || { echo "usage: build-control.sh <name>" >&2; exit 2; }
name=$1

cc=''
for candidate in cl clang gcc; do
    if command -v "$candidate" > /dev/null 2>&1; then
        cc=$candidate
        break
    fi
done
[ -n "$cc" ] || { echo "no cl, clang, or gcc on the path" >&2; exit 1; }

source=$(cygpath -w "$ROOT/evidence/controls/$name.c")
binary=$(cygpath -w "$OUT/$name.exe")

# `cl` takes an option after a dash as well as after a slash, and this uses
# the dash. The shell here is the one that Git carries, and it reads an
# argument that starts with a slash as a path: `/nologo` reached the compiler
# as `C:/Program Files/Git/nologo`, and the compiler called it a source file.
# Measured on 2026-08-15.
case $cc in
    cl) (cd "$OUT" && cl -nologo -W4 "-Fe:$binary" "$source") > /dev/null ;;
    *) "$cc" -O1 -o "$binary" "$source" ;;
esac
