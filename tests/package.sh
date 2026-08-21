#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

mkdir -p target
package_temp=$(mktemp -d "$root/target/package-check.XXXXXX")
trap 'rm -rf "$package_temp"' EXIT HUP INT TERM

check_list() {
    package=$1
    manifest=$2
    fixture=$3
    actual="$package_temp/$package.txt"
    raw="$actual.raw"

    cargo package --manifest-path "$manifest" --list --allow-dirty >"$raw"
    # Cargo can write CRLF on Windows. The package list has one format here.
    tr -d '\r' <"$raw" >"$actual"
    diff -u "$fixture" "$actual"
}

check_list fidelity crates/fidelity/Cargo.toml tests/package/fidelity.txt
check_list tauri-plugin-fidelity bindings/tauri-plugin-fidelity/Cargo.toml \
    tests/package/tauri-plugin-fidelity.txt

cargo check -p fidelity --no-default-features --locked
cargo check -p fidelity --no-default-features --features serde --locked
cargo check -p fidelity --no-default-features --features tracing --locked
cargo check -p fidelity --no-default-features --features serde,tracing --locked

package_set() {
    target=$1
    CARGO_TARGET_DIR="$target" cargo package --workspace --allow-dirty --no-verify --offline
}

first="$package_temp/package-first"
second="$package_temp/package-second"
package_set "$first"
package_set "$second"

for archive in "$first"/package/*.crate; do
    name=$(basename "$archive")
    cmp "$archive" "$second/package/$name"
done

mkdir -p "$package_temp/packages"
for archive in "$first"/package/fidelity*-0.3.0.crate; do
    tar -xzf "$archive" -C "$package_temp/packages"
done
cp tests/package/consumer/Cargo.toml "$package_temp/Cargo.toml"
mkdir -p "$package_temp/src"
cp tests/package/consumer/src/main.rs "$package_temp/src/main.rs"
cargo +1.85 check --manifest-path "$package_temp/Cargo.toml" --offline
RUSTDOCFLAGS=-Dwarnings cargo +1.85 doc \
    -p fidelity --all-features --no-deps --locked

cargo +1.88 check --manifest-path bindings/tauri-plugin-fidelity/Cargo.toml --locked
cargo test --manifest-path bindings/tauri-plugin-fidelity/Cargo.toml --locked
cargo clippy --manifest-path bindings/tauri-plugin-fidelity/Cargo.toml \
    --all-targets --locked -- -D warnings
RUSTDOCFLAGS=-Dwarnings cargo +1.88 doc \
    --manifest-path bindings/tauri-plugin-fidelity/Cargo.toml --no-deps --locked

echo "the package contract passed"
