#!/usr/bin/env bash
# Apple side of the crate, on macOS:
#   1. the Rust library builds for iOS and the iOS Simulator with the `uniffi` feature
#   2. the Swift binding is generated from the compiled library (library mode)
#   3. the Swift package's tests pass on macOS (swift test) and it builds for an iOS device and the iOS Simulator
#   4. the README's conformance snippet (the ```swift block after "conforms a vault")
#      typechecks against the generated binding and apple/'s sources
# Each step fails the script; a snippet that is not found fails it too (no silent skip).
set -euo pipefail
cd "$(dirname "$0")/.."
out="${TMPDIR:-/tmp}/alice-os-keystore-apple.$$"
trap 'rm -rf "$out"' EXIT
mkdir -p "$out/inc"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  rustup target list --installed | grep -q "^${target}\$" || rustup target add "$target"
  cargo build --release --features uniffi --lib --target "$target"
done

cargo build --release --features uniffi --lib
cargo run --release --manifest-path tools/uniffi-bindgen/Cargo.toml -- generate \
  --library target/release/libalice_os_keystore.dylib --language swift --out-dir "$out/gen"
grep -q "protocol ForeignKeyVault" "$out/gen/alice_os_keystore.swift"
cp "$out/gen/alice_os_keystoreFFI.h" "$out/inc/"
cp "$out/gen/alice_os_keystoreFFI.modulemap" "$out/inc/module.modulemap"

(cd apple && swift test)
(cd apple && xcodebuild -scheme AliceOsKeystore -destination 'generic/platform=iOS' -quiet build)
(cd apple && xcodebuild -scheme AliceOsKeystore -destination 'generic/platform=iOS Simulator' -quiet build)

python3 - "$out/glue.swift" <<'PY'
import re, sys
text = open("README.md", encoding="utf-8").read()
at = text.find("conforms a vault")
m = re.search(r"```swift\n(.*?)```", text[at:], re.S) if at >= 0 else None
if not m:
    sys.exit("apple_check: the README conformance snippet was not found")
open(sys.argv[1], "w", encoding="utf-8").write(m.group(1))
PY
xcrun swiftc -typecheck -sdk "$(xcrun --show-sdk-path --sdk macosx)" -target arm64-apple-macos14 \
  -I "$out/inc" "$out/gen/alice_os_keystore.swift" apple/Sources/AliceOsKeystore/*.swift "$out/glue.swift"
echo "apple_check: ios + ios-sim libraries, binding, Swift package (device + simulator), README snippet: ok"
