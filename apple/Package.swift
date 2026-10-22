// swift-tools-version:5.9
import PackageDescription

// Apple key stores for alice-os-keystore. The types here hand out 32-byte data
// keys by generation; a consumer conforms them to the UniFFI-generated
// `ForeignKeyVault` protocol (feature "uniffi" of the Rust crate) to pass them to Rust.
let package = Package(
    name: "AliceOsKeystore",
    platforms: [.iOS(.v17), .macOS(.v14), .visionOS(.v1)],
    products: [.library(name: "AliceOsKeystore", targets: ["AliceOsKeystore"])],
    targets: [.target(name: "AliceOsKeystore")]
)
