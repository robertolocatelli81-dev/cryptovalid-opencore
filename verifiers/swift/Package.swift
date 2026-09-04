// swift-tools-version: 5.9
// CryptoValid independent verifier for Apple platforms (and Linux via swift-crypto).
// Apple builds use the system CryptoKit (no third-party deps); non-Apple builds link
// swift-crypto (API-compatible) for SHA-256 and Ed25519. SHA3-256 is the bundled Keccak.
import PackageDescription

let package = Package(
    name: "CryptoValidVerify",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "CryptoValidVerify", targets: ["CryptoValidVerify"]),
        .executable(name: "cvverify", targets: ["cvverify"]),
    ],
    dependencies: [
        // Only linked on non-Apple platforms; Apple uses system CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CryptoValidVerify",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto",
                         condition: .when(platforms: [.linux, .android, .windows])),
            ]
        ),
        .executableTarget(name: "cvverify", dependencies: ["CryptoValidVerify"]),
        .testTarget(
            name: "CryptoValidVerifyTests",
            dependencies: ["CryptoValidVerify"],
            resources: [.copy("Vectors")]
        ),
    ]
)
