// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "macattacc",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "MacOSShield", targets: ["MacOSShield"]),
        .executable(name: "shield", targets: ["shield"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        // C shim: syscalls Swift can't reach cleanly (ptrace PT_DENY_ATTACH, sysctl kinfo_proc).
        .target(name: "CShieldShim"),
        .target(
            name: "MacOSShield",
            dependencies: ["CShieldShim"]
        ),
        .executableTarget(
            name: "shield",
            dependencies: [
                "MacOSShield",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "MacOSShieldTests",
            dependencies: ["MacOSShield", "shield"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
