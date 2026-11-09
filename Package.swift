// swift-tools-version: 6.0
import PackageDescription
import CompilerPluginSupport

let package = Package(
    name: "macattacc",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "MacOSShield", targets: ["MacOSShield"]),
        // Separate product: adopt compile-time string obfuscation without the runtime detectors.
        .library(name: "MacattaccObfuscation", targets: ["MacattaccObfuscation"]),
        .executable(name: "shield", targets: ["shield"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        // Pinned to the 6xx line matching the installed Swift 6 toolchain's macro protocol.
        .package(url: "https://github.com/swiftlang/swift-syntax.git", "600.0.0"..<"603.0.0"),
    ],
    targets: [
        // C shim: syscalls Swift can't reach cleanly (ptrace PT_DENY_ATTACH, sysctl kinfo_proc).
        .target(name: "CShieldShim"),
        .target(
            name: "MacOSShield",
            dependencies: ["CShieldShim"]
        ),
        // Compile-time string-literal obfuscator (freestanding `#obfuscated` macro) plus its
        // tiny runtime decode. MIT, no third-party obfuscator. Kept apart from MacOSShield.
        .macro(
            name: "MacattaccObfuscationMacros",
            dependencies: [
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
            ]
        ),
        .target(
            name: "MacattaccObfuscation",
            dependencies: ["MacattaccObfuscationMacros"]
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
            dependencies: [
                "MacOSShield",
                "shield",
                "MacattaccObfuscation",
                "MacattaccObfuscationMacros",
                .product(name: "SwiftSyntaxBuilder", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacroExpansion", package: "swift-syntax"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
