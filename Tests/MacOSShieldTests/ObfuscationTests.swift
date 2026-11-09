import XCTest
import Foundation
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacroExpansion
import MacattaccObfuscation
@testable import MacattaccObfuscationMacros

/// A type whose bundle is the test bundle, so `Bundle(for:)` locates the compiled
/// test binary for the strings-absence check below.
private final class BundleAnchor {}

final class ObfuscationTests: XCTestCase {

    // MARK: macro expansion — no plaintext

    /// Expand `#obfuscated("...")` directly and assert the plaintext is absent from the
    /// generated source. `assertMacroExpansion` can't be used for an exact match here: the
    /// XOR key is random per expansion, so the expanded bytes are non-deterministic by design.
    func testExpansionContainsNoPlaintext() throws {
        let node = try XCTUnwrap(
            ExprSyntax(#"#obfuscated("hunter2")"#).as(MacroExpansionExprSyntax.self)
        )
        let context = BasicMacroExpansionContext()
        let expanded = try ObfuscatedMacro.expansion(of: node, in: context)
        let rendered = expanded.description

        XCTAssertFalse(rendered.contains("hunter2"), "plaintext leaked into expansion: \(rendered)")
        XCTAssertTrue(rendered.contains("__obfuscatedDecode"), "expansion should call the runtime decode")
    }

    /// The codec is symmetric (XOR), and a per-literal random key means identical inputs
    /// encode to different ciphertext across call sites.
    func testCodecRoundTripAndPerLiteralKey() {
        let a = ObfuscatedCodec.encode("repeat")
        let b = ObfuscatedCodec.encode("repeat")
        XCTAssertNotEqual(a.cipher, b.cipher, "identical strings must encode differently")
        XCTAssertEqual(__obfuscatedDecode(a.cipher, a.key), "repeat")
        XCTAssertEqual(__obfuscatedDecode(b.cipher, b.key), "repeat")
    }

    // MARK: runtime round-trip

    func testRuntimeRoundTrip() {
        XCTAssertEqual(#obfuscated("hunter2"), "hunter2")
        XCTAssertEqual(#obfuscated(""), "")
        XCTAssertEqual(#obfuscated("café ☕️ — ключ 🔑"), "café ☕️ — ключ 🔑")

        // Long string (> 500 bytes): exercises a key/cipher pair well past a single word.
        let long = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        XCTAssertEqual(
            #obfuscated("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
            long)
    }

    // MARK: build-artifact — sentinel absent from the binary

    /// A sentinel passed through `#obfuscated` must NOT survive as plaintext in the compiled
    /// test binary. The literal lives in source only; the macro replaces it with ciphertext.
    /// The contiguous sentinel is reassembled at runtime from fragments, so searching for it
    /// does not itself embed it. Skips gracefully if the binary path isn't a readable Mach-O.
    func testSentinelAbsentFromBinary() throws {
        // Reassembled at runtime — the contiguous form is never a single literal in the binary.
        let sentinel = ["MACATTACC", "OBFSENTINEL", "9f3a71be"].joined(separator: "_")

        // Proves the macro actually produces the sentinel, without embedding its contiguous form.
        XCTAssertEqual(#obfuscated("MACATTACC_OBFSENTINEL_9f3a71be"), sentinel)

        guard
            let path = Bundle(for: BundleAnchor.self).executableURL?.path,
            let data = FileManager.default.contents(atPath: path)
        else {
            throw XCTSkip("test binary path not found")
        }
        // Mach-O magic (thin or fat/universal); skip if this isn't one.
        let machOMagics: [[UInt8]] = [
            [0xcf, 0xfa, 0xed, 0xfe], [0xce, 0xfa, 0xed, 0xfe], // 64/32 little-endian
            [0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca], // fat
        ]
        let head = Array(data.prefix(4))
        guard machOMagics.contains(head) else {
            throw XCTSkip("binary at \(path) is not a Mach-O (head: \(head))")
        }

        let needle = Data(sentinel.utf8)
        XCTAssertNil(data.range(of: needle),
                     "sentinel plaintext found in \(path) — obfuscation did not strip it")
    }
}
