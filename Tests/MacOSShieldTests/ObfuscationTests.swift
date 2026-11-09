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

    private func decode(_ e: ObfuscatedCodec.Encoded) -> String {
        __obfuscatedDecode(e.cipher, e.salt, e.seedMasked, e.mask)
    }

    /// The codec round-trips (key is re-derived, not stored), and a per-call-site salt means
    /// identical inputs encode to different ciphertext across call sites.
    func testCodecRoundTripAndPerLiteralKey() {
        let a = ObfuscatedCodec.encode("repeat")
        let b = ObfuscatedCodec.encode("repeat")
        XCTAssertNotEqual(a.cipher, b.cipher, "identical strings must encode differently")
        XCTAssertEqual(decode(a), "repeat")
        XCTAssertEqual(decode(b), "repeat")
    }

    /// Parse the `[0x.., 0x.., ...]` byte-array literals out of a rendered expansion.
    private func byteArrays(in rendered: String) -> [[UInt8]] {
        var arrays: [[UInt8]] = []
        var scalars = Substring(rendered)
        while let open = scalars.firstIndex(of: "["),
              let close = scalars[open...].firstIndex(of: "]") {
            let body = scalars[scalars.index(after: open)..<close]
            let bytes = body.split(separator: ",").compactMap { tok -> UInt8? in
                let t = tok.trimmingCharacters(in: .whitespaces)
                guard t.hasPrefix("0x") else { return nil }
                return UInt8(t.dropFirst(2), radix: 16)
            }
            if !bytes.isEmpty { arrays.append(bytes) }
            scalars = scalars[scalars.index(after: close)...]
        }
        return arrays
    }

    /// The raw per-literal key must NOT travel next to the cipher: the expansion emits
    /// cipher + salt + masked seed + mask, and the key is derived at runtime. So (a) the true
    /// key (plain ^ cipher) appears in no emitted array, and (b) no array other than the
    /// cipher itself has the cipher's length — there is no adjacent full-length key to scrape.
    func testExpansionStoresNoRawKeyAdjacentToCipher() throws {
        let plaintext = "adjacent-key-recovery-check"   // 27 bytes: != salt(16), != seed/mask(32)
        let plain = Array(plaintext.utf8)
        let node = try XCTUnwrap(
            ExprSyntax("#obfuscated(\"\(raw: plaintext)\")").as(MacroExpansionExprSyntax.self)
        )
        let expanded = try ObfuscatedMacro.expansion(of: node, in: BasicMacroExpansionContext())
        let rendered = expanded.description

        XCTAssertFalse(rendered.contains(plaintext), "plaintext leaked: \(rendered)")

        let arrays = byteArrays(in: rendered)
        let cipher = try XCTUnwrap(arrays.first)
        XCTAssertEqual(cipher.count, plain.count)

        // (a) the real key never appears verbatim as an emitted array.
        let rawKey = zip(plain, cipher).map { $0 ^ $1 }
        XCTAssertFalse(arrays.contains(rawKey), "raw key found adjacent to cipher")

        // (b) only one emitted array has the cipher's length (the cipher).
        XCTAssertEqual(arrays.filter { $0.count == cipher.count }.count, 1,
                       "a second full-length array sits next to the cipher: \(arrays.map(\.count))")
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
