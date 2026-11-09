import Foundation
import CryptoKit
import SwiftSyntax
import SwiftSyntaxMacros
import SwiftCompilerPlugin

/// Compile-time encoder for ``ObfuscatedMacro``.
///
/// The per-literal XOR key is **derived**, not stored: `key = SHA256(seed || salt ||
/// counter)` (counter mode, so it expands past 32 bytes) from a per-build master seed and
/// a per-call-site random salt. The expansion stores `cipher`, `salt`, and the master seed
/// in masked form (`seedMasked = seed ^ mask`, plus `mask`) — never the raw key — so a
/// static byte scan finds no full-length key adjacent to the cipher. XOR stays symmetric,
/// so the runtime decode re-derives the same key.
enum ObfuscatedCodec {
    /// One master seed per plugin process (≈ one per build). Generated once at load; the
    /// value never ships contiguously because each call site emits it XOR a fresh mask.
    static let masterSeed: [UInt8] = {
        var rng = SystemRandomNumberGenerator()
        return (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
    }()

    /// Derive `length` key bytes. MUST match `__obfuscatedDeriveKey` in the runtime
    /// (`Obfuscation.swift`); the round-trip tests fail loudly if the two ever drift.
    static func deriveKey(seed: [UInt8], salt: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(length + 32)
        var counter: UInt32 = 0
        while out.count < length {
            var hasher = SHA256()
            hasher.update(data: Data(seed))
            hasher.update(data: Data(salt))
            var be = counter.bigEndian
            withUnsafeBytes(of: &be) { hasher.update(bufferPointer: $0) }
            out.append(contentsOf: hasher.finalize())
            counter &+= 1
        }
        return Array(out.prefix(length))
    }

    struct Encoded {
        let cipher: [UInt8]
        let salt: [UInt8]
        let seedMasked: [UInt8]
        let mask: [UInt8]
    }

    static func encode(_ string: String) -> Encoded {
        let plain = Array(string.utf8)
        var rng = SystemRandomNumberGenerator()
        let salt = (0..<16).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let key = deriveKey(seed: masterSeed, salt: salt, length: plain.count)
        let cipher = zip(plain, key).map { $0 ^ $1 }
        let mask = (0..<masterSeed.count).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let seedMasked = zip(masterSeed, mask).map { $0 ^ $1 }
        return Encoded(cipher: cipher, salt: salt, seedMasked: seedMasked, mask: mask)
    }
}

/// `#obfuscated("literal") -> String`.
///
/// Expands at compile time to a call into `MacattaccObfuscation`'s runtime decode,
/// passing the ciphertext, salt, and masked master seed as byte-array literals — never the
/// raw key. The original plaintext appears nowhere in the expansion.
public struct ObfuscatedMacro: ExpressionMacro {
    enum Failure: Error, CustomStringConvertible {
        case notAStringLiteral
        var description: String {
            "#obfuscated requires a single static string literal (no interpolation)"
        }
    }

    public static func expansion(
        of node: some FreestandingMacroExpansionSyntax,
        in context: some MacroExpansionContext
    ) throws -> ExprSyntax {
        guard
            let argument = node.arguments.first?.expression,
            let literal = argument.as(StringLiteralExprSyntax.self),
            let value = literal.representedLiteralValue
        else {
            throw Failure.notAStringLiteral
        }

        let encoded = ObfuscatedCodec.encode(value)
        func list(_ bytes: [UInt8]) -> String {
            bytes.map { "0x\(String($0, radix: 16))" }.joined(separator: ", ")
        }
        return """
        MacattaccObfuscation.__obfuscatedDecode(\
        [\(raw: list(encoded.cipher))], \
        [\(raw: list(encoded.salt))], \
        [\(raw: list(encoded.seedMasked))], \
        [\(raw: list(encoded.mask))])
        """
    }
}

@main
struct MacattaccObfuscationPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [ObfuscatedMacro.self]
}
