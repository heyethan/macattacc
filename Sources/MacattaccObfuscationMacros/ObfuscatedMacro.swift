import SwiftSyntax
import SwiftSyntaxMacros
import SwiftCompilerPlugin

/// Compile-time encoder for ``ObfuscatedMacro``. Pure and testable: XOR the UTF-8
/// bytes with a fresh random key of the same length. XOR is symmetric, so the
/// library's runtime decode is the identical operation. A per-literal key means
/// identical strings encode differently at every call site, and the plaintext
/// never lands in the binary's `__TEXT` string table.
enum ObfuscatedCodec {
    static func encode(_ string: String) -> (cipher: [UInt8], key: [UInt8]) {
        let plain = Array(string.utf8)
        var rng = SystemRandomNumberGenerator()
        let key = (0..<plain.count).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let cipher = zip(plain, key).map { $0 ^ $1 }
        return (cipher, key)
    }
}

/// `#obfuscated("literal") -> String`.
///
/// Expands at compile time to a call into `MacattaccObfuscation`'s runtime decode,
/// passing the XOR ciphertext and its key as byte-array literals. The original
/// plaintext appears nowhere in the expansion.
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

        let (cipher, key) = ObfuscatedCodec.encode(value)
        let cipherList = cipher.map { "0x\(String($0, radix: 16))" }.joined(separator: ", ")
        let keyList = key.map { "0x\(String($0, radix: 16))" }.joined(separator: ", ")
        return "MacattaccObfuscation.__obfuscatedDecode([\(raw: cipherList)], [\(raw: keyList)])"
    }
}

@main
struct MacattaccObfuscationPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [ObfuscatedMacro.self]
}
