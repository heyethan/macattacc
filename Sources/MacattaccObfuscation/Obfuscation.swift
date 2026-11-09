import Foundation
import CryptoKit

/// Compile-time string-literal obfuscation (MIT, commercial-safe).
///
/// `#obfuscated("secret")` encodes the literal at build time so the plaintext never
/// appears in the shipped binary's `__TEXT` string table, and decodes it at runtime on
/// first use. The XOR key is **not** stored next to the ciphertext: each literal's key is
/// derived at runtime as `SHA256(seed || salt || counter)` from a per-build master seed
/// (masked per call site) and a per-call-site salt, so a static `strings`/byte scan finds
/// no full-length key adjacent to the cipher.
///
/// **Honest limits.** This defeats naive `strings`/static scraping and raises the
/// static-recovery bar. It is one layer, not a wall: a debugger or a runtime memory
/// dump still reveals the decrypted value, because the app must decode it to use it — and
/// everything the runtime needs to recompute the key ships in the binary too.
@freestanding(expression)
public macro obfuscated(_ value: String) -> String =
    #externalMacro(module: "MacattaccObfuscationMacros", type: "ObfuscatedMacro")

/// Derive `length` key bytes as `SHA256(seed || salt || counter)` in counter mode.
///
/// MUST stay byte-for-byte identical to `ObfuscatedCodec.deriveKey` in the macro plugin
/// (`ObfuscatedMacro.swift`); the round-trip tests fail loudly if the two ever drift.
func __obfuscatedDeriveKey(seed: [UInt8], salt: [UInt8], length: Int) -> [UInt8] {
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

/// Runtime decode for ``obfuscated(_:)``. Reconstructs the master seed (`seedMasked ^
/// mask`), re-derives the per-literal key, then XORs it with the ciphertext. Underscored:
/// an implementation detail of the macro expansion, not an API to call directly.
public func __obfuscatedDecode(
    _ cipher: [UInt8], _ salt: [UInt8], _ seedMasked: [UInt8], _ mask: [UInt8]
) -> String {
    let seed = zip(seedMasked, mask).map { $0 ^ $1 }
    let key = __obfuscatedDeriveKey(seed: seed, salt: salt, length: cipher.count)
    return String(decoding: zip(cipher, key).map { $0 ^ $1 }, as: UTF8.self)
}
