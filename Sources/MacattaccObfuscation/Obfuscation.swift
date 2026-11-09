/// Compile-time string-literal obfuscation (MIT, commercial-safe).
///
/// `#obfuscated("secret")` encodes the literal at build time (XOR with a per-literal
/// random key) so the plaintext never appears in the shipped binary's `__TEXT` string
/// table, and decodes it at runtime on first use.
///
/// **Honest limits.** This defeats naive `strings`/static scraping and raises the
/// static-recovery bar. It is one layer, not a wall: a debugger or a runtime memory
/// dump still reveals the decrypted value, because the app must decode it to use it.
@freestanding(expression)
public macro obfuscated(_ value: String) -> String =
    #externalMacro(module: "MacattaccObfuscationMacros", type: "ObfuscatedMacro")

/// Runtime decode for ``obfuscated(_:)``. XOR is symmetric, so this reverses the
/// macro's compile-time encode. Underscored: it is an implementation detail of the
/// macro expansion, not an API to call directly.
public func __obfuscatedDecode(_ cipher: [UInt8], _ key: [UInt8]) -> String {
    String(decoding: zip(cipher, key).map { $0 ^ $1 }, as: UTF8.self)
}
