import Foundation

/// Pure, side-effect-free matching logic, factored out so it can be unit-tested
/// with no debugger, Frida, or signed binary present. The live detectors in
/// `Detectors.swift` feed real system data into these functions.
public enum Heuristics {
    /// `P_TRACED` from `<sys/proc.h>` = 0x00000800. Exposed for testing the flag parse
    /// without calling sysctl.
    public static let pTraced: Int32 = 0x0000_0800

    /// True if the P_TRACED bit is set in a process flag word.
    public static func isTraced(pFlag: Int32) -> Bool {
        (pFlag & pTraced) != 0
    }

    /// Marker tokens that signal dynamic instrumentation. Matched against the image
    /// **basename's** tokens (not a substring of the full path), so the shield CLI's own
    /// `libswiftArgumentParser.dylib` is not flagged just because "argument" contains "gum".
    /// HIGH false-positive by nature even so (benign frameworks can share a token).
    static let instrumentationImageMarkers = [
        "frida", "gadget", "gum", "cynject", "substrate", "substitute", "hooker",
    ]

    /// Mach thread names used by instrumentation workers. `gmain`/`gdbus` are included
    /// despite being stock GLib names — that is why these are report-only.
    static let instrumentationThreadMarkers = [
        "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida",
    ]

    /// Split an image path's basename into lowercased tokens, breaking on non-alphanumeric
    /// separators (`.`, `-`, `_`) and camelCase boundaries. `FridaGadget.dylib` →
    /// `["frida", "gadget", "dylib"]`; `libswiftArgumentParser.dylib` →
    /// `["libswift", "argument", "parser", "dylib"]`.
    static func imageBasenameTokens(_ path: String) -> [String] {
        let base = (path as NSString).lastPathComponent
        var tokens: [String] = []
        var current = ""
        var prevIsLower = false
        for ch in base {
            if ch.isLetter || ch.isNumber {
                if ch.isUppercase, prevIsLower, !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                current.append(ch)
                prevIsLower = ch.isLowercase
            } else {
                if !current.isEmpty { tokens.append(current); current = "" }
                prevIsLower = false
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens.map { $0.lowercased() }
    }

    public static func matchesInstrumentationImage(_ path: String) -> Bool {
        // Match a marker only if it equals a whole basename token, or a token with a
        // leading "lib" stripped (so `libsubstrate` → `substrate`). Never a loose substring.
        let tokens = imageBasenameTokens(path)
        let candidates: Set<String> = Set(tokens.flatMap { token -> [String] in
            token.count > 3 && token.hasPrefix("lib")
                ? [token, String(token.dropFirst(3))]
                : [token]
        })
        return instrumentationImageMarkers.contains { candidates.contains($0) }
    }

    public static func matchesInstrumentationThread(_ name: String) -> Bool {
        let lower = name.lowercased()
        return instrumentationThreadMarkers.contains { lower == $0 || lower.contains($0) }
    }

    /// Paths rooted here are OS-shipped and always considered expected.
    static let systemImagePrefixes = [
        "/usr/lib/", "/System/", "/Library/Apple/",
    ]

    /// True if a path is OS-shipped (used as a fast pre-filter before `realpath`).
    public static func isSystemImage(_ path: String) -> Bool {
        systemImagePrefixes.contains { path.hasPrefix($0) }
    }

    /// True if an image path is worth surfacing for triage: NOT a system image, NOT the
    /// main executable, NOT inside the main bundle's own `Contents/` subtree, and NOT
    /// covered by the caller's allowlist.
    ///
    /// All path arguments must already be `realpath`-resolved by the caller so that
    /// `/var` vs `/private/var` and symlinks do not produce phantom mismatches; see
    /// `Detectors.unexpectedImages`.
    public static func isUnexpectedImage(
        _ resolvedPath: String,
        mainExecutableRealPath: String?,
        mainBundleContentsPrefix: String?,
        allowlist: [String]
    ) -> Bool {
        if let main = mainExecutableRealPath, resolvedPath == main { return false }
        if let contents = mainBundleContentsPrefix, resolvedPath.hasPrefix(contents) { return false }
        if isSystemImage(resolvedPath) { return false }
        let lower = resolvedPath.lowercased()
        if allowlist.contains(where: { lower.contains($0.lowercased()) }) { return false }
        return true
    }

    /// Maps a code-signature check result into a detection (or `nil` when the binary is
    /// fine, or legitimately unsigned). `status` is the OSStatus from
    /// `SecStaticCodeCheckValidity`; `errSecCSUnsigned` (-67062) is treated as "not
    /// meaningful on a debug/ad-hoc build", not a failure.
    public static func mapSignatureStatus(
        status: OSStatus,
        errSecSuccess: OSStatus = 0,
        errSecCSUnsigned: OSStatus = -67062,
        expectedTeamID: String?,
        actualTeamID: String?,
        requirementPinned: Bool = false
    ) -> Detection? {
        if status == errSecCSUnsigned {
            // "Not meaningful" on debug/ad-hoc builds — unless the caller pinned a Team ID
            // or a designated requirement, which an unsigned binary cannot satisfy (e.g. a
            // stripped x86_64 re-sign). Must be caught here: an unsigned binary never reaches
            // the requirement status below.
            if let expected = expectedTeamID {
                return .signatureInvalid(reason: "unsigned, expected Team ID \(expected)")
            }
            if requirementPinned {
                return .signatureInvalid(reason: "unsigned, expected a designated requirement")
            }
            return nil
        }
        if status != errSecSuccess {
            return .signatureInvalid(reason: "SecStaticCodeCheckValidity status \(status)")
        }
        guard let expected = expectedTeamID else { return nil }
        guard let actual = actualTeamID else {
            return .signatureInvalid(reason: "no Team ID present, expected \(expected)")
        }
        if actual != expected {
            return .signatureInvalid(reason: "Team ID \(actual) != expected \(expected)")
        }
        return nil
    }
}
