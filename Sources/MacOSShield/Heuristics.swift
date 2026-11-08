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

    /// Image basenames that signal dynamic instrumentation. Matched as case-insensitive
    /// substrings of the full image path. HIGH false-positive by nature.
    static let instrumentationImageMarkers = [
        "frida", "frida-agent", "frida-gadget", "libgadget",
        "gum", "cynject", "substrate", "substitute", "libhooker",
    ]

    /// Mach thread names used by instrumentation workers. `gmain`/`gdbus` are included
    /// despite being stock GLib names — that is why these are report-only.
    static let instrumentationThreadMarkers = [
        "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida",
    ]

    public static func matchesInstrumentationImage(_ path: String) -> Bool {
        let lower = path.lowercased()
        return instrumentationImageMarkers.contains { lower.contains($0) }
    }

    public static func matchesInstrumentationThread(_ name: String) -> Bool {
        let lower = name.lowercased()
        return instrumentationThreadMarkers.contains { lower == $0 || lower.contains($0) }
    }

    /// Paths rooted here are OS-shipped and always considered expected.
    static let systemImagePrefixes = [
        "/usr/lib/", "/System/", "/Library/Apple/",
    ]

    /// True if an image path is NOT a system image, NOT the main executable, and NOT
    /// covered by the caller's allowlist — i.e. worth surfacing for triage.
    public static func isUnexpectedImage(
        _ path: String,
        mainExecutablePath: String?,
        allowlist: [String]
    ) -> Bool {
        if let main = mainExecutablePath, path == main { return false }
        if systemImagePrefixes.contains(where: { path.hasPrefix($0) }) { return false }
        let lower = path.lowercased()
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
        actualTeamID: String?
    ) -> Detection? {
        if status == errSecCSUnsigned { return nil }
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
