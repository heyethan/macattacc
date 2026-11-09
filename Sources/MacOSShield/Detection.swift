import Foundation

/// A single tamper/instrumentation signal found by ``Shield/scan(_:)``.
///
/// Every case is `Sendable` and `Equatable` so detections can cross actor
/// boundaries and be compared in tests. Read ``isHighFalsePositive`` before
/// acting on one: name/thread heuristics are informational, not proof.
public enum Detection: Sendable, Equatable {
    /// A debugger is attached (sysctl `P_TRACED`). High confidence.
    case debuggerAttached(method: String)

    /// A loaded image name matched an instrumentation framework (Frida, Substrate…).
    /// HIGH false-positive: Rosetta, VMs, EDR and accessibility tools perturb the image list.
    case instrumentationImage(name: String)

    /// A Mach thread name matched a known instrumentation worker (e.g. `gum-js-loop`).
    /// HIGH false-positive: `gmain`/`gdbus` are stock GLib names in many benign apps.
    case instrumentationThread(name: String)

    /// `DYLD_INSERT_LIBRARIES` was set in the environment. Specific-but-weak: benign apps
    /// rarely set it (so it is NOT high false-positive), but the hardened runtime strips it,
    /// so its *absence* proves nothing and an attacker can inject by other means.
    case dylibInjectionEnvVar(value: String)

    /// A loaded image lives outside system paths and is not on the allowlist.
    /// HIGH false-positive. Report-only, for triage.
    case unexpectedImage(path: String)

    /// The running binary's code signature failed to validate, or its Team ID / designated
    /// requirement did not match. With `expectedTeamID` and `signatureRequirement` both nil,
    /// this only proves "signed and unmodified vs its OWN signature" — an attacker who
    /// re-signs with their own identity passes. Pin a Team ID or requirement for real weight.
    case signatureInvalid(reason: String)

    /// Rough triage weight. Not a security guarantee.
    public var severity: Severity {
        switch self {
        case .debuggerAttached, .signatureInvalid:
            return .critical
        case .dylibInjectionEnvVar:
            return .warning
        case .instrumentationImage, .instrumentationThread, .unexpectedImage:
            return .info
        }
    }

    /// `true` for heuristics that fire on benign software often enough that they must
    /// never, on their own, gate a `terminate` response. "High-FP" means "fires on benign
    /// apps" (name/thread/unexpected-image heuristics), NOT "easy to evade". ``Shield``
    /// enforces that only non-high-FP detections may gate terminate.
    public var isHighFalsePositive: Bool {
        switch self {
        case .instrumentationImage, .instrumentationThread, .unexpectedImage:
            return true
        case .debuggerAttached, .signatureInvalid, .dylibInjectionEnvVar:
            return false
        }
    }

    /// One-line human summary for `shield doctor` and logs.
    public var summary: String {
        switch self {
        case .debuggerAttached(let m):       return "Debugger attached (\(m))"
        case .instrumentationImage(let n):   return "Instrumentation image: \(n)"
        case .instrumentationThread(let n):  return "Instrumentation thread: \(n)"
        case .dylibInjectionEnvVar(let v):   return "DYLD_INSERT_LIBRARIES set: \(v)"
        case .unexpectedImage(let p):        return "Unexpected image: \(p)"
        case .signatureInvalid(let r):       return "Signature invalid: \(r)"
        }
    }
}

/// Rough triage weight for a ``Detection``.
public enum Severity: Int, Sendable, Comparable {
    case info = 0, warning = 1, critical = 2
    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }
}
