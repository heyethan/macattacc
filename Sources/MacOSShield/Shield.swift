import Foundation
import CShieldShim

/// Umbrella entry point for the runtime library.
///
/// macattacc's runtime half is **defense-in-depth against dynamic tampering
/// and licence-cracking — NOT anti-clone.** A self-check inside the binary it
/// protects is a speed bump of minutes: an attacker (or an LLM) can NOP the
/// branch or hook the syscall. The clone-resistant half is build-hardening +
/// obfuscation (`shield harden`), not this. Read the README before relying on it.
public enum Shield {

    /// Applied at most once per process: `ptrace(PT_DENY_ATTACH)` is irreversible and
    /// SIGSEGVs if a debugger is already attached, so repeat `scan()` calls must not
    /// re-invoke it. A lazy `static let` gives a thread-safe run-once under Swift 6.
    private static let denyAttachOnce: Void = { _ = shield_deny_attach() }()

    /// Run the detectors enabled by `policy`, then apply the policy response.
    ///
    /// - Returns: every detection found (always returned, whatever the response).
    /// - Note: `.terminate` fires only when a non-high-false-positive detection is
    ///   present; name/thread/image heuristics never terminate on their own.
    @discardableResult
    public static func scan(_ policy: ShieldPolicy = .default) -> [Detection] {
        scan(policy, denyAttach: { _ = denyAttachOnce })
    }

    /// Testable core. `denyAttach` is injected so tests can assert the gating without
    /// ever invoking the real, irreversible `PT_DENY_ATTACH` on the test process.
    @discardableResult
    static func scan(_ policy: ShieldPolicy, denyAttach: () -> Void) -> [Detection] {
        var detections: [Detection] = []

        if policy.checkDebugger {
            detections += Detectors.debugger()
        }
        // PT_DENY_ATTACH has its own gate, independent of checkDebugger: decoupled so that
        // a policy with checkDebugger=false, enablePtraceDenyAttach=true still hardens.
        if policy.enablePtraceDenyAttach {
            denyAttach()
        }
        if policy.checkInstrumentationImages {
            detections += Detectors.instrumentationImages()
        }
        if policy.checkInstrumentationThreads {
            detections += Detectors.instrumentationThreads()
        }
        if policy.checkUnexpectedImages {
            detections += Detectors.unexpectedImages(allowlist: policy.imageAllowlist)
        }
        if policy.checkDylibInjection {
            detections += Detectors.dylibInjection()
        }
        if policy.checkSignature {
            detections += Detectors.signature(
                expectedTeamID: policy.expectedTeamID,
                requirementString: policy.signatureRequirement
            )
        }

        apply(policy.onDetection, to: detections)
        return detections
    }

    /// The terminate safety gate: a `.terminate` response fires only when at least one
    /// non-high-false-positive detection is present. Exposed internally so the test and
    /// `apply` share one predicate instead of re-implementing it.
    static func shouldTerminate(_ detections: [Detection]) -> Bool {
        detections.contains { !$0.isHighFalsePositive }
    }

    private static func apply(_ response: ShieldPolicy.Response, to detections: [Detection]) {
        switch response {
        case .report:
            break
        case .callback(let handler):
            // Always invoked, even on a clean scan (empty array), so the host can tell
            // "scanned clean" from "never ran".
            handler(detections)
        case .terminate:
            // Never brick a user on a high-false-positive signal alone. `abort()` (not
            // `exit`) leaves a crash report; see the WARNING below.
            if shouldTerminate(detections) {
                // WARNING: a library killing its host process is drastic. Prefer `.report`
                // or `.callback` and enforce on a server you control. `.terminate` is a
                // last resort for a build you fully own and have tested.
                abort()
            }
        }
    }
}
