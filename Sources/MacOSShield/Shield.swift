import Foundation

/// Umbrella entry point for the runtime library.
///
/// `macos-shield`'s runtime half is **defense-in-depth against dynamic tampering
/// and licence-cracking — NOT anti-clone.** A self-check inside the binary it
/// protects is a speed bump of minutes: an attacker (or an LLM) can NOP the
/// branch or hook the syscall. The clone-resistant half is build-hardening +
/// obfuscation (`shield harden`), not this. Read the README before relying on it.
public enum Shield {

    /// Run the detectors enabled by `policy`, then apply the policy response.
    ///
    /// - Returns: every detection found (always returned, whatever the response).
    /// - Note: `.terminate` fires only when a non-high-false-positive detection is
    ///   present; name/thread/env heuristics never terminate on their own.
    @discardableResult
    public static func scan(_ policy: ShieldPolicy = .default) -> [Detection] {
        var detections: [Detection] = []

        if policy.checkDebugger {
            detections += Detectors.debugger(policy: policy)
        }
        if policy.checkInstrumentation {
            detections += Detectors.instrumentationImages()
            detections += Detectors.instrumentationThreads()
            detections += Detectors.unexpectedImages(allowlist: policy.imageAllowlist)
        }
        if policy.checkDylibInjection {
            detections += Detectors.dylibInjection()
        }
        if policy.checkSignature {
            detections += Detectors.signature(expectedTeamID: policy.expectedTeamID)
        }
        if policy.checkMachOHash {
            detections += Detectors.machOHash(baseline: policy.machOBaseline)
        }

        apply(policy.onDetection, to: detections)
        return detections
    }

    private static func apply(_ response: ShieldPolicy.Response, to detections: [Detection]) {
        guard !detections.isEmpty else { return }
        switch response {
        case .report:
            break
        case .callback(let handler):
            handler(detections)
        case .terminate:
            // Safety gate: never brick a user on a high-false-positive signal alone.
            if detections.contains(where: { !$0.isHighFalsePositive }) {
                exit(EXIT_FAILURE)
            }
        }
    }
}
