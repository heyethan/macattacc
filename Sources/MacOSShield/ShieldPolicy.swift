import Foundation

/// Configures what ``Shield/scan(_:)`` checks and how it reacts.
///
/// Defaults are deliberately safe: **report-only**, no `terminate`, no
/// `PT_DENY_ATTACH`. You must opt in to anything that could disrupt a real user.
/// See the README "Honest limits" section first.
public struct ShieldPolicy: Sendable {
    /// What to do once a scan has collected its detections.
    public enum Response: Sendable {
        /// Return the detections to the caller and do nothing else. **Default.**
        case report
        /// Invoke a handler with the detections — always, even on a clean scan (the host
        /// receives an empty array), so "scanned clean" is distinguishable from "never ran".
        case callback(@Sendable ([Detection]) -> Void)
        /// Terminate the process (via `abort()`) — but ONLY if at least one
        /// non-high-false-positive detection is present. Name/thread/image heuristics never
        /// trigger this alone. A library killing its host is drastic; prefer `.report`.
        case terminate
    }

    public var onDetection: Response

    // Which detectors run.
    public var checkDebugger: Bool
    /// Loaded-image basename vs instrumentation markers. High-FP, report-only.
    public var checkInstrumentationImages: Bool
    /// Mach thread names vs instrumentation workers. High-FP, report-only.
    public var checkInstrumentationThreads: Bool
    /// Loaded images outside system/bundle/allowlist. The noisiest check — split out so it
    /// can be disabled independently of the instrumentation-marker checks.
    public var checkUnexpectedImages: Bool
    public var checkDylibInjection: Bool
    public var checkSignature: Bool

    /// Apply `ptrace(PT_DENY_ATTACH)` during the scan. OFF by default — opt-in within
    /// opt-in. Gated independently of `checkDebugger`. Forfeits your crash telemetry,
    /// can look like a crash on MDM/EDR Macs, and risks notarization review. SIGSEGVs if a
    /// debugger is already attached. Applied at most once per process. Never enable for an
    /// App-Store-bound build.
    public var enablePtraceDenyAttach: Bool

    /// Expected Team ID for the signature self-check. `nil` skips the Team ID comparison.
    /// When set, an *unsigned* binary is reported (it cannot satisfy a pinned Team ID).
    public var expectedTeamID: String?

    /// Optional designated-requirement string (e.g. `anchor apple generic and ...`) passed
    /// to `SecStaticCodeCheckValidity`. `nil` skips it. With both this and `expectedTeamID`
    /// nil, the check only proves "signed and unmodified vs its own signature" — an attacker
    /// who re-signs with their own identity passes it.
    public var signatureRequirement: String?

    /// Substrings (case-insensitive) of image paths treated as benign in the
    /// unexpected-image diff. System paths are always allowed; add your own frameworks here.
    public var imageAllowlist: [String]

    public init(
        onDetection: Response = .report,
        checkDebugger: Bool = true,
        checkInstrumentationImages: Bool = true,
        checkInstrumentationThreads: Bool = true,
        checkUnexpectedImages: Bool = true,
        checkDylibInjection: Bool = true,
        checkSignature: Bool = true,
        enablePtraceDenyAttach: Bool = false,
        expectedTeamID: String? = nil,
        signatureRequirement: String? = nil,
        imageAllowlist: [String] = []
    ) {
        self.onDetection = onDetection
        self.checkDebugger = checkDebugger
        self.checkInstrumentationImages = checkInstrumentationImages
        self.checkInstrumentationThreads = checkInstrumentationThreads
        self.checkUnexpectedImages = checkUnexpectedImages
        self.checkDylibInjection = checkDylibInjection
        self.checkSignature = checkSignature
        self.enablePtraceDenyAttach = enablePtraceDenyAttach
        self.expectedTeamID = expectedTeamID
        self.signatureRequirement = signatureRequirement
        self.imageAllowlist = imageAllowlist
    }

    /// The safe default: everything report-only, nothing destructive.
    public static let `default` = ShieldPolicy()
}
