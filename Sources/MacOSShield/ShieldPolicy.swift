import Foundation

/// Configures what ``Shield/scan(_:)`` checks and how it reacts.
///
/// Defaults are deliberately safe: **report-only**, no `terminate`, no
/// `PT_DENY_ATTACH`, no Mach-O hashing. You must opt in to anything that could
/// disrupt a real user. See the README "Honest limits" section first.
public struct ShieldPolicy: Sendable {
    /// What to do once a scan has collected its detections.
    public enum Response: Sendable {
        /// Return the detections to the caller and do nothing else. **Default.**
        case report
        /// Invoke a handler with the detections. You decide what happens.
        case callback(@Sendable ([Detection]) -> Void)
        /// Terminate the process — but ONLY if at least one non-high-false-positive
        /// detection is present. Name/thread/env heuristics never trigger this alone.
        case terminate
    }

    public var onDetection: Response

    // Which detectors run.
    public var checkDebugger: Bool
    public var checkInstrumentation: Bool
    public var checkDylibInjection: Bool
    public var checkSignature: Bool
    public var checkMachOHash: Bool

    /// Apply `ptrace(PT_DENY_ATTACH)` during the scan. OFF by default — opt-in within
    /// opt-in. Forfeits your crash telemetry, can look like a crash on MDM/EDR Macs,
    /// and risks notarization review. SIGSEGVs if a debugger is already attached.
    /// Never enable for an App-Store-bound build.
    public var enablePtraceDenyAttach: Bool

    /// Expected Team ID for the signature self-check. `nil` skips the Team ID comparison.
    public var expectedTeamID: String?

    /// Substrings (case-insensitive) of image paths treated as benign in the
    /// unexpected-image diff. System paths are always allowed; add your own frameworks here.
    public var imageAllowlist: [String]

    /// Section name -> lowercase hex SHA-256, baked at build time. Only used when
    /// `checkMachOHash` is true. Fragile under re-signing; document before shipping.
    public var machOBaseline: [String: String]

    public init(
        onDetection: Response = .report,
        checkDebugger: Bool = true,
        checkInstrumentation: Bool = true,
        checkDylibInjection: Bool = true,
        checkSignature: Bool = true,
        checkMachOHash: Bool = false,
        enablePtraceDenyAttach: Bool = false,
        expectedTeamID: String? = nil,
        imageAllowlist: [String] = [],
        machOBaseline: [String: String] = [:]
    ) {
        self.onDetection = onDetection
        self.checkDebugger = checkDebugger
        self.checkInstrumentation = checkInstrumentation
        self.checkDylibInjection = checkDylibInjection
        self.checkSignature = checkSignature
        self.checkMachOHash = checkMachOHash
        self.enablePtraceDenyAttach = enablePtraceDenyAttach
        self.expectedTeamID = expectedTeamID
        self.imageAllowlist = imageAllowlist
        self.machOBaseline = machOBaseline
    }

    /// The safe default: everything report-only, nothing destructive.
    public static let `default` = ShieldPolicy()
}
