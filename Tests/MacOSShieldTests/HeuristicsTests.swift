import XCTest
@testable import MacOSShield

final class HeuristicsTests: XCTestCase {

    // MARK: P_TRACED flag parse

    func testTracedFlagSet() {
        XCTAssertTrue(Heuristics.isTraced(pFlag: Heuristics.pTraced))
        XCTAssertTrue(Heuristics.isTraced(pFlag: Heuristics.pTraced | 0x1))
    }

    func testTracedFlagUnset() {
        XCTAssertFalse(Heuristics.isTraced(pFlag: 0))
        XCTAssertFalse(Heuristics.isTraced(pFlag: 0x1 | 0x4)) // other flags, not P_TRACED
    }

    // MARK: image-name matching

    func testInstrumentationImageMatches() {
        XCTAssertTrue(Heuristics.matchesInstrumentationImage("/tmp/frida-agent.dylib"))
        XCTAssertTrue(Heuristics.matchesInstrumentationImage("/Users/x/FridaGadget.dylib"))
        XCTAssertTrue(Heuristics.matchesInstrumentationImage("/opt/libsubstrate.dylib"))
    }

    func testInstrumentationImageIgnoresBenign() {
        XCTAssertFalse(Heuristics.matchesInstrumentationImage("/usr/lib/libSystem.B.dylib"))
        XCTAssertFalse(Heuristics.matchesInstrumentationImage("/System/Library/Frameworks/AppKit.framework/AppKit"))
    }

    // MARK: thread-name matching

    func testInstrumentationThreadMatches() {
        XCTAssertTrue(Heuristics.matchesInstrumentationThread("gum-js-loop"))
        XCTAssertTrue(Heuristics.matchesInstrumentationThread("gmain")) // high-FP but matched
    }

    func testInstrumentationThreadIgnoresBenign() {
        XCTAssertFalse(Heuristics.matchesInstrumentationThread("com.apple.NSEventThread"))
        XCTAssertFalse(Heuristics.matchesInstrumentationThread(""))
    }

    // MARK: allowlist diff

    func testUnexpectedImageFlagsForeignDylib() {
        XCTAssertTrue(Heuristics.isUnexpectedImage("/tmp/evil.dylib", mainExecutablePath: "/App/Bin", allowlist: []))
    }

    func testUnexpectedImageAllowsSystemMainAndAllowlist() {
        XCTAssertFalse(Heuristics.isUnexpectedImage("/usr/lib/libobjc.A.dylib", mainExecutablePath: nil, allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage("/System/Library/X", mainExecutablePath: nil, allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage("/App/Bin", mainExecutablePath: "/App/Bin", allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage("/opt/vendor/MyFramework", mainExecutablePath: nil, allowlist: ["MyFramework"]))
    }

    // MARK: signature-result mapping

    func testSignatureUnsignedIsNotFlagged() {
        XCTAssertNil(Heuristics.mapSignatureStatus(status: -67062, expectedTeamID: nil, actualTeamID: nil))
    }

    func testSignatureValidNoTeamCheck() {
        XCTAssertNil(Heuristics.mapSignatureStatus(status: 0, expectedTeamID: nil, actualTeamID: "ABC"))
    }

    func testSignatureValidTeamMatches() {
        XCTAssertNil(Heuristics.mapSignatureStatus(status: 0, expectedTeamID: "TEAM1", actualTeamID: "TEAM1"))
    }

    func testSignatureValidTeamMismatch() {
        let d = Heuristics.mapSignatureStatus(status: 0, expectedTeamID: "TEAM1", actualTeamID: "OTHER")
        XCTAssertEqual(d, .signatureInvalid(reason: "Team ID OTHER != expected TEAM1"))
    }

    func testSignatureValidTeamMissing() {
        let d = Heuristics.mapSignatureStatus(status: 0, expectedTeamID: "TEAM1", actualTeamID: nil)
        XCTAssertEqual(d, .signatureInvalid(reason: "no Team ID present, expected TEAM1"))
    }

    func testSignatureInvalidStatus() {
        let d = Heuristics.mapSignatureStatus(status: -1, expectedTeamID: nil, actualTeamID: nil)
        XCTAssertEqual(d, .signatureInvalid(reason: "SecStaticCodeCheckValidity status -1"))
    }
}

final class DetectionTests: XCTestCase {

    func testHighFalsePositiveClassification() {
        XCTAssertTrue(Detection.instrumentationImage(name: "frida").isHighFalsePositive)
        XCTAssertTrue(Detection.instrumentationThread(name: "gmain").isHighFalsePositive)
        XCTAssertTrue(Detection.unexpectedImage(path: "/x").isHighFalsePositive)
        XCTAssertTrue(Detection.dylibInjectionEnvVar(value: "/x").isHighFalsePositive)

        XCTAssertFalse(Detection.debuggerAttached(method: "m").isHighFalsePositive)
        XCTAssertFalse(Detection.signatureInvalid(reason: "r").isHighFalsePositive)
        XCTAssertFalse(Detection.machOHashMismatch(section: "__TEXT").isHighFalsePositive)
    }

    func testSeverityOrdering() {
        XCTAssertGreaterThan(Severity.critical, Severity.warning)
        XCTAssertGreaterThan(Severity.warning, Severity.info)
    }

    /// The terminate safety gate's core predicate: a set of only high-FP detections
    /// must not satisfy "contains a non-high-FP detection".
    func testTerminateGatePredicate() {
        let onlyHighFP: [Detection] = [.instrumentationThread(name: "gmain"), .unexpectedImage(path: "/x")]
        XCTAssertFalse(onlyHighFP.contains { !$0.isHighFalsePositive })

        let withReal: [Detection] = onlyHighFP + [.debuggerAttached(method: "sysctl")]
        XCTAssertTrue(withReal.contains { !$0.isHighFalsePositive })
    }

    /// A report-only scan must never terminate, even with real detections present.
    func testReportPolicyReturnsDetections() {
        // Self-scan under `swift test` runs undebugged-or-not; we only assert it returns
        // without crashing and yields an array. Content is environment-dependent.
        let result = MacOSShield.Shield.scan(.default)
        XCTAssertNotNil(result as [Detection]?)
    }
}
