import XCTest
import os
import Security
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

    // Regression: the old substring-of-path match flagged `libswiftArgumentParser` because
    // "argument" contains "gum", flagging the shield CLI itself. Basename-token matching must not.
    func testInstrumentationImageDoesNotFlagArgumentParser() {
        XCTAssertFalse(Heuristics.matchesInstrumentationImage("/usr/lib/swift/libswiftArgumentParser.dylib"))
    }

    // Regression: matching is basename-only — a Frida directory in the path must not match.
    func testInstrumentationImageMatchesBasenameNotPath() {
        XCTAssertFalse(Heuristics.matchesInstrumentationImage("/Users/frida/App.app/Contents/MacOS/App"))
        XCTAssertTrue(Heuristics.matchesInstrumentationImage("/opt/tools/frida-gadget.dylib"))
        XCTAssertTrue(Heuristics.matchesInstrumentationImage("/private/tmp/frida-agent"))
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

    // Regression: the old loose `contains` match flagged "diagmaintenance" because it
    // contains "gmain". Token-anchored matching must flag whole-token markers only.
    func testInstrumentationThreadIsTokenAnchored() {
        XCTAssertTrue(Heuristics.matchesInstrumentationThread("gmain"))
        XCTAssertTrue(Heuristics.matchesInstrumentationThread("gum-js-loop"))
        XCTAssertTrue(Heuristics.matchesInstrumentationThread("pool-frida-1")) // "frida" is a whole token
        XCTAssertFalse(Heuristics.matchesInstrumentationThread("diagmaintenance")) // not a token
        XCTAssertFalse(Heuristics.matchesInstrumentationThread("mainThread"))      // camelCase → main, thread
    }

    // MARK: allowlist diff

    func testUnexpectedImageFlagsForeignDylib() {
        XCTAssertTrue(Heuristics.isUnexpectedImage(
            "/tmp/evil.dylib", mainExecutableRealPath: "/App/Bin",
            mainBundleContentsPrefix: nil, allowlist: []))
    }

    func testUnexpectedImageAllowsSystemMainAndAllowlist() {
        XCTAssertFalse(Heuristics.isUnexpectedImage(
            "/usr/lib/libobjc.A.dylib", mainExecutableRealPath: nil,
            mainBundleContentsPrefix: nil, allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage(
            "/System/Library/X", mainExecutableRealPath: nil,
            mainBundleContentsPrefix: nil, allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage(
            "/App/Bin", mainExecutableRealPath: "/App/Bin",
            mainBundleContentsPrefix: nil, allowlist: []))
        XCTAssertFalse(Heuristics.isUnexpectedImage(
            "/opt/vendor/MyFramework", mainExecutableRealPath: nil,
            mainBundleContentsPrefix: nil, allowlist: ["MyFramework"]))
    }

    // The main bundle's own Contents/ subtree (frameworks, plugins, helpers) is exempt...
    func testUnexpectedImageExemptsBundleContents() {
        let contents = "/Apps/My.app/Contents/"
        XCTAssertFalse(Heuristics.isUnexpectedImage(
            "/Apps/My.app/Contents/Frameworks/Lib.framework/Lib",
            mainExecutableRealPath: "/Apps/My.app/Contents/MacOS/My",
            mainBundleContentsPrefix: contents, allowlist: []))
    }

    // ...but a look-alike sibling path is NOT exempt (prefix must be the real Contents/).
    func testUnexpectedImageContentsPrefixBoundaries() {
        let contents = "/Apps/My.app/Contents/"
        XCTAssertTrue(Heuristics.isUnexpectedImage(
            "/Apps/My.app/ContentsX/Lib",
            mainExecutableRealPath: nil, mainBundleContentsPrefix: contents, allowlist: []))
        XCTAssertTrue(Heuristics.isUnexpectedImage(
            "/Apps/My.app.evil/Contents/Lib",
            mainExecutableRealPath: nil, mainBundleContentsPrefix: contents, allowlist: []))
    }

    // MARK: signature-result mapping

    func testSignatureUnsignedIsNotFlagged() {
        XCTAssertNil(Heuristics.mapSignatureStatus(status: -67062, expectedTeamID: nil, actualTeamID: nil))
    }

    func testSignatureUnsignedButTeamIDPinnedIsFlagged() {
        let d = Heuristics.mapSignatureStatus(status: -67062, expectedTeamID: "TEAM1", actualTeamID: nil)
        XCTAssertEqual(d, .signatureInvalid(reason: "unsigned, expected Team ID TEAM1"))
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

    // The CLI `check` and the library self-check must share ONE hardened flag set:
    // strict + all-architectures + nested-code. A regression that weakened this (e.g. back to
    // bare `SecCSFlags()`) would change this raw value.
    func testHardenedSignatureFlagsAreStrict() {
        let expected = kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate
        XCTAssertEqual(SignatureCheck.hardenedFlags.rawValue, expected)
    }
}

final class DetectionTests: XCTestCase {

    func testHighFalsePositiveClassification() {
        // High-FP = fires on benign apps (name/thread/unexpected-image heuristics).
        XCTAssertTrue(Detection.instrumentationImage(name: "frida").isHighFalsePositive)
        XCTAssertTrue(Detection.instrumentationThread(name: "gmain").isHighFalsePositive)
        XCTAssertTrue(Detection.unexpectedImage(path: "/x").isHighFalsePositive)

        // dylibInjectionEnvVar is specific-but-weak, NOT high-FP: benign apps rarely set
        // DYLD_INSERT_LIBRARIES. "Easy to evade" is not "high false-positive".
        XCTAssertFalse(Detection.dylibInjectionEnvVar(value: "/x").isHighFalsePositive)
        XCTAssertFalse(Detection.debuggerAttached(method: "m").isHighFalsePositive)
        XCTAssertFalse(Detection.signatureInvalid(reason: "r").isHighFalsePositive)
    }

    func testSeverityOrdering() {
        XCTAssertGreaterThan(Severity.critical, Severity.warning)
        XCTAssertGreaterThan(Severity.warning, Severity.info)
    }

    /// The terminate safety gate, exercised through the SAME predicate `Shield.apply` uses
    /// (`Shield.shouldTerminate`), not a re-implementation of it.
    func testTerminateGatePredicate() {
        let onlyHighFP: [Detection] = [.instrumentationThread(name: "gmain"), .unexpectedImage(path: "/x")]
        XCTAssertFalse(MacOSShield.Shield.shouldTerminate(onlyHighFP))
        XCTAssertFalse(MacOSShield.Shield.shouldTerminate([]))

        let withReal: [Detection] = onlyHighFP + [.debuggerAttached(method: "sysctl")]
        XCTAssertTrue(MacOSShield.Shield.shouldTerminate(withReal))

        // dylibInjectionEnvVar is non-high-FP, so it alone can now gate terminate.
        XCTAssertTrue(MacOSShield.Shield.shouldTerminate([.dylibInjectionEnvVar(value: "/x")]))
    }

    /// `.report` returns detections and never terminates. With every detector off the scan
    /// is deterministically empty — a real assertion, not `XCTAssertNotNil` on a non-optional.
    func testReportPolicyReturnsEmptyWhenAllDetectorsOff() {
        let policy = ShieldPolicy(
            checkDebugger: false, checkInstrumentationImages: false,
            checkInstrumentationThreads: false, checkUnexpectedImages: false,
            checkDylibInjection: false, checkSignature: false)
        XCTAssertEqual(MacOSShield.Shield.scan(policy), [])
    }

    /// `.callback` fires even on a clean (empty) scan, so the host can distinguish
    /// "scanned clean" from "never ran". Uses a lock because the handler is `@Sendable`.
    func testCallbackFiresOnCleanScan() {
        let box = OSAllocatedUnfairLock(initialState: (calls: 0, last: [Detection]()))
        var policy = ShieldPolicy(
            checkDebugger: false, checkInstrumentationImages: false,
            checkInstrumentationThreads: false, checkUnexpectedImages: false,
            checkDylibInjection: false, checkSignature: false)
        policy.onDetection = .callback { detections in
            box.withLock { $0.calls += 1; $0.last = detections }
        }
        _ = MacOSShield.Shield.scan(policy)
        box.withLock {
            XCTAssertEqual($0.calls, 1)
            XCTAssertEqual($0.last, [])
        }
    }

    /// PT_DENY_ATTACH is decoupled from checkDebugger: with checkDebugger=false but
    /// enablePtraceDenyAttach=true, the (injected, non-destructive) hook still fires.
    /// The real ptrace is never called here — only the injected spy.
    func testPtraceDenyAttachDecoupledFromCheckDebugger() {
        let box = OSAllocatedUnfairLock(initialState: 0)
        var policy = ShieldPolicy(
            checkDebugger: false, checkInstrumentationImages: false,
            checkInstrumentationThreads: false, checkUnexpectedImages: false,
            checkDylibInjection: false, checkSignature: false)
        policy.enablePtraceDenyAttach = true
        _ = MacOSShield.Shield.scan(policy, denyAttach: { box.withLock { $0 += 1 } })
        XCTAssertEqual(box.withLock { $0 }, 1)

        // And it does NOT fire when the gate is off.
        policy.enablePtraceDenyAttach = false
        _ = MacOSShield.Shield.scan(policy, denyAttach: { box.withLock { $0 += 1 } })
        XCTAssertEqual(box.withLock { $0 }, 1)
    }
}
