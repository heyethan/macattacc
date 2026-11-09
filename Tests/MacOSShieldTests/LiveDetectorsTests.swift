import XCTest
import Darwin
@testable import MacOSShield

/// Integration smoke tests for the live detectors (Detectors.swift). The unit tests cover the pure
/// matching logic in Heuristics; these exercise the real process-state paths — the ones that can
/// leak Mach ports or crash in the field (task_threads cleanup). They assert structural sanity, not
/// the presence/absence of a debugger (CI may or may not run under one).
final class LiveDetectorsTests: XCTestCase {

    func testScanDoesNotCrashAndIsRepeatable() {
        for _ in 0..<200 {
            _ = Shield.scan()
        }
        let detections = Shield.scan()
        for d in detections {
            XCTAssertFalse(d.summary.isEmpty)
        }
    }

    func testLoadedImagesIsNonEmpty() {
        XCTAssertFalse(Detectors.loadedImagePaths().isEmpty)
    }

    // threadNames() may be empty in a clean process: benign threads are often unnamed, and the scan
    // keeps only named threads (Frida's gum-js-loop/gmain are named). We assert only that it is safe
    // to call; the port-leak behaviour of the task_threads path is covered below.
    func testThreadNamesIsCallable() {
        _ = Detectors.threadNames()
    }

    func testEveryLiveDetectorIsCallable() {
        _ = Detectors.debugger()
        _ = Detectors.instrumentationImages()
        _ = Detectors.instrumentationThreads()
        _ = Detectors.unexpectedImages(allowlist: [])
        _ = Detectors.dylibInjection()
        _ = Detectors.signature(expectedTeamID: nil)        // ad-hoc/unsigned test build: must not be fatal
    }

    /// realpath resolves a symlink to its target; a nonexistent path falls back to itself
    /// (dyld-shared-cache images have no on-disk file).
    func testResolveRealPathResolvesSymlinkAndFallsBack() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("macattacc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target")
        try "x".write(to: target, atomically: true, encoding: .utf8)
        let link = dir.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertEqual(Detectors.resolveRealPath(link.path), Detectors.resolveRealPath(target.path))
        XCTAssertEqual(Detectors.resolveRealPath("/no/such/file/xyz"), "/no/such/file/xyz")
    }

    /// A malformed `signatureRequirement` is reported as exactly one `.signatureInvalid`
    /// (reason prefixed "invalid designated requirement"), and the process survives —
    /// covering the requirement path and giving a non-empty report-returns-detections case.
    func testSignatureRequirementMalformedIsReportedNotFatal() {
        var policy = ShieldPolicy(
            checkDebugger: false, checkInstrumentationImages: false,
            checkInstrumentationThreads: false, checkUnexpectedImages: false,
            checkDylibInjection: false, checkSignature: true)
        policy.signatureRequirement = "this is not a valid requirement"
        let detections = Shield.scan(policy)
        XCTAssertEqual(detections.count, 1)
        guard case let .signatureInvalid(reason) = detections.first else {
            return XCTFail("expected signatureInvalid, got \(String(describing: detections.first))")
        }
        XCTAssertTrue(reason.hasPrefix("invalid designated requirement"), "got \(reason)")
    }

    /// The thread scan allocates a thread_act array plus a send right per thread; both must be freed.
    /// A per-call leak would grow the task's Mach port-name count by ~threads each iteration.
    func testThreadScanDoesNotLeakMachPorts() {
        _ = Detectors.threadNames()                    // warm up (lazy allocations)
        let before = machPortNameCount()
        for _ in 0..<500 { _ = Detectors.threadNames() }
        let after = machPortNameCount()
        XCTAssertLessThan(after - before, 50,
                          "port-name count grew by \(after - before) over 500 scans — likely a leak")
    }

    /// Number of port names in this task's IPC space. Frees the arrays it reads so it does not leak itself.
    private func machPortNameCount() -> Int {
        var names: mach_port_name_array_t?
        var namesCount: mach_msg_type_number_t = 0
        var types: mach_port_type_array_t?
        var typesCount: mach_msg_type_number_t = 0
        guard mach_port_names(mach_task_self_, &names, &namesCount, &types, &typesCount) == KERN_SUCCESS else {
            return -1
        }
        if let names {
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: names)),
                          vm_size_t(namesCount) * vm_size_t(MemoryLayout<mach_port_name_t>.stride))
        }
        if let types {
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: types)),
                          vm_size_t(typesCount) * vm_size_t(MemoryLayout<mach_port_type_t>.stride))
        }
        return Int(namesCount)
    }
}
