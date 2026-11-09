import XCTest
import ArgumentParser
@testable import shield

/// Tests for the CLI: argument parsing, `harden` xcconfig generation + `--force` refusal,
/// and the pure `verify` output parsers. Executables are testable via `@testable import`.
final class CLITests: XCTestCase {

    // MARK: argument parsing

    func testParseCheckWithTeamID() throws {
        let cmd = try ShieldCLI.parseAsRoot(["check", "/Apps/X.app", "--team-id", "ABC123"])
        let check = try XCTUnwrap(cmd as? Check)
        XCTAssertEqual(check.path, "/Apps/X.app")
        XCTAssertEqual(check.teamID, "ABC123")
    }

    func testParseCheckWithRequirement() throws {
        let cmd = try ShieldCLI.parseAsRoot(["check", "/Apps/X.app", "--requirement", "anchor apple generic"])
        let check = try XCTUnwrap(cmd as? Check)
        XCTAssertEqual(check.requirement, "anchor apple generic")
    }

    func testParseHardenForceFlag() throws {
        let plain = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", "/tmp"]) as? Harden)
        XCTAssertFalse(plain.force)
        let forced = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", "/tmp", "--force"]) as? Harden)
        XCTAssertTrue(forced.force)
    }

    func testParseVerify() throws {
        let v = try XCTUnwrap(try ShieldCLI.parseAsRoot(["verify", "/Apps/X.app"]) as? Verify)
        XCTAssertEqual(v.path, "/Apps/X.app")
    }

    // MARK: harden xcconfig generation

    func testHardenWritesXcconfigWithAppTargetSettings() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("macattacc-harden-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let cmd = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", dir.path]) as? Harden)
        try cmd.run()

        let dest = dir.appendingPathComponent("Shield.xcconfig")
        let text = try String(contentsOf: dest, encoding: .utf8)
        XCTAssertTrue(text.contains("STRIP_STYLE = all"))
        XCTAssertTrue(text.contains("ENABLE_HARDENED_RUNTIME = YES"))
        XCTAssertTrue(text.contains("OTHER_LDFLAGS = $(inherited) -Wl,-x"))
        XCTAssertTrue(text.contains("SWIFT_REFLECTION_METADATA_LEVEL = without-names"))
        XCTAssertTrue(text.contains("APP TARGET"))          // app-target-only warning present
        XCTAssertTrue(text.contains("Mirror"))              // reflection warning present
    }

    func testHardenRefusesExistingWithoutForce() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("macattacc-harden-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let dest = dir.appendingPathComponent("Shield.xcconfig")
        try "PRE-EXISTING".write(to: dest, atomically: true, encoding: .utf8)

        let refuse = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", dir.path]) as? Harden)
        XCTAssertThrowsError(try refuse.run())
        XCTAssertEqual(try String(contentsOf: dest, encoding: .utf8), "PRE-EXISTING", "must not overwrite")

        let force = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", dir.path, "--force"]) as? Harden)
        try force.run()
        XCTAssertTrue(try String(contentsOf: dest, encoding: .utf8).contains("STRIP_STYLE"), "--force overwrites")
    }

    // MARK: verify output parsers

    func testSymbolsAreStrippedFromNmOutput() {
        XCTAssertTrue(HardeningCheck.symbolsAreStripped(nmOutput: "/path/to/bin: no symbols\n"))
        // Only external/undefined (uppercase / U) symbols → stripped.
        XCTAssertTrue(HardeningCheck.symbolsAreStripped(nmOutput: """
        0000000100003f58 T _main
                         U _abort
        """))
        // A couple of stray locals (≤ threshold) still counts as stripped — a strict-zero gate
        // falsely failed legitimately stripped binaries.
        XCTAssertTrue(HardeningCheck.symbolsAreStripped(nmOutput: """
        0000000100003f58 t _helper
        0000000100008000 s _localData
        """))
        // Many locals (> threshold) → NOT stripped.
        XCTAssertFalse(HardeningCheck.symbolsAreStripped(nmOutput: """
        0000000100003f58 t _a
        0000000100003f60 t _b
        0000000100003f68 t _c
        0000000100003f70 t _d
        0000000100003f78 s _e
        """))
    }

    func testLocalSymbolCountCountsOnlyLocals() {
        XCTAssertEqual(HardeningCheck.localSymbolCount(nmOutput: """
        0000000100003f58 t _helper
        0000000100008000 s _localData
        0000000100003f58 T _main
                         U _abort
        """), 2)
    }

    // Anchoring to "hex address + single lowercase type" means nm's English error text is
    // never miscounted as local symbols (verify also guards on nm's exit status).
    func testNmErrorTextIsNotCountedAsSymbols() {
        XCTAssertEqual(HardeningCheck.localSymbolCount(nmOutput: "nm: /tmp: is a directory"), 0)
    }

    // MARK: pbxproj wiring (harden --write-project)

    /// Locate Tests/Fixtures relative to this source file (not a bundled resource).
    private func fixturesDir() -> URL {
        URL(fileURLWithPath: #filePath)            // .../Tests/MacOSShieldTests/CLITests.swift
            .deletingLastPathComponent()           // .../Tests/MacOSShieldTests
            .deletingLastPathComponent()           // .../Tests
            .appendingPathComponent("Fixtures")
    }

    private func fixturePbxproj() throws -> String {
        let url = fixturesDir()
            .appendingPathComponent("SampleApp.xcodeproj/project.pbxproj")
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testWireSetsOnlyAppReleaseBaseConfig() throws {
        let text = try fixturePbxproj()
        let guid = "ABCDEF0123456789ABCDEF01"
        let out = try PBXProjectWiring.wire(pbxproj: text, xcconfigName: "Shield.xcconfig", guid: guid)

        // Exactly one baseConfigurationReference added — the framework target is untouched.
        let occurrences = out.components(separatedBy: "baseConfigurationReference").count - 1
        XCTAssertEqual(occurrences, 1, "wired more than the one app Release config")
        XCTAssertTrue(out.contains("baseConfigurationReference = \(guid) /* Shield.xcconfig */;"))
        // It landed in the APP Release config (AA…E1), which precedes the framework's (FF…E1).
        let refIdx = try XCTUnwrap(out.range(of: "baseConfigurationReference"))
        let appRelIdx = try XCTUnwrap(out.range(of: "AA00000000000000000000E1 /* Release */"))
        let fwRelIdx = try XCTUnwrap(out.range(of: "FF00000000000000000000E1 /* Release */"))
        XCTAssertTrue(appRelIdx.lowerBound < refIdx.lowerBound && refIdx.lowerBound < fwRelIdx.lowerBound)
        // A PBXFileReference for the xcconfig was added.
        XCTAssertTrue(out.contains("\(guid) /* Shield.xcconfig */ = {isa = PBXFileReference;"))
        XCTAssertTrue(out.contains("lastKnownFileType = text.xcconfig; path = Shield.xcconfig; sourceTree = SOURCE_ROOT;"))
    }

    func testWireRefusesWhenAlreadyConfigured() throws {
        let text = try fixturePbxproj()
        let once = try PBXProjectWiring.wire(pbxproj: text, xcconfigName: "Shield.xcconfig", guid: "ABCDEF0123456789ABCDEF01")
        XCTAssertThrowsError(try PBXProjectWiring.wire(pbxproj: once, xcconfigName: "Shield.xcconfig", guid: "0123456789ABCDEF01234567")) {
            XCTAssertEqual($0 as? PBXProjectWiring.WireError, .alreadyConfigured)
        }
    }

    func testWireRefusesMultipleAppTargets() throws {
        // Duplicate the real app-target block (copied verbatim, only the GUID changed) so
        // two application targets exist — guarantees identical pbxproj formatting.
        let text = try fixturePbxproj()
        let start = try XCTUnwrap(text.range(of: "\t\tAA00000000000000000000A1 /* SampleApp */ = {"))
        let end = try XCTUnwrap(text.range(of: "\t\t};", range: start.upperBound..<text.endIndex))
        let block = String(text[start.lowerBound..<end.upperBound])
        let dup = block.replacingOccurrences(of: "AA00000000000000000000A1", with: "AA00000000000000000000A2")
        let twoApps = text.replacingCharacters(in: end.upperBound..<end.upperBound, with: "\n" + dup)

        XCTAssertThrowsError(try PBXProjectWiring.wire(pbxproj: twoApps, xcconfigName: "Shield.xcconfig", guid: "ABCDEF0123456789ABCDEF01")) {
            guard case .multipleAppTargets(2) = ($0 as? PBXProjectWiring.WireError) else {
                return XCTFail("expected multipleAppTargets(2), got \($0)")
            }
        }
    }

    func testHardenWriteProjectEndToEnd() throws {
        let fm = FileManager.default
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("macattacc-wire-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        // Copy the fixture project into the working directory.
        try fm.copyItem(at: fixturesDir().appendingPathComponent("SampleApp.xcodeproj"),
                        to: dir.appendingPathComponent("SampleApp.xcodeproj"))

        let cmd = try XCTUnwrap(try ShieldCLI.parseAsRoot(["harden", dir.path, "--write-project"]) as? Harden)
        try cmd.run()

        XCTAssertTrue(fm.fileExists(atPath: dir.appendingPathComponent("Shield.xcconfig").path))
        let pbxURL = dir.appendingPathComponent("SampleApp.xcodeproj/project.pbxproj")
        let pbx = try String(contentsOf: pbxURL, encoding: .utf8)
        XCTAssertEqual(pbx.components(separatedBy: "baseConfigurationReference").count - 1, 1)
        XCTAssertTrue(pbx.contains("path = Shield.xcconfig; sourceTree = SOURCE_ROOT;"))
        // A timestamped backup of the original pbxproj exists.
        let backups = try fm.contentsOfDirectory(at: dir.appendingPathComponent("SampleApp.xcodeproj"), includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("project.pbxproj.backup-") }
        XCTAssertEqual(backups.count, 1, "expected exactly one timestamped backup")
    }

    func testReflectionStringsSizeParsing() {
        let otool = """
          Section
          sectname __swift5_reflstr
          segname __TEXT
             addr 0x000000010009adf0
             size 0x0000000000000226
           offset 634352
        """
        XCTAssertEqual(HardeningCheck.reflectionStringsSize(otoolOutput: otool), 0x226)
        XCTAssertNil(HardeningCheck.reflectionStringsSize(otoolOutput: "  sectname __text\n  size 0x10\n"))
    }
}
