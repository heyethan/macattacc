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
        // Local symbols (lowercase type letters) present → NOT stripped.
        XCTAssertFalse(HardeningCheck.symbolsAreStripped(nmOutput: """
        0000000100003f58 t _helper
        0000000100008000 s _localData
        """))
    }

    // Anchoring to "hex address + single lowercase type" means nm's English error text is
    // never miscounted as local symbols (verify also guards on nm's exit status).
    func testNmErrorTextIsNotCountedAsSymbols() {
        XCTAssertEqual(HardeningCheck.localSymbolCount(nmOutput: "nm: /tmp: is a directory"), 0)
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
