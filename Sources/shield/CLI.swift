import ArgumentParser
import Foundation
import Security
import MacOSShield

@main
struct ShieldCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "shield",
        abstract: "macOS code-protection toolkit for authors protecting software they own.",
        discussion: """
        Runtime checks are defense-in-depth against dynamic tampering / licence-cracking,
        NOT anti-clone. The clone-resistant half is `harden` (build-hardening presets).
        """,
        subcommands: [Check.self, Doctor.self, Harden.self, Verify.self]
    )
}

// MARK: check

struct Check: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Validate the code signature and Team ID of an app bundle on disk."
    )

    @Argument(help: "Path to a .app bundle or signed binary.")
    var path: String

    @Option(help: "Expected Team ID; reports a mismatch if given.")
    var teamID: String?

    func run() throws {
        let url = URL(fileURLWithPath: path)
        var staticCode: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode)
        guard created == errSecSuccess, let staticCode else {
            print("FAIL  cannot read code object at \(path) (status \(created))")
            throw ExitCode.failure
        }

        let status = SecStaticCodeCheckValidity(staticCode, SecCSFlags(), nil)
        if status == errSecCSUnsigned {
            print("UNSIGNED  \(path) has no code signature (debug/ad-hoc build?)")
            return
        }
        if status != errSecSuccess {
            print("FAIL  signature invalid (status \(status))")
            throw ExitCode.failure
        }

        var info: CFDictionary?
        _ = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any]
        let team = dict?[kSecCodeInfoTeamIdentifier as String] as? String ?? "(none)"
        let ident = dict?[kSecCodeInfoIdentifier as String] as? String ?? "(none)"

        if let expected = teamID, team != expected {
            print("FAIL  Team ID \(team) != expected \(expected)")
            throw ExitCode.failure
        }
        print("OK    signature valid — identifier=\(ident) teamID=\(team)")
    }
}

// MARK: doctor

struct Doctor: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Self-scan this process and report runtime tamper signals."
    )

    func run() {
        let detections = Shield.scan(.default)
        print("shield doctor — self-scan (report-only)\n")
        if detections.isEmpty {
            print("No detections. (Absence is not proof: these checks are a speed bump, not a wall.)")
            return
        }
        for d in detections.sorted(by: { $0.severity > $1.severity }) {
            let tag = d.isHighFalsePositive ? "[high-FP]" : "[        ]"
            print("\(tag) \(d.severity)  \(d.summary)")
        }
        print("\nHigh-FP signals are informational and must never, alone, gate a terminate.")
    }
}

// MARK: harden

struct Harden: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Write Shield.xcconfig with proven build-hardening presets. Does NOT touch your .xcodeproj."
    )

    @Argument(help: "Directory to write Shield.xcconfig into.")
    var directory: String

    @Flag(help: "Overwrite an existing Shield.xcconfig.")
    var force = false

    func run() throws {
        let dir = URL(fileURLWithPath: directory, isDirectory: true)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else {
            print("FAIL  \(directory) is not a directory")
            throw ExitCode.failure
        }
        let dest = dir.appendingPathComponent("Shield.xcconfig")
        if FileManager.default.fileExists(atPath: dest.path), !force {
            print("""
            REFUSED  \(dest.path) already exists.
            Re-run with --force to overwrite, or move the existing file first.
            """)
            throw ExitCode.failure
        }
        try Self.xcconfig.write(to: dest, atomically: true, encoding: .utf8)

        print("""
        Wrote \(dest.path)

        This file was NOT applied to any Xcode project (that is the riskiest, build-breaking
        surface — v1 leaves it to you). To use it:

          1. In Xcode: Project editor > Info tab > Configurations > expand Release, and set
             your APPLICATION target's row (not the project row, not a framework) to
             Shield.xcconfig. Or #include it from an existing app-target xcconfig.
          2. Apply to the app target ONLY. Stripping a framework/dylib target breaks its
             signature and your build; never set these project-wide.
          3. These settings raise the STATIC / clone bar (strip symbols + reflection
             metadata). The runtime library is separate defense-in-depth.
        """)
    }

    /// The standard Release hardening presets. Kept inline (no resource bundle); it is one constant.
    static let xcconfig = """
    // Shield.xcconfig — build-hardening presets (Release).
    // Generated by `shield harden`. Review before adopting.
    //
    // APPLY TO YOUR APP TARGET'S RELEASE CONFIG ONLY — never project-level.
    // STRIP_* + DEPLOYMENT_POSTPROCESSING applied across a whole project will strip your
    // framework and dylib targets too, breaking their code signatures and your build.
    // Frameworks must NOT be stripped. Set this on the application target's Release config.

    // --- Symbol stripping (app target, Release) ---
    STRIP_STYLE = all
    STRIP_INSTALLED_PRODUCT = YES
    DEPLOYMENT_POSTPROCESSING = YES
    COPY_PHASE_STRIP = YES
    // Strip local symbols at link time too ($(inherited) keeps your existing flags, e.g. -ObjC).
    OTHER_LDFLAGS = $(inherited) -Wl,-x

    // DEAD_CODE_STRIPPING is already ON by default in Xcode; left here as a documented default.
    // DEAD_CODE_STRIPPING = YES

    // --- Reflection metadata ---
    // WARNING: `without-names` strips Swift reflection field/type NAMES. This can break
    // Mirror-based code: reflection logging, some dependency-injection containers, some
    // serialization paths, and SwiftUI debug reflection. TEST your app with this set before
    // shipping — if Mirror(reflecting:) output matters anywhere, use `all` instead.
    SWIFT_REFLECTION_METADATA_LEVEL = without-names

    // --- Hardened runtime ---
    // Required for the DYLD_INSERT_LIBRARIES defense to hold (the hardened runtime strips
    // that variable). May need com.apple.security.cs.* entitlements if your app uses JIT,
    // loads unsigned plugins, or reads DYLD_* variables itself.
    ENABLE_HARDENED_RUNTIME = YES

    // --- dSYM ---
    // Keep a dSYM for every Release build so you can still symbolicate crashes after
    // stripping (Xcode's Release default):
    // DEBUG_INFORMATION_FORMAT = dwarf-with-dsym

    """
}

// MARK: verify

struct Verify: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Check that a shipped binary or .app was actually hardened (symbols stripped, reflection names dropped)."
    )

    @Argument(help: "Path to a built binary or .app bundle.")
    var path: String

    func run() throws {
        let binary = try Self.resolveBinary(path)
        let nm = Self.shell("/usr/bin/nm", [binary.path])
        let otool = Self.shell("/usr/bin/otool", ["-l", binary.path])
        // nm exits nonzero on a non-Mach-O (directory, text file); that is the reliable gate.
        guard nm.status == 0, otool.status == 0 else {
            print("FAIL  \(binary.path) is not a readable Mach-O (nm/otool error).")
            throw ExitCode.failure
        }
        let sizeOut = Self.shell("/usr/bin/size", [binary.path]).output
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let stripped = HardeningCheck.symbolsAreStripped(nmOutput: nm.output)
        let reflSize = HardeningCheck.reflectionStringsSize(otoolOutput: otool.output)
        let runtime = Self.hasHardenedRuntime(binary)

        print("shield verify — \(binary.path)\n")
        print("  symbols stripped      : \(stripped ? "yes" : "NO")")
        if let reflSize {
            print("  __swift5_reflstr      : \(reflSize) bytes (field/type names; without-names shrinks it, never to zero — compare an unhardened build)")
        } else {
            print("  __swift5_reflstr      : absent")
        }
        if let runtime {
            print("  hardened runtime      : \(runtime ? "yes" : "NO")")
        } else {
            print("  hardened runtime      : unknown (unsigned/ad-hoc)")
        }
        if !sizeOut.isEmpty { print("\n  size:\n\(sizeOut)") }

        // PASS/FAIL is gated on symbol stripping — the one signal we can confirm cleanly.
        // Reflection-string size is reported for judgement, not used as a gate.
        print("")
        if stripped {
            print("PASS  symbols stripped.")
        } else {
            print("FAIL  local symbols present (not stripped). Adopt Shield.xcconfig on the Release app target.")
            throw ExitCode.failure
        }
    }

    /// Resolve a path to the actual Mach-O to inspect: `.app` bundles resolve to their
    /// executable, everything else is used as-is.
    static func resolveBinary(_ path: String) throws -> URL {
        let url = URL(fileURLWithPath: path)
        if url.pathExtension == "app" || url.path.hasSuffix(".app/") {
            guard let exe = Bundle(url: url)?.executableURL else {
                throw ValidationError("cannot find executable inside \(path)")
            }
            return exe
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ValidationError("no file at \(path)")
        }
        return url
    }

    static func shell(_ launch: String, _ args: [String]) -> (output: String, status: Int32) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: launch)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe   // nm writes "no symbols" to stderr
        do {
            try proc.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            return (String(data: data, encoding: .utf8) ?? "", proc.terminationStatus)
        } catch {
            return ("", -1)
        }
    }

    /// `CS_RUNTIME` (0x10000) in the code-signing flags means the hardened runtime is on.
    /// `nil` when the binary is unsigned or unreadable.
    static func hasHardenedRuntime(_ url: URL) -> Bool? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let flags = dict[kSecCodeInfoFlags as String] as? UInt32 else { return nil }
        return (flags & 0x1_0000) != 0
    }
}

/// Pure parsers for `shield verify`, factored out so they can be unit-tested with canned
/// `nm`/`otool` output and no real binary present.
enum HardeningCheck {
    /// A stripped binary has no *local* symbols. `nm` prints each symbol as
    /// `<hex address> <type letter> <name>`; local symbols use a lowercase type letter
    /// (`t`, `s`, `d`, `b`…), externals an uppercase one, and undefined symbols (`U`) have no
    /// address. Anchoring to "hex address + single lowercase letter" avoids counting stray
    /// words in nm's English error text. "no symbols" (no symbol table) also counts as stripped.
    static func localSymbolCount(nmOutput: String) -> Int {
        var count = 0
        for line in nmOutput.split(separator: "\n") {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard cols.count >= 3 else { continue }
            let addrIsHex = cols[0].count >= 8 && cols[0].allSatisfy { $0.isHexDigit }
            let type = cols[1]
            let typeIsLocal = type.count == 1 && (type.first.map { $0.isLetter && $0.isLowercase } ?? false)
            if addrIsHex && typeIsLocal { count += 1 }
        }
        return count
    }

    static func symbolsAreStripped(nmOutput: String) -> Bool {
        nmOutput.lowercased().contains("no symbols") || localSymbolCount(nmOutput: nmOutput) == 0
    }

    /// Size in bytes of the `__swift5_reflstr` section (Swift reflection field/type NAMES)
    /// from `otool -l` output, or `nil` if the section is absent.
    /// `SWIFT_REFLECTION_METADATA_LEVEL = without-names` shrinks this section but never to
    /// zero, so it is reported for judgement, not used as a pass/fail gate.
    static func reflectionStringsSize(otoolOutput: String) -> Int? {
        let lines = otoolOutput.split(separator: "\n").map(String.init)
        guard let idx = lines.firstIndex(where: { $0.contains("sectname __swift5_reflstr") }) else {
            return nil
        }
        for line in lines[idx...].prefix(10) {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("size ") else { continue }
            let v = t.dropFirst(5).trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("0x"), let n = Int(v.dropFirst(2), radix: 16) { return n }
            return Int(v)
        }
        return nil
    }
}
