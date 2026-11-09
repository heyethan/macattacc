import Foundation
import MachO
import Security
import CShieldShim

/// The single hardened code-signature validation path. Shared by the library self-check
/// (`Detectors.signature`, via `SecCodeCopySelf`) and the CLI `shield check` (a bundle on
/// disk, via `SecStaticCodeCreateWithPath`), so a hand-run `check` is exactly as strict as
/// the in-app self-check: strict + all-architectures + nested-code flags, with an optional
/// designated requirement and Team ID pin.
public enum SignatureCheck {
    /// Validate every architecture, descend into nested code (frameworks, plugins, helper
    /// tools), and reject the designated-requirement shortcuts Gatekeeper allows. Using the
    /// bare `SecCSFlags()` default here would let a re-signed/stripped slice or an
    /// unvalidated nested helper slip through.
    public static let hardenedFlags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate
    )

    /// Run the hardened validity check on an already-created `SecStaticCode`, mapping the
    /// result to a `Detection` (`nil` == valid, or legitimately unsigned-and-unpinned).
    public static func evaluate(
        _ staticCode: SecStaticCode,
        expectedTeamID: String?,
        requirementString: String?
    ) -> Detection? {
        // Optional designated requirement (e.g. `anchor apple generic and ...`). A malformed
        // string is surfaced, never silently ignored.
        var requirement: SecRequirement?
        if let reqStr = requirementString {
            let created = SecRequirementCreateWithString(reqStr as CFString, SecCSFlags(), &requirement)
            guard created == errSecSuccess, requirement != nil else {
                return .signatureInvalid(reason: "invalid designated requirement (status \(created))")
            }
        }

        let status = SecStaticCodeCheckValidity(staticCode, hardenedFlags, requirement)

        var actualTeamID: String?
        if expectedTeamID != nil {
            var info: CFDictionary?
            let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
            if SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
               let dict = info as? [String: Any] {
                actualTeamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
            }
        }

        return Heuristics.mapSignatureStatus(
            status: status,
            errSecCSUnsigned: OSStatus(errSecCSUnsigned),
            expectedTeamID: expectedTeamID,
            actualTeamID: actualTeamID,
            requirementPinned: requirementString != nil
        )
    }
}

/// Live detectors: they read real process state and feed `Heuristics` for the
/// matching decisions. These are the "live-only" paths — unit tests exercise the
/// pure logic in `Heuristics`, not these.
enum Detectors {

    // MARK: Debugger

    static func debugger() -> [Detection] {
        shield_is_being_traced() ? [.debuggerAttached(method: "sysctl P_TRACED")] : []
    }

    // MARK: Loaded images

    static func loadedImagePaths() -> [String] {
        let count = _dyld_image_count()
        var paths: [String] = []
        paths.reserveCapacity(Int(count))
        for i in 0..<count {
            if let c = _dyld_get_image_name(i) {
                paths.append(String(cString: c))
            }
        }
        return paths
    }

    static func instrumentationImages() -> [Detection] {
        loadedImagePaths()
            .filter(Heuristics.matchesInstrumentationImage)
            .map { .instrumentationImage(name: $0) }
    }

    /// Resolve a path through `realpath(3)`, falling back to the original path when the
    /// file has no on-disk entry (most `/usr/lib` and `/System` dylibs live only in the
    /// dyld shared cache). Resolving collapses `/var` vs `/private/var` and symlinks.
    static func resolveRealPath(_ path: String) -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(path, &buffer) != nil else { return path }
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    static func unexpectedImages(allowlist: [String]) -> [Detection] {
        let mainReal = Bundle.main.executablePath.map(resolveRealPath)
        let contentsReal = resolveRealPath(
            Bundle.main.bundleURL.appendingPathComponent("Contents", isDirectory: true).path
        ) + "/"
        return loadedImagePaths().compactMap { path in
            // Fast pre-filter: skip realpath for OS-shipped images (the vast majority).
            if Heuristics.isSystemImage(path) { return nil }
            let real = resolveRealPath(path)
            guard Heuristics.isUnexpectedImage(
                real,
                mainExecutableRealPath: mainReal,
                mainBundleContentsPrefix: contentsReal,
                allowlist: allowlist
            ) else { return nil }
            return .unexpectedImage(path: real)
        }
    }

    // MARK: Mach thread names

    static func threadNames() -> [String] {
        var threads: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &threads, &count) == KERN_SUCCESS,
              let threads else {
            return []
        }
        defer {
            // Free every port, then the array itself — or it leaks.
            for i in 0..<Int(count) {
                mach_port_deallocate(mach_task_self_, threads[i])
            }
            let size = vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride)
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: threads)), size)
        }
        var names: [String] = []
        for i in 0..<Int(count) {
            guard let pthread = pthread_from_mach_thread_np(threads[i]) else { continue }
            var buf = [CChar](repeating: 0, count: 64)
            if pthread_getname_np(pthread, &buf, buf.count) == 0 {
                let name = buf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                if !name.isEmpty { names.append(name) }
            }
        }
        return names
    }

    static func instrumentationThreads() -> [Detection] {
        threadNames()
            .filter(Heuristics.matchesInstrumentationThread)
            .map { .instrumentationThread(name: $0) }
    }

    // MARK: Dylib injection

    static func dylibInjection() -> [Detection] {
        guard let value = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"],
              !value.isEmpty else {
            return []
        }
        return [.dylibInjectionEnvVar(value: value)]
    }

    // MARK: Code signature self-check

    static func signature(expectedTeamID: String?, requirementString: String? = nil) -> [Detection] {
        var codeRef: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &codeRef) == errSecSuccess, let codeRef else {
            return [.signatureInvalid(reason: "SecCodeCopySelf failed")]
        }
        var staticRef: SecStaticCode?
        guard SecCodeCopyStaticCode(codeRef, SecCSFlags(), &staticRef) == errSecSuccess,
              let staticRef else {
            return [.signatureInvalid(reason: "SecCodeCopyStaticCode failed")]
        }

        // Same hardened validity path the CLI `check` runs.
        if let detection = SignatureCheck.evaluate(
            staticRef, expectedTeamID: expectedTeamID, requirementString: requirementString
        ) {
            return [detection]
        }
        return []
    }
}
