import Foundation
import MachO
import Security
import CryptoKit
import CShieldShim

/// Live detectors: they read real process state and feed `Heuristics` for the
/// matching decisions. These are the "live-only" paths — unit tests exercise the
/// pure logic in `Heuristics`, not these.
enum Detectors {

    // MARK: Debugger

    static func debugger(policy: ShieldPolicy) -> [Detection] {
        var out: [Detection] = []
        if shield_is_being_traced() {
            out.append(.debuggerAttached(method: "sysctl P_TRACED"))
        }
        if policy.enablePtraceDenyAttach {
            // Side-effect hardening. SIGSEGVs if a debugger is already attached — by then
            // the sysctl check above has already run, so a report still happens first when
            // the host app wraps scan() appropriately. Return value ignored by design.
            _ = shield_deny_attach()
        }
        return out
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

    static func unexpectedImages(allowlist: [String]) -> [Detection] {
        let main = Bundle.main.executablePath
        return loadedImagePaths()
            .filter { Heuristics.isUnexpectedImage($0, mainExecutablePath: main, allowlist: allowlist) }
            .map { .unexpectedImage(path: $0) }
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
            // Free every port, then the array itself — or it leaks (Fable's note).
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

    static func signature(expectedTeamID: String?) -> [Detection] {
        var codeRef: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &codeRef) == errSecSuccess, let codeRef else {
            return [.signatureInvalid(reason: "SecCodeCopySelf failed")]
        }
        var staticRef: SecStaticCode?
        guard SecCodeCopyStaticCode(codeRef, SecCSFlags(), &staticRef) == errSecSuccess,
              let staticRef else {
            return [.signatureInvalid(reason: "SecCodeCopyStaticCode failed")]
        }
        let status = SecStaticCodeCheckValidity(staticRef, SecCSFlags(), nil)

        var actualTeamID: String?
        if expectedTeamID != nil {
            var info: CFDictionary?
            let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
            if SecCodeCopySigningInformation(staticRef, flags, &info) == errSecSuccess,
               let dict = info as? [String: Any] {
                actualTeamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
            }
        }

        if let detection = Heuristics.mapSignatureStatus(
            status: status,
            errSecCSUnsigned: OSStatus(errSecCSUnsigned),
            expectedTeamID: expectedTeamID,
            actualTeamID: actualTeamID
        ) {
            return [detection]
        }
        return []
    }

    // MARK: Mach-O section hashing (optional, off by default)

    /// Lowercase hex SHA-256 of a segment in the main executable, or `nil` if absent.
    /// Hash only `__TEXT` / `__DATA_CONST` (stable, read-only under signing).
    static func sectionHash(segment: String) -> String? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        var size: UInt = 0
        // getsegmentdata wants mach_header_64 on 64-bit; _dyld_get_image_header gives mach_header.
        let data = header.withMemoryRebound(to: mach_header_64.self, capacity: 1) { h64 in
            segment.withCString { getsegmentdata(h64, $0, &size) }
        }
        guard let data, size > 0 else { return nil }
        let buffer = UnsafeRawBufferPointer(start: data, count: Int(size))
        let digest = SHA256.hash(data: Data(buffer))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static func machOHash(baseline: [String: String]) -> [Detection] {
        baseline.compactMap { segment, expected in
            let actual = sectionHash(segment: segment)
            return actual == expected ? nil : .machOHashMismatch(section: segment)
        }
    }
}
