import Foundation

/// Conservative `.pbxproj` editor for `shield harden --write-project`.
///
/// It does exactly one thing: set the single application target's **Release**
/// `baseConfigurationReference` to a generated xcconfig. It is deliberately picky — it
/// refuses (never guesses) on anything it does not recognise, touches no other target, and
/// performs no destructive rewrite. The caller makes a timestamped backup before writing.
///
/// Parsing assumes Xcode's canonical pbxproj formatting (objects at two-tab indent, keys at
/// three). If the file is in some other shape, `wire` throws rather than corrupt it.
enum PBXProjectWiring {
    enum WireError: Error, CustomStringConvertible, Equatable {
        case noAppTarget
        case multipleAppTargets(Int)
        case unparseable(String)
        case alreadyConfigured

        var description: String {
            switch self {
            case .noAppTarget:
                return "no application target found (need exactly one com.apple.product-type.application)"
            case .multipleAppTargets(let n):
                return "found \(n) application targets; refusing to guess which to wire"
            case .unparseable(let what):
                return "could not parse the project: \(what)"
            case .alreadyConfigured:
                return "the app target's Release config already has a baseConfigurationReference; refusing to overwrite"
            }
        }
    }

    /// A single multi-line object block: `\t\t<guid> ... = {` … `\t\t};`.
    private struct Block { let guid: String; let body: String }

    private static func blocks(_ text: String) -> [Block] {
        let lines = text.components(separatedBy: "\n")
        let header = try! NSRegularExpression(pattern: #"^\t\t([0-9A-Fa-f]{24})\b.*= \{$"#)
        var result: [Block] = []
        var i = 0
        while i < lines.count {
            let line = lines[i]
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            if let m = header.firstMatch(in: line, range: range),
               let gr = Range(m.range(at: 1), in: line) {
                let guid = String(line[gr])
                var body: [String] = []
                var j = i + 1
                while j < lines.count, lines[j] != "\t\t};" {
                    body.append(lines[j]); j += 1
                }
                result.append(Block(guid: guid, body: body.joined(separator: "\n")))
                i = j + 1
            } else {
                i += 1
            }
        }
        return result
    }

    private static func firstGUID(in body: String, after key: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: key + #"\s*=\s*([0-9A-Fa-f]{24})"#)
        else { return nil }
        let range = NSRange(body.startIndex..<body.endIndex, in: body)
        guard let m = re.firstMatch(in: body, range: range),
              let r = Range(m.range(at: 1), in: body) else { return nil }
        return String(body[r])
    }

    private static func guids(in body: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: #"([0-9A-Fa-f]{24})"#) else { return [] }
        let range = NSRange(body.startIndex..<body.endIndex, in: body)
        return re.matches(in: body, range: range).compactMap {
            Range($0.range(at: 1), in: body).map { String(body[$0]) }
        }
    }

    /// Pure transform: return the pbxproj text with the app target's Release config wired to
    /// `xcconfigName` (as fileRef `guid`), or throw a `WireError`. `guid` is injected so the
    /// result is deterministic under test.
    static func wire(pbxproj text: String, xcconfigName: String, guid: String) throws -> String {
        let all = blocks(text)
        guard !all.isEmpty else { throw WireError.unparseable("no object blocks") }

        let appTargets = all.filter {
            $0.body.contains("isa = PBXNativeTarget;")
                && $0.body.contains("com.apple.product-type.application")
        }
        guard !appTargets.isEmpty else { throw WireError.noAppTarget }
        guard appTargets.count == 1 else { throw WireError.multipleAppTargets(appTargets.count) }

        guard let listGUID = firstGUID(in: appTargets[0].body, after: "buildConfigurationList") else {
            throw WireError.unparseable("app target has no buildConfigurationList")
        }
        guard let listBlock = all.first(where: { $0.guid == listGUID }) else {
            throw WireError.unparseable("no XCConfigurationList \(listGUID)")
        }

        // The Release config is the one, among this target's configs only, named Release.
        let configGUIDs = Set(guids(in: listBlock.body))
        let releaseConfigs = all.filter {
            configGUIDs.contains($0.guid)
                && $0.body.contains("isa = XCBuildConfiguration;")
                && $0.body.contains("name = Release;")
        }
        guard let release = releaseConfigs.first, releaseConfigs.count == 1 else {
            throw WireError.unparseable("could not find exactly one Release config for the app target")
        }
        guard !release.body.contains("baseConfigurationReference") else {
            throw WireError.alreadyConfigured
        }

        // --- Mutate the raw text with two targeted insertions. ---
        var out = text

        // 1. baseConfigurationReference line, right after the Release config's header line.
        guard let headerRange = out.range(of: "\t\t\(release.guid) ") else {
            throw WireError.unparseable("lost the Release config header while editing")
        }
        guard let braceNewline = out.range(of: " = {\n", range: headerRange.lowerBound..<out.endIndex) else {
            throw WireError.unparseable("Release config header is not a multi-line object")
        }
        let baseRefLine = "\t\t\tbaseConfigurationReference = \(guid) /* \(xcconfigName) */;\n"
        out.replaceSubrange(braceNewline, with: " = {\n" + baseRefLine)

        // 2. A PBXFileReference for the xcconfig, right after that section's begin marker.
        let fileRefLine = "\t\t\(guid) /* \(xcconfigName) */ = {isa = PBXFileReference; "
            + "lastKnownFileType = text.xcconfig; path = \(xcconfigName); sourceTree = SOURCE_ROOT; };\n"
        if let marker = out.range(of: "/* Begin PBXFileReference section */\n") {
            out.replaceSubrange(marker, with: "/* Begin PBXFileReference section */\n" + fileRefLine)
        } else {
            throw WireError.unparseable("no PBXFileReference section to add the xcconfig reference to")
        }

        return out
    }

    /// A fresh 24-hex-uppercase object identifier not already present in `text`.
    static func freshGUID(notIn text: String) -> String {
        while true {
            let g = (0..<12).map { _ in String(format: "%02X", UInt8.random(in: 0...255)) }.joined()
            if !text.contains(g) { return g }
        }
    }
}
