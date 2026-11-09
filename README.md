# macattacc

**A macOS-native Swift toolkit for developers protecting software they own.** Build-hardening
presets, an opt-in runtime tamper-detection library, and a drop-in CLI. MIT licensed.

> Protect your own software. This is defensive developer tooling. See [DISCLAIMER.md](DISCLAIMER.md).

The runtime self-protection suites (IOSSecuritySuite, freeRASP) are iOS/Android only, and the macOS
obfuscators (SwiftShield, Hikari) are dead or archived. No maintained macOS-native equivalent that
combines runtime protection with build hardening surfaced in a 2026-11-08 survey (not exhaustive);
macattacc packages both so an agent can drop it in and run.

## Two threats, two defenses (read this first)

| Threat | What stops it | Where it lives |
|---|---|---|
| Cloning your app from the shipped binary (static analysis) | Build hardening + obfuscation: strip symbols, drop reflection metadata, and obfuscate string literals | `shield harden` writes `Shield.xcconfig`; `#obfuscated` (the `MacattaccObfuscation` library) |
| Dynamic tampering: debuggers, licence patches, Frida hooks on a running app | Runtime self-checks (this library), as defense-in-depth | `MacOSShield` / `shield doctor` |

Lead with hardening. The runtime library is defense-in-depth against dynamic tampering and
licence-cracking. It is not anti-clone, and does little against someone statically reverse-engineering
your binary.

### Honest limits

A self-check inside the binary it protects is a speed bump of minutes, not a wall. An attacker, or an
LLM pointed at your binary, can NOP the branch that acts on a detection, or hook the syscall the check
relies on. These techniques raise cost; they do not make an app uncrackable.

Specifics:

- Name, thread, and image heuristics are high false-positive. `gmain` is a stock GLib thread name in
  benign apps; Rosetta, VMs, EDR, and accessibility tools perturb the loaded-image list. These signals
  are report-only and can never alone trigger a terminate.
- `DYLD_INSERT_LIBRARIES` is already stripped under the hardened runtime, so that detector is weak.
- The signature self-check is only meaningful on a properly signed build. Debug and ad-hoc builds
  report `errSecCSUnsigned`, which is not treated as a failure. With `expectedTeamID` and
  `signatureRequirement` both nil it only proves "signed and unmodified vs its *own* signature" — an
  attacker who re-signs with their own identity passes it. Pin a Team ID or a designated requirement
  for that check to carry weight.
- `PT_DENY_ATTACH` has real costs (below) and is off by default.

## Quickstart

### 1. Harden your build (the anti-clone half)

```sh
swift run shield harden /path/to/your/project
```

Writes `Shield.xcconfig` with the presets (`STRIP_STYLE=all`, `STRIP_INSTALLED_PRODUCT`,
`DEAD_CODE_STRIPPING`, `DEPLOYMENT_POSTPROCESSING`, `SWIFT_REFLECTION_METADATA_LEVEL=without-names`)
and prints how to adopt it. By default it does not touch your `.xcodeproj`; you include the xcconfig
on your Release configuration. Pass `--write-project` to opt in to wiring the single `.xcodeproj` in
the directory automatically — it sets the app target's Release `baseConfigurationReference`, after a
timestamped `project.pbxproj` backup, and refuses rather than guess if it can't find exactly one app
target or the config is already set. No other target is touched.

### 1b. Obfuscate string literals (the anti-scrape layer)

Plaintext secrets — licence-server URLs, API endpoints, feature-flag keys — sit in the binary's
`__TEXT` string table where `strings` dumps them in one command. The `MacattaccObfuscation` library
is a separate product (adopt it without the runtime detectors) exposing a compile-time macro:

```swift
.product(name: "MacattaccObfuscation", package: "macattacc")
```

```swift
import MacattaccObfuscation

let endpoint = #obfuscated("https://licence.example.com/verify")
```

`#obfuscated` encodes the literal at build time (XOR with a per-literal random key generated during
macro expansion) and decodes it at runtime on use. The plaintext never appears in the expanded
source or the shipped binary, and two identical strings encode differently at each call site.

**Honest limits.** This defeats naive `strings` and static scraping and raises the static-recovery
bar. It is one layer, not a wall: a debugger or a runtime memory dump still reveals the decrypted
value, because the app has to decode it to use it. Don't put anything behind it that a server-side
check should own.

For heavier, IR-level obfuscation, the Obscura LLVM obfuscator is an option **for non-commercial
projects only** — it is PolyForm Noncommercial licensed, so it is NOT bundled here and cannot be
used on commercial apps. macattacc stays MIT and commercial-safe.

### 2. Add the runtime library (defense-in-depth)

```swift
// Package.swift
.package(url: "https://github.com/heyethan/macattacc.git", from: "0.1.0")
```

```swift
import MacOSShield

// Safe default: report-only, nothing destructive.
let detections = Shield.scan()
for d in detections where !d.isHighFalsePositive {
    log("tamper signal: \(d.summary)")
}
```

Opt in to a response when you understand the trade-offs:

```swift
var policy = ShieldPolicy()
policy.expectedTeamID = "YOURTEAMID"
policy.onDetection = .callback { detections in
    // your telemetry or soft licence-gate here
}
Shield.scan(policy)
```

### 3. Inspect from the CLI

```sh
swift run shield doctor              # self-scan, report-only
swift run shield check /Applications/YourApp.app --team-id YOURTEAMID
```

## Safety defaults

- `onDetection` defaults to `.report` and never crashes a user. `.terminate` is opt-in, and even then
  fires only when a non-high-false-positive detection is present.
- `PT_DENY_ATTACH` is opt-in within opt-in, off by default. It forfeits your own crash telemetry
  (blocks `sample`, Instruments, the crash reporter), can look like a crash on MDM/EDR-managed Macs,
  and risks notarization review. Never enable it for an App-Store-bound build. It also SIGSEGVs if a
  debugger is already attached.
- Set `ShieldPolicy.imageAllowlist` for your own frameworks.

## Requirements

macOS 13+, Swift 6 (strict concurrency), arm64 and x86_64. No third-party runtime dependencies; the
CLI uses swift-argument-parser.

## For agents

Point an agent at this repo and it can harden a project. See [SKILL.md](SKILL.md) and
[AGENTS.md](AGENTS.md).

## Before production

Prefer `.report`. The destructive paths (`.terminate`, `PT_DENY_ATTACH`) are opt-in, early,
single-maintainer code with no independent security audit. Put real enforcement on a server you
control (a revocable licence), not on a self-check the binary can be patched to skip.

## What v1 is, honestly

The clone-resistant value is the build hardening, and those are standard Apple Release settings
packaged into one command: anyone could assemble them from Apple's docs. v1's edge is packaging,
candor, and macOS-native runtime detection with no maintained equivalent surfaced in that survey,
not novel capability. Compile-time
string obfuscation (`#obfuscated`) ships in 0.2.0. The live detectors have integration and
Mach-port-leak tests (`swift test`), but a determined attacker still bypasses any in-binary check.

## Status

v1: runtime library, build-hardening presets, CLI, tests. 0.2.0 adds the `#obfuscated` string-literal
obfuscation macro (MIT, commercial-safe). Integrity is handled by macOS code signing (the signature
self-check + `shield verify`), not a hand-rolled hash baseline. IR-level obfuscation stays out: the
known option (Obscura) is PolyForm Noncommercial, so it cannot be bundled in this MIT repo or used on
commercial apps. Still open: `harden` project editing.

See [docs/DESIGN.md](docs/DESIGN.md), [PRIOR-ART.md](PRIOR-ART.md) (clean-room statement), and
[DISCLAIMER.md](DISCLAIMER.md).
