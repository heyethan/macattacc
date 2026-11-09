# macattacc

**A macOS-native Swift toolkit for developers protecting software they own.** Build-hardening
presets, an opt-in runtime tamper-detection library, and a drop-in CLI. MIT licensed.

> Protect your own software. This is defensive developer tooling. See [DISCLAIMER.md](DISCLAIMER.md).

The runtime self-protection suites (IOSSecuritySuite, freeRASP) are iOS/Android only, and the macOS
obfuscators (SwiftShield, Hikari) are dead or archived. macattacc combines macOS-native runtime
protection with build hardening in a package an agent can drop in and run.

## Two threats, two defenses (read this first)

| Threat | What stops it | Where it lives |
|---|---|---|
| Cloning your app from the shipped binary (static analysis) | Build hardening and obfuscation: strip symbols, drop reflection metadata, plus (phase 2) IR obfuscation | `shield harden` writes `Shield.xcconfig` |
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
  report `errSecCSUnsigned`, which is not treated as a failure.
- `PT_DENY_ATTACH` has real costs (below) and is off by default.

## Quickstart

### 1. Harden your build (the anti-clone half)

```sh
swift run shield harden /path/to/your/project
```

Writes `Shield.xcconfig` with the presets (`STRIP_STYLE=all`, `STRIP_INSTALLED_PRODUCT`,
`DEAD_CODE_STRIPPING`, `DEPLOYMENT_POSTPROCESSING`, `SWIFT_REFLECTION_METADATA_LEVEL=without-names`)
and prints how to adopt it. It does not touch your `.xcodeproj`; you include the xcconfig on your
Release configuration.

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
- The 27042 Frida port probe was dropped from v1 (high false-positive, needs a network entitlement).
- Set `ShieldPolicy.imageAllowlist` for your own frameworks.

## Requirements

macOS 13+, Swift 6 (strict concurrency), arm64 and x86_64. No third-party runtime dependencies; the
CLI uses swift-argument-parser.

## For agents

Point an agent at this repo and it can harden a project. See [SKILL.md](SKILL.md) and
[AGENTS.md](AGENTS.md).

## Status

v1: runtime library, build-hardening presets, CLI. Phase 2: wrap a maintained LLVM obfuscator (e.g.
Obscura) after a licence audit, and `harden` project editing.

See [docs/DESIGN.md](docs/DESIGN.md), [PRIOR-ART.md](PRIOR-ART.md) (clean-room statement), and
[DISCLAIMER.md](DISCLAIMER.md).
