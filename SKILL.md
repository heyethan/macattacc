---
name: macos-shield
description: Harden and self-protect a macOS app the user owns. Use when the user wants to strip/obfuscate a Swift/macOS binary against cloning, or add runtime tamper/debugger/instrumentation detection to their own app. Writes a build-hardening xcconfig and scans a process or app bundle. Defensive, for software the user owns.
---

# macos-shield

Protect a macOS app **the user owns**. Two halves, different jobs — be honest about which:

- **Anti-clone (static):** build-hardening presets → `shield harden`. This is the half that matters
  for cloning.
- **Defense-in-depth (dynamic):** runtime tamper detection → the `MacOSShield` library /
  `shield doctor`. NOT anti-clone. A self-check inside the binary is a speed bump of minutes.

Never tell the user runtime checks stop cloning. Never enable a destructive response by default.

## Build and verify

```sh
cd macos-shield
swift build          # must succeed
swift test           # must be green (pure logic; no debugger/Frida needed)
```

## Commands

```sh
# Anti-clone: write Shield.xcconfig with proven presets, print adoption steps.
# Does NOT mutate the user's .xcodeproj — they include the xcconfig themselves.
swift run shield harden <project-dir>

# Self-scan a process, report-only.
swift run shield doctor

# Validate an app bundle's signature + Team ID.
swift run shield check <path-to.app> [--team-id TEAMID]
```

## Using the library

```swift
import MacOSShield
let detections = Shield.scan()                 // report-only default
for d in detections where !d.isHighFalsePositive { /* act on real signals only */ }
```

`ShieldPolicy` knobs: `onDetection` (`.report`/`.callback`/`.terminate`), `expectedTeamID`,
`imageAllowlist`, `enablePtraceDenyAttach` (OFF — has crash-telemetry/notarization costs),
`checkMachOHash` (OFF — fragile under re-signing).

## Rules when applying this

1. Lead with `harden`. Present the runtime library as defense-in-depth only.
2. Keep `onDetection` on `.report` unless the user explicitly asks to terminate, and explain that
   high-FP heuristics (image/thread names, env var) never gate terminate alone.
3. Do not enable `PT_DENY_ATTACH` for anything App-Store-bound; warn about lost crash telemetry.
4. This is for software the user owns. See DISCLAIMER.md.
