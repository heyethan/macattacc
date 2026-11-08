# AGENTS.md

Guidance for an AI agent pointed at this repo. Goal: harden a macOS app the user owns, and/or add
runtime tamper detection — without breaking their build or overstating what it buys.

## Orient

- `Package.swift` — SwiftPM, macOS 13+, Swift 6. Targets: `CShieldShim` (C syscalls), `MacOSShield`
  (library), `shield` (CLI), tests.
- Entry points: `Sources/MacOSShield/Shield.swift` (`Shield.scan(_:)`), `Sources/shield/CLI.swift`.
- Read `README.md` "What actually raises the bar" and "Honest limits" before you advise the user.

## Build / test (always verify)

```sh
swift build && swift test
```

Both must pass. Tests are pure logic and need no debugger or Frida present.

## Do

- Run `swift run shield harden <dir>` to produce `Shield.xcconfig`; explain the user must include it
  on their Release config themselves. Do **not** edit their `.xcodeproj`.
- Default `ShieldPolicy.onDetection` to `.report`. Act only on `!detection.isHighFalsePositive`.
- Tell the user plainly: runtime self-checks are defense-in-depth against dynamic tampering, not a
  wall against cloning, and an attacker/LLM can NOP the branch.

## Don't

- Don't enable `enablePtraceDenyAttach` by default, or at all for App-Store-bound apps (lost crash
  telemetry, notarization risk, SIGSEGV if a debugger is already attached).
- Don't let a high-FP heuristic gate a `terminate`. The library already refuses this; don't work
  around it.
- Don't use this on software the user does not own. See `DISCLAIMER.md`.
- Don't copy code from GPL/unlicensed protection repos into this MIT project (see `PRIOR-ART.md`).
