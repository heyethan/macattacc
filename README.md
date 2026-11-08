# macos-shield

**A macOS-native Swift toolkit for developers protecting software they own.** Build-hardening
presets + an opt-in runtime tamper-detection library + a drop-in CLI. MIT licensed.

> Protect **your own** software. This is defensive developer tooling. See [DISCLAIMER.md](DISCLAIMER.md).

It fills a real gap: the runtime self-protection suites (IOSSecuritySuite, freeRASP) are iOS/Android
only, and the macOS obfuscators (SwiftShield, Hikari) are dead or archived. Nothing combined
macOS-native runtime protection with build-hardening in a package an agent can drop in and run.

## What actually raises the bar — read this first

There are two very different threats, and they need different defenses:

| Threat | What stops it | Where it lives here |
|---|---|---|
| **Cloning** your app from the shipped binary (static analysis) | Build-hardening + obfuscation — strip symbols, drop reflection metadata, (phase 2) IR obfuscation | `shield harden` → `Shield.xcconfig` |
| **Dynamic tampering** — debuggers, licence patches, Frida hooks on a *running* app | Runtime self-checks (this library) as **defense-in-depth** | `MacOSShield` / `shield doctor` |

**Lead with hardening.** The runtime library is *defense-in-depth against dynamic tampering and
licence-cracking — it is NOT anti-clone.* Runtime checks do little against someone statically
reverse-engineering your binary. Never read the runtime half as "this stops cloning."

### Honest limits

A self-check that lives **inside the binary it protects is a speed bump of minutes, not a wall.** An
attacker — or an LLM pointed at your binary — can NOP the branch that acts on a detection, or hook
the syscall the check relies on. These techniques raise cost; they do not make your app
uncrackable. Anyone who tells you otherwise is selling something.

Specific weaknesses, stated plainly:

- **Name/thread/image heuristics are high false-positive.** `gmain` is a stock GLib thread name in
  benign apps; Rosetta, VMs, EDR and accessibility tools perturb the loaded-image list. These
  signals are **report-only** and, by design, can never *alone* trigger a terminate.
- **`DYLD_INSERT_LIBRARIES` is already stripped under the hardened runtime**, so that detector is
  weak — its absence proves nothing.
- **The signature self-check is only meaningful on a properly signed build.** Debug/ad-hoc builds
  report `errSecCSUnsigned`, which is *not* treated as a failure.
- **`PT_DENY_ATTACH` has real costs** (see below) and is **off by default**.

## Quickstart

### 1. Harden your build (the anti-clone half)

```sh
swift run shield harden /path/to/your/project
```

Writes `Shield.xcconfig` with the proven presets (`STRIP_STYLE=all`, `STRIP_INSTALLED_PRODUCT`,
`DEAD_CODE_STRIPPING`, `DEPLOYMENT_POSTPROCESSING`, `SWIFT_REFLECTION_METADATA_LEVEL=without-names`)
and prints how to adopt it. **It does not touch your `.xcodeproj`** — you include the xcconfig
yourself, on your Release configuration.

### 2. Add the runtime library (defense-in-depth)

```swift
// Package.swift
.package(url: "https://github.com/<you>/macos-shield.git", from: "0.1.0")
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
    // your telemetry / soft licence-gate here
}
Shield.scan(policy)
```

### 3. Inspect from the CLI

```sh
swift run shield doctor              # self-scan this toolkit, report-only
swift run shield check /Applications/YourApp.app --team-id YOURTEAMID
```

## Safety defaults

- `onDetection` defaults to **`.report`** — never crashes a paying customer. `.terminate` is opt-in,
  and even then fires **only** when a non-high-false-positive detection is present.
- **`PT_DENY_ATTACH` is opt-in within opt-in, OFF by default.** It forfeits your own crash telemetry
  (blocks `sample`, Instruments, the crash reporter), can look like a crash on MDM/EDR-managed Macs,
  and risks notarization review (Apple runs apps in analysis harnesses). Never enable it for an
  App-Store-bound build. It also SIGSEGVs if a debugger is *already* attached.
- The 27042 Frida port probe was **dropped from v1** (high FP, needs a network entitlement).
- Ship a documented **image allowlist** (`ShieldPolicy.imageAllowlist`) for your own frameworks.

## Requirements

macOS 13+, Swift 6 (strict concurrency), arm64 + x86_64. No third-party runtime dependencies; the
CLI uses swift-argument-parser.

## For agents

An agent can harden a project by pointing itself at this repo — see [SKILL.md](SKILL.md) and
[AGENTS.md](AGENTS.md).

## Status

v1: runtime library + build-hardening presets + CLI. Phase 2: wrap (not rebuild) a maintained LLVM
obfuscator (e.g. Obscura) after a licence audit; `harden` project-editing; Geass dogfood.

See [docs/DESIGN.md](docs/DESIGN.md), [PRIOR-ART.md](PRIOR-ART.md) (clean-room statement), and
[DISCLAIMER.md](DISCLAIMER.md).
