# macos-shield (provisional name) — build plan

## What it is
First open-source, maintained, **macOS-native Swift** runtime code-protection toolkit, for developers protecting
software **they own**. Fills a real gap (survey 2026-11-08): IOSSecuritySuite/freeRASP are iOS/Android only;
SwiftShield (GPL, dead 2022) and Hikari (archived) are the only obfuscators. Nothing combines runtime protection +
build hardening for Mac, and nothing is agent-droppable.

## Non-negotiables
- **Clean-room.** Rebuild every technique from scratch in fresh Swift/C. Study ideas/APIs only; copy NO code from
  GPL (SwiftShield) or unlicensed (Hikari, SwiftyShield) repos. Credit prior art in PRIOR-ART.md.
- **Licence:** MIT (max adoption for a drop-in tool).
- **Defensive only.** For authors protecting their own apps. DISCLAIMER.md. No AV/security-product evasion, no
  malware features.
- **Fail-safe.** Default response to a detection is **report-only** (callback/log), never a hard crash — must never
  brick a paying customer. Terminate is opt-in.
- **Agent-droppable.** A user points Claude Code / any agent at the repo and runs one command to harden their app.
  Ship SKILL.md + AGENTS.md + a CLI.

## Architecture (SwiftPM)
- `CShieldShim` (C target): syscalls Swift can't reach cleanly — `ptrace(PT_DENY_ATTACH)`, `sysctl` kinfo_proc.
- `MacOSShield` (Swift 6, strict concurrency): umbrella `Shield` type; `Shield.scan() -> [Detection]`; a
  `ShieldPolicy` (onDetection: report | callback | terminate, default report). macOS 13+, arm64 + x86_64.
- `shield` CLI (ArgumentParser): `shield check <app>`, `shield harden <xcodeproj|dir>` (applies build presets),
  `shield doctor`. This is what an agent runs.

## Detectors (runtime, macOS-native, all rebuilt from scratch)
1. **Debugger:** `sysctl` KERN_PROC_PID then `kp_proc.p_flag & P_TRACED`; `ptrace(PT_DENY_ATTACH)` opt-in; parent-process check.
2. **Frida / instrumentation:** enumerate loaded images via `_dyld_image_count`/`_dyld_get_image_name`, flag
   frida/gum/gadget/cynject/substrate; scan Mach thread names (gum-js-loop, gmain); optional 27042 port probe (documented FP risk).
3. **Dylib injection:** `DYLD_INSERT_LIBRARIES` environment var; loaded-image allowlist diff.
4. **Code-signature self-check:** Security.framework `SecCode`/`SecStaticCode` — verify the running app's signature
   and Team ID at runtime; detect re-signing. (Documented: needs a signed build to be meaningful.)
5. **Mach-O integrity (optional):** hash chosen sections vs a baked baseline; off by default (fragile with signing).

## Build hardening (packaged presets)
- An xcconfig plus a SwiftPM-settings doc bundling what Geass already proved: `STRIP_STYLE=all`,
  `STRIP_INSTALLED_PRODUCT`, `DEAD_CODE_STRIPPING`, `DEPLOYMENT_POSTPROCESSING`,
  `SWIFT_REFLECTION_METADATA_LEVEL=without-names`. `shield harden` applies them.

## Obscura (phase 2, wrap not rebuild)
- Obscura (LLVM pass, arm64 macOS, maintained) already does IR obfuscation. Document plus script integration; don't
  rebuild an LLVM obfuscator.

## Tests
- Unit-test pure logic (sysctl flag parse, image-name matching, allowlist diff, signature-result mapping) so CI is
  green with no debugger/Frida present. Mark live-only checks (actual PT_DENY_ATTACH, real Frida) in docs.
- `swift build` plus `swift test` must pass.

## First execution run (this one): design plus runtime lib
Deliver in ~/macos-shield: `Package.swift`, `Sources/CShieldShim`, `Sources/MacOSShield`, `Sources/shield` (CLI),
`Tests`, `README.md` (prominent "protect software you own" plus quickstart), `SKILL.md`, `AGENTS.md`, `LICENSE` (MIT),
`DISCLAIMER.md`, `PRIOR-ART.md`, `docs/DESIGN.md`. `swift test` green. Phase 2 = Obscura wrap, CLI `harden` polish,
Geass dogfood.

## REVISIONS after Fable + Opus-5.5 review (2026-11-08) — these override anything above that conflicts

**Re-centering (devil's advocate, correct):** the anti-CLONE threat is *static* binary analysis; runtime detection
does little against it. So:
- **Lead the product with build-hardening + obfuscation** (strip/metadata + Obscura wrap) — the only part that
  raises the static/clone bar. The runtime library is **defense-in-depth against dynamic tampering / licence-crack,
  NOT anti-clone**, and must be labelled exactly that way in README/docs. Never imply runtime checks stop cloning.
- The first build still includes the runtime lib (it is the real macOS gap) **and** the build-hardening presets +
  xcconfig in the same deliverable, so the anti-clone half ships from day one.

**Honest framing in all docs:** a self-check inside the binary it protects is a speed bump of minutes, not a wall
(an attacker/LLM NOPs the branch or hooks the syscall). Say so plainly.

**Safety defaults (hard requirements):**
- `onDetection` default = **report-only**. `terminate` opt-in. `PT_DENY_ATTACH` is opt-in-WITHIN-opt-in, OFF by
  default; document that it forfeits your own crash telemetry (blocks `sample`/Instruments/crash reporter), can look
  like a crash on MDM/EDR Macs, and risks notarization review (Apple runs apps in analysis harnesses). Off for
  anything App-Store-bound.
- Every name/thread/port heuristic = **high false-positive, report-only, must never solely gate terminate.** `gmain`
  is a stock GLib thread name in many benign apps; Rosetta/VMs/EDR/accessibility tools perturb the image list. Ship a
  documented allowlist. **Drop the 27042 port probe from v1** (or default-off, needs network entitlement).

**Fable's correctness notes (fold in):** `ptrace`/`kinfo_proc` live in the C shim only (hidden from Swift overlay);
`PT_DENY_ATTACH`=31 SIGSEGVs if a debugger is already attached (document); Frida **thread-name** scan is more
reliable than image-name but `task_threads` must `mach_port_deallocate` each port + `vm_deallocate` the array or it
leaks; signature check must handle `errSecCSUnsigned` on debug/ad-hoc builds; hash only `__TEXT`/`__DATA_CONST`;
`DYLD_INSERT_LIBRARIES` is already stripped under hardened runtime, so that detector is weak — say so. `Detection`
Sendable; `ShieldPolicy` callback `@Sendable`; `swiftLanguageModes: [.v6]`, `platforms: [.macOS(.v13)]`.

**Clean-room process (legal):** write `PRIOR-ART.md` FIRST, committed before any implementation commit; cite Apple
headers/man pages (sys/ptrace.h, sys/sysctl.h, mach-o/dyld.h, Security.framework) as the source, not the GPL repos;
record that no GPL/unlicensed source was opened while coding. Audit Obscura's licence permits wrap+ship before the
Obscura phase.

**Scope honesty:** `shield harden` auto-editing a user's xcodeproj is the RISKIEST surface (can break real builds) —
treat as hard work, not polish; v1 may instead PRINT the settings / write an xcconfig the user includes, rather than
mutate their project. Dual-use is real: the detection half is the same code sandbox-evading malware uses — the honest
differentiator is the protective build-hardening half; don't let a DISCLAIMER pretend the line is cleaner than it is.

## Constraints for the builder
- Work only in ~/macos-shield. Commit locally (heyethan / ethandsouzaftw@gmail.com). Do NOT create or push any
  GitHub repo. Do NOT run anything touching the screen/pointer/other apps. Verify with `swift build`/`swift test`.
