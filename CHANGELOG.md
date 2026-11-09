# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

First tagged release.

### Added

- `MacOSShield` runtime library: `Shield.scan(_:)` with report-only, callback, and gated
  terminate responses; pure matching logic isolated in `Heuristics` for unit testing.
- Live detectors: debugger (`sysctl P_TRACED`), instrumentation images (basename-token match),
  instrumentation threads, unexpected images (realpath diff), `DYLD_INSERT_LIBRARIES`, and a
  code-signature self-check with optional Team ID and designated-requirement pinning.
- Per-detector `ShieldPolicy` toggles: `checkInstrumentationImages`,
  `checkInstrumentationThreads`, `checkUnexpectedImages`, and the rest.
- Optional, idempotent `ptrace(PT_DENY_ATTACH)`, gated independently of the debugger check
  and off by default.
- `shield` CLI: `check`, `doctor`, `harden` (with `--force`), and `verify`.
  - `harden` writes an app-target-only `Shield.xcconfig` (strip + reflection-metadata presets,
    hardened runtime, dSYM guidance) and refuses to overwrite without `--force`.
  - `verify <binary-or-.app>` confirms symbols are stripped (PASS/FAIL) and reports the
    `__swift5_reflstr` size and hardened-runtime flag.
- Integration and Mach-port-leak tests for the live detectors; unit tests for all pure logic.
- `.github/workflows/ci.yml` running `swift build` + `swift test` on macOS.

### Notes

- Runtime self-checks are defense-in-depth against dynamic tampering, **not** anti-clone, and an
  attacker or LLM can NOP the branch or hook the syscall. Mach-O section hashing is deferred to
  phase 2 (needs a baseline generator + post-link patch step); it is not shipped.

[0.1.0]: https://github.com/heyethan/macattacc/releases/tag/0.1.0
