# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-09

### Changed

- Obfuscation no longer ships the raw XOR key next to the ciphertext. Each literal's key is
  derived at runtime as `SHA256(seed || salt || counter)` (counter mode) from a per-build master
  seed (emitted per call site in masked form) and a per-call-site salt. The expansion stores
  cipher + salt + masked seed + mask — no full-length key adjacent to the cipher. Same honest
  ceiling: a debugger/dump still recovers the value.
- One hardened code-signature validation path (strict + all-architectures + nested-code, optional
  requirement / Team ID) is now shared by the library self-check and the CLI `shield check`, which
  previously used the weaker bare `SecCSFlags()`. `check` gains a `--requirement` option.
- `Heuristics.matchesInstrumentationThread` is token-anchored like the image matcher, so `gmain`
  no longer matches `diagmaintenance`. Still report-only / high-FP.
- `shield verify` reports a missing `nm`/`otool`/`size` tool clearly, and PASSes on a local-symbol
  count at/below a small threshold instead of requiring strict zero (a stripped binary can retain
  a stray local). The reflection-metadata size report is unchanged.

### Added

- `shield harden --write-project` (opt-in): wires `Shield.xcconfig` into the single `.xcodeproj`'s
  app-target Release config via a conservative, non-destructive `.pbxproj` edit — timestamped
  backup first, refuses on anything ambiguous (not exactly one app target, already configured),
  never touches other targets. Default behaviour (print instructions) is unchanged.

### Docs

- `PRIOR-ART.md`: the commit-order claim is replaced with a dated (2026-11-08) clean-room
  attestation that does not depend on visible commit order.

[0.2.1]: https://github.com/heyethan/macattacc/releases/tag/0.2.1

## [0.2.0] - 2026-11-09

### Added

- `MacattaccObfuscation`: a compile-time string-literal obfuscator, a separate library product so
  it can be adopted without the runtime detectors. The freestanding macro `#obfuscated("literal")`
  XOR-encodes the literal at build time against a per-literal random key, so the plaintext is absent
  from the expansion and the binary's `__TEXT` string table, and identical strings differ across
  call sites. Backed by a SwiftSyntax `.macro` target (`MacattaccObfuscationMacros`).
- Tests: macro-expansion (no plaintext in the expansion), runtime round-trip (empty, unicode, long),
  and a strings-absence check that a sentinel routed through `#obfuscated` is absent from the
  compiled test binary.

### Notes

- Honest ceiling: obfuscation defeats naive `strings`/static scraping and raises the static-recovery
  bar, but a debugger or runtime memory dump still recovers the decrypted value — one layer, not a
  wall. IR-level obfuscation is not bundled: Obscura is PolyForm Noncommercial, so it cannot ship in
  this MIT repo or run on commercial apps; it stays a non-commercial-only option.
- Integrity is handled by macOS code signing (the signature self-check + `shield verify`), not a
  hand-rolled Mach-O hash baseline.

[0.2.0]: https://github.com/heyethan/macattacc/releases/tag/0.2.0

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
