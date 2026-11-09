# Design

## Threat model, honestly

Two distinct threats, different defenses. Conflating them is the field's core dishonesty.

1. **Cloning (static).** Attacker reads your shipped binary, lifts logic. Countered only by raising
   the static-analysis bar: strip symbols, drop reflection metadata, obfuscate IR. → `shield harden`.
2. **Dynamic tampering (runtime).** Attacker attaches a debugger, patches a licence check, or hooks
   with Frida on a running process. Countered by runtime self-checks — **defense-in-depth, minutes
   of friction, not a wall.** → `MacOSShield`.

A self-check inside the binary it protects is bypassable by NOPing the branch or hooking the
syscall. We say so everywhere. The runtime half is never labelled anti-clone.

## Layout

- **`CShieldShim` (C).** Only the syscalls the Swift Darwin overlay hides or makes awkward:
  `sysctl(KERN_PROC_PID)` → `p_flag & P_TRACED`, `ptrace(PT_DENY_ATTACH)`, `getppid`. Keeping these
  in C keeps `ptrace`/`kinfo_proc` out of Swift. Sources: `man 2 ptrace`, `man 3 sysctl`,
  `<sys/proc.h>`.
- **`MacOSShield` (Swift 6).** `Shield.scan(_ policy:) -> [Detection]`. `Detection` is a `Sendable`
  enum; `ShieldPolicy` carries detector toggles + a `Sendable` response. Pure matching logic is
  isolated in `Heuristics` so it is unit-testable with no debugger/Frida/signed binary present; the
  live system reads are in `Detectors`.
- **`shield` (CLI).** `check` / `doctor` / `harden`. What an agent runs.

## Detectors

| Detector | Policy toggle | Mechanism | Confidence | Default |
|---|---|---|---|---|
| Debugger | `checkDebugger` | sysctl `P_TRACED` | high | on, report |
| `PT_DENY_ATTACH` | `enablePtraceDenyAttach` | `ptrace(31)` | prevention | **off** |
| Instrumentation image | `checkInstrumentationImages` | `_dyld_*` image enum vs basename markers | high-FP | on, report |
| Instrumentation thread | `checkInstrumentationThreads` | `task_threads` + `pthread_getname_np` | high-FP | on, report |
| Unexpected image | `checkUnexpectedImages` | realpath diff vs system/bundle/allowlist | high-FP | on, report |
| Dylib injection | `checkDylibInjection` | `DYLD_INSERT_LIBRARIES` env | specific-but-weak | on, report |
| Signature self-check | `checkSignature` | `SecStaticCode` + Team ID / requirement | high only if pinned | on, report |

The unexpected-image check is the noisiest, so it has its own toggle: disable
`checkUnexpectedImages` independently while keeping the instrumentation-marker checks.

### Correctness notes

- `PT_DENY_ATTACH` = 31; SIGSEGVs if a debugger is already attached. Forfeits crash telemetry, risks
  notarization analysis. Opt-in within opt-in, applied at most once per process, and gated
  independently of `checkDebugger`.
- Instrumentation markers match the image **basename's** tokens, never a substring of the full path,
  so `libswiftArgumentParser.dylib` is not flagged by `gum` inside "argument".
- Thread-name scan is more reliable than image-name scan, but `task_threads` leaks unless every port
  is `mach_port_deallocate`'d and the array `vm_deallocate`'d — done in `Detectors.threadNames()`.
- Unexpected-image comparison resolves `realpath(3)` so `/var` vs `/private/var` and symlinks do not
  produce phantom mismatches, and exempts the main bundle's own `Contents/` subtree.
- Signature check treats `errSecCSUnsigned` as "not meaningful here" (debug/ad-hoc), *unless* a Team
  ID or designated requirement is pinned, which an unsigned binary cannot satisfy. With neither
  pinned it only proves "signed and unmodified vs its own signature" — a re-sign passes.
- `DYLD_INSERT_LIBRARIES` is stripped under the hardened runtime, so that detector is weak (its
  absence proves nothing), but it is specific: benign apps rarely set it, so it is not high-FP.

## Safety model

- Response defaults to `.report`. `.terminate` is opt-in and gated via `Shield.shouldTerminate`,
  which terminates (with `abort()`) only when `detections.contains { !$0.isHighFalsePositive }`. A
  set of only name/thread/image signals can never brick a user.
- `Detection.isHighFalsePositive` is the single source of truth for that gate and is unit-tested.
  "High-FP" means "fires on benign apps" (name/thread/unexpected-image), not "easy to evade".
- A library killing its host process is drastic: prefer `.report`/`.callback` and enforce on a
  server you control.

## Build hardening

`shield harden` writes `Shield.xcconfig` (the standard Release hardening presets) and prints adoption steps. v1
deliberately does **not** mutate a user's `.xcodeproj` — auto-editing project files is the riskiest,
build-breaking surface and is treated as future work, not polish.

## Phase 2

- Wrap (not rebuild) a maintained LLVM obfuscator (e.g. Obscura) after a licence audit; `harden`
  project integration.
- **Mach-O section hashing** (dropped from v1). Hashing a `__TEXT`/`__DATA_CONST` section and
  comparing against a baked baseline needs a baseline generator plus a post-link patch step to write
  the expected digest after the hash sites are compiled; without that the baseline is self-referential
  and the detector is unusable. Not shipped. Phase 2 would add the generator and the patch step.
