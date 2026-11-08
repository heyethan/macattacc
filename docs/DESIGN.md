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

| Detector | Mechanism | Confidence | Default |
|---|---|---|---|
| Debugger | sysctl `P_TRACED` | high | on, report |
| `PT_DENY_ATTACH` | `ptrace(31)` | prevention | **off** |
| Instrumentation image | `_dyld_*` image enum vs markers | high-FP | on, report |
| Instrumentation thread | `task_threads` + `pthread_getname_np` | high-FP | on, report |
| Unexpected image | allowlist diff vs system/main/allowlist | high-FP | on, report |
| Dylib injection | `DYLD_INSERT_LIBRARIES` env | weak | on, report |
| Signature self-check | `SecStaticCode` + Team ID | high (signed only) | on, report |
| Mach-O section hash | `getsegmentdata` + SHA-256 vs baseline | fragile | **off** |

### Correctness notes (folded in from review)

- `PT_DENY_ATTACH` = 31; SIGSEGVs if a debugger is already attached. Forfeits crash telemetry, risks
  notarization analysis. Opt-in within opt-in.
- Thread-name scan is more reliable than image-name scan, but `task_threads` leaks unless every port
  is `mach_port_deallocate`'d and the array `vm_deallocate`'d — done in `Detectors.threadNames()`.
- Signature check treats `errSecCSUnsigned` as "not meaningful here" (debug/ad-hoc), not a failure.
- Hash only `__TEXT` / `__DATA_CONST` — stable, read-only under signing.
- `DYLD_INSERT_LIBRARIES` is stripped under the hardened runtime, so that detector is weak.

## Safety model

- Response defaults to `.report`. `.terminate` is opt-in and gated: `Shield.apply` terminates only
  when `detections.contains { !$0.isHighFalsePositive }`. A set of only name/thread/env signals can
  never brick a user.
- `Detection.isHighFalsePositive` is the single source of truth for that gate and is unit-tested.

## Build hardening

`shield harden` writes `Shield.xcconfig` (the presets Geass proved) and prints adoption steps. v1
deliberately does **not** mutate a user's `.xcodeproj` — auto-editing project files is the riskiest,
build-breaking surface and is treated as future work, not polish.

## Phase 2

Wrap (not rebuild) a maintained LLVM obfuscator (e.g. Obscura) after a licence audit; `harden`
project integration; Geass dogfood.
