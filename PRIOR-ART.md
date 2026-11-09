# Prior art and clean-room statement

This document is committed **before any implementation code** in this repository, as a record of
how `macattacc` was built and what it is (and is not) derived from.

## Clean-room process

Every technique in this toolkit was rebuilt from scratch in fresh Swift and C. While writing the
code, **no source code from GPL-licensed or unlicensed protection projects was opened, read, or
copied.** The APIs used here are public Apple system interfaces; the authoritative sources consulted
were Apple's own headers and manual pages, not third-party implementations:

- `ptrace(2)` and `PT_DENY_ATTACH` — `<sys/ptrace.h>`, `man 2 ptrace`
- `sysctl(3)` with `KERN_PROC_PID` and the `kinfo_proc` / `extern_proc` layout, and the `P_TRACED`
  process flag — `<sys/sysctl.h>`, `<sys/proc.h>`, `man 3 sysctl`
- Loaded-image enumeration — `_dyld_image_count`, `_dyld_get_image_name`, `_dyld_get_image_header`
  in `<mach-o/dyld.h>`
- Mach thread enumeration — `task_threads`, `mach_port_deallocate`, `vm_deallocate`
  (`<mach/mach.h>`), and `pthread_from_mach_thread_np` / `pthread_getname_np` (`<pthread.h>`)
- Code-signature verification — `SecCode` / `SecStaticCode` in `Security.framework`
  (`SecCodeCopySelf`, `SecStaticCodeCheckValidity`, `SecCodeCopySigningInformation`)
- Mach-O section data — `getsegmentdata` in `<mach-o/getsect.h>`; hashing via `CryptoKit.SHA256`

These are the same documented building blocks any macOS developer would reach for; the ideas
(checking `P_TRACED`, scanning the dyld image list for instrumentation frameworks, reading Mach
thread names) are widely described in Apple documentation and public security literature.

## Projects studied as ideas only (no code copied)

The macOS/iOS protection landscape was surveyed to understand what gap this fills. These projects
were **noted for the techniques they demonstrate the existence of**, as motivation — their source
code was not used:

- **SwiftShield** (GPL-3.0, unmaintained since ~2022) — a Swift symbol obfuscator. GPL; its code
  was deliberately **not** opened, so that this MIT project carries no GPL-derived material.
- **Hikari** (archived) — an LLVM-based obfuscator fork.
- **IOSSecuritySuite / freeRASP** — iOS/Android runtime self-protection suites; the inspiration for
  a *macOS-native* equivalent, which did not exist.

The gap (survey 2026-11-08): nothing combines macOS-native runtime tamper detection with packaged
build-hardening presets as an agent-droppable tool. That is what this project is.

## Licence

This project is MIT (see `LICENSE`) for maximum adoption as a drop-in dependency. Because no
GPL/unlicensed source was incorporated, MIT licensing is clean.

## Phase 2 note (Obscura wrap)

A later phase may *wrap* (not rebuild) an existing maintained LLVM obfuscation pass such as Obscura.
Before that work begins, Obscura's licence will be audited to confirm it permits wrapping and
shipping under this project's terms. No obfuscator source is included in this first version.
