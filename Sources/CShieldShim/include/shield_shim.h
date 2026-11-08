#ifndef SHIELD_SHIM_H
#define SHIELD_SHIM_H

#include <stdbool.h>
#include <stdint.h>

// Syscalls the Swift Darwin overlay hides or makes awkward. Sources:
//   man 2 ptrace, man 3 sysctl, <sys/ptrace.h>, <sys/sysctl.h>, <sys/proc.h>.

// True if this process currently has the P_TRACED flag set (a debugger is attached),
// read via sysctl KERN_PROC_PID. Fail-safe: returns false if the sysctl call errors,
// so a transient failure never reports a phantom debugger.
bool shield_is_being_traced(void);

// ptrace(PT_DENY_ATTACH). Opt-in anti-debug. Returns 0 on success, -1 on error (errno set).
// WARNING: if a debugger is ALREADY attached this delivers SIGSEGV. It also forfeits your
// own crash telemetry (blocks sample/Instruments/crash reporter) and can trip notarization
// analysis. OFF by default in the Swift policy; callers opt in explicitly.
int shield_deny_attach(void);

// getppid(), for an optional parent-process heuristic.
int32_t shield_parent_pid(void);

#endif /* SHIELD_SHIM_H */
