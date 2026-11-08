#include "shield_shim.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

bool shield_is_being_traced(void) {
    // sysctl(KERN_PROC, KERN_PROC_PID, getpid()) fills a kinfo_proc; p_flag & P_TRACED
    // is set when a debugger is attached. See man 3 sysctl, <sys/sysctl.h>, <sys/proc.h>.
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));

    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return false; // fail-safe: never report on a sysctl error
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int shield_deny_attach(void) {
    return ptrace(PT_DENY_ATTACH, 0, 0, 0);
}

int32_t shield_parent_pid(void) {
    return (int32_t)getppid();
}
