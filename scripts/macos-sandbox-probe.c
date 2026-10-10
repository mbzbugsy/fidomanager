// Test-only helper (never bundled). For each pid prints: whether the kernel has it sandboxed
// (sandbox_check with no operation), its kernel code-signing status flags (csops CS_OPS_STATUS),
// and its executable path. Used by scripts/test-macos-sandbox-runtime.py (ADR-018).
#include <libproc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        pid_t pid = (pid_t)atoi(argv[i]);
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        uint32_t flags = 0;
        int sandboxed = sandbox_check(pid, NULL, 0);
        int cs = csops(pid, 0 /* CS_OPS_STATUS */, &flags, sizeof flags);
        proc_pidpath(pid, path, sizeof path);
        printf("{\"pid\": %d, \"sandboxed\": %d, \"cs_status_ok\": %d, \"cs_flags\": %u, \"path\": \"%s\"}\n",
               pid, sandboxed, cs == 0, flags, path);
    }
    return 0;
}
