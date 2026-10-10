// Sandbox probe: reports whether this process is sandboxed, whether HOME is redirected, whether
// it can write outside its container, and whether IOKit HID devices can be enumerated/opened.
// Optionally spawns a child (argv[1] = path) and waits for it. Never sends any HID report.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

static void report(const char *who) {
    printf("[%s] pid=%d ppid=%d sandboxed=%d HOME=%s\n", who, getpid(), getppid(),
           sandbox_check(getpid(), NULL, 0), getenv("HOME") ? getenv("HOME") : "(unset)");
    int fd = open("/private/tmp/fm-sbx-probe-write-test", O_CREAT | O_WRONLY, 0600);
    printf("[%s] write /private/tmp: %s\n", who, fd >= 0 ? "ALLOWED" : strerror(errno));
    if (fd >= 0) { close(fd); unlink("/private/tmp/fm-sbx-probe-write-test"); }

    IOHIDManagerRef manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    IOHIDManagerSetDeviceMatching(manager, NULL);
    CFSetRef devices = IOHIDManagerCopyDevices(manager);
    CFIndex count = devices ? CFSetGetCount(devices) : -1;
    printf("[%s] IOHIDManagerCopyDevices: %ld devices\n", who, (long)count);
    if (count > 0) {
        const void **values = calloc((size_t)count, sizeof(void *));
        CFSetGetValues(devices, values);
        int opened = 0, denied = 0;
        for (CFIndex i = 0; i < count; i++) {
            IOHIDDeviceRef device = (IOHIDDeviceRef)values[i];
            CFNumberRef page = IOHIDDeviceGetProperty(device, CFSTR(kIOHIDPrimaryUsagePageKey));
            int usage_page = 0;
            if (page) CFNumberGetValue(page, kCFNumberIntType, &usage_page);
            // Only vendor/consumer pages; never keyboards/pointers (usage page 1).
            if (usage_page == 1) continue;
            IOReturn r = IOHIDDeviceOpen(device, kIOHIDOptionsTypeNone);
            if (r == kIOReturnSuccess) { opened++; IOHIDDeviceClose(device, kIOHIDOptionsTypeNone); }
            else denied++;
        }
        printf("[%s] IOHIDDeviceOpen non-keyboard devices: opened=%d failed=%d\n", who, opened, denied);
        free(values);
    }
    if (devices) CFRelease(devices);
    CFRelease(manager);
    fflush(stdout);
}

int main(int argc, char **argv) {
    report(argc > 1 ? "parent" : "child");
    if (argc > 1) {
        pid_t pid;
        char *child_argv[] = {argv[1], NULL};
        int rc = posix_spawn(&pid, argv[1], NULL, NULL, child_argv, environ);
        if (rc != 0) { printf("[parent] posix_spawn: %s\n", strerror(rc)); return 1; }
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) printf("[parent] child killed by signal %d\n", WTERMSIG(status));
        else printf("[parent] child exit %d\n", WEXITSTATUS(status));
    }
    return 0;
}
