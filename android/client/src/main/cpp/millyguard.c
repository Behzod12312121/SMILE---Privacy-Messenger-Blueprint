// Runtime self-protection, in native code on purpose.
//
// Everything here answers one question — does this process look like it is
// being watched, hooked, or run somewhere it should not be — and returns the
// answer as a bitfield the Kotlin side reports to the gateway. It is written in
// C because the equivalent Kotlin is a decompiler pass away from being read and
// patched out, and because a debugger self-attach has no JVM expression at all.
//
// Read the honest limits before trusting any of this: a determined attacker
// with root defeats every check below. Magisk's DenyList hides the su binary
// and the mounts; Frida can be renamed and its ports moved; the maps can be
// scrubbed. These raise the cost of the cheap, scalable attack — malware, mass
// tooling, an APK run through stock Frida — and they are signals, not a wall.
// The wall is the StrongBox-wrapped, non-extractable vault key. This is the
// moat around it.

#include <jni.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/system_properties.h>

// Must stay in step with TamperSignals.kt. A mismatch would mislabel a device.
enum {
    FLAG_ROOT             = 1 << 0,  // su binary, Magisk, writable system
    FLAG_DEBUGGER         = 1 << 1,  // something is tracing this process
    FLAG_EMULATOR         = 1 << 2,  // qemu/goldfish/ranchu fingerprints
    FLAG_HOOK             = 1 << 3,  // Frida / Substrate / injected .so in our maps
    // Bits 4 and 5 belong to the Kotlin half (debuggable build, unknown
    // installer) and are never set here.
    FLAG_DEBUGGER_UNKNOWN = 1 << 6,  // the debugger question could not be answered
};

// What the self-attach at startup actually did. Read by collect() below,
// because the answer changes what TracerPid means afterwards.
enum {
    ARM_UNKNOWN     = 0,  // never ran — the library did not load, or the call threw
    ARM_SELF_TRACED = 1,  // PTRACE_TRACEME succeeded; we now have a tracer of our own making
    ARM_REFUSED     = 2,  // it failed with EPERM, which is very nearly always "already traced"
    ARM_FAILED      = 3,  // it failed for some other reason and told us nothing
};

static int g_arm_status = ARM_UNKNOWN;
// The pid we expect to see in TracerPid purely because of our own arming, so a
// tracer that is not that one can be told apart from the one we installed.
static long g_arm_tracer = -1;

static int file_exists(const char *path) {
    struct stat sb;
    return stat(path, &sb) == 0;
}

// --- root ---------------------------------------------------------------
// The su binary in any of the usual locations, plus Magisk's own daemon path.
// A rooted phone that has actively hidden itself will pass this; that is the
// expected ceiling.
static int detect_root(void) {
    static const char *paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk", "/data/adb/modules",
        "/system/bin/magisk", "/dev/.magisk", NULL,
    };
    for (int i = 0; paths[i]; i++) {
        if (file_exists(paths[i])) return 1;
    }
    // A writable /system is a rooted or engineering build; on a stock retail
    // device it is mounted read-only and this open fails.
    if (access("/system", W_OK) == 0) return 1;
    return 0;
}

// --- debugger -----------------------------------------------------------
// TracerPid in /proc/self/status names the process that is tracing this one,
// and is zero when nobody is. Reading it as a bare present/absent boolean was
// wrong once the self-attach below started succeeding: after PTRACE_TRACEME
// this process has a tracer of its own making, TracerPid is non-zero for that
// reason alone, and the flag stuck on for every launch on every handset. The
// pid itself is what makes the reading useful — it can be compared against the
// tracer we installed ourselves — so it is returned rather than flattened.
//
// Returns the tracer pid, 0 for none, or -1 when the file could not be read or
// did not contain the field. That last case is not "clean": it is "we do not
// know", and the caller must say so rather than reporting an answer it does not
// have.
static long tracer_pid_value(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    const char *p = strstr(buf, "TracerPid:");
    if (!p) return -1;
    p += strlen("TracerPid:");
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return -1;
    return strtol(p, NULL, 10);
}

// --- emulator -----------------------------------------------------------
// System properties an emulator sets and a retail phone does not. Cloud phones
// and some rooted devices can spoof these, so it is a soft signal.
static int detect_emulator(void) {
    static const char *keys[] = {
        "ro.kernel.qemu", "ro.boot.qemu", "qemu.hw.mainkeys", NULL,
    };
    char value[PROP_VALUE_MAX];
    for (int i = 0; keys[i]; i++) {
        if (__system_property_get(keys[i], value) > 0 && value[0] != '\0') return 1;
    }
    if (__system_property_get("ro.hardware", value) > 0) {
        if (strstr(value, "goldfish") || strstr(value, "ranchu") ||
            strstr(value, "vbox") || strstr(value, "ttVM")) return 1;
    }
    if (__system_property_get("ro.product.model", value) > 0) {
        if (strstr(value, "sdk") || strstr(value, "Emulator") ||
            strstr(value, "Android SDK")) return 1;
    }
    // The qemu pipe device exists only under emulation.
    if (file_exists("/dev/qemu_pipe") || file_exists("/dev/socket/qemud")) return 1;
    return 0;
}

// --- hooking framework --------------------------------------------------
// The names of injected libraries and instrumentation frameworks show up in
// the process's own memory map. Scanning our maps for them catches Frida's
// gadget, Substrate, and the Xposed/LSPosed bridges even when the tool tries
// to be quiet about its ports.
static int detect_hooks(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[512];
    static const char *needles[] = {
        "frida", "gum-js", "gadget", "substrate", "xposed", "lspatch",
        "libriru", "zygisk", NULL,
    };
    int found = 0;
    while (!found && fgets(line, sizeof(line), fp)) {
        for (int i = 0; needles[i]; i++) {
            if (strstr(line, needles[i])) { found = 1; break; }
        }
    }
    fclose(fp);
    return found;
}

// The self-attach. A process may be traced by only one tracer at a time, so by
// arranging a tracer first this makes a later debugger or Frida-attach fail at
// the PTRACE_ATTACH step. Called once, early, from Kotlin.
//
// It used to return nothing, and that was the bug. PTRACE_TRACEME has exactly
// two interesting outcomes and the old code threw both away:
//
//   It succeeded. Note what that means — TRACEME does not make a process trace
//   itself, it makes its *parent* the tracer, and the parent of an app process
//   is zygote, which is not expecting to trace anybody. TracerPid is now
//   non-zero forever, for a reason that has nothing to do with an attacker, and
//   a caller reading it as a boolean reports "debugger" on every launch of
//   every clean handset. A signal that fires for everyone identifies no one.
//
//   It failed with EPERM. That is the interesting case, because on Android it
//   very nearly always means somebody else already holds the tracer slot — a
//   debugger, or Frida in attach mode, that got there before we did. The old
//   code discarded precisely the reading worth having.
//
// So the status is returned, recorded, and used to interpret TracerPid instead
// of guessing at it. What is still not knowable from inside this process is
// whether an EPERM came from a tracer or from a seccomp or SELinux policy that
// forbids ptrace outright; that case reports ARM_FAILED and the caller is
// expected to treat the debugger question as unanswered rather than clean. None
// of this has been confirmed against a physical handset in the change that
// introduced it, which is the other reason the "unknown" state exists: a signal
// the gateway cannot trust is worse than no signal, and reporting nothing is an
// honest answer where reporting "clean" would not be.
JNIEXPORT jint JNICALL
Java_uz_millygram_client_TamperSignals_armAntiDebug(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    errno = 0;
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
        g_arm_status = ARM_SELF_TRACED;
        g_arm_tracer = (long) getppid();
    } else if (errno == EPERM) {
        g_arm_status = ARM_REFUSED;
        g_arm_tracer = -1;
    } else {
        g_arm_status = ARM_FAILED;
        g_arm_tracer = -1;
    }
    return (jint) g_arm_status;
}

// Reads TracerPid in the light of what the arming did.
//
// Four answers, and the third is the one the old code could not express:
// somebody else is tracing us; nobody is; we cannot tell; or the tracer is the
// one we installed ourselves at startup and therefore says nothing about
// anyone. A tracer pid that is neither zero nor our own is the real signal, and
// it is the only case that sets FLAG_DEBUGGER from this file.
static int debugger_flags(void) {
    if (g_arm_status == ARM_REFUSED) return FLAG_DEBUGGER;

    long tracer = tracer_pid_value();
    if (tracer < 0) return FLAG_DEBUGGER_UNKNOWN;
    // Zero is a real reading whichever way the arming went: nothing holds the
    // tracer slot at this instant. It is worth remembering that a tracer with
    // root can hide itself from this file, which is the standing ceiling on
    // every check in here and not a reason to report uncertainty on the one
    // reading that is actually definitive.
    if (tracer == 0) return 0;
    if (g_arm_status == ARM_SELF_TRACED && tracer == g_arm_tracer) return 0;
    return FLAG_DEBUGGER;
}

JNIEXPORT jint JNICALL
Java_uz_millygram_client_TamperSignals_collect(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    int flags = 0;
    if (detect_root())      flags |= FLAG_ROOT;
    flags |= debugger_flags();
    if (detect_emulator())  flags |= FLAG_EMULATOR;
    if (detect_hooks())     flags |= FLAG_HOOK;
    return flags;
}
