package uz.millygram.client

import android.content.Context
import android.os.Build
import android.os.Debug

/**
 * A read of how trustworthy the environment this process runs in looks.
 *
 * The native half answers the questions that are cheap to read and delete in
 * Kotlin — root, emulator, debugger, injected hooks — and this half adds the
 * questions the JVM can answer well: is the build itself debuggable, was the
 * app installed from somewhere other than a store, is a debugger attached at
 * the Java layer.
 *
 * What this is NOT is a gate. Nothing here decides whether the app runs. A hard
 * block built on defeatable checks punishes the false positives (a cheap phone
 * with an odd ROM) far more reliably than it stops the real attacker, who has
 * already hidden from every one of them. The account's protection is the
 * StrongBox-wrapped key it cannot extract, not this.
 *
 * Nor is it sent anywhere unless somebody asks for it to be. It used to travel
 * to the gateway on every token refresh, which made it a durable per-device
 * fingerprint filed next to the account id — and one that only ever described
 * the honest, since anybody with something to hide reports "clean". It is
 * computed here for the app to show a user about their own handset, and goes on
 * the wire only when [MillygramOptions.reportEnvironment] is turned on.
 */
object TamperSignals {

    // Kept in step with millyguard.c.
    private const val FLAG_ROOT = 1 shl 0
    private const val FLAG_DEBUGGER = 1 shl 1
    private const val FLAG_EMULATOR = 1 shl 2
    private const val FLAG_HOOK = 1 shl 3
    private const val FLAG_DEBUGGABLE_BUILD = 1 shl 4
    private const val FLAG_UNKNOWN_INSTALLER = 1 shl 5

    /**
     * Set when the debugger question could not be answered rather than answered
     * in the negative. It exists because the two are not the same thing and
     * were being reported as though they were: the native library failing to
     * load, or /proc/self/status failing to read, used to come out as a clean
     * device. A gateway that cannot tell "no debugger" from "no idea" is being
     * told something the client does not know, and a signal like that is worth
     * less than nothing — it is a false reassurance with a device fingerprint
     * attached.
     */
    private const val FLAG_DEBUGGER_UNKNOWN = 1 shl 6

    // Mirrors the ARM_* values in millyguard.c. Declared before nativeLoaded
    // because an object's properties initialise in source order and the library
    // load below writes to this one.
    private const val ARM_UNKNOWN = 0
    private const val ARM_REFUSED = 2

    /**
     * What the startup self-attach actually managed to do, kept because it is
     * the only thing that makes a later TracerPid reading interpretable. The
     * native side does the interpreting; this is recorded so the state is
     * visible from Kotlin rather than living entirely inside a .so.
     */
    private var armStatus: Int = ARM_UNKNOWN

    private val nativeLoaded: Boolean = runCatching {
        System.loadLibrary("millyguard")
        armStatus = armAntiDebug()
        true
    }.getOrDefault(false)

    private external fun collect(): Int

    /**
     * Occupies the ptrace slot so a debugger cannot, and reports which of the
     * possible outcomes happened. See millyguard.c for why the return value is
     * the whole point of the call: the old signature returned nothing, so a
     * successful self-attach — which leaves this process with a tracer of its
     * own making — was indistinguishable from a refusal caused by somebody else
     * already tracing us, and the first of those was being reported as a
     * debugger on every launch of every clean handset.
     */
    private external fun armAntiDebug(): Int

    /**
     * The current signal bitfield.
     *
     * Recomputed on each call rather than cached: a debugger or hook can attach
     * after launch, and a stale "clean" read taken at startup would be exactly
     * the read an attacker would want it to keep.
     */
    fun snapshot(context: Context): Int {
        // With no native library there is no view of ptrace at all, and the
        // honest report is that the question is open rather than that the
        // answer is no.
        var flags = if (nativeLoaded) {
            runCatching { collect() }.getOrDefault(FLAG_DEBUGGER_UNKNOWN)
        } else {
            FLAG_DEBUGGER_UNKNOWN
        }

        // The Java-layer debugger check, separate from the native TracerPid
        // one: they catch attachment at different levels and a tool may sit at
        // only one. JDWP is also visible without ptrace, so when this fires the
        // question is answered and the uncertainty above is no longer true —
        // one certain yes settles it regardless of what the native half could
        // or could not see.
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            flags = (flags or FLAG_DEBUGGER) and FLAG_DEBUGGER_UNKNOWN.inv()
        }

        // A refusal at arming time is the strongest debugger reading this
        // process ever gets — it means somebody else already held the tracer
        // slot when we reached for it — and it is worth restating here so the
        // finding survives a later collect() that failed to run.
        if (armStatus == ARM_REFUSED) {
            flags = (flags or FLAG_DEBUGGER) and FLAG_DEBUGGER_UNKNOWN.inv()
        }

        // A debuggable build in a user's hands is either our own mistake or a
        // repackage. Either way the gateway should know.
        val appInfo = context.applicationInfo
        if (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            flags = flags or FLAG_DEBUGGABLE_BUILD
        }

        if (installedFromUnknownSource(context)) flags = flags or FLAG_UNKNOWN_INSTALLER

        return flags
    }

    /**
     * Whether the installer is something other than a recognised store.
     *
     * A sideloaded build is not itself an attack — this is a debug build being
     * sideloaded right now — but on a release channel it is the fingerprint of
     * a repackaged APK handed out through a link, which in this market is a
     * common delivery route for a trojaned clone. Reported, weighed by the
     * gateway alongside the rest, never acted on alone.
     */
    private fun installedFromUnknownSource(context: Context): Boolean = runCatching {
        val pm = context.packageManager
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(context.packageName)
        }
        installer !in KNOWN_STORES
    }.getOrDefault(false)

    private val KNOWN_STORES = setOf(
        "com.android.vending",      // Google Play
        "com.huawei.appmarket",     // Huawei AppGallery — real share of this market
        "com.sec.android.app.samsungapps",
    )

    /**
     * A compact string for the wire and the logs, e.g. "root,emulator".
     *
     * "debugger-unknown" is deliberately its own token rather than being folded
     * into "debugger" or dropped. An operator who blocks on "debugger" should
     * not find themselves blocking every handset whose /proc read failed, and a
     * reader of the logs should be able to see the difference between a device
     * that answered no and a device that could not answer. It is a distinct
     * string, so a gateway configured against the old vocabulary treats it as
     * the unrecognised token it is and does nothing with it.
     */
    fun describe(flags: Int): String {
        if (flags == 0) return "clean"
        val parts = buildList {
            if (flags and FLAG_ROOT != 0) add("root")
            if (flags and FLAG_DEBUGGER != 0) add("debugger")
            if (flags and FLAG_DEBUGGER_UNKNOWN != 0) add("debugger-unknown")
            if (flags and FLAG_EMULATOR != 0) add("emulator")
            if (flags and FLAG_HOOK != 0) add("hook")
            if (flags and FLAG_DEBUGGABLE_BUILD != 0) add("debuggable")
            if (flags and FLAG_UNKNOWN_INSTALLER != 0) add("sideloaded")
        }
        return parts.joinToString(",")
    }
}
