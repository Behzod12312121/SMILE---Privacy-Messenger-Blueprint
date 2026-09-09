plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * How the staging build gets signed, and why it is allowed to refuse.
 *
 * Staging is release's minification pointed at a development gateway, so it is
 * the only build that ever exercises the R8 keep rules against a running app.
 * It used to inherit `signingConfigs.getByName("debug")` with a comment saying
 * it must never be published, which is a rule written down in the one place
 * nothing enforces it. The debug key lives on every developer machine and in
 * every CI image; an APK signed with it is an APK anybody who has ever checked
 * out this repository can produce an update for. One wrong assemble target and
 * that artifact exists, indistinguishable from a real one to whoever is handed
 * the file — which, on a market where apps are passed around as APKs over
 * Telegram because the Play Store is not where people get them, is how a
 * backdoored MillyGram reaches somebody's phone wearing our signature.
 *
 * So the unsafe outcome has to be chosen rather than inherited. Given a real
 * staging keystore, staging is signed with it. Given nothing, the build stops
 * and says what to pass. The debug key is still reachable, because there are
 * afternoons where it is genuinely what you want, but only by naming it out
 * loud with -PmgStagingAllowDebugSigning=true, which lands in the shell history
 * and the CI log where somebody can see it was a decision.
 *
 * Read with findProperty for the same reason mgServer and mgRelay are: this
 * comes from ~/.gradle/gradle.properties or the command line, never from a
 * secret committed next to the source.
 */
/**
 * Where a development build talks to, with no flag and no typing.
 *
 * These used to be `http://localhost`, which on a handset means the handset:
 * every tester had to be told the gateway address and type it into onboarding,
 * and a typo looked exactly like a server that was down. So the address is
 * still compiled in and a tester still types nothing.
 *
 * It is read from a property rather than written here, because this file is
 * published and the address is not. It is not secret in the cryptographic
 * sense — it is a public endpoint, and anyone handed the APK can extract it in
 * a minute — but it names the maintainer's personal machine, and a repository
 * that ships it invites strangers to point traffic at somebody's laptop and
 * tells them exactly where to aim. Publishing an address is a decision the
 * person running the server should make deliberately, not one this file makes
 * for them by existing.
 *
 * Set them in ~/.gradle/gradle.properties, which is outside the repository and
 * cannot be committed by accident:
 *
 *     mgDevGateway=https://your-gateway.example
 *     mgDevRelay=https://your-relay.example:8443
 *
 * The relay port is not a typo: the reverse proxy puts the gateway on 443 and
 * the relay on 8443. Both are served by the same compose file, so they are up
 * or down together.
 *
 * Unset, these fall back to a placeholder that is deliberately not reachable —
 * a debug build then behaves exactly as it did before anyone configured it, and
 * a release build is refused outright by the check further down. A plausible
 * dead hostname that ships is worse than no default at all, because it survives
 * review looking like a decision somebody made.
 */
val PLACEHOLDER_GATEWAY = "https://your-gateway.example"
val PLACEHOLDER_RELAY = "https://your-relay.example:8443"
val DEV_GATEWAY = (findProperty("mgDevGateway") as String?)?.trim().takeUnless { it.isNullOrEmpty() } ?: PLACEHOLDER_GATEWAY
val DEV_RELAY = (findProperty("mgDevRelay") as String?)?.trim().takeUnless { it.isNullOrEmpty() } ?: PLACEHOLDER_RELAY

val stagingKeystore = findProperty("mgStagingStoreFile") as String?

/**
 * The keystore a shipped build is signed with.
 *
 * Read from a property rather than committed, because this key is the single
 * thing that cannot be replaced later: it is the app's identity to every phone
 * that has installed it. Lose it and no existing install can ever be updated
 * again — Android refuses an update signed by a different key, and the only
 * remedy is a new package name and every user reinstalling from scratch. Leak
 * it and somebody else can ship an update over yours, which for a messenger
 * means shipping a build that reads the messages.
 */
val releaseKeystore = findProperty("mgReleaseStoreFile") as String?
val stagingAllowsDebugKey = (findProperty("mgStagingAllowDebugSigning") as String?) == "true"

android {
    namespace = "uz.millygram.app"
    compileSdk = 35

    // Without an NDK the strip task silently does nothing, and libsignal ships
    // with full debug symbols: 109 MB of .so that strips to 8 MB. On a market
    // where people pay for every megabyte that difference decides whether the
    // app gets installed at all.
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "uz.millygram"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        // The build identifier shown in settings. It names the exact commit a
        // handset is running, so a report about behaviour can be tied to
        // source rather than to a version string that never changes.
        buildConfigField("String", "GIT_SHA", "\"${gitSha()}\"")
    }

    /**
     * Where a fresh install looks for the gateway and the relay.
     *
     * A debug build talks to a gateway on the developer's machine, reached over
     * `adb reverse tcp:8443 tcp:8443`, which works the same on an emulator and
     * on a handset — unlike 10.0.2.2, which only means anything on an emulator
     * and left every physical device unable to connect out of the box.
     *
     * A release build has no business defaulting to a development address, and
     * cleartext is refused there anyway, so it points at the production names.
     * Override either at build time with -PmgServer= / -PmgRelay=.
     */
    fun endpoints(server: String, relay: String) = mapOf(
        "DEFAULT_SERVER" to (findProperty("mgServer") as String? ?: server),
        "DEFAULT_RELAY" to (findProperty("mgRelay") as String? ?: relay),
    )

    /**
     * Release endpoints, which have no default on purpose.
     *
     * This used to bake in `https://gateway.millygram.uz` and
     * `https://relay.millygram.uz`. Neither name is registered — they resolve to
     * NXDOMAIN — so a release APK built today would install cleanly and then be
     * unable to reach anything, with no signal at build time that anything was
     * wrong. A plausible-looking dead hostname is worse than none: it survives
     * review because it reads like a decision somebody made.
     *
     * The deployment is a Tailscale Funnel on a `*.ts.net` name, and that name
     * is a personal tailnet identifier. Committing it would put one developer's
     * account into every build and make the repository the place the production
     * endpoint is edited. So it is passed in at build time instead, and its
     * absence stops the build rather than shipping an empty string.
     */
    fun releaseEndpoints() = mapOf(
        "DEFAULT_SERVER" to (findProperty("mgServer") as String? ?: DEV_GATEWAY),
        "DEFAULT_RELAY" to (findProperty("mgRelay") as String? ?: DEV_RELAY),
    )

    compileOptions {
        // libsignal 0.101 uses java.time, which needs desugaring below API 34.
        // Without it the AAR metadata check refuses the dependency outright.
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    signingConfigs {
        // Created only when there is something to create it from. Declaring it
        // unconditionally with empty fields would give the staging build type a
        // signing config that looks configured and fails deep inside the
        // packaging task, which is exactly the kind of failure people learn to
        // work around by reaching for the debug key.
        releaseKeystore?.let { path ->
            create("production") {
                storeFile = project.file(path)
                storePassword = project.findProperty("mgReleaseStorePassword") as String?
                keyAlias = project.findProperty("mgReleaseKeyAlias") as String?
                keyPassword = project.findProperty("mgReleaseKeyPassword") as String?
            }
        }

        stagingKeystore?.let { path ->
            create("staging") {
                storeFile = project.file(path)
                storePassword = project.findProperty("mgStagingStorePassword") as String?
                keyAlias = project.findProperty("mgStagingKeyAlias") as String?
                keyPassword = project.findProperty("mgStagingKeyPassword") as String?
            }
        }
    }

    buildTypes {
        debug {
            endpoints(DEV_GATEWAY, DEV_RELAY)
                .forEach { (name, value) -> buildConfigField("String", name, "\"$value\"") }
        }
        release {
            // Unset when no keystore was given. The task-graph check below
            // refuses to produce the artifact in that case rather than quietly
            // emitting an unsigned APK, which is a failure people discover at
            // `adb install` and work around with the debug key.
            signingConfig = releaseKeystore?.let { signingConfigs.getByName("production") }
            releaseEndpoints()
                .forEach { (name, value) -> buildConfigField("String", name, "\"$value\"") }
            isMinifyEnabled = true
            // Strip unused resources too, so the shipped APK carries nothing it
            // does not use — smaller, and less to fingerprint.
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }

        /**
         * Release, made testable.
         *
         * The shipping build is minified, and the keep rules that stop R8
         * removing libsignal's reflectively-reached classes had never been
         * exercised against a running app — release refuses cleartext, so every
         * end-to-end run had been against the unminified debug build. That left
         * the one failure mode the rules exist to prevent completely untested,
         * and it is the mode that only appears in the build users install.
         *
         * This is release's minification and rules, pointed at a development
         * gateway so it can actually be driven. It must never be published, and
         * how it is signed is decided above rather than inherited — see the
         * note on stagingKeystore.
         */
        create("staging") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            signingConfig = when {
                stagingKeystore != null -> signingConfigs.getByName("staging")
                stagingAllowsDebugKey -> {
                    project.logger.warn(
                        "MillyGram: staging is being signed with the DEBUG key, because " +
                            "-PmgStagingAllowDebugSigning=true was passed. That key is on every " +
                            "developer machine and in every CI image. Do not distribute this APK " +
                            "to anybody, and do not upload it anywhere.",
                    )
                    signingConfigs.getByName("debug")
                }
                // Neither a keystore nor an explicit blessing. Left unset here
                // and refused outright below, at the point where somebody
                // actually asks for a staging artifact — assigning nothing on
                // its own would only produce an unsigned APK, quietly, which is
                // a warning nobody reads.
                else -> null
            }
            endpoints(DEV_GATEWAY, DEV_RELAY)
                .forEach { (name, value) -> buildConfigField("String", name, "\"$value\"") }
        }
    }

    // libsignal ships one ~110 MB native library per ABI, plus a *testing*
    // variant of the same size. Left alone the debug APK is 979 MB and the
    // testing library goes to production, which is both unshippable and wrong.
    splits {
        abi {
            isEnable = true
            reset()
            // arm64 covers every phone worth targeting; x86_64 is for the
            // emulator. armeabi-v7a is deliberately dropped — the 32-bit
            // devices it serves cannot run this comfortably anyway.
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }

    packaging {
        resources.excludes += setOf(
            "/META-INF/{AL2.0,LGPL2.1}",
            // libsignal-android depends on the plain libsignal-client jar, and
            // that jar carries desktop natives for macOS, Windows and Linux as
            // ordinary resources. Around 170 MB of code that can never execute
            // on a phone was being packaged into the APK.
            "**/*.dylib",
            "**/*.dll",
            "libsignal_jni*.so",
            "signal_jni*.so",
        )
        // Test-only native code has no business in a shipped artifact either.
        jniLibs.excludes += setOf("**/libsignal_jni_testing.so")
    }
}

dependencies {
    implementation(project(":client"))

    // The history migration is pure string work and worth testing off-device;
    // org.json is stubbed on the JVM, so the real implementation is needed.
    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20240303")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-text-google-fonts")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    // The screen lock. Needs a FragmentActivity to host its prompt, which is
    // why MainActivity extends AppCompatActivity rather than ComponentActivity.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")
}

/**
 * Stops a staging build that has made no signing decision.
 *
 * Checked against the task graph rather than at configuration time, because
 * configuration runs for every build: throwing while the buildTypes block is
 * being evaluated would break `assembleDebug` for somebody who has never asked
 * for staging in their life. This fires only when a staging task is genuinely
 * about to run, and it fires before any of it does, so the failure arrives as a
 * sentence about keystores rather than as an APK nobody can install.
 */
gradle.taskGraph.whenReady(Action {
    if (stagingKeystore != null || stagingAllowsDebugKey) return@Action
    val asked = allTasks.any {
        it.path.startsWith("${project.path}:") && it.name.contains("Staging")
    }
    if (!asked) return@Action
    throw GradleException(
        """
        MillyGram: refusing to build staging without deciding how it is signed.

        Staging is the release build with release's minification, and it used to
        inherit the debug signing key silently. That key is not a secret, so an
        APK carrying it is one anybody can forge an update for.

        Sign it properly:
          -PmgStagingStoreFile=/path/to/staging.jks \
          -PmgStagingStorePassword=... -PmgStagingKeyAlias=... -PmgStagingKeyPassword=...

        Or say plainly that you want the debug key for a local run, knowing the
        artifact must not leave your machine:
          -PmgStagingAllowDebugSigning=true
        """.trimIndent(),
    )
})

/**
 * Refuses to build a release artifact that has nowhere to talk to.
 *
 * Hooked to the task graph for the same reason the staging signing check is:
 * throwing while buildTypes is evaluated would break `assembleDebug` for
 * somebody who never asked for a release. This fires only when a release
 * artifact is genuinely about to be produced.
 *
 * Both checks matter. Missing means the APK would carry an empty endpoint and
 * fail at first launch, in the field, with no way for the person holding the
 * phone to tell why. Cleartext means the transport is readable by anyone on the
 * path, which for this project is the whole of what it claims to prevent — the
 * one place a typo in a build flag turns into a wire-visible deployment.
 */
gradle.taskGraph.whenReady(Action {
    val producesArtifact = listOf("assemble", "bundle", "package", "install")
    val asked = allTasks.any { task ->
        task.path.startsWith("${project.path}:") &&
            task.name.contains("Release") &&
            producesArtifact.any { task.name.startsWith(it) }
    }
    if (!asked) return@Action

    // What the APK will actually carry: the override if one was given, the
    // built-in address otherwise. Checking the flag rather than the value used
    // to be right, back when there was no default worth shipping; now it would
    // reject a correct build and accept nothing extra.
    val server = ((findProperty("mgServer") as String?) ?: DEV_GATEWAY).trim()
    val relay = ((findProperty("mgRelay") as String?) ?: DEV_RELAY).trim()
    val problems = buildList {
        if (server.isEmpty()) add("no gateway address")
        else if (!server.startsWith("https://")) add("gateway is not https: $server")
        if (relay.isEmpty()) add("no relay address")
        else if (!relay.startsWith("https://")) add("relay is not https: $relay")
        if (server == PLACEHOLDER_GATEWAY || relay == PLACEHOLDER_RELAY) {
            add("the endpoint is still the placeholder — set mgDevGateway/mgDevRelay or pass -PmgServer/-PmgRelay")
        }
        if (releaseKeystore == null) {
            add("-PmgReleaseStoreFile is not set, so the APK would be unsigned and could not install")
        }
    }
    if (problems.isEmpty()) return@Action

    throw GradleException(
        """
        MillyGram: refusing to build a release without a deployment address.

        ${problems.joinToString("\n        ")}

        A release build has no default endpoint on purpose. The names that used
        to be compiled in here were never registered, so the APK installed and
        then could not reach anything.

        Pass the deployment in, over https:
          -PmgServer=https://<host> -PmgRelay=https://<host>:<port>

        For the current Tailscale Funnel deployment those are the two Funnel
        endpoints from `tailscale serve status`. Keep them out of the repository
        — a tailnet name belongs to an account, not to the source.
        """.trimIndent(),
    )
})

/** The short commit hash, or "unknown" outside a git checkout. */
fun gitSha(): String = runCatching {
    val process = ProcessBuilder("git", "rev-parse", "--short", "HEAD")
        .directory(rootDir)
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.bufferedReader().readText().trim()
    if (process.waitFor() == 0 && output.isNotEmpty()) output else "unknown"
}.getOrDefault("unknown")
