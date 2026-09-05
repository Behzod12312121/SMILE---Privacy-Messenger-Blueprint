// One place the libsignal version is written. The drift guard in
// LibsignalVersionTest compares it against the version the Node gateway
// recorded, so the two implementations cannot quietly diverge again.
val libsignalVersion = "0.101.2"

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "uz.millygram.client"
    compileSdk = 35

    defaultConfig {
        // Android 8.0 covers the great majority of devices in Uzbekistan and
        // gives access to modern crypto APIs — Cipher AEAD, the AndroidX SQLite
        // wrapper, and a native SecureRandom that is not backed by /dev/random.
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    // Compile with the installed JDK (21 here), emit JDK 17 bytecode. Android's
    // D8 desugars either way; pinning the target keeps output stable across
    // build machines with different JDKs.
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

    buildFeatures { buildConfig = false }

    // Unit tests exercise the pure-JVM half of this module (transport shapes,
    // protocol framing). Anything that needs real Android or libsignal natives
    // belongs in androidTest, on a device.
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    api(project(":protocol"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    // Pinned to the exact version the Node gateway runs. Maven Central stops
    // at 0.86.5; Signal publish current releases to their own host, which the
    // root settings file adds. One version across both implementations means
    // no cross-version wire compatibility to reason about.
    api("org.signal:libsignal-android:$libsignalVersion")

    // OkHttp + WebSocket. sqlite-framework is Android's own SQLite,
    // wrapped so that tests can substitute an alternative implementation.
    api("com.squareup.okhttp3:okhttp:4.12.0")
    api("androidx.sqlite:sqlite-framework:2.4.0")

    testImplementation(kotlin("test"))
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.json:json:20240303")

    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

tasks.withType<Test>().configureEach {
    systemProperty("millygram.libsignalVersion", libsignalVersion)
}
