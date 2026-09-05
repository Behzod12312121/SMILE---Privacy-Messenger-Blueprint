plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

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
    }

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

    buildFeatures { compose = true }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-text-google-fonts")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")
}
