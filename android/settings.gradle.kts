pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }

    plugins {
        id("org.jetbrains.kotlin.jvm") version "2.1.0"
        id("org.jetbrains.kotlin.android") version "2.1.0"
        id("com.android.library") version "8.7.3"
        id("com.android.application") version "8.7.3"
        id("org.jetbrains.kotlin.plugin.compose") version "2.1.0"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()

        // Signal's own artifact host. Maven Central lags well behind it —
        // 0.86.5 there against 0.101.2 here — and the gateway runs 0.101.2, so
        // this is what lets both implementations sit on one version.
        //
        // Scoped to org.signal deliberately: an unfiltered extra repository is
        // a dependency-confusion foothold, because it gets asked about every
        // coordinate in the build and could answer for one it has no business
        // serving.
        maven("https://build-artifacts.signal.org/libraries/maven") {
            content { includeGroup("org.signal") }
        }
    }
}

rootProject.name = "millygram"

include(":protocol")
include(":client")
include(":app")
