plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(21)
    compilerOptions { allWarningsAsErrors.set(true) }
}

dependencies {
    // scrypt. BouncyCastle is well-audited and its scrypt landed in 1.60;
    // the JDK still ships no scrypt of its own.
    api("org.bouncycastle:bcprov-jdk18on:1.79")

    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20240303")
}

tasks.test { useJUnitPlatform() }
