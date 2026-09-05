# libsignal is a JNI library: its Java classes are looked up by name from Rust,
# and its store interfaces are implemented by us and called back into. R8 cannot
# see either edge, so without these rules a minified release build compiles
# cleanly and then fails at runtime with NoSuchMethodError — the worst possible
# failure mode, because it only appears in the build users actually install.
-keep class org.signal.libsignal.** { *; }
-keepclassmembers class org.signal.libsignal.** { *; }
-dontwarn org.signal.libsignal.**

# Our own store implementations are reached only through libsignal's interfaces.
-keep class uz.millygram.client.Millygram*Store { *; }
-keep class uz.millygram.client.CombinedProtocolStore { *; }

# BouncyCastle provides scrypt for the vault; parts of it are reflective.
-keep class org.bouncycastle.crypto.generators.SCrypt { *; }
-dontwarn org.bouncycastle.**

# OkHttp ships its own consumer rules, but these silence platform-optional
# classes it references and R8 cannot resolve on Android.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**

# Keep the line numbers needed to make a crash report legible, without keeping
# the original source file name.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
