# Applied to any app that consumes this library. Same reasoning as the app's
# own rules: libsignal's JNI boundary is invisible to R8 in both directions.
-keep class org.signal.libsignal.** { *; }
-keepclassmembers class org.signal.libsignal.** { *; }
-dontwarn org.signal.libsignal.**

-keep class uz.millygram.client.Millygram*Store { *; }
-keep class uz.millygram.client.CombinedProtocolStore { *; }

-keep class org.bouncycastle.crypto.generators.SCrypt { *; }
-dontwarn org.bouncycastle.**
