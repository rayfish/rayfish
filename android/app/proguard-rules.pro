# Keep JNA and the UniFFI bindings intact for reflection-based native access.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.** { *; }
