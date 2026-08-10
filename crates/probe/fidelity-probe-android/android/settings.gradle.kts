// The Android library project that fidelity-probe-android owns.
//
// It exists for two reasons that a plain `cargo test` cannot serve: the Java
// interfaces need a real JVM, and `hasSigningCertificate` needs a real package.
// An instrumented test supplies both, because it runs inside an application
// process on a device.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "fidelity-probe-android"
