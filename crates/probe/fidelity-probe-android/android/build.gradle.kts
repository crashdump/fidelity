import java.security.KeyStore
import java.security.MessageDigest

plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

val fidelityAndroidAbi = providers.environmentVariable("FIDELITY_ANDROID_ABI")
    .getOrElse("arm64-v8a")
val fidelityRustTarget = when (fidelityAndroidAbi) {
    "arm64-v8a" -> "aarch64-linux-android"
    "x86_64" -> "x86_64-linux-android"
    else -> error("Fidelity supports no Android test ABI named $fidelityAndroidAbi")
}
android {
    namespace = "fidelity.probe"
    compileSdk = 35

    defaultConfig {
        // The floor that docs/plan/04-detectors-and-platforms.md states.
        minSdk = 34
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += fidelityAndroidAbi }
    }

    // The Rust cdylib arrives here. `cargo-ndk` is not used on purpose: the
    // build script below calls cargo directly, so the project takes no build
    // dependency that the workspace does not already have.
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))
    sourceSets["main"].kotlin.srcDir("src/main/kotlin")
    sourceSets["androidTest"].kotlin.srcDir("src/androidTest/kotlin")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { jvmToolchain(17) }
}

dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
}

// The signing certificate of the archive that the tests run from, as the
// lowercase hexadecimal SHA-256 that the probe reports.
//
// `guarded!()` binds to this value at build time, and the probe reads it back
// at run time from the archive itself. The two must agree, so the build reads
// the same keystore that AGP signs the test archive with. A hard-coded digest
// would break on every other machine, because each one holds its own debug
// keystore.
fun debugSigningCertificateSha256(): String {
    val file = File("${System.getProperty("user.home")}/.android/debug.keystore")
    require(file.isFile) { "no debug keystore at ${file.path}. Build any debug variant once." }
    // AGP writes PKCS12 today and wrote JKS before, so try both.
    val password = "android".toCharArray()
    val store = listOf("PKCS12", "JKS").firstNotNullOfOrNull { type ->
        runCatching {
            val keystore = KeyStore.getInstance(type)
            file.inputStream().use { stream -> keystore.load(stream, password) }
            keystore
        }.getOrNull()
    }
    require(store != null) { "the debug keystore at ${file.path} did not open as PKCS12 or JKS" }
    val certificate = store.getCertificate("androiddebugkey")
    require(certificate != null) { "the debug keystore holds no androiddebugkey entry" }
    val digest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
    return digest.joinToString("") { byte -> "%02x".format(byte) }
}

// Builds the harness cdylib for the device, then puts it where the library
// packages it from.
val buildRust by tasks.registering(Exec::class) {
    workingDir = file("harness")
    val ndk = "${System.getProperty("user.home")}/Library/Android/sdk/ndk/29.0.14206865"
    val bin = "$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    val linker = providers.environmentVariable("FIDELITY_NDK_CC")
        .getOrElse("$bin/${fidelityRustTarget}34-clang")
    val targetName = fidelityRustTarget.uppercase().replace('-', '_')
    environment("CARGO_TARGET_${targetName}_LINKER", linker)
    environment("CC_${fidelityRustTarget.replace('-', '_')}", linker)
    // The seed is fixed, because this harness is a control and two runs of it
    // must produce the same guarded value. A host states a seed that it owns.
    environment("FIDELITY_BUILD_SEED", "fidelity-harness")
    // The value names the kind of material, because a value that Apple reports
    // and a value that Android reports both used to read as a bare string.
    environment("FIDELITY_CODE_IDENTITY", "android:" + debugSigningCertificateSha256())
    commandLine("cargo", "build", "--release", "--target", fidelityRustTarget)
    doLast {
        copy {
            from("harness/target/$fidelityRustTarget/release/libfidelity_harness.so")
            into(layout.buildDirectory.dir("rustJniLibs/$fidelityAndroidAbi"))
        }
    }
}

tasks.named("preBuild") { dependsOn(buildRust) }
