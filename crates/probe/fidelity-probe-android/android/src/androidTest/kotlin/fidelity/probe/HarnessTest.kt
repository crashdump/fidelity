package fidelity.probe

import android.content.pm.PackageManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.ByteBuffer
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HarnessTest {
    @Test
    fun the_device_loads_the_probe_and_calls_into_it() {
        // The pipeline control. It proves that cargo built a library for this
        // device, that Gradle packaged it, and that the runtime resolved the
        // symbol. Every test below depends on all three.
        assertEquals(42, Harness.smoke())
    }

    @Test
    fun the_runtime_hands_the_host_a_virtual_machine() {
        // The precondition for every Java interface, and the value that the
        // comparison below checks against.
        assertEquals(1, Harness.hasVirtualMachine())
    }

    @Test
    fun the_worker_thread_joins_the_virtual_machine() {
        // The capability itself, with the host supplying the handle. The call
        // runs on a thread the machine has never seen, because the test thread
        // already belongs to it and would report success without attaching.
        assertEquals(Harness.PREPARED, Harness.prepareOnNewThread())
    }

    @Test
    fun the_probe_finds_the_machine_that_the_host_was_handed() {
        // What removes the handle from the public API. The comparison is the
        // point: a call that found some other machine would attach the worker
        // to the wrong one, and a test that only checked for "some machine"
        // would not notice.
        assertEquals(1, Harness.findsTheSameVirtualMachine())
    }

    @Test
    fun the_worker_joins_with_no_help_from_the_host() {
        // The consequence. A host that passes nothing still gets a worker that
        // can reach the Java interfaces. The negative control lives in the Rust
        // unit tests, because a shell binary genuinely runs no machine and this
        // process always does.
        assertEquals(Harness.PREPARED, Harness.prepareByDiscoveryOnly())
    }

    @Test
    fun the_probe_reads_the_certificate_that_android_reports() {
        // The decisive test for image identity on Android. The probe walks the
        // archive that this process runs from, because PackageManager needs a
        // Context that a library cannot reach. That route is only correct if
        // it gives the answer PackageManager would have given, so this asks
        // both and compares.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        val signers = info.signingInfo!!.apkContentsSigners
        assertEquals(1, signers.size)

        val digest = MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray())
        val expected = ByteBuffer.wrap(digest).int

        assertNotEquals("the probe must find a certificate", 0, Harness.signerPrefix())
        assertEquals(expected, Harness.signerPrefix())
    }

    @Test
    fun the_probe_reads_the_dispatch_table_of_the_library_of_the_host() {
        // The decisive test for dispatch on Android. An application forks from
        // zygote, so its main image is /system/bin/app_process64, which every
        // application on the device shares and which no call of the host
        // reaches. The four other platforms read the main image, and Android
        // must read the library that holds Fidelity instead.
        //
        // Only an application process separates the two. In the shell binary
        // that the Rust unit tests run, the library and the main image are one
        // image, so that test cannot fail this way.
        val directory = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationInfo.nativeLibraryDir
        Log.i("fidelity", "the application loads its libraries from $directory")
        assertEquals(1, Harness.dispatchImageIsThisLibrary())
    }

    @Test
    fun the_dispatch_table_of_an_application_process_holds_targets() {
        // The walk itself, in a process that runs the runtime of Android. A
        // library with an empty table would report clean forever and prove
        // nothing, so the count is what states that the detector has something
        // to compare.
        val count = Harness.dispatchTargetCount()
        Log.i("fidelity", "the library of the host holds $count dispatch targets")
        assertTrue("the probe must report a dispatch table, and it reported $count", count > 0)
    }

    @Test
    fun the_identity_read_stays_inside_its_recorded_ceiling() {
        // The worker re-reads the identity on every cycle, and on Android that
        // read walks the command line, the mapping table, and the archive. A
        // shell binary maps no archive, so the Rust unit tests and the cost
        // example both stop early and cannot measure this. Only an application
        // process pays the whole route.
        //
        // docs/plan/07-state-and-budgets.md holds the ceilings, and a release
        // that passes one fails the gate. The harness reports the fastest call
        // rather than the mean, because another test in this same process
        // starts a Fidelity runtime whose worker then scans for the rest of
        // the run. A mean would measure that worker too, and it would move
        // with the order that JUnit picks.
        val identity = Harness.identityCostMicros()
        val cycle = Harness.cycleCostMicros()
        Log.i("fidelity", "code_identity ${identity}us, one worker cycle ${cycle}us")
        assertTrue("the reads must do real work, and they reported ${identity}us", identity > 0)
        assertTrue("code_identity cost ${identity}us, above ${IDENTITY_CEILING}us", identity <= IDENTITY_CEILING)
        assertTrue("one cycle cost ${cycle}us, above ${CYCLE_CEILING}us", cycle <= CYCLE_CEILING)
    }

    @Test
    fun a_guarded_constant_returns_its_literal_in_the_archive_that_the_build_named() {
        // The clean control for `guarded!()`, and only an application process
        // can run it. The build binds to the signing certificate of this
        // archive, so the key that encrypted the constant is the key that this
        // process derives, and the read returns the literal.
        //
        // `tests/platform/controls/repackage-android.sh` is the hostile half. It
        // signs this same archive with another key, and the same read returns
        // something else with no error anywhere.
        val found = Harness.guardedPrefix()
        val expected = Harness.guardedLiteralPrefix()
        Log.i("fidelity", "guarded prefix " + Integer.toHexString(found))
        assertNotEquals("start() must succeed in an application process", 0, found)
        assertEquals(expected, found)
    }

    private companion object {
        // The recorded ceilings, in microseconds. Measured on Android 37 on
        // 2026-08-11: the identity read costs about 510 us, and one cycle
        // costs about 2.4 ms. Both numbers are the fastest call rather than
        // the mean, and even so the emulator produced single runs of 5.8 ms
        // and 10.8 ms for the cycle. The ceilings sit well above that, because
        // they catch a regression of one order and not a noisy neighbour.
        // docs/plan/07-state-and-budgets.md holds the numbers themselves.
        const val IDENTITY_CEILING = 4000
        const val CYCLE_CEILING = 20000
    }
}
