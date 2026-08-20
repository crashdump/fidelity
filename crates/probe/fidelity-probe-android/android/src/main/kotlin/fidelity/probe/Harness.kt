package fidelity.probe

/**
 * The Rust side of the instrumented tests.
 *
 * This object plays the host. The library it loads owns `JNI_OnLoad`, captures
 * the virtual machine, and hands the address to the probe, which is the shape
 * that `docs/plan/06-delivery.md` requires of a real host.
 */
object Harness {
    init {
        System.loadLibrary("fidelity_harness")
    }

    /** The codes that a prepare call returns. */
    const val PREPARED = 1
    const val FAILED = 2
    const val NOTHING = 3

    /** Reports that the library loaded and the symbol resolved. */
    external fun smoke(): Int

    /** Reports whether the runtime handed the library a virtual machine. */
    external fun hasVirtualMachine(): Int

    /** Prepares a thread the machine has never seen, the way the worker does. */
    external fun prepareOnNewThread(): Int

    /** Reports 1 when the probe finds the same machine the host was handed. */
    external fun findsTheSameVirtualMachine(): Int

    /** Prepares a thread with no host handle, so discovery is the only path. */
    external fun prepareByDiscoveryOnly(): Int

    /** The first four bytes of the signing-certificate digest the probe reads. */
    external fun signerPrefix(): Int

    /** Reports 1 when the probe reads the dispatch table of this library. */
    external fun dispatchImageIsThisLibrary(): Int

    /** How many dispatch targets the probe reports in this process. */
    external fun dispatchTargetCount(): Int

    /** The fastest cost of one identity read in this process, in microseconds. */
    external fun identityCostMicros(): Int

    /** The fastest cost of one worker cycle in this process, in microseconds. */
    external fun cycleCostMicros(): Int

    /** The first four bytes of one guarded constant, as this process reads it. */
    external fun guardedPrefix(): Int

    /** The first four bytes of the literal that the guarded constant carries. */
    external fun guardedLiteralPrefix(): Int
}
