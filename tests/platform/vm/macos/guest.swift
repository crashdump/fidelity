// Installs and runs the macOS guest that the Virtualization control needs.
//
//     guest catalog
//     guest install <bundle> <ipsw>
//     guest run     <bundle> [--display] [--share <directory>]
//     guest mac     <bundle>
//
// Why this file exists rather than a Packer template. QEMU runs the Linux and
// the Windows guests, and it runs no macOS guest on Apple Silicon. Only
// Virtualization.framework boots macOS here, so the macOS guest takes the
// framework directly. That also keeps the tool chain at zero third-party
// parts, which matches the position that `docs/plan/06-delivery.md` states.
//
// The process must carry the `com.apple.security.virtualization` entitlement.
// An ad-hoc signature grants it on macOS, so `build.sh` needs no certificate.
// Without it the framework refuses every call, and the restore catalog reports
// only "failed to load", which names no cause. Measured on 2026-08-18.

import AppKit
import Foundation
import Virtualization

// ------------------------------------------------------------------ the parts

/// Reports a cause and stops, because every failure here ends the run.
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("guest: \(message)\n".utf8))
    exit(1)
}

func say(_ message: String) {
    print(message)
    fflush(stdout)
}

/// The files that one guest owns.
///
/// The bundle holds every part of the machine, so a copy of the directory is a
/// copy of the guest. `vm.sh` clones it on APFS, which costs no space until
/// the guest writes.
struct Bundle {
    let root: URL

    init(_ path: String) {
        root = URL(fileURLWithPath: path)
    }

    var disk: URL { root.appendingPathComponent("disk.img") }
    var auxiliary: URL { root.appendingPathComponent("aux.img") }
    var model: URL { root.appendingPathComponent("hardware-model") }
    var identifier: URL { root.appendingPathComponent("machine-identifier") }
    /// The address, as text, because `vm.sh` reads it to find the DHCP lease.
    var address: URL { root.appendingPathComponent("mac") }

    func read(_ url: URL) -> Data {
        guard let data = try? Data(contentsOf: url) else {
            fail("\(url.path) does not exist. Run: vm.sh macos build")
        }
        return data
    }

    func write(_ data: Data, to url: URL) {
        do {
            try data.write(to: url)
        } catch {
            fail("\(url.path) did not save: \(error)")
        }
    }
}

/// Holds the machine and the signal sources for the whole run.
///
/// The framework stops a guest whose machine object goes away, and a signal
/// source that goes away stops firing. Both live here.
final class Runner: NSObject, VZVirtualMachineDelegate {
    var machine: VZVirtualMachine?
    var stops: [DispatchSourceSignal] = []

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        say("the guest stopped")
        exit(0)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fail("the guest stopped with an error: \(error)")
    }
}

let runner = Runner()

/// Creates a sparse file of the size that the guest disk needs.
///
/// APFS stores the holes, so an 80 GB disk costs what the guest writes.
func createDisk(at url: URL, size: UInt64) {
    guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
        fail("\(url.path) did not open")
    }
    do {
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: size)
        try handle.close()
    } catch {
        fail("\(url.path) did not take its size: \(error)")
    }
}

/// Builds the machine that both commands boot.
///
/// The install and the run must describe one machine. A field that differs
/// between the two makes the guest report new hardware, and macOS then asks to
/// be activated again.
func configure(
    _ bundle: Bundle,
    cpus: Int,
    memory: UInt64,
    share: String?
) -> VZVirtualMachineConfiguration {
    let platform = VZMacPlatformConfiguration()
    guard let model = VZMacHardwareModel(dataRepresentation: bundle.read(bundle.model)) else {
        fail("the hardware model of the bundle does not parse")
    }
    guard model.isSupported else {
        fail("this machine does not support the hardware model of the bundle")
    }
    guard
        let identifier = VZMacMachineIdentifier(
            dataRepresentation: bundle.read(bundle.identifier))
    else {
        fail("the machine identifier of the bundle does not parse")
    }
    platform.hardwareModel = model
    platform.machineIdentifier = identifier
    platform.auxiliaryStorage = VZMacAuxiliaryStorage(url: bundle.auxiliary)

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = platform
    configuration.bootLoader = VZMacOSBootLoader()
    configuration.cpuCount = cpus
    configuration.memorySize = memory

    // A macOS guest needs a display even when nobody watches it. The setup
    // assistant runs on the first boot, and it draws to this device.
    let graphics = VZMacGraphicsDeviceConfiguration()
    graphics.displays = [
        VZMacGraphicsDisplayConfiguration(
            widthInPixels: 1920, heightInPixels: 1200, pixelsPerInch: 80)
    ]
    configuration.graphicsDevices = [graphics]
    configuration.keyboards = [VZUSBKeyboardConfiguration()]
    configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]

    do {
        let attachment = try VZDiskImageStorageDeviceAttachment(
            url: bundle.disk, readOnly: false)
        configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
    } catch {
        fail("the disk did not attach: \(error)")
    }

    // The framework puts the guest on the shared `vmnet` network, so the host
    // reaches it by address and needs no forwarded port. The address stays in
    // the bundle, because the lease file of the host maps it to the address
    // that SSH needs.
    let network = VZVirtioNetworkDeviceConfiguration()
    network.attachment = VZNATNetworkDeviceAttachment()
    if let stored = try? String(contentsOf: bundle.address, encoding: .utf8),
        let parsed = VZMACAddress(string: stored.trimmingCharacters(in: .whitespacesAndNewlines))
    {
        network.macAddress = parsed
    }
    configuration.networkDevices = [network]

    // macOS mounts this tag by itself, at "/Volumes/My Shared Files". That is
    // what makes the one manual step one command: the setup script is already
    // inside the guest when the setup assistant finishes.
    if let share {
        let directory = VZSharedDirectory(url: URL(fileURLWithPath: share), readOnly: true)
        let device = VZVirtioFileSystemDeviceConfiguration(
            tag: VZVirtioFileSystemDeviceConfiguration.macOSGuestAutomountTag)
        device.share = VZSingleDirectoryShare(directory: directory)
        configuration.directorySharingDevices = [device]
    }

    do {
        try configuration.validate()
    } catch {
        fail("the machine is not valid: \(error)")
    }
    return configuration
}

// -------------------------------------------------------------- the commands

func install(bundle: Bundle, ipsw: String, cpus: Int, memory: UInt64, disk: UInt64) {
    do {
        try FileManager.default.createDirectory(
            at: bundle.root, withIntermediateDirectories: true)
    } catch {
        fail("\(bundle.root.path) did not open: \(error)")
    }

    say("the restore image loads")
    VZMacOSRestoreImage.load(from: URL(fileURLWithPath: ipsw)) { result in
        // The framework answers on a queue of its own, and every call below
        // belongs to the queue that runs the machine. `VZMacOSInstaller` states
        // that itself: it asserts the queue in its initializer, and the process
        // stops with a trap that names no cause. Measured on 2026-08-18.
        DispatchQueue.main.async { finish(result) }
    }

    /// Builds the machine and installs it, on the queue that owns both.
    func finish(_ result: Result<VZMacOSRestoreImage, Error>) {
        guard case .success(let image) = result else {
            if case .failure(let error) = result {
                fail("the restore image did not load: \(error)")
            }
            fail("the restore image did not load")
        }
        guard let requirements = image.mostFeaturefulSupportedConfiguration else {
            fail("this machine runs no configuration of that restore image")
        }

        let version = image.operatingSystemVersion
        say(
            "the guest is macOS \(version.majorVersion).\(version.minorVersion)."
                + "\(version.patchVersion), build \(image.buildVersion)")

        // The requirements floor wins over the request, because a guest below
        // it does not boot.
        let cpus = max(cpus, requirements.minimumSupportedCPUCount)
        let memory = max(memory, requirements.minimumSupportedMemorySize)

        bundle.write(requirements.hardwareModel.dataRepresentation, to: bundle.model)
        bundle.write(VZMacMachineIdentifier().dataRepresentation, to: bundle.identifier)
        bundle.write(
            Data(VZMACAddress.randomLocallyAdministered().string.utf8), to: bundle.address)
        do {
            _ = try VZMacAuxiliaryStorage(
                creatingStorageAt: bundle.auxiliary,
                hardwareModel: requirements.hardwareModel,
                options: [.allowOverwrite])
        } catch {
            fail("the auxiliary storage did not build: \(error)")
        }
        createDisk(at: bundle.disk, size: disk)

        let configuration = configure(bundle, cpus: cpus, memory: memory, share: nil)
        let machine = VZVirtualMachine(configuration: configuration)
        runner.machine = machine
        machine.delegate = runner

        let installer = VZMacOSInstaller(
            virtualMachine: machine, restoringFromImageAt: URL(fileURLWithPath: ipsw))
        say("the install starts. It takes about 20 minutes.")

        // A poll reports the same number that KVO would, and it adds no
        // observer that this file then has to remove.
        let ticker = DispatchSource.makeTimerSource(queue: .main)
        ticker.schedule(deadline: .now() + 15, repeating: 15)
        ticker.setEventHandler {
            let percent = Int(installer.progress.fractionCompleted * 100)
            say("the install is \(percent) percent done")
        }
        ticker.resume()

        installer.install { result in
            ticker.cancel()
            switch result {
            case .success:
                say("the install finished")
                say("the guest is \(bundle.root.path)")
                exit(0)
            case .failure(let error):
                fail("the install did not finish: \(error)")
            }
        }
    }
}

func run(bundle: Bundle, cpus: Int, memory: UInt64, share: String?, display: Bool) {
    let configuration = configure(bundle, cpus: cpus, memory: memory, share: share)
    let machine = VZVirtualMachine(configuration: configuration)
    runner.machine = machine
    machine.delegate = runner

    // A stop that the guest never hears corrupts its disk, so the run asks the
    // guest to shut down and lets it finish.
    for number in [SIGTERM, SIGINT] {
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
        source.setEventHandler {
            say("the guest shuts down")
            try? machine.requestStop()
        }
        source.resume()
        runner.stops.append(source)
    }

    machine.start { result in
        if case .failure(let error) = result {
            fail("the guest did not start: \(error)")
        }
        say("the guest runs")
    }

    if display {
        let view = VZVirtualMachineView(frame: NSRect(x: 0, y: 0, width: 1280, height: 800))
        view.virtualMachine = machine
        view.capturesSystemKeys = true
        let window = NSWindow(
            contentRect: view.frame,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "fidelity macOS guest"
        window.contentView = view
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

// ------------------------------------------------------------------ the entry

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    fail(
        "usage: guest catalog | guest install <bundle> <ipsw> | guest run <bundle> "
            + "[--display] [--share <dir>] | guest mac <bundle>")
}

// The catalog names no bundle, so it answers before the bundle is read.
if command == "catalog" {
    // Apple serves this list to a program, so the macOS guest needs no manual
    // download. The Windows guest does, and `vm.sh` states why there.
    VZMacOSRestoreImage.fetchLatestSupported { result in
        switch result {
        case .success(let image):
            let version = image.operatingSystemVersion
            say("url\t\(image.url.absoluteString)")
            say("build\t\(image.buildVersion)")
            say(
                "version\t\(version.majorVersion).\(version.minorVersion)."
                    + "\(version.patchVersion)")
            exit(0)
        case .failure(let error):
            fail("the restore catalog did not load: \(error)")
        }
    }
    dispatchMain()
}

guard arguments.count >= 2 else {
    fail(
        "usage: guest catalog | guest install <bundle> <ipsw> | guest run <bundle> "
            + "[--display] [--share <dir>] | guest mac <bundle>")
}
let bundle = Bundle(arguments[1])
let cpus = Int(ProcessInfo.processInfo.environment["FIDELITY_MACOS_CORES"] ?? "") ?? 4
let memoryGigabytes = UInt64(ProcessInfo.processInfo.environment["FIDELITY_MACOS_MEMORY"] ?? "") ?? 8
let diskGigabytes = UInt64(ProcessInfo.processInfo.environment["FIDELITY_MACOS_DISK"] ?? "") ?? 80
let memory = memoryGigabytes * 1024 * 1024 * 1024
let disk = diskGigabytes * 1024 * 1024 * 1024
var wantsWindow = false

switch command {
case "mac":
    // `vm.sh` reads this to turn the lease file of the host into an address.
    guard let text = try? String(contentsOf: bundle.address, encoding: .utf8) else {
        fail("\(bundle.address.path) does not exist. Run: vm.sh macos build")
    }
    print(text.trimmingCharacters(in: .whitespacesAndNewlines))
    exit(0)
case "install":
    guard arguments.count >= 3 else { fail("usage: guest install <bundle> <ipsw>") }
    let image = arguments[2]
    DispatchQueue.main.async {
        install(bundle: bundle, ipsw: image, cpus: cpus, memory: memory, disk: disk)
    }
case "run":
    var share: String?
    var index = 2
    while index < arguments.count {
        switch arguments[index] {
        case "--display": wantsWindow = true
        case "--share":
            index += 1
            guard index < arguments.count else { fail("--share needs a directory") }
            share = arguments[index]
        case let other: fail("unknown option \(other)")
        }
        index += 1
    }
    let directory = share
    let display = wantsWindow
    DispatchQueue.main.async {
        run(bundle: bundle, cpus: cpus, memory: memory, share: directory, display: display)
    }
default:
    fail("unknown command \(command)")
}

// A window needs the AppKit loop, and a headless run needs no window server at
// all. Both drain the main queue, which is the queue the machine runs on.
if wantsWindow {
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    application.run()
} else {
    dispatchMain()
}
