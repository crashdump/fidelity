# Builds the golden Windows guest image that the evidence harness runs against.
#
# The build boots the installation image, runs `install.cmd` in WinPE to apply
# the image, waits for the OpenSSH server that `setup.ps1` installs, and then
# provisions the toolchain over SSH. The output is one qcow2 plus the firmware
# variable store beside it, and `evidence/controls/vm.sh` starts both.
#
# Windows 11 25H2 boots a new Setup that ignores an answer file on its first
# pages, so this does not use Setup. `install.cmd` partitions the disk and
# applies the image with the tools that WinPE carries, and the answer file
# drives only the passes that run inside the installed system. The boot
# command reaches the WinPE prompt and starts that script.
#
#     evidence/vm/windows/make-answers.sh
#     packer init evidence/vm/windows
#     packer build -force evidence/vm/windows
#
# Run the commands from the root of the repository. The build expects the
# installation image at `windows_iso`, and `vm.sh windows iso` states where a
# person fetches it.
#
# The device list below is measured, not designed. A hand-driven install paid
# for each line, and `evidence/controls/vm.sh` records the findings in full:
#
#   - The system disk is NVMe and the two media are USB, because Windows 11
#     ARM64 carries an inbox driver for those and for nothing else here. The
#     network device is virtio, which Windows cannot drive until `install.cmd`
#     injects the driver into the offline image.
#   - `ramfb` is the display. The `virt` machine offers no framebuffer, and a
#     guest without one shows nothing and reads like a hung install.
#   - The firmware refuses to boot a USB CD-ROM, so the first boot drops to
#     the firmware shell, and `startup.nsh` on the answer disk starts the
#     loader. The answer disk takes `bootindex=2` so the firmware connects it
#     and can read that script. The loader then asks a person to press a key,
#     which the boot command answers.
#   - The installation image keeps `bootindex=0`, the disk keeps
#     `bootindex=1`, and the answer disk keeps `bootindex=2`, so the order
#     never changes. `install.cmd` writes the disk's own loader to the
#     removable-media default path, so every later boot takes the disk.
#
# The `qemuargs` list replaces every drive and device that the plugin would
# add on its own. The plugin still creates the disk file, still forwards the
# SSH port it chose, and still types the boot command, so the two template
# variables below come from it.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

variable "windows_iso" {
  type        = string
  default     = "${env("HOME")}/.local/share/fidelity-vm/windows/windows.iso"
  description = "The Windows 11 ARM64 installation image. See: evidence/controls/vm.sh windows iso"
}

variable "firmware_code" {
  type    = string
  default = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
}

locals {
  # The staging directory that `make-answers.sh` fills. It sits outside the
  # output directory, because Packer deletes and recreates that one.
  stage = abspath("${path.root}/../../../target/vm/windows")
}

source "qemu" "windows" {
  iso_url      = var.windows_iso
  iso_checksum = "none"

  qemu_binary  = "qemu-system-aarch64"
  machine_type = "virt,highmem=on"
  accelerator  = "hvf"
  cpus         = 4
  memory       = 8192
  disk_size    = "64G"
  format       = "qcow2"
  headless     = true

  qemuargs = [
    ["-cpu", "host"],
    # Eight ports of each speed. The default controller offers four, and a
    # fifth device makes QEMU add a hub, at full speed, in silence. The
    # firmware cannot enumerate through that hub, so the device behind it is
    # invisible, the shell finds no `startup.nsh`, and the install never
    # starts. `info usb` on the monitor shows the hub when this returns.
    ["-device", "qemu-xhci,p2=8,p3=8"],
    ["-device", "usb-kbd"],
    ["-device", "usb-tablet"],
    ["-device", "ramfb"],
    ["-drive", "if=pflash,format=raw,readonly=on,file=${var.firmware_code}"],
    ["-drive", "if=pflash,format=raw,file=${local.stage}/vars.fd"],
    ["-drive", "file={{ .OutputDir }}/{{ .Name }},if=none,id=boot,format=qcow2"],
    ["-device", "nvme,drive=boot,serial=fidelity,bootindex=1"],
    ["-drive", "file=${var.windows_iso},if=none,id=install,media=cdrom,readonly=on"],
    ["-device", "usb-storage,drive=install,bootindex=0"],
    # The answer disk takes a boot index on purpose, and not to boot. The
    # firmware connects the devices that its boot order names and no other,
    # measured with `connect -r` at its shell, so a disk with no index is one
    # that its shell cannot read. The index puts the disk in that list. The
    # boot attempt on it finds no loader and falls through, and the shell
    # that follows then finds `startup.nsh` on it.
    ["-drive", "file=${local.stage}/answers.dmg,if=none,id=answers,format=raw"],
    ["-device", "usb-storage,drive=answers,bootindex=2"],
    ["-netdev", "user,id=user.0,hostfwd=tcp::{{ .SSHHostPort }}-:22"],
    ["-device", "virtio-net-pci,netdev=user.0"],
    # The plugin adds `-boot once=d` when an installation image is present,
    # and QEMU refuses a boot order on this machine type. This entry replaces
    # it with a value that changes nothing, because `bootindex` above already
    # states the order.
    ["-boot", "menu=off"],
    # The monitor is how a person reads a silent build: `screendump` writes
    # what the guest shows, with no window and no VNC client.
    ["-monitor", "unix:${local.stage}/monitor.sock,server,nowait"],
  ]

  # The whole install, driven from the keyboard, because Windows 11 25H2
  # ignores an answer file on its own (measured 2026-08-15). The sequence is:
  #
  #   1. `startup.nsh` boots the installation image, which prints "Press any
  #      key to boot from CD or DVD" and waits about five seconds. The Enter
  #      presses blanket that window. They land while WinPE is loading, so a
  #      stray one is an empty command, and none reaches the Setup UI yet.
  #   2. WinPE loads its Setup, and Shift+F10 opens a command prompt on top.
  #   3. `install.cmd` on the answer disk does the install. Its drive letter
  #      is not certain, so this changes to each letter WinPE uses and runs
  #      the file from there. `C:` then a bare file name needs no backslash,
  #      which the guest keyboard layout would mistype. The letter that is
  #      the answer disk runs it, the install reboots, and the later lines
  #      never run.
  boot_wait = "12s"
  boot_command = [
    "<enter><wait2s><enter><wait2s><enter><wait2s><enter><wait2s><enter><wait2s>",
    "<enter><wait2s><enter><wait2s><enter><wait2s><enter><wait2s><enter><wait2s>",
    "<wait50s>",
    "<leftShiftOn><f10><leftShiftOff><wait12s>",
    "C:<enter><wait1s>install.cmd<enter><wait6s>",
    "D:<enter><wait1s>install.cmd<enter><wait6s>",
    "E:<enter><wait1s>install.cmd<enter>",
  ]

  # The port answers only after the install, the first logon, and the OpenSSH
  # download all finish, and that takes most of an hour. The forwarded port
  # accepts a connection before the guest listens, so the attempt count has
  # to survive the whole wait, not only the timeout.
  communicator           = "ssh"
  ssh_username           = "fidelity"
  ssh_password           = "fidelity"
  ssh_timeout            = "120m"
  ssh_handshake_attempts = 10000

  output_directory = "${local.stage}/image"
  vm_name          = "disk.qcow2"

  # The dashes matter: the final provisioner makes bash the login shell, and
  # bash rewrites an argument that starts with a slash into a drive path.
  shutdown_command = "shutdown -s -t 10 -f"
  shutdown_timeout = "15m"
}

build {
  sources = ["source.qemu.windows"]

  # Two installs, and the order matters. The Rust target for this platform is
  # `aarch64-pc-windows-msvc`, which links with the Microsoft linker, so a
  # guest with only rustup on it builds nothing. The build tools carry that
  # linker and they carry `cl`, which the C controls need as well, so one
  # install answers both.
  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "if (-not (Test-Path 'C:\\BuildTools')) {",
      "  Invoke-WebRequest https://aka.ms/vs/17/release/vs_BuildTools.exe -OutFile $env:TEMP\\vs.exe",
      "  Start-Process -Wait -FilePath $env:TEMP\\vs.exe -ArgumentList @(",
      "    '--quiet', '--wait', '--norestart', '--nocache',",
      "    '--installPath', 'C:\\BuildTools',",
      "    '--add', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64',",
      "    '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.26100')",
      "}",
      "if (-not (Test-Path 'C:\\BuildTools\\VC')) { throw 'the build tools did not install' }",
    ]
  }

  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "if (-not (Test-Path \"$env:USERPROFILE\\.cargo\\bin\\rustup.exe\")) {",
      "  Invoke-WebRequest https://win.rustup.rs/aarch64 -OutFile $env:TEMP\\rustup-init.exe",
      "  & $env:TEMP\\rustup-init.exe -y --default-toolchain stable --profile minimal",
      "}",
      "& \"$env:USERPROFILE\\.cargo\\bin\\rustc.exe\" --version",
    ]
  }

  # The harness runs as one POSIX shell script on every system, so the guest
  # needs a shell that reports a Windows `uname`, and `cygpath` beside it.
  # Git for Windows carries both. The version is pinned, so a rebuild uses
  # the release that the evidence names.
  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "if (-not (Test-Path 'C:\\Program Files\\Git\\bin\\bash.exe')) {",
      "  Invoke-WebRequest https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.4/Git-2.55.0.4-arm64.exe -OutFile $env:TEMP\\git-setup.exe",
      "  Start-Process -Wait -FilePath $env:TEMP\\git-setup.exe -ArgumentList @('/VERYSILENT', '/NORESTART', '/SP-')",
      "}",
      "& 'C:\\Program Files\\Git\\bin\\bash.exe' -c 'uname -s'",
    ]
  }

  # The machine environment that lets `cl` compile without a developer
  # prompt. The harness finds a compiler with `command -v`, and a found `cl`
  # that cannot find `windows.h` would be worse than none. The version
  # directories move with every tools update, so this reads them rather than
  # name them.
  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "$msvc = (Get-ChildItem 'C:\\BuildTools\\VC\\Tools\\MSVC' | Sort-Object Name | Select-Object -Last 1).FullName",
      "$sdk = 'C:\\Program Files (x86)\\Windows Kits\\10'",
      "$ver = (Get-ChildItem \"$sdk\\Include\" | Sort-Object Name | Select-Object -Last 1).Name",
      "[Environment]::SetEnvironmentVariable('INCLUDE', \"$msvc\\include;$sdk\\Include\\$ver\\ucrt;$sdk\\Include\\$ver\\um;$sdk\\Include\\$ver\\shared\", 'Machine')",
      "[Environment]::SetEnvironmentVariable('LIB', \"$msvc\\lib\\arm64;$sdk\\Lib\\$ver\\ucrt\\arm64;$sdk\\Lib\\$ver\\um\\arm64\", 'Machine')",
      "$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')",
      "[Environment]::SetEnvironmentVariable('Path', \"$path;$msvc\\bin\\Hostarm64\\arm64\", 'Machine')",
      "if (-not (Test-Path \"$msvc\\bin\\Hostarm64\\arm64\\cl.exe\")) { throw 'no ARM64 cl.exe under the build tools' }",
    ]
  }

  # The access that the harness uses afterward. `vm.sh` reaches the guest
  # with the key that `make-key.sh` made, and it speaks POSIX, so the login
  # shell becomes the bash that Git carries. The authorized-keys file for an
  # administrator lives under ProgramData, and the service refuses it unless
  # only administrators can write it, so the build locks it down.
  provisioner "powershell" {
    inline = [
      "$ErrorActionPreference = 'Stop'",
      "New-Item -ItemType Directory -Force -Path C:\\ProgramData\\ssh | Out-Null",
      "Set-Content -Path C:\\ProgramData\\ssh\\administrators_authorized_keys -Value '${trimspace(file("${local.stage}/../id_ed25519.pub"))}'",
      "icacls C:\\ProgramData\\ssh\\administrators_authorized_keys /inheritance:r /grant 'SYSTEM:F' /grant 'BUILTIN\\Administrators:F' | Out-Null",
      "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Program Files\\Git\\bin\\bash.exe' -PropertyType String -Force | Out-Null",
    ]
  }
}
