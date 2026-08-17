# Builds the golden Linux guest image that the evidence harness runs against.
#
# The guest replaces the container that ran the Linux controls before. A
# container shares the kernel of its host, so it holds no filesystem of its own
# and fs-verity cannot be enabled there, and it needs a capability grant for the
# tracer controls. A guest owns its kernel and its disk, so both answers become
# real. See `docs/plan/06-delivery.md`.
#
# This template boots the Debian cloud image, lets cloud-init create the build
# account, installs the toolchain and the control dependencies, and writes one
# qcow2 that `evidence/controls/vm.sh` starts. The build is declarative and
# repeatable, so the image is an artifact rather than a machine that a person
# set up by hand.
#
#     evidence/vm/make-key.sh
#     packer init evidence/vm/linux
#     packer build -force evidence/vm/linux

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

variable "debian_image" {
  type        = string
  default     = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2"
  description = "The Debian release that the evidence record names. A guest that reported another distribution would not compare against the recorded rows."
}

variable "firmware_code" {
  type    = string
  default = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
}

source "qemu" "linux" {
  # Boot the cloud image directly, rather than run an installer. The image is
  # already an installed system, so cloud-init is the whole setup.
  iso_url      = var.debian_image
  iso_checksum = "none"
  disk_image   = true

  qemu_binary    = "qemu-system-aarch64"
  machine_type   = "virt,highmem=on"
  accelerator    = "hvf"
  cpus           = 4
  memory         = 4096
  disk_size      = "32G"
  disk_interface = "virtio-scsi"
  net_device     = "virtio-net"
  format         = "qcow2"
  headless       = true

  # The `virt` machine has no built-in firmware, so the build names it. The
  # vars store is a copy, because the firmware writes to it.
  efi_boot          = true
  efi_firmware_code = var.firmware_code
  efi_firmware_vars = "${path.root}/../efivars-template.fd"

  # HVF runs an ARM64 guest at host speed, and it needs the host CPU model.
  qemuargs = [
    ["-cpu", "host"],
  ]

  # cloud-init reads a volume that carries the label `cidata`. The build
  # account takes a password for the SSH communicator, and it takes the key
  # from `make-key.sh` for the harness, so run that script before this build.
  cd_label = "cidata"
  cd_content = {
    "meta-data" = "instance-id: fidelity-linux\nlocal-hostname: fidelity-linux\n"
    "user-data" = <<-EOF
      #cloud-config
      users:
        - name: fidelity
          sudo: ALL=(ALL) NOPASSWD:ALL
          shell: /bin/bash
          lock_passwd: false
          plain_text_passwd: fidelity
          ssh_authorized_keys:
            - ${trimspace(file("${abspath(path.root)}/../../../target/vm/id_ed25519.pub"))}
      ssh_pwauth: true
    EOF
  }

  communicator = "ssh"
  ssh_username = "fidelity"
  ssh_password = "fidelity"
  ssh_timeout  = "10m"

  # The one artifact this build produces. The parent directory is staging
  # space, and Packer owns `image/` alone, because it deletes and recreates
  # its output directory on every build.
  output_directory = "${path.root}/../../../target/vm/linux/image"
  vm_name          = "disk.qcow2"

  shutdown_command = "sudo poweroff"
}

build {
  sources = ["source.qemu.linux"]

  provisioner "shell" {
    # cloud-init has to finish before apt runs, or the two fight over the lock.
    # The toolchain matches what every machine that runs these controls needs:
    # a Rust toolchain, a C compiler for the agents, and the fs-verity tool for
    # the platform-trust control.
    inline = [
      "cloud-init status --wait || true",
      "sudo apt-get update -q",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential fsverity e2fsprogs gdb curl",
      "curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal",
      "echo '. \"$HOME/.cargo/env\"' >> $HOME/.bashrc",
      ". $HOME/.cargo/env && rustc --version",
      # The harness shares the workspace over 9p at /work, the same path the
      # container used, and it keeps the build directory on the disk of the
      # guest. `nofail` is the point: the build runs with no share attached, so
      # a hard mount would hang every boot. The runtime attaches the share, and
      # the mount then succeeds.
      "sudo mkdir -p /work /var/tmp/target",
      "sudo chown fidelity:fidelity /var/tmp/target",
      "echo 'workspace /work 9p trans=virtio,version=9p2000.L,msize=524288,nofail,x-systemd.device-timeout=1 0 0' | sudo tee -a /etc/fstab",
    ]
  }
}
