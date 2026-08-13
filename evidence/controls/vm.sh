#!/bin/sh
# Manages the guests that the platform controls need.
#
#     vm.sh <guest> <command>
#
#     guest:    linux | windows
#     command:  create | install | start | stop | status | run <cmd> | provision
#
# Why this exists. The controls for a platform have to run on that platform,
# and this machine runs one of the five. The Linux controls already took this
# shape, because `docker run` on a Mac is a Linux virtual machine, so a guest
# is the pattern this harness already had rather than a new one.
#
# QEMU runs both guests with the hypervisor of this machine, so an ARM64 guest
# runs at the speed of the host.
#
# The Linux guest replaces what the container gave, and it answers two things
# the container could not. A container shares the kernel of the machine that
# hosts it, so it has no filesystem of its own: fs-verity cannot be enabled
# there, and the platform-trust tier of the Linux identity capability has no
# way to report anything but a gap. A guest owns its disk, so that tier gets a
# real control. The container also needed `--cap-add=SYS_PTRACE` for the tracer
# controls, and a guest needs no such grant, so the control matches what a host
# really runs under.
#
# A guest is a virtual machine, so a `Virtualization` detector would report
# both of these. That category holds no code. Every capability that these
# guests exercise reads memory, a debug port, a mapping table, or a signature,
# and none of them changes under a hypervisor.
#
# A guest keeps its disk outside the workspace, because an installed system is
# tens of gigabytes and no part of it belongs in a repository.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BASE=${FIDELITY_VM_DIR:-$HOME/.local/share/fidelity-vm}
FIRMWARE=/opt/homebrew/share/qemu/edk2-aarch64-code.fd

# The Debian release that the evidence record already names. A guest that
# reported another distribution would not compare against the rows that the
# container produced.
LINUX_IMAGE_URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------ the guest itself

# Each guest states its own port, memory, and disk. Two guests can run at once,
# so the ports differ.
setup() {
    GUEST=$1
    DIR=$BASE/$GUEST
    DISK=$DIR/disk.qcow2
    VARS=$DIR/vars.fd
    PIDFILE=$DIR/qemu.pid
    KEY=$DIR/id_ed25519
    case $GUEST in
        linux)
            PORT=${FIDELITY_LINUX_PORT:-2223}
            MEMORY=${FIDELITY_LINUX_MEMORY:-4G}
            CORES=${FIDELITY_LINUX_CORES:-4}
            DISK_SIZE=${FIDELITY_LINUX_DISK:-32G}
            USER_NAME=fidelity
            ;;
        windows)
            PORT=${FIDELITY_WINDOWS_PORT:-2222}
            MEMORY=${FIDELITY_WINDOWS_MEMORY:-8G}
            CORES=${FIDELITY_WINDOWS_CORES:-4}
            DISK_SIZE=${FIDELITY_WINDOWS_DISK:-64G}
            USER_NAME=fidelity
            # The guest holds no secret and reaches no network but this port,
            # and the answer file carries the value either way, so hiding it
            # here would state nothing.
            WINDOWS_PASSWORD=fidelity
            ;;
        *) die "usage: vm.sh <linux|windows> <command>" ;;
    esac
}

ssh_to_guest() {
    if [ "$GUEST" = linux ]; then
        ssh -p "$PORT" -i "$KEY" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR -o ConnectTimeout=5 \
            "$USER_NAME@127.0.0.1" "$@"
    else
        ssh -p "$PORT" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR -o ConnectTimeout=5 \
            "$USER_NAME@127.0.0.1" "$@"
    fi
}

# ------------------------------------------------------------------- the Linux

# cloud-init reads a volume that carries the label `cidata`, so the answers
# ship as a small disk rather than as a file. This is the same idea as the
# Windows answer file, and the two guests differ only in the format.
linux_seed() {
    work=$DIR/seed
    rm -rf "$work" "$DIR/seed.iso"
    mkdir -p "$work"

    [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY" -C fidelity-vm

    cat > "$work/meta-data" <<EOF
instance-id: fidelity-linux
local-hostname: fidelity-linux
EOF

    # The guest holds no secret and reaches no network but this port, so the
    # key is the whole authentication and no password is set at all.
    cat > "$work/user-data" <<EOF
#cloud-config
users:
  - name: $USER_NAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
package_update: true
packages:
  - build-essential
  - fsverity
  - gdb
ssh_pwauth: false
# The workspace arrives over 9p, in the same place the container mounted it, so
# a control reads the same path in both. The build directory stays on the disk
# of the guest, because the host and the guest otherwise fight over one target/
# and because a build over a shared filesystem is far slower.
mounts:
  - [ workspace, /work, 9p, "trans=virtio,version=9p2000.L,msize=524288,rw", "0", "0" ]
runcmd:
  - [ mkdir, -p, /work ]
  - [ mount, -a ]
  - [ mkdir, -p, /var/tmp/target ]
  - [ chown, "fidelity:fidelity", /var/tmp/target ]
EOF

    hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata \
        -o "$DIR/seed.iso" "$work" || die "the cloud-init seed did not build"
    say "wrote the cloud-init seed $DIR/seed.iso"
}

linux_create() {
    mkdir -p "$DIR"
    if [ ! -f "$DISK" ]; then
        say "fetching the Debian cloud image, which is about 400 MB"
        curl -fsSL "$LINUX_IMAGE_URL" -o "$DIR/base.qcow2" ||
            die "the cloud image did not download"
        cp "$DIR/base.qcow2" "$DISK"
        qemu-img resize -q "$DISK" "$DISK_SIZE" || die "the disk did not resize"
        say "made the guest disk $DISK, $DISK_SIZE"
    fi
    linux_seed
    say "ready. Next: evidence/controls/vm.sh linux start"
}

# ----------------------------------------------------------------- the Windows

# Windows 11 25H2 asks a person a few questions that its own answer file does
# not remove, and this is what they are and how to answer them. Measured on
# 2026-08-13, driving the guest through the QEMU monitor.
#
#   - the setup pages come from the new setup, which shows them whether or not
#     an answer file is present. The page offers a previous version of setup,
#     and that one honors the file.
#   - the hardware check refuses a guest, because it has no security chip and
#     no secure boot. Shift+F10 opens a command prompt inside setup, and three
#     `reg add` lines under HKLM\System\Setup\LabConfig turn the three checks
#     off. Confirmed: the check passes on the next attempt.
#   - the guest keyboard follows the language of the image. An EN-GB image
#     takes a UK layout, where the QEMU key named `backslash` produces `#`.
#     The UK backslash is the key left of Z, which QEMU calls `less`. A
#     registry path typed the obvious way lands as `HKLM#System#Setup`.
#
# The one download step that a person takes has a different reason, and it is
# Microsoft's rather than this project's.
#
# The download has four steps, and three of them answer a script. The page
# names the ARM64 product, and an interface returns the language list. The
# fourth, which turns a language into a link, refuses with
# `ErrorSettings.SentinelReject`, because Microsoft guards that endpoint
# against automation on purpose. Measured on 2026-08-13.
#
# Defeating that guard is not this project's business, and a control built on a
# guard that somebody works around breaks the week it changes. So this step
# reads what it can, states the exact build it expects, and asks once.
WINDOWS_ISO=${FIDELITY_WINDOWS_ISO:-$BASE/windows/windows.iso}

windows_iso() {
    if [ -f "$WINDOWS_ISO" ]; then
        say "the installation image is $WINDOWS_ISO"
        return 0
    fi
    mkdir -p "$DIR"
    cat <<EOF
No installation image at $WINDOWS_ISO

Windows 11 for ARM64 is about 5 GB, and Microsoft serves the final link only to
a browser. Take the image once:

  1. Open https://www.microsoft.com/software-download/windows11arm64
  2. Choose "Windows 11 (multi-edition ISO for Arm64)" and English.
  3. Move the file to $WINDOWS_ISO

The v1 floor is Windows 11 25H2, and that page served 25H2 on 2026-08-13, so
the current image satisfies it. Check the floor again before a release.

Every step after this one runs from this shell.
EOF
    return 1
}

# The answer file. Windows Setup reads `autounattend.xml` from the root of any
# volume it can see, so the file ships as a small disk rather than as a file.
# That is the same idea as the cloud-init seed above, in the other format.
#
# Three things matter here, and each one removes a question that a person would
# otherwise answer with a mouse:
#
#   - the LabConfig keys turn off the checks for a security chip, for secure
#     boot, and for memory. A guest has none of the three, and the installer
#     stops on all of them.
#   - the OOBE block skips every first-boot page.
#   - the FirstLogonCommands install the OpenSSH server and start it, which is
#     the only way this script reaches the guest afterwards.
windows_answers() {
    work=$DIR/answers
    rm -rf "$work" "$DIR/answers.dmg"
    mkdir -p "$work"

    cat > "$work/autounattend.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add HKLM\\System\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg add HKLM\\System\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg add HKLM\\System\\Setup\\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
      <UserData><AcceptEula>true</AcceptEula></UserData>
      <ImageInstall>
        <OSImage>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order><Type>EFI</Type><Size>260</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order><Type>MSR</Type><Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order><Type>Primary</Type><Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order><PartitionID>1</PartitionID>
              <Format>FAT32</Format><Label>System</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order><PartitionID>2</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order><PartitionID>3</PartitionID>
              <Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>$USER_NAME</Name>
            <Group>Administrators</Group>
            <Password><Value>$WINDOWS_PASSWORD</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>$USER_NAME</Username>
        <LogonCount>1</LogonCount>
        <Password><Value>$WINDOWS_PASSWORD</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>powershell -NoProfile -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <CommandLine>powershell -NoProfile -Command "Set-Service -Name sshd -StartupType Automatic; Start-Service sshd"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>3</Order>
          <CommandLine>powershell -NoProfile -Command "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force"</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>4</Order>
          <CommandLine>netsh advfirewall firewall add rule name="sshd" dir=in action=allow protocol=TCP localport=22</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
EOF

    # The firmware needs telling, and this is the file that tells it.
    #
    # EDK2 finds no boot option it likes for an installation image on a USB
    # CD-ROM, and a `bootindex` does not change that. It drops to its own
    # interactive shell instead, where the installer never runs. That shell
    # runs `startup.nsh` from any filesystem it can see, and this disk is one,
    # so the answer disk carries the boot as well as the answers.
    #
    # `FS0:` is the image, and the loader path came from reading it rather
    # than from a guess.
    cat > "$work/startup.nsh" <<'NSH'
FS0:
cd \efi\boot
bootaa64.efi
NSH

    # The disk keeps its partition table, and that is measured rather than
    # assumed. A run with `-layout NONE` put the filesystem at the start of the
    # disk with no table, and Windows Setup then listed this disk as 8 MB of
    # unallocated space: it could not read the volume at all, so it could never
    # have found an answer file on it. The firmware reads either layout, so
    # only Windows decides this one.
    hdiutil create -quiet -srcfolder "$work" -fs MS-DOS -volname ANSWERS \
        -format UDRW -ov "$DIR/answers" || die "the answer disk did not build"
    say "wrote the answer disk $DIR/answers.dmg, with the boot script"
}

windows_create() {
    windows_iso || return 1
    mkdir -p "$DIR"
    if [ ! -f "$DISK" ]; then
        qemu-img create -q -f qcow2 "$DISK" "$DISK_SIZE" ||
            die "the guest disk did not build"
        say "made the guest disk $DISK, $DISK_SIZE"
    fi
    # The firmware keeps its variables in a file of its own.
    [ -f "$VARS" ] || dd if=/dev/zero of="$VARS" bs=1m count=64 2> /dev/null
    windows_answers
    say "ready. Next: evidence/controls/vm.sh windows install"
}

# The installer runs with a window on purpose. It answers itself, and a failed
# install has to be readable, so this is the one step that shows anything.
windows_install() {
    [ -f "$WINDOWS_ISO" ] || die "no installation image. Run: vm.sh windows create"
    [ -f "$DISK" ] || die "no guest disk. Run: vm.sh windows create"
    say "the installer answers itself. Close the window when the guest reaches its desktop,"
    say "then run: evidence/controls/vm.sh windows start"

    rm -f "$DIR/monitor.sock"
    qemu_run \
        -device usb-storage,drive=install,bootindex=0 \
        -drive "file=$WINDOWS_ISO,if=none,id=install,media=cdrom,readonly=on" \
        -device usb-storage,drive=answers \
        -drive "file=$DIR/answers.dmg,if=none,id=answers,format=raw" \
        -monitor "unix:$DIR/monitor.sock,server,nowait" \
        -display default,show-cursor=on &
    installer=$!

    # Windows install media asks a person to press a key before it boots, and
    # an unattended install has nobody to press it. The firmware then falls
    # through to the empty disk and waits there, at almost no processor cost,
    # which reads exactly like a slow install and is not one.
    #
    # The monitor is the keyboard. It sends a few returns over the first half
    # minute, so whichever prompt is on screen gets one.
    (
        tries=0
        while [ "$tries" -lt 15 ]; do
            [ -S "$DIR/monitor.sock" ] &&
                printf 'sendkey ret\n' | nc -U "$DIR/monitor.sock" > /dev/null 2>&1
            tries=$((tries + 1))
            sleep 2
        done
    ) &

    wait "$installer"
}

# ---------------------------------------------------------------------- QEMU

# The Linux guest takes virtio for everything, because a Linux kernel carries
# those drivers. The Windows guest takes NVMe and USB, because Windows on ARM64
# carries neither virtio driver, and an installer on a virtio disk finds no
# disk to install onto.
#
# The boot order is stated rather than left to the firmware. Without a
# `bootindex` the firmware finds no boot option it likes and drops to its own
# interactive shell, where the installer never runs and a blind keypress lands
# in a shell prompt. The image gets index 0 and the empty disk gets index 1, so
# the first boot takes the installer and every later boot takes the disk.
#
# The Windows guest also needs a display adapter named, and the reason cost an
# hour. The `virt` machine provides no framebuffer of its own, so a guest with
# no adapter gives the firmware nowhere to draw. The screen then stays black
# with a cursor, the installer never appears, and the whole thing reads as a
# slow install rather than as a guest that never started one. `ramfb` is the
# adapter, and the firmware and Windows Setup both drive it through UEFI.
qemu_run() {
    if [ "$GUEST" = linux ]; then
        qemu-system-aarch64 \
            -M virt,highmem=on -accel hvf -cpu host \
            -smp "$CORES" -m "$MEMORY" \
            -bios "$FIRMWARE" \
            -drive "file=$DISK,if=virtio,format=qcow2" \
            -drive "file=$DIR/seed.iso,if=virtio,format=raw,readonly=on" \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::$PORT-:22" \
            -virtfs "local,path=$ROOT,mount_tag=workspace,security_model=mapped-xattr,id=workspace" \
            "$@"
    else
        qemu-system-aarch64 \
            -M virt,highmem=on -accel hvf -cpu host \
            -smp "$CORES" -m "$MEMORY" \
            -drive "if=pflash,format=raw,readonly=on,file=$FIRMWARE" \
            -drive "if=pflash,format=raw,file=$VARS" \
            -drive "file=$DISK,if=none,id=boot,format=qcow2" \
            -device nvme,drive=boot,serial=fidelity,bootindex=1 \
            -device ramfb \
            -device qemu-xhci -device usb-kbd -device usb-tablet \
            -device usb-net,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::$PORT-:22" \
            "$@"
    fi
}

cmd_start() {
    [ -f "$DISK" ] || die "no guest disk. Run: vm.sh $GUEST create"
    if ssh_to_guest 'exit' > /dev/null 2>&1; then
        say "the $GUEST guest already answers on port $PORT"
        return 0
    fi
    qemu_run -display none -daemonize -pidfile "$PIDFILE" ||
        die "the $GUEST guest did not start"

    # A first boot runs cloud-init or the Windows first-logon commands, and
    # neither answers the port until it finishes.
    tries=0
    while [ "$tries" -lt 90 ]; do
        if ssh_to_guest 'exit' > /dev/null 2>&1; then
            say "the $GUEST guest answers on port $PORT"
            return 0
        fi
        tries=$((tries + 1))
        sleep 5
    done
    die "the $GUEST guest started and never answered on port $PORT"
}

cmd_stop() {
    if [ "$GUEST" = linux ]; then
        ssh_to_guest 'sudo poweroff' > /dev/null 2>&1
    else
        ssh_to_guest 'shutdown /s /t 0' > /dev/null 2>&1
    fi
    sleep 8

    # The pid file alone is not enough. A guest that this script started before
    # the file existed, or one whose file a crash left behind, keeps the
    # forwarded port and the next start then fails on it. The disk path names
    # exactly one guest, so the search finds that one and no other.
    pid=$(cat "$PIDFILE" 2> /dev/null)
    [ -n "${pid:-}" ] && kill "$pid" 2> /dev/null
    for stray in $(pgrep -f "qemu-system-aarch64.*$DISK" 2> /dev/null); do
        kill "$stray" 2> /dev/null
    done
    sleep 2
    for stray in $(pgrep -f "qemu-system-aarch64.*$DISK" 2> /dev/null); do
        kill -9 "$stray" 2> /dev/null
    done
    rm -f "$PIDFILE"
    say "the $GUEST guest is down"
}

cmd_status() {
    ssh_to_guest 'exit' > /dev/null 2>&1 ||
        die "the $GUEST guest does not answer on port $PORT"
    say "the $GUEST guest answers on port $PORT"
}

cmd_run() {
    [ "$#" -gt 0 ] || die "usage: vm.sh $GUEST run <command>"
    ssh_to_guest "$@"
}

cmd_provision() {
    cmd_status > /dev/null || die "start the guest first"
    if [ "$GUEST" = linux ]; then
        ssh_to_guest 'command -v cargo > /dev/null 2>&1 ||
            curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal' ||
            die "the toolchain did not install"
        ssh_to_guest '. "$HOME/.cargo/env" && rustc --version'
    else
        # Two installs, and the order matters. The Rust target for this
        # platform is `aarch64-pc-windows-msvc`, which links with the Microsoft
        # linker, so a guest with only rustup on it builds nothing. The build
        # tools carry that linker and they carry `cl`, which the C controls
        # need as well, so one install answers both.
        say "installing the Microsoft build tools, which is a long download"
        ssh_to_guest 'powershell -NoProfile -Command "
            $vs = \"C:\BuildTools\";
            if (-not (Test-Path $vs)) {
                Invoke-WebRequest https://aka.ms/vs/17/release/vs_BuildTools.exe -OutFile vs.exe;
                Start-Process -Wait -FilePath .\vs.exe -ArgumentList @(
                    \"--quiet\", \"--wait\", \"--norestart\", \"--nocache\",
                    \"--installPath\", $vs,
                    \"--add\", \"Microsoft.VisualStudio.Component.VC.Tools.ARM64\",
                    \"--add\", \"Microsoft.VisualStudio.Component.Windows11SDK.26100\"
                );
            }
            Test-Path $vs"' || die "the build tools did not install"

        ssh_to_guest 'powershell -NoProfile -Command "
            if (-not (Test-Path \"$env:USERPROFILE\.cargo\bin\rustup.exe\")) {
                Invoke-WebRequest https://win.rustup.rs/aarch64 -OutFile rustup-init.exe;
                .\rustup-init.exe -y --default-toolchain stable --profile minimal;
            }
            & \"$env:USERPROFILE\.cargo\bin\rustc.exe\" --version"' ||
            die "the toolchain did not install"
    fi
    say "the $GUEST guest holds a Rust toolchain"
}

[ "$#" -ge 1 ] || { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
setup "$1"
shift
[ -f "$FIRMWARE" ] || die "no ARM64 firmware at $FIRMWARE. Install it with: brew install qemu"

case "${1:-}" in
    create) [ "$GUEST" = linux ] && linux_create || windows_create ;;
    iso) windows_iso ;;
    install) windows_install ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    provision) cmd_provision ;;
    run) shift; cmd_run "$@" ;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
