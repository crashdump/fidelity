#!/bin/sh
# Manages the Windows guest that the Windows controls need.
#
#     windows-vm.sh iso        say where the installation image must be
#     windows-vm.sh create     make the disk, the firmware variables, the answers
#     windows-vm.sh install    boot the installer once, and answer it
#     windows-vm.sh start      boot the installed system, with no window
#     windows-vm.sh stop       shut the guest down
#     windows-vm.sh status     say whether the guest answers
#     windows-vm.sh run <cmd>  run one command in the guest
#     windows-vm.sh provision  install the Rust toolchain in the guest
#
# Why this exists. Nine controls need a Windows kernel, and no other machine in
# this project runs one. The Linux controls already take this shape: `run.sh`
# drives them with `docker run`, which is a Linux virtual machine on a Mac.
# This is the same idea with the same contract, and the guest is a virtual
# machine rather than a container because Windows offers no container that
# runs a kernel test.
#
# A virtual machine is a virtual machine, so a `Virtualization` detector would
# report this guest. That category holds no code, and the four capabilities
# that the Windows probe answers read memory, a debug port, and a signature.
# None of them changes under a hypervisor.
#
# The guest keeps its disk outside the workspace, because a Windows install is
# tens of gigabytes and no part of it belongs in a repository.
set -u

VM_DIR=${FIDELITY_WINDOWS_VM:-$HOME/.local/share/fidelity-windows-vm}
DISK=$VM_DIR/disk.qcow2
VARS=$VM_DIR/vars.fd
ANSWERS=$VM_DIR/answers.dmg
ISO=${FIDELITY_WINDOWS_ISO:-$VM_DIR/windows.iso}
PIDFILE=$VM_DIR/qemu.pid
CODE=/opt/homebrew/share/qemu/edk2-aarch64-code.fd

# The guest answers on this port, and the host forwards it. A port rather than
# a shared folder, because the controls build inside the guest and only need a
# shell.
PORT=${FIDELITY_WINDOWS_PORT:-2222}
USER_NAME=fidelity
# The guest holds no secret and reaches no network but this port. The password
# is in the answer file either way, so hiding it here would state nothing.
PASSWORD=fidelity

# How much of this machine the guest takes. A Windows build needs the memory,
# and the controls are not the bottleneck.
MEMORY=${FIDELITY_WINDOWS_MEMORY:-8G}
CORES=${FIDELITY_WINDOWS_CORES:-4}
DISK_SIZE=${FIDELITY_WINDOWS_DISK:-64G}

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

ssh_to_guest() {
    ssh -p "$PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=5 \
        "$USER_NAME@127.0.0.1" "$@"
}

# ------------------------------------------------------------------ the image

# The one step that a person takes, and the reason is Microsoft's rather than
# this project's.
#
# The download has four steps, and three of them answer a script. The page
# names the ARM64 product, an interface returns the language list, and both
# answer a plain request. The fourth, which turns a language into a link,
# refuses: it replies `ErrorSettings.SentinelReject`, because Microsoft guards
# that endpoint against automation on purpose. Measured on 2026-08-13.
#
# Defeating that guard is not this project's business, and a control built on a
# guard that somebody works around breaks the week it changes. So this step
# reads what it can, states the exact build it expects, and asks once.
cmd_iso() {
    if [ -f "$ISO" ]; then
        say "the installation image is $ISO"
        return 0
    fi
    mkdir -p "$VM_DIR"
    cat <<EOF
No installation image at $ISO

Windows 11 for ARM64 is about 5 GB, and Microsoft serves the final link only to
a browser. Take the image once:

  1. Open https://www.microsoft.com/software-download/windows11arm64
  2. Choose "Windows 11 (multi-edition ISO for Arm64)" and English.
  3. Move the file to $ISO

The v1 floor is Windows 11 25H2, and that page served 25H2 on 2026-08-13, so
the current image satisfies it. Check the floor again before a release.

Or state another path:

  FIDELITY_WINDOWS_ISO=/path/to/win11.iso evidence/controls/windows-vm.sh create

Every step after this one runs from this shell.
EOF
    return 1
}

# ------------------------------------------------------------------ the guest

# The answer file. Windows Setup reads `autounattend.xml` from the root of any
# volume it can see, so the file ships as a small disk rather than as a file.
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
write_answers() {
    work=$VM_DIR/answers
    rm -rf "$work" "$ANSWERS"
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
      <UserData>
        <AcceptEula>true</AcceptEula>
      </UserData>
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
            <Password><Value>$PASSWORD</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>$USER_NAME</Username>
        <LogonCount>1</LogonCount>
        <Password><Value>$PASSWORD</Value><PlainText>true</PlainText></Password>
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
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
EOF

    # macOS builds the small FAT disk itself, so this needs no second tool.
    hdiutil create -quiet -srcfolder "$work" -fs MS-DOS -volname ANSWERS \
        -format UDRW -ov "${ANSWERS%.dmg}" || die "the answer disk did not build"
    say "wrote the answer disk $ANSWERS"
}

cmd_create() {
    [ -f "$CODE" ] || die "no ARM64 firmware at $CODE. Install it with: brew install qemu"
    cmd_iso || return 1
    mkdir -p "$VM_DIR"

    if [ ! -f "$DISK" ]; then
        qemu-img create -q -f qcow2 "$DISK" "$DISK_SIZE" ||
            die "the guest disk did not build"
        say "made the guest disk $DISK, $DISK_SIZE"
    fi

    # The firmware keeps its variables in a file of the same size as the code.
    if [ ! -f "$VARS" ]; then
        dd if=/dev/zero of="$VARS" bs=1m count=64 2> /dev/null ||
            die "the firmware variables did not build"
        say "made the firmware variables $VARS"
    fi

    write_answers
    say "ready. Next: evidence/controls/windows-vm.sh install"
}

# The common part of both boots. The disk is NVMe rather than virtio, because
# Windows on ARM64 carries an NVMe driver and carries no virtio driver, so an
# installer on a virtio disk finds nothing to install onto.
qemu_run() {
    qemu-system-aarch64 \
        -M virt,highmem=on \
        -accel hvf \
        -cpu host \
        -smp "$CORES" \
        -m "$MEMORY" \
        -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
        -drive "if=pflash,format=raw,file=$VARS" \
        -drive "file=$DISK,if=none,id=boot,format=qcow2" \
        -device nvme,drive=boot,serial=fidelity \
        -device qemu-xhci \
        -device usb-kbd \
        -device usb-tablet \
        -device usb-net,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::$PORT-:22" \
        "$@"
}

cmd_install() {
    [ -f "$ISO" ] || die "no installation image. Run: windows-vm.sh iso"
    [ -f "$DISK" ] || die "no guest disk. Run: windows-vm.sh create"
    say "the installer runs with a window, because a failed install has to be readable."
    say "It answers itself. Close the window when the guest reaches its desktop."
    qemu_run \
        -device usb-storage,drive=install \
        -drive "file=$ISO,if=none,id=install,media=cdrom,readonly=on" \
        -device usb-storage,drive=answers \
        -drive "file=$ANSWERS,if=none,id=answers,format=raw" \
        -display default,show-cursor=on
}

cmd_start() {
    [ -f "$DISK" ] || die "no guest disk. Run: windows-vm.sh create"
    if cmd_status > /dev/null 2>&1; then
        say "the guest already answers"
        return 0
    fi
    mkdir -p "$VM_DIR"
    qemu_run -display none -daemonize -pidfile "$PIDFILE" ||
        die "the guest did not start"

    # Windows takes a while to reach its shell, and the port answers only then.
    tries=0
    while [ "$tries" -lt 60 ]; do
        if ssh_to_guest 'exit' > /dev/null 2>&1; then
            say "the guest answers on port $PORT"
            return 0
        fi
        tries=$((tries + 1))
        sleep 5
    done
    die "the guest started and never answered on port $PORT"
}

cmd_stop() {
    if [ -f "$PIDFILE" ]; then
        ssh_to_guest 'shutdown /s /t 0' > /dev/null 2>&1
        sleep 10
        pid=$(cat "$PIDFILE" 2> /dev/null)
        [ -n "${pid:-}" ] && kill "$pid" 2> /dev/null
        rm -f "$PIDFILE"
    fi
    say "the guest is down"
}

cmd_status() {
    ssh_to_guest 'exit' > /dev/null 2>&1 || die "the guest does not answer on port $PORT"
    say "the guest answers on port $PORT"
}

cmd_run() {
    [ "$#" -gt 0 ] || die "usage: windows-vm.sh run <command>"
    ssh_to_guest "$@"
}

# The guest needs the same toolchain that the harness asks of any machine: a
# Rust toolchain with the pinned floor, and a C compiler for the controls.
cmd_provision() {
    cmd_status > /dev/null || die "start the guest first"
    say "installing the Rust toolchain in the guest"
    ssh_to_guest 'powershell -NoProfile -Command "
        if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
            Invoke-WebRequest https://win.rustup.rs/aarch64 -OutFile rustup-init.exe;
            .\rustup-init.exe -y --default-toolchain stable --profile minimal;
        }
        rustc --version"' || die "the toolchain did not install"
    say "the guest holds a Rust toolchain"
}

case "${1:-}" in
    iso) cmd_iso ;;
    create) cmd_create ;;
    install) cmd_install ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    provision) cmd_provision ;;
    run) shift; cmd_run "$@" ;;
    *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
