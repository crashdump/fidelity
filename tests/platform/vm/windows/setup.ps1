# Runs once, at the first logon of the build account. Windows Setup starts it
# from the answer disk. It makes the guest reachable over SSH, and it writes a
# transcript to C:\fidelity-setup.log, so a failed build leaves a record.
#
# The steps run in this order, and the order matters:
#
#   1. Install the virtio network driver. The `virt` machine offers no network
#      device that Windows 11 ARM64 drives with an inbox driver, so the guest
#      has no network until this step. The catalog carries a Microsoft
#      signature, so pnputil asks no question.
#   2. Wait for an address. Step 3 downloads from Windows Update.
#   3. Install the OpenSSH server, with retries. It is a Windows capability,
#      and a cold guest refuses the first calls while its services settle.
#   4. Start the service, set its shell, and open the firewall port.
#   5. Turn off the automatic update restart. A restart in the middle of a
#      build breaks the SSH session that drives it.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\fidelity-setup.log' -Append

pnputil /add-driver "$PSScriptRoot\drivers\netkvm\netkvm.inf" /install

foreach ($try in 1..60) {
    $addr = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp `
        -ErrorAction SilentlyContinue
    if ($addr) { break }
    Start-Sleep -Seconds 5
}

foreach ($try in 1..20) {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    $state = (Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State
    if ($state -eq 'Installed') { break }
    Start-Sleep -Seconds 30
}

Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -PropertyType String -Force | Out-Null
netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=22

# QEMU presents the hardware clock as UTC, and Windows reads that clock as
# local time. The guest then sits one hour from the host for every hour that
# its zone offsets from UTC, and a file that the host wrote reads as a file
# from the future. `tar` calls that an error, and Cargo rebuilds what it did
# not need to. This key tells Windows that the clock is UTC, which is what
# QEMU gives it. Measured at exactly 3600 s on 2026-08-15.
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' `
    -Name RealTimeIsUniversal -Value 1 -PropertyType DWord -Force | Out-Null
Set-TimeZone -Id 'UTC'
Start-Service w32time -ErrorAction SilentlyContinue
w32tm /resync /force

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' `
    -Name NoAutoRebootWithLoggedOnUsers -Value 1 -PropertyType DWord -Force | Out-Null
powercfg /change standby-timeout-ac 0

Stop-Transcript
