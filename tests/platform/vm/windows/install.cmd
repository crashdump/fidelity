@echo off
rem Installs Windows onto the guest disk, with no person and no Setup UI.
rem
rem Windows 11 25H2 boots a new Setup that ignores an answer file on its first
rem pages, measured on 2026-08-15: it stops on the language page and honors
rem neither an auto-discovered `autounattend.xml` nor an explicit
rem `setup.exe /unattend:`. So this script does the install that Setup would,
rem with the tools that WinPE carries, and every step here is one that Setup
rem hides.
rem
rem The Packer boot command reaches a WinPE command prompt and runs this file
rem from the answer disk. WinPE assigns the drive letters, so this searches
rem for the two volumes rather than name them.
setlocal

set WIM=
for %%d in (C D E F G H I) do if exist %%d:\sources\install.wim set WIM=%%d:\sources\install.wim
set ANS=
for %%d in (C D E F G H I) do if exist %%d:\install.cmd set ANS=%%d:
echo the image is %WIM%
echo the answer disk is %ANS%
if "%WIM%"=="" ( echo no install.wim found & exit /b 1 )
if "%ANS%"=="" ( echo no answer disk found & exit /b 1 )

rem The guest disk is one NVMe device, and it is disk 0. GPT, an EFI system
rem partition, the reserved partition that Windows wants, and the rest for
rem Windows.
(
  echo select disk 0
  echo clean
  echo convert gpt
  echo create partition efi size=300
  echo format quick fs=fat32 label=System
  echo assign letter=S
  echo create partition msr size=16
  echo create partition primary
  echo format quick fs=ntfs label=Windows
  echo assign letter=W
) > X:\diskpart.txt
diskpart /s X:\diskpart.txt || ( echo diskpart failed & exit /b 1 )

rem Index 3 is Windows 11 Pro on the pinned 25H2 media, read with
rem `dism /get-wiminfo`. Pro takes an unattended first boot that Home does not.
dism /apply-image /imagefile:%WIM% /index:3 /applydir:W:\ || ( echo apply failed & exit /b 1 )

rem The virtio network driver, injected into the offline image, so the
rem installed system has a network at its first boot. Without it the guest
rem reports no adapter and the first-logon script cannot reach Windows Update.
rem The exit code matters here. A driver that does not inject leaves the guest
rem with no network, and the build then waits two hours for an SSH server that
rem cannot start. A stop here names the cause instead.
dism /image:W:\ /add-driver /driver:%ANS%\drivers\netkvm /recurse || ( echo the driver did not inject & exit /b 1 )

rem The first-logon script and its data, on the system drive, so a boot does
rem not depend on the answer disk staying attached.
copy %ANS%\setup.ps1 W:\setup.ps1
xcopy /e /i /y %ANS%\drivers W:\drivers\

rem The answer file drives the specialize and oobe passes from the standard
rem offline location: it creates the account, skips the OOBE pages, and runs
rem the first-logon script. Its windowsPE pass is gone, because this script
rem is that pass now.
mkdir W:\Windows\Panther
copy %ANS%\autounattend.xml W:\Windows\Panther\unattend.xml

rem The boot files on the EFI system partition. bcdboot writes the Windows
rem boot manager to \EFI\Microsoft\Boot, and the copy to \EFI\Boot is the
rem removable-media default that this firmware always tries. The copy means
rem the disk boots whether or not the firmware keeps an NVRAM entry.
bcdboot W:\Windows /s S: /f UEFI || ( echo bcdboot failed & exit /b 1 )
mkdir S:\EFI\Boot
copy S:\EFI\Microsoft\Boot\bootmgfw.efi S:\EFI\Boot\bootaa64.efi

echo the install is done, rebooting into Windows
wpeutil reboot
