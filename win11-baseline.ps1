<#
.SYNOPSIS
  Windows 11 privacy/security baseline (no third‑party software).

.DESCRIPTION
  Applies a developer-friendly, privacy-first configuration using only built-in
  Windows features where possible. Designed for a fresh install of Windows 11.
  Run in an elevated PowerShell (Run as Administrator). A system restore point
  is created first when supported.

  Notes/limits:
  - Switching to a Local Account and setting your default browser still require
    manual steps in Windows 11 Home due to protected OS flows.
  - Tamper Protection toggle is not exposed to PowerShell on Home/Pro.
  - BitLocker is available on Pro/Enterprise/Education; Device Encryption may
    exist on Home—this script detects capability and skips if unavailable.
#>

#-------------------------------
# Helper: Require elevation
#-------------------------------
function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script in an elevated PowerShell (Run as Administrator)."
    exit 1
  }
}
Assert-Admin

#-------------------------------
# Helper: Registry change logger
#-------------------------------
function Write-RegLog {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "[$timestamp] $Message" | Out-File -FilePath "set-reg.log" -Append -Encoding UTF8
}

#-------------------------------
# Helper: Safe registry setter
# Creates registry path if needed and sets value with proper type conversion
#-------------------------------
function Set-Reg {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][Object]$Value,
    [ValidateSet('String','DWord','QWord')][string]$Type='DWord'
  )
  
  # Check existing value
  $existingValue = $null
  $existingType = $null
  try {
    $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
      $existingValue = $existing.$Name
      $existingType = (Get-ItemProperty -Path $Path -Name $Name).PSObject.Properties[$Name].TypeNameOfValue
    }
  } catch {}
  
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
  
  switch ($Type) {
    'String' { New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null }
    'DWord'  { New-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -PropertyType DWord -Force | Out-Null }
    'QWord'  { New-ItemProperty -Path $Path -Name $Name -Value ([long]$Value) -PropertyType QWord -Force | Out-Null }
  }
  
  # Log the change
  if ($existingValue -ne $null) {
    Write-RegLog "MODIFIED: $Path\$Name | Old: $existingValue ($existingType) | New: $Value ($Type)"
  } else {
    Write-RegLog "CREATED: $Path\$Name | Value: $Value ($Type)"
  }
}

#-------------------------------
# 0) Create a System Restore Point (if enabled)
#-------------------------------
Write-Host "Creating a system restore point (if supported)..." -ForegroundColor Cyan
try {
  Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue | Out-Null
  Checkpoint-Computer -Description "Pre-privacy-security-baseline" -RestorePointType "MODIFY_SETTINGS"
} catch {
  Write-Warning "Could not create a restore point (service disabled or not supported). Continuing..."
}

#-------------------------------
# 1) Privacy: Diagnostics & Feedback
#-------------------------------
Write-Host "Configuring Diagnostics & Feedback..." -ForegroundColor Cyan
# AllowTelemetry: 0=Security(Enterprise only), 1=Basic/Required, 3=Full. Home minimum is 1.
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1
# Disable tailored experiences
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
# Silence feedback requests
Set-Reg -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0
# Disable consumer content/suggestions
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Value 1

#-------------------------------
# 2) Privacy: Activity History & Connected Devices
#-------------------------------
Write-Host "Disabling Activity History (Timeline) & CDP..." -ForegroundColor Cyan
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
# Disable Connected Devices Platform (also disables Nearby sharing)
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0

#-------------------------------
# 3) Privacy: Advertising ID & General
#-------------------------------
Write-Host "Turning off Advertising ID and general personalization..." -ForegroundColor Cyan
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
# General personalization toggles
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "PrivacyConsentStatus" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "EnableAdaptivePrivacy" -Value 0

#-------------------------------
# 4) Privacy: Location
#-------------------------------
Write-Host "Disabling Location services (system-wide policy)..." -ForegroundColor Cyan
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1

#-------------------------------
# 5) Privacy: Search & Web
#-------------------------------
Write-Host "Hardening Search (no web, no cloud content)..." -ForegroundColor Cyan
# Disable web search & Bing integration in Start
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0
# Disable cloud content & history in Windows search
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsCloudSearchEnabled" -Value 0
# Disable Search Highlights
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Value 0

#-------------------------------
# 6) Privacy: Background apps
#-------------------------------
Write-Host "Disabling background apps globally (Store apps)..." -ForegroundColor Cyan
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2  # 2=Force deny
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1

#-------------------------------
# 7) Security: Windows Defender (Microsoft Defender) & SmartScreen
#-------------------------------
Write-Host "Configuring Microsoft Defender & SmartScreen..." -ForegroundColor Cyan
# Ensure real-time protection is enabled
try {
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
} catch { Write-Warning "Could not set real-time protection (permissions or policy). $_" }

# Optional: Enable Controlled Folder Access (can break dev tools—enable cautiously)
# Modes: Disabled/Enabled/AuditMode
$EnableCFA = $false  # Set $true if you want it ON by default
try {
  if ($EnableCFA) {
    Set-MpPreference -EnableControlledFolderAccess Enabled
  } else {
    Set-MpPreference -EnableControlledFolderAccess Disabled
  }
} catch { Write-Warning "Controlled Folder Access toggle failed: $_" }

# SmartScreen for apps and files (system-wide)
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Warn" -Type String
# Note: Edge-specific SmartScreen settings are left untouched (you may not use Edge).

#-------------------------------
# 8) Security: Firewall
#-------------------------------
Write-Host "Enabling Windows Firewall for all profiles..." -ForegroundColor Cyan
try {
  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
} catch { Write-Warning "Failed to enforce firewall for all profiles: $_" }

#-------------------------------
# 9) Security: BitLocker / Device Encryption
#-------------------------------
Write-Host "Checking BitLocker/Device Encryption capability..." -ForegroundColor Cyan
function Enable-IfBitLockerAvailable {
  try {
    $bl = Get-Command Enable-BitLocker -ErrorAction Stop
    if ($bl) {
      $osVol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
      if ($osVol -and $osVol.ProtectionStatus -eq 'On') {
        Write-Host "BitLocker already enabled on C:."
      } else {
        Write-Host "Attempting to enable BitLocker on C: (used-space only, TPM)..." -ForegroundColor Yellow
        try {
          Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -TpmProtector -ErrorAction Stop
          Write-Host "BitLocker enable initiated. A reboot may be required to fully activate."
        } catch {
          Write-Warning "BitLocker enable failed (edition, TPM, or policy). $_"
        }
      }
    }
  } catch {
    Write-Host "BitLocker cmdlets not available (Windows edition may be Home). Skipping..."
  }
}
Enable-IfBitLockerAvailable

#-------------------------------
# 10) System: Windows Update hygiene
#-------------------------------
Write-Host "Adjusting Windows Update settings..." -ForegroundColor Cyan
# Turn off "Receive updates for other Microsoft products"
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AllowMUUpdateService" -Value 0

#-------------------------------
# 11) System: Startup items & tips/suggestions
#-------------------------------
Write-Host "Disabling tips/suggestions and startup cruft..." -ForegroundColor Cyan
# Kill OneDrive autorun (doesn't uninstall; you can still use it manually)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
# Group Policy equivalents to reduce consumer suggestions & Spotlight
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
Set-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
# Personalization/Start recommendations off
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
# Lock screen "fun facts, tips, etc."
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0

#-------------------------------
# 12) System: Clipboard sync & Nearby sharing
#-------------------------------
Write-Host "Disabling Clipboard cloud sync & Nearby sharing..." -ForegroundColor Cyan
# Clipboard history ON is fine locally; disable cross-device sync
Set-Reg -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableCloudClipboard" -Value 0
Set-Reg -Path "HKCU:\Software\Microsoft\Clipboard" -Name "CloudClipboardAutomaticUpload" -Value 0
# Nearby sharing already disabled by EnableCdp=0 above

#-------------------------------
# 13) UI: Taskbar Widgets
#-------------------------------
Write-Host "Hiding Widgets button on the taskbar..." -ForegroundColor Cyan
# Windows 11 uses 'TaskbarDa' for Widgets toggle
Set-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0

#-------------------------------
# 14) Browser defaults (manual note)
#-------------------------------
Write-Host @"
[NOTE] Default browser changes are restricted by Windows 11's protected hash.
Please set your preferred browser manually:
  Settings → Apps → Default apps → <Your Browser> → Set for .htm, .html, HTTP, HTTPS.
"@ -ForegroundColor Yellow

#-------------------------------
# 15) Restart Explorer to apply some UX changes
#-------------------------------
Write-Host "Restarting Explorer to apply taskbar/start changes..." -ForegroundColor Cyan
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

Write-Host "`nAll done. You may want to reboot to ensure every policy takes effect." -ForegroundColor Green
