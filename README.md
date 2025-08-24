# Windows 11 Initial Setup

A PowerShell script to configure Windows 11 with privacy-first and security-focused settings for personal use.

## Purpose

This project applies a baseline configuration to improve basic security and privacy on a fresh Windows 11 installation using only built-in Windows features.

## Features

- **Privacy Controls**: Disables telemetry, advertising ID, location services, and background apps
- **Security Hardening**: Enables Windows Defender, firewall, and BitLocker (where available)
- **System Cleanup**: Removes startup bloat, tips/suggestions, and unnecessary features
- **Logging**: Tracks all registry changes to `set-reg.log`
- **Restore Points**: Creates system restore point before changes (configurable)

## Requirements

- Windows 11 (Home/Pro/Enterprise/Education)
- PowerShell running as Administrator
- Fresh installation recommended

## Usage

1. Right-click PowerShell and select "Run as Administrator"
2. Navigate to the script directory
3. Run: `.\win11-baseline.ps1`

## Configuration

Edit these variables at the top of the script:

```powershell
$CreateRestorePoint = $true   # Set to $false to skip restore point
```

## What It Does

- **Privacy**: Minimizes telemetry, disables advertising ID, location services
- **Search**: Removes Bing integration and web search from Start menu
- **Security**: Enables Windows Defender, firewall, and BitLocker (if supported)
- **UI**: Disables widgets, tips, and promotional content
- **Apps**: Prevents background apps from running

## Limitations

- Some settings require manual configuration on Windows 11 Home
- BitLocker availability depends on Windows edition and TPM
- Tamper Protection toggle not accessible via PowerShell on Home/Pro

## Files

- `win11-baseline.ps1` - Main configuration script
- `set-reg.log` - Registry change log (created during execution)
- `.vscode/settings.json` - VSCode workspace settings for PowerShell formatting