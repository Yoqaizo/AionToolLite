<div align="center">
  <img src="AionToolp.png" alt="AionToolLite Logo" width="116" />
  <h1>AionToolLite</h1>
  <p><strong>A sleek, phone-proportioned, one-tap Windows DNS, Hosts &amp; Network Companion built for everyone.</strong></p>

  <p>
    <a href="https://github.com/Yoqaizo/AionToolLite/releases/latest">
      <img src="https://img.shields.io/badge/Version-v1.1.1-B57BFF?style=for-the-badge" alt="Version v1.1.1" />
    </a>
    <img src="https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" alt=".NET 8.0 WPF" />
    <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 10/11 x64" />
    <a href="LICENSE">
      <img src="https://img.shields.io/badge/License-GPL--3.0-10B981?style=for-the-badge" alt="License GPL-3.0" />
    </a>
  </p>

  <p>
    <a href="https://github.com/Yoqaizo/AionToolLite/releases/latest"><strong>⬇ Download Latest Installer</strong></a>
    &nbsp;·&nbsp;
    <a href="CHANGELOG.md">Changelog</a>
    &nbsp;·&nbsp;
    <a href="https://github.com/Yoqaizo/AionToolLite/issues">Report a Bug</a>
  </p>
</div>

---

## Overview

**AionToolLite** brings the core networking tools of **AionToolPro** into a compact vertical desktop companion (`424 × 744`, auto-fitting shorter/DPI-scaled displays). Connect to a DNS server with one click, toggle native Windows 11 DNS-over-HTTPS, check modem vs. internet packet loss and jitter, manage Windows `hosts`, or restart a stuck adapter safely.

## Key Features

| Module | What It Does |
| :--- | :--- |
| **One-Tap Power Orb** | Animated connect/disconnect control that backs up your original IPv4 (including `127.0.0.1` local resolvers) and IPv6 DNS on first change, restores them cleanly on disconnect, and flushes the Windows DNS cache. |
| **25 DNS Presets + 5 Custom Slots** | Real RFC 1035 **UDP/53** latency benchmark, **Smart Auto** (strictly limited to 6 neutral, unfiltered global resolvers), one-tap **Connect to Fastest**, `★` pinned favorites, and up to **5 named Saved Custom DNS** slots. |
| **Native Windows 11 DoH Encryption** | One-tap native **DNS-over-HTTPS** (`netsh dns add encryption` with `udpfallback=yes`) on supported resolvers, plus IPv6 DNS leak warnings when an IPv4-only preset is active alongside router IPv6 DNS. |
| **Clickable 3-Mode Live Ping** | Cycle between **Global (`4.2.2.4`)**, **Iran Intranet** (`ArvanCloud` with automatic Iranian fallback), and **Modem Gateway** latency alongside live adapter download/upload rates. |
| **Physical-First Adapter Scanner** | Uses Windows Registry hardware flags (`NCF_PHYSICAL`) across all Windows display languages (including disabled physical NICs) while filtering out VPN tunnels (`Wintun`, `WireGuard`, `Sing-box`, `OpenVPN`), `VMware`, `WSL`, and virtual adapters. |
| **Boost, Stability & Scoped Adapter Reset** | **Game Mode** (allowlisted 4 services with reboot detection), **Ad & Tracker Shield**, **Quick Fix**, **Scoped Adapter Reset** (restarts only the chosen adapter without wiping global static IPs), 6-second **Speed Check**, and a 4-second **Stability & Packet Loss / Jitter Check** (detecting routers that drop ICMP separately). |
| **Windows Hosts Manager** | Serialized (`SemaphoreSlim`), fail-closed backup-protected management of Windows `hosts` with lightweight and full blocklists, clean original/manual Restore, Notepad shortcut, and Default reset. |
| **System Tray, Auto-Connect & Hotkey** | Emerald connection badge on the Tray icon (kept in sync even while minimized), **Start with Windows** via battery-safe XML Task Scheduler, network-ready **Auto-Connect on Startup**, silent GitHub **Update Badge**, and global **`Ctrl + Alt + D`** toggle. |
| **Clean Uninstall** | The uninstaller automatically restores backed-up original DNS, original `hosts` (or removes all AionTool-managed blocks), and paused Game Mode services before deleting app files. |

---

## Built-In DNS Catalog (25 Servers)

* **Smart Auto Eligible (6 Unfiltered Global Resolvers):** Cloudflare *(DoH + IPv6)*, Google DNS *(DoH + IPv6)*, OpenDNS *(DoH + IPv6)*, ControlD *(DoH + IPv6)*, Mullvad DNS *(Unfiltered `194.242.2.2` + `2a07:e340::2`, DoH)*, Level3
* **Other Global (3):** Yandex DNS *(IPv6)*, AliDNS *(DoH + IPv6)*, 114DNS
* **Iran & Gaming (8):** Shecan *(DoH)*, Electro, Radar Game, 403 Online, Begzar, Shelter, Shatel DNS, HostIran
* **Ad & Security (8):** AdGuard *(DoH + IPv6)*, Quad9 *(DoH + IPv6)*, Cloudflare Safe *(DoH + IPv6)*, Cloudflare Family *(DoH + IPv6)*, CleanBrowsing *(DoH + IPv6)*, dns0.eu *(DoH + IPv6)*, Comodo Secure, Alternate DNS

---

## Security Architecture

Because changing Windows network configuration requires `Administrator` privileges, AionToolLite enforces strict, fail-closed security boundaries:

* **Fail-Closed Cryptographic Auto-Updater:**
  * Downloads strictly over `TLS 1.2 / 1.3` from verified `github.com` / `.githubusercontent.com` HTTPS hosts (including post-redirect verification).
  * Requires a matching `SHA256` entry in `checksums.txt` (verified in constant time) **and** an independent cryptographic trust anchor—either a detached **RSA-3072 / SHA-256** signature (`checksums.txt.sig`) verified against the developer's offline public key pinned at build time, or a matching Windows **Authenticode** publisher signature (`WinVerifyTrust`). Unsigned/unpinned local builds refuse silent admin auto-installation and direct users to download manually.
  * Stages updates inside a freshly created random directory under `%ProgramFiles%\AionToolLite\Updates` created atomically with admin-only NTFS ACLs (`SYSTEM` + `Administrators`), verifying ancestor and staging folder ownership before download and again before execution.
* **Admin-Only Privileged State & Backups:** `hosts.backup.*`, `dns_original_backup.json`, and `gamemode_state.json` are stored in `%ProgramFiles%\AionToolLite\State` (owned by `Administrators`, writable only by `SYSTEM` and `Administrators`) and verified before every read/restore—preventing same-user tampering via `%APPDATA%`. Only non-privileged UI settings live in `%APPDATA%`.
* **Elevated Auto-Start Restricted to `Program Files`:** Registering the elevated logon task is refused unless `AionToolLite.exe` and every ancestor directory up through `Program Files` are non-symlink, admin-owned, and non-user-writable. The scheduled task XML disables battery termination and the 72-hour execution timeout.
* **System32-Only Process Execution & Non-Recursive Temp Cleanup:** System utilities are resolved strictly from `System32`, invoked via `ProcessStartInfo.ArgumentList` with native Win32 OEM output decoding, and the confirmed Temp cleaner deletes only individual files older than 24 hours and empty non-reparse folders.

---

## Installation

1. Go to the [**Latest Release**](https://github.com/Yoqaizo/AionToolLite/releases/latest) page.
2. Download **`AionToolLite_Setup_v1.1.1.exe`**.
3. Run the installer (installs to `C:\Program Files\AionToolLite`) and launch **AionToolLite**.
4. Verify integrity optionally with `Get-FileHash .\AionToolLite_Setup_v1.1.1.exe -Algorithm SHA256` against `checksums.txt`.

---

## Building from Source

### Requirements
* Windows 10 or Windows 11 (`x64`)
* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
* [Inno Setup 6 or 7](https://jrsoftware.org/isinfo.php) *(optional, for compiling `AionToolLite_Installer.iss`)*

### Build Commands
```powershell
# Fast Release build
dotnet build AionToolLite\AionToolLite.csproj -c Release

# Self-contained single-file Windows x64 executable (with embedded native WPF libraries)
dotnet publish AionToolLite\AionToolLite.csproj -c Release -r win-x64 --self-contained true `
  /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true `
  /p:PublishReadyToRun=true /p:EnableCompressionInSingleFile=true `
  /p:DebugType=None /p:DebugSymbols=false
```

---

## License

This project is open-source software licensed under the **GNU General Public License v3.0 (GPL-3.0)** — see the [LICENSE](LICENSE) file for full details.

<div align="center">
  <sub>Created by <strong>Yoqaizo</strong></sub>
</div>
