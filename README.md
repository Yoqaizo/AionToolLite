<div align="center">
  <img src="AionToolp.png" alt="AionToolLite Logo" width="116" />
  <h1>AionToolLite</h1>
  <p><strong>A sleek, phone-proportioned, one-tap Windows DNS, Hosts &amp; Network Companion built for everyone.</strong></p>

  <p>
    <a href="https://github.com/Yoqaizo/AionToolLite/releases/latest">
      <img src="https://img.shields.io/badge/Version-v1.1.0-B57BFF?style=for-the-badge" alt="Version v1.1.0" />
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

**AionToolLite** brings the essential power of **AionToolPro** into a compact, mobile-inspired vertical desktop app (`424 × 744`) crafted to be effortless for everyone. No terminal commands, no cluttered menus — just one animated button to connect to the fastest DNS, enable native Windows 11 DoH encryption, block ads system-wide, check line stability, or repair your network in seconds.

## Key Features

| Module | What It Does |
| :--- | :--- |
| **One-Tap Power Orb** | Animated connect/disconnect centerpiece with sonar pulse, automatic detection of active Windows DNS across restarts, and instant native cache flush (`DnsFlushResolverCache` + `ipconfig /flushdns`). |
| **25 Verified DNS Servers + 5 Custom Slots** | Real RFC 1035 **UDP/53** latency benchmark, **Smart Auto**, one-tap **Connect to Fastest** banner, star-pinned favorites (`★`), and up to **5 named Saved Custom DNS** slots. |
| **Native Windows 11 DoH Encryption** | One-tap native **DNS-over-HTTPS** (`netsh dns add encryption` with automatic UDP fallback) for supported resolvers including Cloudflare, Google, Quad9, AdGuard, OpenDNS, ControlD, Mullvad, CleanBrowsing, dns0.eu, AliDNS, and Shecan. |
| **Clickable 3-Mode Live Ping** | Tap the ping card on Home to smoothly cycle between **Global (`4.2.2.4`)**, **Local Iran (`ArvanCloud`)**, and **PC-to-Modem Gateway** latency alongside live download/upload speeds. |
| **Physical-First Adapter Scanner** | Uses Windows Registry hardware flags (`NCF_PHYSICAL`) to display only real Ethernet/Wi-Fi adapters — filtering out VPN tunnels (`Wintun`, `WireGuard`, `Sing-box`, `OpenVPN`), `VMware`, `WSL`, and virtual adapters. |
| **Boost, Stability & Network Repair** | **Game Mode**, **Ad & Tracker Shield**, **Quick Fix**, **Full Adapter Reset**, 6-second **Speed Check**, and a 4-second **Stability & Packet Loss / Jitter Check** comparing Modem vs Internet. |
| **Windows Hosts Manager** | Atomic, backup-protected management of Windows `hosts` including built-in **TeamSpeak Custom Fix**, **StevenBlack**, **Peter Lowe**, and **Dan Pollock** blocklists, plus Backup, Restore, Notepad, and Default reset. |
| **System Tray, Auto-Connect & Global Hotkey** | Live emerald status dot on the Tray icon when connected, dark right-click quick-switch menu, **Start with Windows**, **Auto-Connect on Startup**, silent GitHub **Update Badge**, and global **`Ctrl + Alt + D`** toggle hotkey. |
| **Bilingual & 6 Animated Themes** | Instant **English / فارسی (Persian)** switching and 6 smooth-transition themes led by the signature **Aion Lavender** palette. |

---

## Built-In DNS Catalog (25 Servers)

* **Iran & Gaming (8):** Shecan *(DoH)*, Electro, Radar Game, 403 Online, Begzar, Shelter, Shatel DNS, HostIran
* **Global (9):** Cloudflare *(DoH)*, Google DNS *(DoH)*, OpenDNS *(DoH)*, ControlD *(DoH)*, Mullvad DNS *(DoH)*, Yandex DNS, Level3, AliDNS *(DoH)*, 114DNS
* **Ad & Security (8):** AdGuard *(DoH)*, Quad9 *(DoH)*, Cloudflare Safe *(DoH)*, Cloudflare Family *(DoH)*, CleanBrowsing *(DoH)*, dns0.eu *(DoH)*, Comodo Secure, Alternate DNS

---

## Security Architecture

Because network configuration requires `Administrator` privileges, AionToolLite is built with defense-in-depth protections:

* **Admin-Locked Silent Auto-Updater:** Downloads installers exclusively over `TLS 1.2 / 1.3` from verified `github.com` / `.githubusercontent.com` HTTPS hosts (including post-redirect checks) into an NTFS-locked `%ProgramData%\AionToolLite\Updates` folder accessible only to `SYSTEM` and `Administrators`, validates the Windows `MZ` PE header, and verifies `SHA256` against `checksums.txt` before execution.
* **Strict System32 Process Execution:** All Windows utilities (`netsh`, `ipconfig`, `schtasks`, `sc`, `icacls`, `nbtstat`, `notepad`) are resolved strictly from `System32` and invoked via `ProcessStartInfo.ArgumentList`.
* **Symlink & Atomic File Safety:** Hosts writes are serialized with `SemaphoreSlim`, written atomically without UTF-8 BOM via `File.Replace`, and reject `ReparsePoint` / symbolic links across hosts, backups, and temp cleanup.
* **Strict Allowlists & Automatic DNS Backup:** Game Mode only touches an explicit 4-service allowlist, and your original DNS configuration is backed up automatically before the first change.

---

## Installation

1. Go to the [**Latest Release**](https://github.com/Yoqaizo/AionToolLite/releases/latest) page.
2. Download **`AionToolLite_Setup_v1.1.0.exe`**.
3. Run the installer and launch **AionToolLite**.
4. Future updates are flagged automatically by a subtle badge dot on **Settings** and can be installed silently in one click.

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
