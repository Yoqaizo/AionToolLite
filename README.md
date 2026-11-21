<div align="center">
  <img src="AionToolp.png" alt="AionToolLite Logo" width="110" />
  <h1>AionToolLite</h1>
  <p><strong>A sleek, phone-proportioned, one-tap Windows DNS, Hosts &amp; Network Companion built for everyone.</strong></p>

  <p>
    <a href="https://github.com/Yoqaizo/AionToolLite/releases/latest">
      <img src="https://img.shields.io/badge/Version-v1.2.4-6366F1?style=for-the-badge" alt="Version v1.2.2" />
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

**AionToolLite** brings the core power of **AionToolPro** into a compact, mobile-inspired vertical desktop window (`424 × 744`) designed to be effortless for non-technical users. No confusing menus, no terminal commands — just one animated button to connect to the fastest DNS, switch servers, block ads system-wide, or repair your network in seconds.

## Key Features

| Module | What It Does |
| :--- | :--- |
| **One-Tap Power Orb** | Animated connect/disconnect centerpiece with sonar pulse, automatic detection of active Windows DNS across restarts, and instant native cache flush (`DnsFlushResolverCache` + `ipconfig /flushdns`). |
| **25 Verified DNS Servers + Smart Auto** | Real RFC 1035 **UDP/53** latency benchmark (not just ICMP ping), one-tap **Connect to Fastest** banner, star-pinned favorites (`★`), and custom IPv4 DNS support. |
| **Clickable 3-Mode Live Ping** | Tap the ping card on Home to smoothly cycle between **Global (`4.2.2.4`)**, **Local Iran (`ArvanCloud`)**, and **PC-to-Modem Gateway** latency alongside live download/upload speeds. |
| **Physical-First Adapter Scanner** | Uses Windows Registry hardware flags (`NCF_PHYSICAL`) to show only real Ethernet/Wi-Fi adapters — filtering out VPN tunnels (`Wintun`, `WireGuard`, `Sing-box`, `OpenVPN`), `VMware`, `WSL`, and virtual Wi-Fi clutter. |
| **Boost & Network Repair** | **Game Mode** toggle (safely pauses & restores non-essential background services), **Ad & Tracker Shield** (system-wide hosts ad blocker), **Quick Fix**, **Full Adapter Reset**, and a 6-second **Speed Check**. |
| **Windows Hosts Manager** | Atomic, backup-protected management of Windows `hosts` including built-in **TeamSpeak Custom Fix**, **StevenBlack**, **Peter Lowe**, and **Dan Pollock** blocklists, plus Backup, Restore, Notepad, and Default reset. |
| **System Tray & Auto-Start** | Runs quietly beside the Windows clock with a dark right-click menu for quick Connect/Disconnect and DNS switching, plus optional **Start with Windows** (elevated Task Scheduler, no UAC prompt). |
| **Bilingual & Animated Themes** | Instant **English / فارسی (Persian)** switching and 5 smooth-transition themes (4 glassmorphic dark palettes + Clean Daylight). |

---

## Built-In DNS Catalog (25 Servers)

* **Iran & Gaming (8):** Shecan, Electro, Radar Game, 403 Online, Begzar, Shelter, Shatel DNS, HostIran
* **Global (9):** Cloudflare, Google DNS, OpenDNS, ControlD, Mullvad DNS, Yandex DNS, Level3, AliDNS, 114DNS
* **Ad & Security (8):** AdGuard, Quad9, Cloudflare Safe, Cloudflare Family, CleanBrowsing, dns0.eu, Comodo Secure, Alternate DNS

---

## Security Architecture

Because network configuration requires `Administrator` privileges, AionToolLite is engineered with defense-in-depth protections:

* **Admin-Locked Silent Auto-Updater:** Downloads installers exclusively over `TLS 1.2 / 1.3` from verified `github.com` / `.githubusercontent.com` HTTPS hosts (including post-redirect verification) into an NTFS-locked `%ProgramData%\AionToolLite\Updates` folder accessible only to `SYSTEM` and `Administrators`, validates the Windows `MZ` PE header, and verifies `SHA256` against `checksums.txt` before execution.
* **Strict System32 Process Execution:** All Windows utilities (`netsh`, `ipconfig`, `schtasks`, `sc`, `icacls`, `nbtstat`, `notepad`) are resolved strictly from `System32` and invoked via `ProcessStartInfo.ArgumentList` to eliminate path hijacking and command injection.
* **Symlink & Atomic File Safety:** Hosts writes are serialized with `SemaphoreSlim`, written atomically without UTF-8 BOM via `File.Replace`, and reject `ReparsePoint` / symbolic links across hosts, backups, and temp cleanup.
* **Strict Allowlists & Automatic DNS Backup:** Game Mode only touches an explicit 4-service allowlist, and your original DNS configuration is backed up automatically before the first change.

---

## Installation

1. Go to the [**Latest Release**](https://github.com/Yoqaizo/AionToolLite/releases/latest) page.
2. Download **`AionToolLite_Setup_v1.2.4.exe`**.
3. Run the installer and launch **AionToolLite**.
4. Future updates can be installed silently in one click from **Settings → Check for Updates**.

---

## Building from Source

### Requirements
* Windows 10 or Windows 11 (`x64`)
* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
* [Inno Setup 6 / 7](https://jrsoftware.org/isinfo.php) *(optional, for building the Setup installer)*
* [GitHub CLI (`gh`)](https://cli.github.com/) *(optional, for automated one-click GitHub Releases)*

### Quick Scripts
* **`Build-Release-Exe.bat`** — Fast Release build (`AionToolLite\bin\Release\net8.0-windows\AionToolLite.exe`)
* **`Publish-Standalone-Exe.bat`** — Self-contained single-file `win-x64` executable
* **`Publish-GitHub-Release.bat`** — Interactive Version Manager that syncs versions, pushes to GitHub, builds the standalone binary & Inno Setup installer, generates `checksums.txt`, and publishes a GitHub Release

---

## License

This project is open-source software licensed under the **GNU General Public License v3.0 (GPL-3.0)** — see the [LICENSE](LICENSE) file for full details.

<div align="center">
  <sub>Created by <strong>Yoqaizo</strong></sub>
</div>
