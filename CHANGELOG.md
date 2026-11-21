# Changelog

All notable changes to **AionToolLite** are documented in this file.

## [1.1.0] - 2026-11-21
### Added
- **Native Windows 11 DoH Encryption:** One-tap DoH toggle (`netsh dns add encryption` with `udpfallback=yes`) and `DoH` micro-badges on supported resolvers.
- **Stability & Packet Loss / Jitter Check:** 4-second diagnostic comparing Modem Gateway vs. Internet (`4.2.2.4`) with separate detection for routers that block ICMP.
- **5 Saved Custom DNS Slots:** Named custom IPv4 DNS slots (up to 5) with `★` pinning, `✕` deletion, UDP/53 benchmarking, and Tray quick-switching.
- **Tray Connected Status Dot & Global Hotkey (`Ctrl + Alt + D`):** Dynamic emerald status dot on the Tray icon (synced even when minimized) and toggleable Win32 `RegisterHotKey` shortcut.
- **Network-Ready Auto-Connect on Startup & Silent Update Badge:** Retries adapter readiness on logon and shows a non-blocking update indicator on Settings.
- **Clean Uninstall Restoration (`--uninstall-cleanup`):** Uninstaller automatically restores original DNS, original `hosts` (or removes managed blocks), and paused Game Mode services before removing files.

### Security & Hardening
- **Fail-Closed Signed Updater:** Enforced mandatory `SHA256` (`checksums.txt`) plus offline **RSA-3072** detached signature (`checksums.txt.sig`) and/or `WinVerifyTrust` Authenticode verification; unsigned builds refuse silent admin updates.
- **Admin-Owned Atomic Staging & State Storage:** Moved update staging and privileged backups/state (`hosts.backup.*`, `dns_original_backup.json`, `gamemode_state.json`) to owner- and DACL-verified admin-only directories under `%ProgramFiles%\AionToolLite`.
- **Restricted Elevated Auto-Start & Laptop-Safe Task XML:** Elevated logon tasks are only permitted from admin-owned `Program Files` installations and disable battery stop and the 72-hour timeout.

### Fixed
- Removed destructive global `netsh int ip reset` from Full Network Fix (now scoped to the chosen adapter).
- Replaced recursive Temp folder deletion with safe non-recursive file-only deletion (>24h creation & write time) plus confirmation prompt.
- Made hosts backups fail-closed before apply/reset, separated manual vs. original backups, serialized read-modify-write under `_hostsLock`, and tightened blocklist tag matching.
- Fixed lossless original DNS backup/restore for `127.0.0.1` loopback and static IPv6 DNS, and restored original DNS on normal Disconnect.
- Added IPv6 leak warning on IPv4-only presets and partial-failure reporting for secondary/IPv6 DNS steps.
- Restricted **Smart Auto** to 6 neutral, unfiltered global resolvers and fixed Mullvad DNS secondary (`194.242.2.2` + `2a07:e340::2` unfiltered).
- Added native Win32 OEM output decoding (`MultiByteToWideChar`) and Registry-based locale-independent disabled adapter detection.
- Added boot-timestamp tracking for Game Mode so stale state clears automatically after a reboot.
- Fixed Alt+F4 / taskbar Close minimizing to Tray while allowing Shutdown / Restart Manager to exit cleanly; clamped window height for 768p/DPI displays; added explicit `📋` copy button for Public IP; fixed DoH toggle revert on failure; added large-blocklist warning; made regional ping channel locale-aware.

## [1.0.0] - 2026-11-21
### Added
- **Initial Official Release of AionToolLite** (.NET 8 WPF, Windows 10/11 x64, GNU GPL v3.0).
- New custom squircle robot logo (`AionToolp.png` & multi-resolution hybrid BMP/PNG `AionToolp.ico`) and signature **Aion Lavender** default theme alongside 5 additional animated themes.
- Phone-proportioned glassmorphic UI with bilingual **English / فارسی** support and animated **Power Orb** (Connect / Disconnect with sonar pulse, active DNS detection, original DNS backup, and native `DnsFlushResolverCache` cleanup).
- **25 verified DNS presets + Smart Auto** with real UDP/53 latency benchmarking, one-tap **Connect to Fastest** banner, star-pinned favorites (`★`), and custom IPv4 DNS.
- Clickable 3-mode Live Ping card (Global `4.2.2.4` → Local Iran `ArvanCloud` → Modem Gateway) and live adapter traffic monitor.
- Physical-first hardware network adapter scanner (`NCF_PHYSICAL` registry verification) filtering out VPN, WSL, VM, and virtual interfaces.
- **Boost & Repair** tools: safe allowlisted **Game Mode**, system-wide **Ad & Tracker Shield**, **Quick Network Fix**, **Full Network Fix** (complete adapter reset), and 6-second **Speed Check**.
- **Utilities & Hosts** tab: atomic backup-protected Windows `hosts` manager with built-in **TeamSpeak Custom Fix**, StevenBlack / Peter Lowe / Dan Pollock blocklists, Public IP checker, and symlink-safe old Temp cleaner.
- **System Tray** integration with dark right-click quick-switch menu, single-instance wake event, and optional elevated **Start with Windows** (`--minimized`).
- Hardened silent GitHub Auto-Updater with admin-locked `%ProgramData%` staging, `TLS 1.2/1.3`, `MZ` PE header validation, and `SHA256` checksum verification (`checksums.txt`).
- Self-contained single-file packaging (`IncludeNativeLibrariesForSelfExtract=true`) and Inno Setup 6/7 installer with `runascurrentuser shellexec` launch and automatic pre-install cleanup.
