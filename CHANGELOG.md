# Changelog

All notable changes to **AionToolLite** are documented in this file.

## [1.1.0] - 2026-11-21
### Added
- **Native Windows 11 DoH Encryption:** Added one-tap DoH toggle (`netsh dns add encryption` with `udpfallback=yes`) and `DoH` micro-badges across 13 supported built-in DNS servers.
- **Stability & Packet Loss / Jitter Check:** Added 4-second Boost diagnostic comparing Modem Gateway vs Internet (`4.2.2.4`) latency, jitter, and packet loss with automatic root-cause verdict.
- **5 Saved Custom DNS Slots:** Added named custom DNS persistence (up to 5 slots) with pin (`★`), delete (`✕`), UDP/53 benchmarking, Smart Auto inclusion, and Tray quick-switch support.
- **Tray Connected Status Dot & Global Hotkey (`Ctrl + Alt + D`):** Added dynamic emerald badge on the System Tray icon when connected (with GDI `DestroyIcon` cleanup) and toggleable Win32 `RegisterHotKey` support.
- **Auto-Connect on Startup:** Added optional setting to automatically connect the selected DNS / Smart Auto on app launch.
- **Silent Startup Update Badge:** Added non-blocking background GitHub release check showing a subtle dot on Settings when a newer version is available.

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
