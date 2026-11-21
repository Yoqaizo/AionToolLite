# Changelog

All notable changes to **AionToolLite** are documented in this file.

## [1.2.4] - 2026-11-21
### Fixed
- **Critical:** Fixed silent exit after installation by embedding all .NET 8 WPF native DLLs (`IncludeNativeLibrariesForSelfExtract=true`), cleaning `win-x64\publish` before publish, and adding `*.dll` fallback packaging to `AionToolLite_Installer.iss`.
- Protected `%TEMP%\.net` from deletion inside `CleanOldTempFilesAsync()`.
- Added native Win32 `MessageBoxW` fallback for fatal `AppDomain.UnhandledException` errors so startup failures never die silently.
- Cleared active animation clocks in `RestoreFromTray()` and added `_loadedOnce` guard to `MainWindow_Loaded`.

## [1.2.3] - 2026-11-21
### Fixed
- Fixed Inno Setup `CreateProcess failed; code 740` on finish/launch by adding `runascurrentuser shellexec` to `[Run]` in `AionToolLite_Installer.iss`.
- Fixed Minimize-to-Tray intercepting external `WM_CLOSE` requests from Inno Setup upgrades and Windows shutdown (`SessionEnding` hook + direct `HideToTray` on `✕` click).
- Fixed silent auto-updater `timeout.exe` non-console exit by switching to System32 `ping.exe` + `taskkill.exe` with outer-quoted `cmd.exe /c`.
- Enhanced `Scripts/Release-Manager.ps1` to cleanly attach to existing GitHub `origin/main` commit history when run from a freshly extracted folder.

## [1.2.2] - 2026-11-21
### Changed
- Rewrote `ScanAdaptersAsync` with a **Physical-First** hardware scanner using Windows Registry `NCF_PHYSICAL` flags and MAC/IPv4 checks to hide virtual, WSL, VM, and VPN/TUN adapters.
- Added adapter hardware tooltip and prioritized connected adapters with an active IPv4 default gateway.
- Added dynamic assembly version syncing in UI footer and HTTP `User-Agent`.
- Added official `GNU GPL v3.0` `LICENSE`, professional `README.md`, `RELEASE_NOTES.md`, and automated `Publish-GitHub-Release.bat` version/release manager.

## [1.2.1] - 2026-11-21
### Security
- Hardened auto-updater with NTFS ACL-locked `%ProgramData%\AionToolLite\Updates` staging, post-redirect GitHub HTTPS verification, 150 MB size cap, `MZ` PE header check, and `SHA256` checksum validation.
- Enforced `TLS 1.2 / TLS 1.3` on `HttpClient` and strict domain matching for GitHub URLs.
- Added `ReparsePoint` / symlink checks for hosts writes, backup restores, and temp cleanup.
- Enforced strict service allowlist for Game Mode and scoped IPC Mutex/Event to `Local\`.
- Added automatic removal of scheduled startup task and `%ProgramData%` staging folder on uninstall.
### Added
- Expanded built-in DNS catalog to **25 verified servers** + Smart Auto.
- Suppressed `WFAC010` analyzer warning for clean zero-warning WPF + WinForms Tray builds.

## [1.2.0] - 2026-11-21
### Added
- Added System Tray (`TrayManager`) with dark quick-action right-click menu and single-instance wake event.
- Added **Start with Windows** (`schtasks` elevated `--minimized`) and **Minimize to Tray** settings.
- Added one-tap **Fastest Server Found** connect banner and star-pinned favorite DNS servers (`★`).
- Added automatic first-time backup of original DNS configuration (`dns_original_backup.json`).
### Fixed
- Fixed WPF `MC4111` / frozen `ScaleTransform` triggers by targeting `FrameworkElement`s cleanly across `App.xaml` and `MainWindow.xaml`.
- Fixed stale `ProfileNameServer` detection, serialized IPv4/IPv6 `netsh` updates, and added `SemaphoreSlim` locking for hosts writes.

## [1.1.1] - 2026-11-21
### Changed
- Removed duplicate TeamSpeak toggle and Disable Proxy button for a cleaner Tools view.
- Added startup & continuous detection of active Windows static DNS with active status pill and fast native `DnsFlushResolverCache` disconnect.

## [1.1.0] - 2026-11-21
### Added
- Added clickable 3-mode Live Ping card (Global `4.2.2.4` → Local Iran `ArvanCloud` → Modem Gateway).
- Added **Full Network Fix** (complete adapter reset protocol) beneath Quick Fix.
- Added **Utilities & Hosts** tab with Windows hosts manager, TeamSpeak custom fix, blocklists, Public IP check, and old temp cleaner.

## [1.0.0] - 2026-11-21
### Added
- Initial release of **AionToolLite** with phone-proportioned glassmorphic WPF UI, animated Power Orb, Smart Auto UDP/53 DNS selector, Game Mode, Ad & Tracker Shield, Speed Check, bilingual English/Persian UI, and 5 animated themes.
