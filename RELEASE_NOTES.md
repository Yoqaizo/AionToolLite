## What's New in AionToolLite v1.2.4 (Hotfix)

This critical hotfix resolves the issue where the installed `AionToolLite.exe` exited silently without opening a window after installation.

### Fixes
* **Fixed Silent Crash After Installation (Embedded Native WPF Libraries):** Enabled `IncludeNativeLibrariesForSelfExtract=true` in `.csproj`, `Publish-Standalone-Exe.bat`, and `Release-Manager.ps1` (plus wildcard `*.dll` fallback in `AionToolLite_Installer.iss`) so all required .NET 8 WPF native runtime libraries (`wpfgfx_cor3.dll`, `PresentationNative_cor3.dll`, `D3DCompiler_47_cor3.dll`, `PenImc_cor3.dll`, `vcruntime140_cor3.dll`) are bundled directly inside `AionToolLite.exe`.
* **Protected `.NET` Extraction Cache:** Updated the built-in Temp Cleaner to preserve `%TEMP%\.net` so single-file native extraction caches are never deleted.
* **Native Fatal Startup Error Dialog:** Added a Win32 `MessageBoxW` fallback in `App.xaml.cs` so any fatal pre-UI error displays clearly instead of closing silently.
* **Clean Tray Restore Animation Reset:** Cleared lingering opacity/scale animations in `RestoreFromTray()` and guarded `MainWindow_Loaded` against duplicate execution.

### Installation & Verification
1. Download **`AionToolLite_Setup_v1.2.4.exe`** below and run it.
2. *(Optional)* Verify integrity against **`checksums.txt`** using PowerShell:
   ```powershell
   Get-FileHash .\AionToolLite_Setup_v1.2.4.exe -Algorithm SHA256
   ```
