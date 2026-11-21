## What's New in AionToolLite v1.2.3 (Hotfix)

This hotfix resolves the installer post-install launch error (`CreateProcess failed; code 740`) and improves silent auto-update and upgrade reliability.

### Fixes
* **Fixed Installer Launch Error (`code 740`):** Updated Inno Setup `[Run]` launch flags to `nowait postinstall runascurrentuser shellexec` so `AionToolLite.exe` launches smoothly with administrator privileges right after installation and after silent updates without triggering `CreateProcess failed; code 740`.
* **Improved Upgrade & Shutdown Closing:** Only the in-app `✕` button minimizes to the System Tray; external close signals (such as Inno Setup Restart Manager during upgrades or Windows shutdown) now exit the app cleanly without leaving file locks.
* **Hardened Silent Auto-Updater Wait Logic:** Replaced `timeout.exe` (which fails in non-console GUI contexts) with System32 `ping.exe` + `taskkill.exe` and safe outer quoting so silent in-app updates cleanly close the old instance, install the new version, and relaunch automatically.
* **Smarter Release Script (`Publish-GitHub-Release.bat`):** Automatically syncs with existing `origin/main` history even when run from a freshly extracted folder.

### Installation & Verification
1. Download **`AionToolLite_Setup_v1.2.3.exe`** below and run it.
2. *(Optional)* Verify integrity against **`checksums.txt`** using PowerShell:
   ```powershell
   Get-FileHash .\AionToolLite_Setup_v1.2.3.exe -Algorithm SHA256
   ```

> **Tip:** Users on `v1.2.2` can also update directly from **Settings → Check for Updates**.
