## What's New in AionToolLite v1.2.2

A sleek, hardened, one-tap Windows DNS, Hosts & Network Companion — now with smart physical adapter filtering, 25 verified DNS servers, System Tray controls, and verified silent updates.

### Highlights
* **Physical-First Network Adapter Scanner:** Reads Windows hardware registry flags (`NCF_PHYSICAL`) to display only real Ethernet / Wi-Fi / WWAN adapters and cleanly hide VPN tunnels (`Wintun`, `WireGuard`, `Sing-box`, `OpenVPN`, `WARP`, `Tailscale`), `VMware`, `WSL`, and virtual adapters. Hovering any adapter shows its exact hardware name.
* **Expanded DNS Catalog (25 Servers + Smart Auto):** Added Shatel, HostIran, OpenDNS, Mullvad, Yandex, Level3, AliDNS, 114DNS, Cloudflare Safe (`1.1.1.2`), Cloudflare Family (`1.1.1.3`), CleanBrowsing, dns0.eu, Comodo Secure, and Alternate DNS — all benchmarked via real UDP/53 queries.
* **System Tray & Start with Windows:** Minimize to the Windows System Tray with a dark right-click menu (Quick Connect/Disconnect, Switch DNS, Open, Exit) and optional elevated **Start with Windows** (`--minimized`, zero UAC prompts).
* **One-Tap Fastest Banner & Favorite Pins:** Pin your favorite DNS servers (`★`) to the top of the list and Tray menu, and connect directly to the benchmark winner in one click.
* **Automatic DNS Detection & Clean Disconnect:** Automatically detects your active Windows static DNS even after closing and reopening the app, backs up your original DNS before first change, and performs an instant native + OS cache flush on disconnect.
* **Cybersecurity Hardening:** Admin-locked `%ProgramData%` update staging with `SHA256` checksum verification (`checksums.txt`), strict TLS 1.2/1.3 & GitHub HTTPS redirect enforcement, `ReparsePoint`/symlink protection across hosts & temp cleaner, and strict service allowlisting.

### Installation & Verification
1. Download **`AionToolLite_Setup_v1.2.2.exe`** below and run it.
2. *(Optional)* Verify integrity against **`checksums.txt`** using PowerShell:
   ```powershell
   Get-FileHash .\AionToolLite_Setup_v1.2.2.exe -Algorithm SHA256
   ```

> **Note:** Existing installations can update silently in one click from **Settings → Check for Updates**.
