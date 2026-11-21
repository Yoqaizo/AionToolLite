using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using AionToolLite.Models;

namespace AionToolLite.Services
{
    public sealed class LiteNetworkService
    {
        private const string AdShieldTag = "AIONLITE-ADSHIELD";
        private const string TeamSpeakTag = "TeamSpeak-Blocked";
        private const string AutoStartTaskName = "AionToolLite_AutoStart";
        private const string AdShieldUrl = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext";
        private const long MaxConfigFileBytes = 64 * 1024;
        private const long MaxBlocklistBytes = 12 * 1024 * 1024;
        private const long MaxUpdaterBytes = 150 * 1024 * 1024;
        private const int MaxBlocklistEntries = 200_000;
        private const int MaxBackupsToKeep = 10;

        private readonly ProcessRunner _runner = new();
        private readonly object _ioLock = new();
        private readonly SemaphoreSlim _hostsLock = new(1, 1);
        private static readonly byte[] PingPayload = new byte[16];
        private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
        private readonly ConcurrentDictionary<string, (IPAddress Ip, DateTime ExpiresUtc)> _resolveCache = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HttpClient SharedHttp = CreateHttpClient();

        private readonly string _cfgDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AionToolLite");
        private readonly string _secureUpdatesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AionToolLite", "Updates");
        private readonly string _hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

        private static readonly HashSet<string> AllowedGameModeServices = new(StringComparer.OrdinalIgnoreCase)
        {
            "SysMain", "DiagTrack", "WSearch", "wuauserv"
        };

        private static readonly string[] IgnoredAdapters =
        {
            "Loopback", "vEthernet", "WSL", "Hyper-V", "VMware", "VMnet", "VirtualBox",
            "Virtual", "Wi-Fi Direct", "Hosted Network", "Local Area Connection*",
            "Teredo", "ISATAP", "6to4", "Bluetooth", "Miniport", "Filter", "Kernel Debug",
            "Npcap", "WinPcap", "Wintun", "WireGuard", "TAP-Windows", "OpenVPN",
            "Tailscale", "ZeroTier", "Radmin", "Hamachi", "Cloudflare", "WARP",
            "Sing-box", "singbox", "sing-tun", "Nekoray", "NekoBox", "Hiddify",
            "Clash", "mihomo", "v2ray", "Xray", "Outline", "Amnezia", "ProtonVPN",
            "NordLynx", "NordVPN", "ExpressVPN", "Surfshark", "Windscribe", "Mullvad",
            "SoftEther", "Fortinet", "Cisco AnyConnect", "AnyConnect", "PANGP",
            "GlobalProtect", "Check Point", "ExitLag", "GearUP", "LagoFast",
            "KM-TEST", "Pseudo", "Multiplexor", "Bridge", "Packet Scheduler",
            "RAS Async", "VPN", "utun", "tun0"
        };

        private static readonly char[] ForbiddenInterfaceChars = { '\r', '\n', '\0', '"', '\'', '&', '|', ';', '<', '>' };
        private static readonly char[] ForbiddenShellChars = { '\r', '\n', '\0', '"', '&', '|', ';', '<', '>', '^', '%' };

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        private string SettingsFilePath => Path.Combine(_cfgDir, "settings.json");
        private string GameModeStatePath => Path.Combine(_cfgDir, "gamemode_state.json");
        private string HostsOriginalBackupPath => Path.Combine(_cfgDir, "hosts.backup.original");
        private string OriginalDnsBackupPath => Path.Combine(_cfgDir, "dns_original_backup.json");

        private static HttpClient CreateHttpClient()
        {
            var handler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                AutomaticDecompression = DecompressionMethods.All,
                MaxAutomaticRedirections = 5,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }
            };
            var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            string uaVer = v != null ? $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}" : "1.1.0";
            c.DefaultRequestHeaders.UserAgent.ParseAdd($"AionToolLite/{uaVer}");
            return c;
        }

        // ==================== SECURITY HELPERS ====================
        private static bool IsReparsePoint(string path)
        {
            try
            {
                if (!File.Exists(path) && !Directory.Exists(path)) return false;
                return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
            }
            catch
            {
                return true;
            }
        }

        private static bool TryValidateInterfaceName(string? interfaceName, out string sanitized)
        {
            sanitized = string.Empty;
            if (string.IsNullOrWhiteSpace(interfaceName)) return false;
            string trimmed = interfaceName.Trim();
            if (trimmed.Length == 0 || trimmed.Length > 128) return false;
            if (trimmed.IndexOfAny(ForbiddenInterfaceChars) >= 0) return false;
            sanitized = trimmed;
            return true;
        }

        private static string? ReadSmallJsonTextSafe(string path)
        {
            if (!File.Exists(path) || IsReparsePoint(path)) return null;
            var fi = new FileInfo(path);
            if (fi.Length == 0 || fi.Length > MaxConfigFileBytes) return null;
            return File.ReadAllText(path, Encoding.UTF8);
        }

        private static string SanitizeHeaderToken(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "Unknown";
            return input.Replace("\r", "").Replace("\n", "").Replace(":", "-").Trim();
        }

        // ==================== FAST NATIVE DNS CACHE FLUSH ====================
        private async Task FastFlushDnsCacheAsync(CancellationToken token)
        {
            _resolveCache.Clear();
            try { DnsFlushResolverCache(); } catch { }
            try { await _runner.RunAsync("ipconfig", new[] { "/flushdns" }, token, TimeSpan.FromSeconds(6)).ConfigureAwait(false); } catch { }
        }

        // ==================== AUTOMATIC ORIGINAL DNS BACKUP ====================
        private void EnsureOriginalDnsBackupSaved(string interfaceName)
        {
            lock (_ioLock)
            {
                try
                {
                    Directory.CreateDirectory(_cfgDir);
                    string? existingJson = ReadSmallJsonTextSafe(OriginalDnsBackupPath);
                    var map = !string.IsNullOrEmpty(existingJson)
                        ? JsonSerializer.Deserialize<Dictionary<string, OriginalDnsBackup>>(existingJson)
                          ?? new Dictionary<string, OriginalDnsBackup>(StringComparer.OrdinalIgnoreCase)
                        : new Dictionary<string, OriginalDnsBackup>(StringComparer.OrdinalIgnoreCase);

                    if (map.ContainsKey(interfaceName))
                        return;

                    var current = DetectActiveStaticDns(interfaceName);
                    map[interfaceName] = new OriginalDnsBackup(
                        interfaceName,
                        WasDhcp: !current.IsStaticConnected,
                        PrimaryIp: current.PrimaryIp,
                        SecondaryIp: current.SecondaryIp,
                        SavedAtUtc: DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));

                    File.WriteAllText(OriginalDnsBackupPath, JsonSerializer.Serialize(map, JsonOpts), new UTF8Encoding(false));
                }
                catch { }
            }
        }

        public OriginalDnsBackup? GetOriginalDnsBackup(string interfaceName)
        {
            lock (_ioLock)
            {
                try
                {
                    string? json = ReadSmallJsonTextSafe(OriginalDnsBackupPath);
                    if (string.IsNullOrEmpty(json)) return null;
                    var map = JsonSerializer.Deserialize<Dictionary<string, OriginalDnsBackup>>(json);
                    if (map == null) return null;
                    foreach (var kv in map)
                    {
                        if (kv.Key.Equals(interfaceName, StringComparison.OrdinalIgnoreCase))
                            return kv.Value;
                    }
                }
                catch { }
                return null;
            }
        }

        public async Task<OperationResult> RestoreOriginalDnsAsync(string interfaceName, CancellationToken token = default)
        {
            var backup = GetOriginalDnsBackup(interfaceName);
            if (backup != null && !backup.WasDhcp && LiteCatalog.IsSafeDnsIpv4(backup.PrimaryIp))
            {
                var r = await ApplyDnsAsync(
                    interfaceName,
                    backup.PrimaryIp,
                    string.IsNullOrWhiteSpace(backup.SecondaryIp) ? null : backup.SecondaryIp,
                    "Original DNS",
                    skipBackup: true,
                    token: token).ConfigureAwait(false);

                return r.Success
                    ? new OperationResult(true, $"Restored your original DNS ({backup.PrimaryIp}).", $"دی‌ان‌اس قبلی شما ({backup.PrimaryIp}) بازیابی شد.")
                    : r;
            }

            return await DisconnectDnsToAutoAsync(interfaceName, token).ConfigureAwait(false);
        }

        // ==================== AUTOMATIC ACTIVE STATIC DNS DETECTION ====================
        public Task<ActiveDnsStatus> DetectActiveStaticDnsAsync(string interfaceName, IReadOnlyList<SavedCustomDnsEntry>? customEntries = null)
        {
            return Task.Run(() => DetectActiveStaticDns(interfaceName, customEntries));
        }

        public ActiveDnsStatus DetectActiveStaticDns(string interfaceName, IReadOnlyList<SavedCustomDnsEntry>? customEntries = null)
        {
            try
            {
                if (!TryValidateInterfaceName(interfaceName, out string iface))
                    return ActiveDnsStatus.Automatic;

                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.Name.Equals(iface, StringComparison.OrdinalIgnoreCase));

                if (nic == null)
                    return ActiveDnsStatus.Automatic;

                string? rawStatic = null;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{nic.Id}", false);
                    if (key != null)
                    {
                        rawStatic = key.GetValue("NameServer") as string;
                    }
                }
                catch { }

                if (string.IsNullOrWhiteSpace(rawStatic))
                    return ActiveDnsStatus.Automatic;

                var ips = rawStatic
                    .Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(LiteCatalog.IsSafeDnsIpv4)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (ips.Count == 0)
                    return ActiveDnsStatus.Automatic;

                string primary = ips[0];
                string secondary = ips.Count > 1 ? ips[1] : string.Empty;

                var matched = LiteCatalog.DnsPresets.FirstOrDefault(p =>
                    !p.IsSmartAuto && p.PrimaryIp.Equals(primary, StringComparison.OrdinalIgnoreCase));

                if (matched != null)
                {
                    return new ActiveDnsStatus(true, primary, secondary, matched.Name, matched.Name, matched.Id);
                }

                if (customEntries != null)
                {
                    var customMatched = customEntries.FirstOrDefault(c =>
                        c.PrimaryIp.Equals(primary, StringComparison.OrdinalIgnoreCase));
                    if (customMatched != null)
                        return new ActiveDnsStatus(true, primary, secondary, customMatched.Name, customMatched.Name, customMatched.Id);
                }

                return new ActiveDnsStatus(true, primary, secondary, "Custom DNS", "دی‌ان‌اس دستی", null);
            }
            catch
            {
                return ActiveDnsStatus.Automatic;
            }
        }

        // ==================== START WITH WINDOWS (HARDENED ELEVATED SCHEDULED TASK) ====================
        public async Task<bool> IsAutoStartEnabledAsync(CancellationToken token = default)
        {
            try
            {
                var res = await _runner.RunAsync("schtasks", new[] { "/Query", "/TN", AutoStartTaskName }, token, TimeSpan.FromSeconds(8)).ConfigureAwait(false);
                return res.IsSuccess;
            }
            catch
            {
                return false;
            }
        }

        public async Task<OperationResult> SetAutoStartAsync(bool enable, CancellationToken token = default)
        {
            try
            {
                if (enable)
                {
                    string? rawExePath = Environment.ProcessPath;
                    if (string.IsNullOrWhiteSpace(rawExePath) || !File.Exists(rawExePath))
                        return new OperationResult(false, "Could not locate executable path.", "مسیر فایل اجرایی پیدا نشد.");

                    string exePath = Path.GetFullPath(rawExePath);
                    if (!exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        exePath.IndexOfAny(ForbiddenShellChars) >= 0 ||
                        IsReparsePoint(exePath))
                    {
                        return new OperationResult(false, "Blocked auto-start: unsafe executable path.", "شروع خودکار مسدود شد: مسیر فایل اجرایی ایمن نیست.");
                    }

                    string tempRoot = Path.GetFullPath(Path.GetTempPath());
                    if (exePath.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        return new OperationResult(
                            false,
                            "Move AionToolLite out of Temp (or install via Setup) before enabling Start with Windows.",
                            "قبل از فعال‌سازی شروع خودکار، برنامه را نصب کنید یا از پوشه Temp خارج کنید.");
                    }

                    var res = await _runner.RunAsync("schtasks", new[]
                    {
                        "/Create",
                        "/TN", AutoStartTaskName,
                        "/TR", $"\"{exePath}\" --minimized",
                        "/SC", "ONLOGON",
                        "/RL", "HIGHEST",
                        "/F"
                    }, token, TimeSpan.FromSeconds(12)).ConfigureAwait(false);

                    return res.IsSuccess
                        ? new OperationResult(true, "Start with Windows enabled (starts quietly in Tray).", "شروع خودکار با ویندوز فعال شد (بی‌صدا در نوار ساعت).")
                        : new OperationResult(false, "Could not create Windows startup task.", "ساخت تسک شروع خودکار ناموفق بود.");
                }
                else
                {
                    await _runner.RunAsync("schtasks", new[] { "/Delete", "/TN", AutoStartTaskName, "/F" }, token, TimeSpan.FromSeconds(12)).ConfigureAwait(false);
                    return new OperationResult(true, "Start with Windows disabled.", "شروع خودکار با ویندوز غیرفعال شد.");
                }
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Auto-start error: {ex.Message}", $"خطای شروع خودکار: {ex.Message}");
            }
        }

        // ==================== PHYSICAL-FIRST ADAPTER SCANNER & 3-CHANNEL LIVE TELEMETRY ====================
        private sealed record RegAdapterMeta(
            bool IsPhysical,
            bool IsVirtualOrHidden,
            bool IsSoftwareComponent,
            string DriverDesc);

        private static bool IsAllowedAdapterType(NetworkInterfaceType type) => type switch
        {
            NetworkInterfaceType.Ethernet => true,
            NetworkInterfaceType.GigabitEthernet => true,
            NetworkInterfaceType.FastEthernetT => true,
            NetworkInterfaceType.FastEthernetFx => true,
            NetworkInterfaceType.Ethernet3Megabit => true,
            NetworkInterfaceType.Wireless80211 => true,
            NetworkInterfaceType.Wwanpp => true,
            NetworkInterfaceType.Wwanpp2 => true,
            _ => false
        };

        private static bool IsIgnoredAdapterText(string? name, string? description)
        {
            foreach (var keyword in IgnoredAdapters)
            {
                if (!string.IsNullOrEmpty(name) && name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (!string.IsNullOrEmpty(description) && description.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static bool HasValidPhysicalMac(NetworkInterface nic)
        {
            try
            {
                byte[] mac = nic.GetPhysicalAddress().GetAddressBytes();
                return mac.Length == 6 && mac.Any(b => b != 0);
            }
            catch
            {
                return false;
            }
        }

        private static bool HasIpv4DefaultGateway(NetworkInterface nic)
        {
            try
            {
                return nic.GetIPProperties().GatewayAddresses.Any(g =>
                    g.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.Any.Equals(g.Address));
            }
            catch
            {
                return false;
            }
        }

        private static (Dictionary<string, RegAdapterMeta> ByGuid, Dictionary<string, string> NameToGuid) ReadWindowsAdapterClassMetadata()
        {
            var byGuid = new Dictionary<string, RegAdapterMeta>(StringComparer.OrdinalIgnoreCase);
            var nameToGuid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // 1. Read hardware class flags (NCF_PHYSICAL=0x4, NCF_VIRTUAL=0x1, NCF_HIDDEN=0x8)
            try
            {
                const string classPath = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
                using var classKey = Registry.LocalMachine.OpenSubKey(classPath, false);
                if (classKey != null)
                {
                    foreach (var subName in classKey.GetSubKeyNames())
                    {
                        if (subName.Length != 4 || !subName.All(char.IsDigit)) continue;
                        try
                        {
                            using var sub = classKey.OpenSubKey(subName, false);
                            if (sub == null) continue;

                            string? guid = sub.GetValue("NetCfgInstanceId") as string;
                            if (string.IsNullOrWhiteSpace(guid)) continue;

                            int chars = 0;
                            object? rawChars = sub.GetValue("Characteristics");
                            if (rawChars != null)
                            {
                                try { chars = Convert.ToInt32(rawChars); } catch { }
                            }

                            string compId = (sub.GetValue("ComponentId") as string ?? string.Empty).Trim();
                            string desc = (sub.GetValue("DriverDesc") as string ?? string.Empty).Trim();

                            bool isPhysical = (chars & 0x4) != 0;
                            bool isVirtualOrHidden = (chars & 0x1) != 0 || (chars & 0x8) != 0;
                            bool isSoftwareComp =
                                compId.StartsWith("root\\", StringComparison.OrdinalIgnoreCase) ||
                                compId.StartsWith("ms_", StringComparison.OrdinalIgnoreCase) ||
                                compId.StartsWith("swd\\", StringComparison.OrdinalIgnoreCase) ||
                                compId.StartsWith("*", StringComparison.Ordinal) ||
                                compId.StartsWith("bth\\", StringComparison.OrdinalIgnoreCase) ||
                                compId.Contains("wintun", StringComparison.OrdinalIgnoreCase) ||
                                compId.Contains("wireguard", StringComparison.OrdinalIgnoreCase) ||
                                compId.Contains("tap0901", StringComparison.OrdinalIgnoreCase) ||
                                compId.Contains("openvpn", StringComparison.OrdinalIgnoreCase);

                            byGuid[guid.Trim()] = new RegAdapterMeta(isPhysical, isVirtualOrHidden, isSoftwareComp, desc);
                        }
                        catch { }
                    }
                }
            }
            catch { }

            // 2. Map friendly Windows connection names (e.g. "Ethernet", "Wi-Fi") back to their GUIDs
            try
            {
                const string netPath = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
                using var netKey = Registry.LocalMachine.OpenSubKey(netPath, false);
                if (netKey != null)
                {
                    foreach (var guidName in netKey.GetSubKeyNames())
                    {
                        if (!guidName.StartsWith("{", StringComparison.Ordinal)) continue;
                        try
                        {
                            using var connKey = netKey.OpenSubKey($@"{guidName}\Connection", false);
                            string? friendly = connKey?.GetValue("Name") as string;
                            if (!string.IsNullOrWhiteSpace(friendly))
                                nameToGuid[friendly.Trim()] = guidName.Trim();
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return (byGuid, nameToGuid);
        }

        public Task<List<LiteAdapterItem>> ScanAdaptersAsync(CancellationToken token = default)
        {
            return Task.Run(async () =>
            {
                var physicalMap = new Dictionary<string, LiteAdapterItem>(StringComparer.OrdinalIgnoreCase);
                var fallbackMap = new Dictionary<string, LiteAdapterItem>(StringComparer.OrdinalIgnoreCase);
                var (regByGuid, nameToGuid) = ReadWindowsAdapterClassMetadata();

                try
                {
                    foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (!IsAllowedAdapterType(nic.NetworkInterfaceType))
                            continue;

                        if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                            continue;

                        if (IsIgnoredAdapterText(nic.Name, nic.Description))
                            continue;

                        if (!HasValidPhysicalMac(nic))
                            continue;

                        bool isUp = nic.OperationalStatus == OperationalStatus.Up;
                        bool hasGw = isUp && HasIpv4DefaultGateway(nic);

                        var item = new LiteAdapterItem
                        {
                            Name = nic.Name,
                            HardwareDesc = nic.Description,
                            HasGateway = hasGw,
                            Health = isUp ? AdapterHealth.Connected : AdapterHealth.Disconnected
                        };

                        if (regByGuid.TryGetValue(nic.Id, out var meta))
                        {
                            if (meta.IsSoftwareComponent || (meta.IsVirtualOrHidden && !meta.IsPhysical))
                                continue;

                            if (meta.IsPhysical)
                                physicalMap[nic.Name] = item;
                            else
                                fallbackMap[nic.Name] = item;
                        }
                        else
                        {
                            fallbackMap[nic.Name] = item;
                        }
                    }
                }
                catch { }

                // Include Disabled physical hardware adapters only (cross-verified via Registry NCF_PHYSICAL)
                try
                {
                    var res = await _runner.RunAsync("netsh", new[] { "interface", "show", "interface" }, token, TimeSpan.FromSeconds(4)).ConfigureAwait(false);
                    if (res.IsSuccess && !string.IsNullOrWhiteSpace(res.StandardOutput))
                    {
                        foreach (var raw in res.StandardOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Skip(2))
                        {
                            var line = raw.Trim();
                            var m = Regex.Match(line, @"^(Enabled|Disabled)\s+(Connected|Disconnected)\s+\S+\s+(.+)$", RegexOptions.IgnoreCase);
                            if (!m.Success) continue;

                            string admin = m.Groups[1].Value;
                            string name = m.Groups[3].Value.Trim();
                            if (!admin.Equals("Disabled", StringComparison.OrdinalIgnoreCase)) continue;
                            if (physicalMap.ContainsKey(name) || IsIgnoredAdapterText(name, null)) continue;

                            if (nameToGuid.TryGetValue(name, out string? guid) &&
                                regByGuid.TryGetValue(guid, out var meta) &&
                                meta.IsPhysical &&
                                !meta.IsVirtualOrHidden &&
                                !meta.IsSoftwareComponent &&
                                !IsIgnoredAdapterText(name, meta.DriverDesc))
                            {
                                physicalMap[name] = new LiteAdapterItem
                                {
                                    Name = name,
                                    HardwareDesc = meta.DriverDesc,
                                    HasGateway = false,
                                    Health = AdapterHealth.Disabled
                                };
                            }
                        }
                    }
                }
                catch { }

                var chosen = physicalMap.Count > 0 ? physicalMap.Values : fallbackMap.Values;

                return chosen
                    .OrderBy(a => (int)a.Health)
                    .ThenByDescending(a => a.HasGateway)
                    .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }, token);
        }

        private static string DetectGatewayIp(string preferredInterfaceName)
        {
            try
            {
                var nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();

                var selected = nics.FirstOrDefault(n => n.Name.Equals(preferredInterfaceName, StringComparison.OrdinalIgnoreCase));
                if (selected != null)
                {
                    var gw = selected.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.Any.Equals(g.Address));
                    if (gw != null) return gw.Address.ToString();
                }

                foreach (var n in nics.Where(x => x.OperationalStatus == OperationalStatus.Up))
                {
                    var gw = n.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.Any.Equals(g.Address));
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return string.Empty;
        }

        private async Task<IPAddress?> ResolveCachedAsync(string hostOrIp)
        {
            if (IPAddress.TryParse(hostOrIp, out var direct)) return direct;
            if (_resolveCache.TryGetValue(hostOrIp, out var cached) && DateTime.UtcNow < cached.ExpiresUtc)
                return cached.Ip;

            try
            {
                using var cts = new CancellationTokenSource(1100);
                var addrs = await Dns.GetHostAddressesAsync(hostOrIp, cts.Token).ConfigureAwait(false);
                var ipv4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ipv4 != null)
                {
                    _resolveCache[hostOrIp] = (ipv4, DateTime.UtcNow.AddMinutes(5));
                    return ipv4;
                }
            }
            catch { }

            if (_resolveCache.TryGetValue(hostOrIp, out var stale))
                return stale.Ip;

            if (hostOrIp.Contains("arvancloud.ir", StringComparison.OrdinalIgnoreCase))
            {
                var fallback = IPAddress.Parse("185.143.232.253");
                _resolveCache[hostOrIp] = (fallback, DateTime.UtcNow.AddMinutes(1));
                return fallback;
            }
            return null;
        }

        private async Task<long?> PingHostFastAsync(string hostOrIp, int timeoutMs, int fallbackTcpPort)
        {
            if (string.IsNullOrWhiteSpace(hostOrIp)) return null;
            var ip = await ResolveCachedAsync(hostOrIp).ConfigureAwait(false);
            if (ip == null) return null;

            var opts = new PingOptions(64, false);
            try
            {
                using var p = new Ping();
                var r = await p.SendPingAsync(ip, timeoutMs, PingPayload, opts).ConfigureAwait(false);
                if (r.Status == IPStatus.Success) return r.RoundtripTime;
            }
            catch { }

            if (fallbackTcpPort > 0)
            {
                try
                {
                    using var tcp = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    using var cts = new CancellationTokenSource(750);
                    var sw = Stopwatch.StartNew();
                    await tcp.ConnectAsync(new IPEndPoint(ip, fallbackTcpPort), cts.Token).ConfigureAwait(false);
                    sw.Stop();
                    return sw.ElapsedMilliseconds;
                }
                catch { }
            }

            return null;
        }

        public async Task<LiteTelemetry> CaptureTelemetryAsync(string interfaceName, IReadOnlyList<SavedCustomDnsEntry>? customEntries = null)
        {
            string routerIp = await Task.Run(() => DetectGatewayIp(interfaceName)).ConfigureAwait(false);

            var tRouter = !string.IsNullOrEmpty(routerIp)
                ? PingHostFastAsync(routerIp, 800, 80)
                : Task.FromResult<long?>(null);
            await Task.Delay(25).ConfigureAwait(false);
            var tIntranet = PingHostFastAsync("www.arvancloud.ir", 1100, 443);
            await Task.Delay(25).ConfigureAwait(false);
            var tGlobal = PingHostFastAsync("4.2.2.4", 1100, 53);

            var tNic = Task.Run(() =>
            {
                try
                {
                    var nic = NetworkInterface.GetAllNetworkInterfaces()
                        .FirstOrDefault(n => n.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));
                    var activeDns = DetectActiveStaticDns(interfaceName, customEntries);
                    if (nic == null)
                        return (Found: false, Rx: 0L, Tx: 0L, ActiveDns: activeDns);

                    var stats = nic.GetIPStatistics();
                    return (Found: true, Rx: stats.BytesReceived, Tx: stats.BytesSent, ActiveDns: activeDns);
                }
                catch
                {
                    return (Found: false, Rx: 0L, Tx: 0L, ActiveDns: ActiveDnsStatus.Automatic);
                }
            });

            await Task.WhenAll(tRouter, tIntranet, tGlobal, tNic).ConfigureAwait(false);

            long? globalMs = tGlobal.Result;
            long? intranetMs = tIntranet.Result;
            long? routerMs = tRouter.Result;
            var nicInfo = tNic.Result;

            return new LiteTelemetry(
                HasInternet: globalMs.HasValue || intranetMs.HasValue,
                GlobalPingMs: globalMs,
                IntranetPingMs: intranetMs,
                RouterPingMs: routerMs,
                RouterIp: routerIp,
                AdapterName: interfaceName,
                AdapterFound: nicInfo.Found,
                BytesReceived: nicInfo.Rx,
                BytesSent: nicInfo.Tx,
                ActiveDns: nicInfo.ActiveDns);
        }

        // ==================== REAL UDP/53 DNS LATENCY & FAST SMART AUTO ====================
        public static async Task<long?> QueryDnsUdpMsAsync(string serverIpStr, int timeoutMs = 1100, CancellationToken token = default)
        {
            if (!IPAddress.TryParse(serverIpStr, out var serverIp))
                return null;

            byte[] packet = BuildDnsAQuery("google.com", out ushort txId);
            try
            {
                using var udp = new UdpClient(serverIp.AddressFamily);
                var ep = new IPEndPoint(serverIp, 53);
                using var tCts = new CancellationTokenSource(timeoutMs);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, tCts.Token);

                var sw = Stopwatch.StartNew();
                await udp.SendAsync(packet.AsMemory(), ep, linked.Token).ConfigureAwait(false);
                var resp = await udp.ReceiveAsync(linked.Token).ConfigureAwait(false);
                sw.Stop();

                byte[] buf = resp.Buffer;
                if (buf.Length < 12) return null;
                ushort respId = (ushort)((buf[0] << 8) | buf[1]);
                bool isResponse = (buf[2] & 0x80) != 0;
                int rcode = buf[3] & 0x0F;

                if (respId == txId && isResponse && (rcode == 0 || rcode == 3))
                    return sw.ElapsedMilliseconds;
            }
            catch { }

            return null;
        }

        private static byte[] BuildDnsAQuery(string domain, out ushort txId)
        {
            txId = (ushort)RandomNumberGenerator.GetInt32(1, 65535);
            using var ms = new MemoryStream(48);
            ms.WriteByte((byte)(txId >> 8));
            ms.WriteByte((byte)(txId & 0xFF));
            ms.WriteByte(0x01); ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x01);
            ms.WriteByte(0x00); ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x00);
            foreach (var label in domain.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                byte[] b = Encoding.ASCII.GetBytes(label);
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x01);
            ms.WriteByte(0x00); ms.WriteByte(0x01);
            return ms.ToArray();
        }

        public async Task<Dictionary<string, long?>> BenchmarkAllPresetsAsync(
            int rounds = 2,
            int timeoutMs = 1100,
            IEnumerable<LiteDnsPreset>? extraPresets = null,
            CancellationToken token = default)
        {
            var results = new Dictionary<string, long?>(StringComparer.OrdinalIgnoreCase);
            using var sem = new SemaphoreSlim(12);

            var pool = LiteCatalog.DnsPresets.Where(p => !p.IsSmartAuto);
            if (extraPresets != null)
                pool = pool.Concat(extraPresets.Where(p => !p.IsSmartAuto && LiteCatalog.IsSafeDnsIpv4(p.PrimaryIp)));

            var tasks = pool
                .Select(async preset =>
                {
                    await sem.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        long? best = null;
                        for (int r = 0; r < rounds; r++)
                        {
                            long? ms = await QueryDnsUdpMsAsync(preset.PrimaryIp, timeoutMs, token).ConfigureAwait(false);
                            if (ms.HasValue && (!best.HasValue || ms.Value < best.Value))
                                best = ms.Value;
                        }
                        return (preset.Id, best);
                    }
                    finally
                    {
                        sem.Release();
                    }
                });

            foreach (var (id, ms) in await Task.WhenAll(tasks).ConfigureAwait(false))
                results[id] = ms;

            return results;
        }

        public async Task<(LiteDnsPreset? Best, long? LatencyMs)> FindFastestPresetAsync(
            IEnumerable<LiteDnsPreset>? extraPresets = null,
            CancellationToken token = default)
        {
            var customList = extraPresets?.Where(p => !p.IsSmartAuto && LiteCatalog.IsSafeDnsIpv4(p.PrimaryIp)).ToList();
            var map = await BenchmarkAllPresetsAsync(rounds: 1, timeoutMs: 950, extraPresets: customList, token: token).ConfigureAwait(false);
            LiteDnsPreset? best = null;
            long bestMs = long.MaxValue;

            var candidates = customList != null
                ? LiteCatalog.DnsPresets.Where(x => !x.IsSmartAuto).Concat(customList)
                : LiteCatalog.DnsPresets.Where(x => !x.IsSmartAuto);

            foreach (var p in candidates)
            {
                if (map.TryGetValue(p.Id, out var ms) && ms.HasValue && ms.Value < bestMs)
                {
                    bestMs = ms.Value;
                    best = p;
                }
            }

            return best != null ? (best, bestMs) : (null, null);
        }

        // ==================== NATIVE WINDOWS 11 DNS-OVER-HTTPS (DoH) ====================
        public static bool IsWindows11NativeDohSupported() => Environment.OSVersion.Version.Build >= 22000;

        private static bool IsSafeDohTemplate(string? template)
        {
            if (string.IsNullOrWhiteSpace(template)) return false;
            string t = template.Trim();
            if (t.IndexOfAny(ForbiddenShellChars) >= 0) return false;
            return Uri.TryCreate(t, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
        }

        private async Task<bool> ConfigureNativeDohForIpAsync(string ip, string? dohTemplate, bool enable, CancellationToken token)
        {
            if (!IsWindows11NativeDohSupported() || !LiteCatalog.IsSafeDnsIpv4(ip))
                return false;

            try
            {
                if (enable)
                {
                    if (!IsSafeDohTemplate(dohTemplate)) return false;
                    var r = await _runner.RunAsync("netsh", new[]
                    {
                        "dns", "add", "encryption",
                        $"server={ip}",
                        $"dohtemplate={dohTemplate!.Trim()}",
                        "autoupgrade=yes",
                        "udpfallback=yes"
                    }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    return r.IsSuccess;
                }
                else
                {
                    var r = await _runner.RunAsync("netsh", new[]
                    {
                        "dns", "delete", "encryption",
                        $"server={ip}"
                    }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    return r.IsSuccess;
                }
            }
            catch
            {
                return false;
            }
        }

        public async Task<OperationResult> ToggleNativeDohOnActiveDnsAsync(string interfaceName, bool enable, CancellationToken token = default)
        {
            if (!IsWindows11NativeDohSupported())
            {
                return new OperationResult(
                    false,
                    "Native DoH requires Windows 11 (Build 22000+).",
                    "رمزنگاری بومی DoH فقط در ویندوز ۱۱ پشتیبانی می‌شود.");
            }

            var active = DetectActiveStaticDns(interfaceName);
            if (!active.IsStaticConnected)
            {
                return new OperationResult(
                    true,
                    enable
                        ? "Native DoH ON — will encrypt supported servers when you connect."
                        : "Native DoH OFF.",
                    enable
                        ? "رمزنگاری بومی DoH فعال شد — هنگام اتصال به سرورهای پشتیبانی‌شده اعمال می‌شود."
                        : "رمزنگاری بومی DoH غیرفعال شد.");
            }

            var preset = LiteCatalog.DnsPresets.FirstOrDefault(p =>
                !p.IsSmartAuto && p.PrimaryIp.Equals(active.PrimaryIp, StringComparison.OrdinalIgnoreCase));

            if (enable)
            {
                if (preset == null || !preset.HasDoh)
                {
                    return new OperationResult(
                        true,
                        $"DoH ON — saved for supported servers (current '{active.DisplayNameEn}' uses standard UDP).",
                        $"DoH فعال شد — سرور فعلی ({active.DisplayNameFa}) فاقد آدرس DoH است و روی سرورهای پشتیبانی‌شده اعمال می‌شود.");
                }

                bool ok = await ConfigureNativeDohForIpAsync(preset.PrimaryIp, preset.DohTemplate, true, token).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(preset.SecondaryIp))
                    await ConfigureNativeDohForIpAsync(preset.SecondaryIp, preset.DohTemplate, true, token).ConfigureAwait(false);
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);

                return ok
                    ? new OperationResult(true, $"Native DoH enabled for {preset.Name}!", $"رمزنگاری بومی DoH برای {preset.Name} فعال شد!")
                    : new OperationResult(false, $"Could not register DoH rule for {preset.Name}.", $"ثبت تنظیمات DoH برای {preset.Name} ناموفق بود.");
            }
            else
            {
                await ConfigureNativeDohForIpAsync(active.PrimaryIp, null, false, token).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(active.SecondaryIp))
                    await ConfigureNativeDohForIpAsync(active.SecondaryIp, null, false, token).ConfigureAwait(false);
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
                return new OperationResult(true, "Native DoH disabled for active DNS.", "رمزنگاری بومی DoH غیرفعال شد.");
            }
        }

        // ==================== OPTIMIZED SEQUENTIAL DNS CONNECT & CLEAN DISCONNECT ====================
        public async Task<OperationResult> ApplyDnsAsync(
            string interfaceName,
            string primaryIp,
            string? secondaryIp,
            string label,
            string? primaryIpv6 = null,
            string? secondaryIpv6 = null,
            string? dohTemplate = null,
            bool enableNativeDoh = false,
            bool skipBackup = false,
            CancellationToken token = default)
        {
            if (!TryValidateInterfaceName(interfaceName, out string iface))
                return new OperationResult(false, "Invalid or missing network adapter.", "کارت شبکه انتخاب‌شده نامعتبر است.");

            if (!LiteCatalog.IsSafeDnsIpv4(primaryIp))
                return new OperationResult(false, "Invalid primary IPv4 address.", "آدرس DNS اول نامعتبر است.");

            if (!string.IsNullOrWhiteSpace(secondaryIp) && !LiteCatalog.IsSafeDnsIpv4(secondaryIp))
                return new OperationResult(false, "Invalid secondary IPv4 address.", "آدرس DNS دوم نامعتبر است.");

            string cleanPrimary = primaryIp.Trim();
            string? cleanSecondary = string.IsNullOrWhiteSpace(secondaryIp) ? null : secondaryIp.Trim();
            if (cleanSecondary != null && cleanSecondary.Equals(cleanPrimary, StringComparison.OrdinalIgnoreCase))
                cleanSecondary = null;

            if (!skipBackup)
                EnsureOriginalDnsBackupSaved(iface);

            var r1 = await _runner.RunAsync("netsh", new[]
            {
                "interface", "ip", "set", "dnsservers",
                $"name={iface}", "source=static", $"address={cleanPrimary}", "validate=no"
            }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);

            if (!r1.IsSuccess)
            {
                return new OperationResult(
                    false,
                    $"Could not apply {label}. Make sure the adapter is enabled.",
                    $"اعمال {label} انجام نشد. مطمئن شوید کارت شبکه فعال است.");
            }

            if (cleanSecondary != null)
            {
                await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ip", "add", "dnsservers",
                    $"name={iface}", $"address={cleanSecondary}", "index=2", "validate=no"
                }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            }

            if (!string.IsNullOrWhiteSpace(primaryIpv6) && IPAddress.TryParse(primaryIpv6, out var v6p) && v6p.AddressFamily == AddressFamily.InterNetworkV6)
            {
                await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "set", "dnsservers",
                    $"name={iface}", "source=static", $"address={v6p}", "validate=no"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

                if (!string.IsNullOrWhiteSpace(secondaryIpv6) && IPAddress.TryParse(secondaryIpv6, out var v6s) && v6s.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    await _runner.RunAsync("netsh", new[]
                    {
                        "interface", "ipv6", "add", "dnsservers",
                        $"name={iface}", $"address={v6s}", "index=2", "validate=no"
                    }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
            }
            else
            {
                await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "set", "dnsservers",
                    $"name={iface}", "source=dhcp"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }

            bool dohApplied = false;
            if (enableNativeDoh && IsWindows11NativeDohSupported() && IsSafeDohTemplate(dohTemplate))
            {
                dohApplied = await ConfigureNativeDohForIpAsync(cleanPrimary, dohTemplate, true, token).ConfigureAwait(false);
                if (cleanSecondary != null)
                    await ConfigureNativeDohForIpAsync(cleanSecondary, dohTemplate, true, token).ConfigureAwait(false);
            }

            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);

            string dohSuffix = dohApplied ? " · DoH" : string.Empty;
            return new OperationResult(
                true,
                $"Connected to {label} ({cleanPrimary}){dohSuffix}",
                $"متصل به {label} ({cleanPrimary}){dohSuffix}");
        }

        public async Task<OperationResult> DisconnectDnsToAutoAsync(string interfaceName, CancellationToken token = default)
        {
            if (!TryValidateInterfaceName(interfaceName, out string iface))
                return new OperationResult(false, "Invalid or missing network adapter.", "کارت شبکه انتخاب‌شده نامعتبر است.");

            var r1 = await _runner.RunAsync("netsh", new[]
            {
                "interface", "ip", "set", "dnsservers", $"name={iface}", "source=dhcp"
            }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);

            await _runner.RunAsync("netsh", new[]
            {
                "interface", "ipv6", "set", "dnsservers", $"name={iface}", "source=dhcp"
            }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);

            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);

            return r1.IsSuccess
                ? new OperationResult(true, "Disconnected — DNS removed & cache cleared!", "قطع شد — دی‌ان‌اس برداشته شد و کش پاکسازی شد!")
                : new OperationResult(false, "Could not reset DNS to automatic.", "حذف دی‌ان‌اس و بازگشت به خودکار ناموفق بود.");
        }

        // ==================== QUICK FIX & FULL ADAPTER RESET ====================
        public async Task<OperationResult> QuickNetworkRefreshAsync(string interfaceName, CancellationToken token = default)
        {
            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
            await _runner.RunAsync("netsh", new[] { "interface", "ip", "delete", "arpcache" }, token).ConfigureAwait(false);
            await _runner.RunAsync("ipconfig", new[] { "/registerdns" }, token).ConfigureAwait(false);
            return new OperationResult(
                true,
                "DNS cache & network table refreshed!",
                "کش شبکه و دی‌ان‌اس با موفقیت تازه شد!");
        }

        public async Task<OperationResult> FullAdapterResetAsync(string interfaceName, CancellationToken token = default)
        {
            if (!TryValidateInterfaceName(interfaceName, out string iface))
                return new OperationResult(false, "Invalid or missing network adapter.", "کارت شبکه انتخاب‌شده نامعتبر است.");

            bool disabledAdapter = false;
            try
            {
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
                await _runner.RunAsync("netsh", new[] { "int", "ip", "reset" }, token).ConfigureAwait(false);

                await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=disabled" }, token).ConfigureAwait(false);
                disabledAdapter = true;
                await Task.Delay(2000, token).ConfigureAwait(false);

                await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=enabled" }, CancellationToken.None).ConfigureAwait(false);
                disabledAdapter = false;
                await Task.Delay(2000, token).ConfigureAwait(false);

                await _runner.RunAsync("ipconfig", new[] { "/release", iface }, token).ConfigureAwait(false);
                await _runner.RunAsync("ipconfig", new[] { "/renew", iface }, token).ConfigureAwait(false);
                await _runner.RunAsync("ipconfig", new[] { "/registerdns" }, token).ConfigureAwait(false);
                await _runner.RunAsync("nbtstat", new[] { "-R" }, token).ConfigureAwait(false);
                await _runner.RunAsync("nbtstat", new[] { "-RR" }, token).ConfigureAwait(false);

                return new OperationResult(
                    true,
                    $"Full reset completed for '{iface}'!",
                    $"کارت شبکه «{iface}» به صورت کامل ریست و تعمیر شد!");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Full reset error: {ex.Message}", $"خطا در ریست کارت شبکه: {ex.Message}");
            }
            finally
            {
                if (disabledAdapter)
                {
                    try { await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=enabled" }, CancellationToken.None).ConfigureAwait(false); } catch { }
                }
            }
        }

        // ==================== SAFE GAME MODE TOGGLE (STRICT SERVICE ALLOWLIST) ====================
        public bool IsGameModeActive()
        {
            lock (_ioLock)
            {
                try
                {
                    string? json = ReadSmallJsonTextSafe(GameModeStatePath);
                    if (string.IsNullOrEmpty(json)) return false;
                    var list = JsonSerializer.Deserialize<List<string>>(json);
                    return list != null && list.Count > 0;
                }
                catch { return false; }
            }
        }

        private async Task<bool> IsServiceRunningAsync(string svc, CancellationToken token)
        {
            var res = await _runner.RunAsync("sc", new[] { "query", svc }, token, TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            return res.IsSuccess && (res.StandardOutput.Contains("RUNNING", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(res.StandardOutput, @":\s*4\s"));
        }

        public async Task<OperationResult> SetGameModeAsync(bool enable, CancellationToken token = default)
        {
            if (enable)
            {
                var stopped = new List<string>();

                foreach (var s in AllowedGameModeServices)
                {
                    if (await IsServiceRunningAsync(s, token).ConfigureAwait(false))
                    {
                        var r = await _runner.RunAsync("net", new[] { "stop", s }, token, TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                        if (r.IsSuccess) stopped.Add(s);
                    }
                }

                string[] safeWidgets = { "WidgetService", "Widgets", "YourPhone", "PhoneExperienceHost" };
                foreach (var app in safeWidgets)
                {
                    foreach (var proc in Process.GetProcessesByName(app))
                    {
                        using (proc) { try { proc.Kill(); } catch { } }
                    }
                }

                lock (_ioLock)
                {
                    Directory.CreateDirectory(_cfgDir);
                    var saveList = stopped.Count > 0 ? stopped : new List<string> { "_ACTIVE_MARKER_" };
                    File.WriteAllText(GameModeStatePath, JsonSerializer.Serialize(saveList, JsonOpts), new UTF8Encoding(false));
                }

                return new OperationResult(
                    true,
                    $"Game Mode ON — paused {stopped.Count} background service(s).",
                    $"حالت گیم فعال شد — {stopped.Count} سرویس پس‌زمینه متوقف شد.");
            }
            else
            {
                List<string> toRestore;
                lock (_ioLock)
                {
                    string? json = ReadSmallJsonTextSafe(GameModeStatePath);
                    toRestore = !string.IsNullOrEmpty(json)
                        ? JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>()
                        : new List<string>();
                }

                // Security: strictly filter against AllowedGameModeServices so tampered JSON in %APPDATA% cannot start arbitrary services
                int restored = 0;
                foreach (var s in toRestore.Where(x => AllowedGameModeServices.Contains(x)))
                {
                    var r = await _runner.RunAsync("net", new[] { "start", s }, token, TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                    if (r.IsSuccess) restored++;
                }

                lock (_ioLock)
                {
                    try { if (File.Exists(GameModeStatePath)) File.Delete(GameModeStatePath); } catch { }
                }

                return new OperationResult(
                    true,
                    $"Game Mode OFF — restored {restored} service(s).",
                    $"حالت گیم خاموش شد — {restored} سرویس به حالت عادی برگشت.");
            }
        }

        // ==================== ATOMIC, SYMLINK-SAFE & LOCKED WINDOWS HOSTS MANAGER ====================
        private async Task AtomicWriteHostsAsync(string content, CancellationToken token)
        {
            await _hostsLock.WaitAsync(token).ConfigureAwait(false);
            try
            {
                if (File.Exists(_hostsPath) && IsReparsePoint(_hostsPath))
                    throw new IOException("Refused to modify hosts file because it is a symbolic link / reparse point.");

                string dir = Path.GetDirectoryName(_hostsPath)!;
                string tmp = Path.Combine(dir, $"hosts.aionlite.{Guid.NewGuid():N}.tmp");
                var utf8NoBom = new UTF8Encoding(false);

                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    try
                    {
                        await File.WriteAllTextAsync(tmp, content, utf8NoBom, token).ConfigureAwait(false);
                        if (File.Exists(_hostsPath))
                        {
                            var attrs = File.GetAttributes(_hostsPath);
                            if ((attrs & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System)) != 0)
                                File.SetAttributes(_hostsPath, FileAttributes.Normal);
                            File.Replace(tmp, _hostsPath, null, ignoreMetadataErrors: true);
                        }
                        else
                        {
                            File.Move(tmp, _hostsPath);
                        }
                        return;
                    }
                    catch when (attempt < 3)
                    {
                        await Task.Delay(250, token).ConfigureAwait(false);
                    }
                    finally
                    {
                        try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                    }
                }
            }
            finally
            {
                _hostsLock.Release();
            }
        }

        public bool IsAdShieldActive() => IsBlocklistTagPresent(AdShieldTag);

        public bool IsBlocklistTagPresent(string tag)
        {
            try
            {
                if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath)) return false;
                string p1 = $"# AIONTOOL-BEGIN:{tag}";
                string p2 = $"# {tag}-BEGIN";
                foreach (var raw in File.ReadLines(_hostsPath))
                {
                    string t = raw.Trim();
                    if (t.StartsWith(p1, StringComparison.OrdinalIgnoreCase) || t.StartsWith(p2, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
        }

        public Task<HostsSummaryInfo> GetHostsSummaryAsync()
        {
            return Task.Run(() =>
            {
                int total = 0;
                var tags = new List<string>();

                try
                {
                    if (File.Exists(_hostsPath) && !IsReparsePoint(_hostsPath))
                    {
                        foreach (var raw in File.ReadLines(_hostsPath))
                        {
                            string line = raw.Trim();
                            if (line.Length == 0) continue;

                            if (line.StartsWith("# AIONTOOL-BEGIN:", StringComparison.OrdinalIgnoreCase))
                            {
                                var parts = line.Split(':');
                                string tag = parts.Length >= 2 ? parts[1] : "";
                                string label = parts.Length >= 3 ? parts[2] : tag;
                                if (!string.IsNullOrEmpty(label) && !tags.Contains(label)) tags.Add(label);
                                continue;
                            }
                            if (line.StartsWith($"# {AdShieldTag}-BEGIN", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!tags.Contains("Ad Shield")) tags.Add("Ad Shield");
                                continue;
                            }
                            if (line[0] == '#') continue;
                            total++;
                        }
                    }
                }
                catch { }

                return new HostsSummaryInfo(total, tags);
            });
        }

        public Task<OperationResult> BackupHostsAsync()
        {
            return Task.Run(() =>
            {
                lock (_ioLock)
                {
                    try
                    {
                        Directory.CreateDirectory(_cfgDir);
                        if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath))
                            return new OperationResult(false, "Windows hosts file not found or unsafe.", "فایل hosts ویندوز پیدا نشد یا ایمن نیست.");

                        if (!File.Exists(HostsOriginalBackupPath))
                            File.Copy(_hostsPath, HostsOriginalBackupPath, overwrite: false);

                        string stamped = Path.Combine(_cfgDir, $"hosts.backup.{DateTime.Now:yyyyMMdd_HHmmss}");
                        File.Copy(_hostsPath, stamped, overwrite: true);

                        var oldBackups = Directory.GetFiles(_cfgDir, "hosts.backup.*")
                            .Where(p => !p.EndsWith(".original", StringComparison.OrdinalIgnoreCase))
                            .OrderByDescending(File.GetLastWriteTimeUtc)
                            .Skip(MaxBackupsToKeep);
                        foreach (var old in oldBackups) { try { File.Delete(old); } catch { } }

                        return new OperationResult(true, "Hosts backup saved!", "پشتیبان فایل hosts ذخیره شد!");
                    }
                    catch (Exception ex)
                    {
                        return new OperationResult(false, $"Backup error: {ex.Message}", $"خطا در پشتیبان‌گیری: {ex.Message}");
                    }
                }
            });
        }

        public async Task<OperationResult> RestoreHostsAsync(CancellationToken token = default)
        {
            string? target = null;
            lock (_ioLock)
            {
                if (Directory.Exists(_cfgDir))
                {
                    target = Directory.GetFiles(_cfgDir, "hosts.backup.*")
                        .Where(p => !p.EndsWith(".original", StringComparison.OrdinalIgnoreCase))
                        .OrderByDescending(File.GetLastWriteTimeUtc)
                        .FirstOrDefault();
                }
                if (target == null && File.Exists(HostsOriginalBackupPath))
                    target = HostsOriginalBackupPath;
            }

            if (target == null || IsReparsePoint(target))
                return new OperationResult(false, "No valid hosts backup found yet.", "پشتیبان معتبری از فایل hosts یافت نشد.");

            try
            {
                var fi = new FileInfo(target);
                if (fi.Length > MaxBlocklistBytes)
                    return new OperationResult(false, "Backup file exceeds 12 MB safety cap.", "حجم فایل پشتیبان بیش از حد مجاز است.");

                string content = await File.ReadAllTextAsync(target, token).ConfigureAwait(false);
                if (content.IndexOf('\0') >= 0)
                    return new OperationResult(false, "Backup file is corrupted (binary data detected).", "فایل پشتیبان خراب است.");

                await AtomicWriteHostsAsync(content, token).ConfigureAwait(false);
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
                return new OperationResult(true, "Hosts file restored from backup!", "فایل hosts از پشتیبان بازگردانی شد!");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Restore error: {ex.Message}", $"خطا در بازگردانی: {ex.Message}");
            }
        }

        public async Task<OperationResult> ResetHostsToDefaultAsync(CancellationToken token = default)
        {
            await BackupHostsAsync().ConfigureAwait(false);
            string defaultHosts =
                "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
                "#\r\n" +
                "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
                "# localhost name resolution is handled within DNS itself.\r\n" +
                "#\t127.0.0.1       localhost\r\n" +
                "#\t::1             localhost\r\n";

            await AtomicWriteHostsAsync(defaultHosts, token).ConfigureAwait(false);
            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
            return new OperationResult(true, "Hosts file reset to Windows default!", "فایل hosts به حالت پیش‌فرض ویندوز برگشت!");
        }

        public void OpenHostsInNotepad()
        {
            string notepadPath = _runner.ResolveSystemExecutable("notepad.exe");
            var psi = new ProcessStartInfo { FileName = notepadPath, UseShellExecute = false };
            psi.ArgumentList.Add(_hostsPath);
            Process.Start(psi);
        }

        public async Task<OperationResult> SetAdShieldAsync(bool enable, CancellationToken token = default)
        {
            var item = new LiteBlocklistItem(AdShieldTag, "Ad Shield", "Ads", AdShieldUrl, false);
            return enable
                ? await ApplyBlocklistAsync(item, token).ConfigureAwait(false)
                : await RemoveBlocklistByTagAsync(AdShieldTag, "Ad Shield", token).ConfigureAwait(false);
        }

        public async Task<OperationResult> ApplyBlocklistAsync(LiteBlocklistItem item, CancellationToken token = default)
        {
            try
            {
                var validEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (item.IsBuiltInCustom && item.Tag == TeamSpeakTag)
                {
                    string[] tsRules =
                    {
                        "0.0.0.0 accounting.teamspeak.com",
                        "0.0.0.0 backupaccounting.teamspeak.com",
                        "0.0.0.0 blacklist.teamspeak.com",
                        "0.0.0.0 blacklist2.teamspeak.com",
                        "0.0.0.0 ipcheck.teamspeak.com",
                        "0.0.0.0 hardy.teamspeak.4players.de",
                        "0.0.0.0 weblist.teamspeak.com",
                        "0.0.0.0 reportpiracy-env.elasticbeanstalk.com",
                        "0.0.0.0 versions.teamspeak.com"
                    };
                    foreach (var r in tsRules) validEntries.Add(r);
                }
                else
                {
                    if (!Uri.TryCreate(item.DownloadUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                        return new OperationResult(false, "Only HTTPS blocklists are allowed.", "فقط آدرس‌های امن HTTPS مجاز هستند.");

                    using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                    using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                    resp.EnsureSuccessStatusCode();

                    // Ensure no HTTP downgrade occurred across redirects
                    if (resp.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
                        return new OperationResult(false, "Blocked insecure redirect on blocklist download.", "ریدایرکت ناامن در دانلود لیست مسدود شد.");

                    if (resp.Content.Headers.ContentLength > MaxBlocklistBytes)
                        return new OperationResult(false, "Blocklist exceeds 12 MB safety limit.", "حجم لیست از سقف ایمن ۱۲ مگابایت بیشتر است.");

                    using var stream = await resp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                    using var reader = new StreamReader(stream, Encoding.UTF8);
                    long readBytes = 0;
                    string? raw;
                    while ((raw = await reader.ReadLineAsync(token).ConfigureAwait(false)) != null)
                    {
                        readBytes += raw.Length + 2;
                        if (readBytes > MaxBlocklistBytes) break;

                        string line = raw.Trim();
                        if (line.Length == 0 || line[0] == '#') continue;
                        int commentIdx = line.IndexOf('#');
                        if (commentIdx > 0) line = line[..commentIdx].Trim();

                        var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 2) continue;

                        string ip = parts[0];
                        string host = parts[1].ToLowerInvariant();
                        if ((ip == "127.0.0.1" || ip == "0.0.0.0") && LiteCatalog.IsValidBlocklistHostname(host))
                        {
                            validEntries.Add($"0.0.0.0 {host}");
                            if (validEntries.Count >= MaxBlocklistEntries) break;
                        }
                    }
                }

                if (validEntries.Count == 0)
                    return new OperationResult(false, "No valid entries found in blocklist.", "هیچ قانون معتبری در لیست پیدا نشد.");

                await BackupHostsAsync().ConfigureAwait(false);

                var existing = File.Exists(_hostsPath) && !IsReparsePoint(_hostsPath)
                    ? (await File.ReadAllLinesAsync(_hostsPath, token).ConfigureAwait(false)).ToList()
                    : new List<string>();

                string safeTag = SanitizeHeaderToken(item.Tag);
                string safeName = SanitizeHeaderToken(item.Name);

                var cleaned = StripBlocklistTagSafe(existing, safeTag);
                var sb = new StringBuilder(cleaned.Count * 32 + validEntries.Count * 32);
                foreach (var l in cleaned) sb.AppendLine(l);
                if (cleaned.Count > 0 && !string.IsNullOrWhiteSpace(cleaned[^1])) sb.AppendLine();

                sb.AppendLine($"# AIONTOOL-BEGIN:{safeTag}:{safeName}:{DateTime.Now:yyyy-MM-dd}");
                foreach (var e in validEntries) sb.AppendLine(e);
                sb.AppendLine($"# AIONTOOL-END:{safeTag}");

                await AtomicWriteHostsAsync(sb.ToString(), token).ConfigureAwait(false);
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);

                return new OperationResult(
                    true,
                    $"{item.Name} applied ({validEntries.Count:N0} rules).",
                    $"{item.Name} اعمال شد ({validEntries.Count:N0} قانون).");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Hosts error: {ex.Message}", $"خطای فایل هاست: {ex.Message}");
            }
        }

        public async Task<OperationResult> RemoveBlocklistByTagAsync(string tag, string label, CancellationToken token = default)
        {
            if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath))
                return new OperationResult(false, "Windows hosts file not found or unsafe.", "فایل hosts ویندوز یافت نشد یا ایمن نیست.");

            var existing = (await File.ReadAllLinesAsync(_hostsPath, token).ConfigureAwait(false)).ToList();
            var cleaned = StripBlocklistTagSafe(existing, SanitizeHeaderToken(tag));

            if (cleaned.Count == existing.Count)
                return new OperationResult(true, $"{label} was not installed.", $"{label} در فایل hosts وجود نداشت.");

            await AtomicWriteHostsAsync(string.Join(Environment.NewLine, cleaned) + Environment.NewLine, token).ConfigureAwait(false);
            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
            return new OperationResult(true, $"Removed {label} from hosts.", $"{label} از فایل hosts حذف شد.");
        }

        private static List<string> StripBlocklistTagSafe(IReadOnlyList<string> lines, string tag)
        {
            string[] beginPrefixes = { $"# AIONTOOL-BEGIN:{tag}", $"# AIOTOOL-BEGIN:{tag}", $"# {tag}-BEGIN" };
            string[] endExacts = { $"# AIONTOOL-END:{tag}", $"# AIOTOOL-END:{tag}", $"# {tag}-END" };

            var output = new List<string>(lines.Count);
            int i = 0;
            while (i < lines.Count)
            {
                string t = lines[i].Trim();
                if (beginPrefixes.Any(p => t.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                {
                    int endIdx = -1;
                    for (int j = i + 1; j < lines.Count; j++)
                    {
                        string t2 = lines[j].Trim();
                        if (endExacts.Any(e => t2.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        {
                            endIdx = j;
                            break;
                        }
                    }
                    if (endIdx >= 0) { i = endIdx + 1; continue; }
                }
                output.Add(lines[i]);
                i++;
            }
            return output;
        }

        // ==================== EXTRA COMPACT UTILITIES (PUBLIC IP & SYMLINK-SAFE TEMP CLEAN) ====================
        public async Task<(bool Success, string Ip, string SummaryEn, string SummaryFa)> GetPublicIpAsync(CancellationToken token = default)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(10));
                using var req = new HttpRequestMessage(HttpMethod.Get, "https://ipinfo.io/json");
                using var resp = await SharedHttp.SendAsync(req, cts.Token).ConfigureAwait(false);
                resp.EnsureSuccessStatusCode();

                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false));
                var root = doc.RootElement;
                string ip = root.TryGetProperty("ip", out var ipEl) ? ipEl.GetString() ?? "" : "";
                string country = root.TryGetProperty("country", out var cEl) ? cEl.GetString() ?? "" : "";
                string org = root.TryGetProperty("org", out var oEl) ? oEl.GetString() ?? "" : "";

                string shortOrg = org.Length > 26 ? org[..26] + "…" : org;
                return (true, ip, $"{ip} · {country} ({shortOrg})", $"{ip} · {country} ({shortOrg})");
            }
            catch
            {
                return (false, "", "Could not fetch Public IP", "خطا در دریافت آی‌پی عمومی");
            }
        }

        public async Task<OperationResult> CleanOldTempFilesAsync()
        {
            int deleted = 0;
            long bytes = 0;
            DateTime cutoff = DateTime.UtcNow.AddHours(-24);

            await Task.Run(() =>
            {
                string[] folders = { Path.GetTempPath(), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp") };
                foreach (var dir in folders.Where(d => Directory.Exists(d) && !IsReparsePoint(d)))
                {
                    foreach (var f in Directory.GetFiles(dir))
                    {
                        try
                        {
                            var fi = new FileInfo(f);
                            // Security: never follow or delete symlink/reparse files while running elevated
                            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            if (fi.LastWriteTimeUtc >= cutoff) continue;
                            long len = fi.Length;
                            File.Delete(f);
                            deleted++;
                            bytes += len;
                        }
                        catch { }
                    }
                    foreach (var sub in Directory.GetDirectories(dir))
                    {
                        try
                        {
                            var di = new DirectoryInfo(sub);
                            if ((di.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            // Preserve .NET single-file native extraction cache folder
                            if (di.Name.Equals(".net", StringComparison.OrdinalIgnoreCase)) continue;
                            if (di.LastWriteTimeUtc >= cutoff) continue;
                            Directory.Delete(sub, true);
                            deleted++;
                        }
                        catch { }
                    }
                }
            }).ConfigureAwait(false);

            double mb = Math.Round(bytes / 1048576.0, 1);
            return new OperationResult(
                true,
                $"Cleaned {deleted} old temp items (~{mb:F1} MB).",
                $"{deleted} فایل موقت قدیمی پاکسازی شد (~{mb:F1} مگابایت).");
        }

        // ==================== QUICK 6-SECOND SPEED CHECK ====================
        public async Task<(bool Success, double Mbps, string SummaryEn, string SummaryFa)> RunQuickSpeedCheckAsync(CancellationToken token = default)
        {
            try
            {
                const int streams = 2;
                const int perStreamBytes = 10_000_000;
                const double maxSecs = 6.0;
                long totalBytes = 0;
                var sw = new Stopwatch();
                object swLock = new();

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(15));

                var tasks = Enumerable.Range(0, streams).Select(async _ =>
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, $"https://speed.cloudflare.com/__down?bytes={perStreamBytes}");
                    using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                    resp.EnsureSuccessStatusCode();
                    using var stream = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                    byte[] buf = new byte[65536];
                    int r;
                    while ((r = await stream.ReadAsync(buf.AsMemory(), cts.Token).ConfigureAwait(false)) > 0)
                    {
                        lock (swLock) { if (!sw.IsRunning) sw.Start(); }
                        Interlocked.Add(ref totalBytes, r);
                        if (sw.Elapsed.TotalSeconds >= maxSecs) break;
                    }
                });

                await Task.WhenAll(tasks).ConfigureAwait(false);
                sw.Stop();

                double secs = Math.Max(0.1, sw.Elapsed.TotalSeconds);
                double mbps = Math.Round((totalBytes * 8.0) / 1_000_000.0 / secs, 1);
                double mbs = Math.Round(mbps / 8.0, 1);
                return (true, mbps, $"{mbps:F1} Mbps ({mbs:F1} MB/s)", $"{mbps:F1} مگابیت ({mbs:F1} مگابایت/ث)");
            }
            catch
            {
                return (false, 0, "Could not reach speed server", "خطا در اتصال به سرور تست سرعت");
            }
        }

        // ==================== QUICK STABILITY / PACKET LOSS & JITTER CHECK (~4-5s) ====================
        private static async Task<(double LossPct, long? AvgMs, long? JitterMs)> ProbeHostStabilityAsync(
            string hostOrIp, int count, int intervalMs, CancellationToken token)
        {
            if (!IPAddress.TryParse(hostOrIp, out var ip))
                return (100.0, null, null);

            var rtts = new List<long>(count);
            var opts = new PingOptions(64, false);

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var p = new Ping();
                    var reply = await p.SendPingAsync(ip, 900, PingPayload, opts).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                        rtts.Add(reply.RoundtripTime);
                }
                catch { }

                if (i < count - 1)
                    await Task.Delay(intervalMs, token).ConfigureAwait(false);
            }

            double lossPct = Math.Round(((count - rtts.Count) * 100.0) / count, 1);
            if (rtts.Count == 0)
                return (lossPct, null, null);

            long avg = (long)Math.Round(rtts.Average());
            long jitter = 0;
            if (rtts.Count >= 2)
            {
                long diffSum = 0;
                for (int i = 1; i < rtts.Count; i++)
                    diffSum += Math.Abs(rtts[i] - rtts[i - 1]);
                jitter = (long)Math.Round(diffSum / (double)(rtts.Count - 1));
            }

            return (lossPct, avg, jitter);
        }

        public async Task<StabilityCheckResult> RunStabilityCheckAsync(string interfaceName, CancellationToken token = default)
        {
            const int probes = 14;
            const int intervalMs = 260;

            try
            {
                string routerIp = await Task.Run(() => DetectGatewayIp(interfaceName), token).ConfigureAwait(false);
                var tGlobal = ProbeHostStabilityAsync("4.2.2.4", probes, intervalMs, token);
                Task<(double LossPct, long? AvgMs, long? JitterMs)>? tRouter = !string.IsNullOrEmpty(routerIp)
                    ? ProbeHostStabilityAsync(routerIp, probes, intervalMs, token)
                    : null;

                if (tRouter != null)
                    await Task.WhenAll(tGlobal, tRouter).ConfigureAwait(false);
                else
                    await tGlobal.ConfigureAwait(false);

                var g = tGlobal.Result;
                (double LossPct, long? AvgMs, long? JitterMs)? r = tRouter != null ? tRouter.Result : null;

                string verdictEn;
                string verdictFa;

                if (r.HasValue && (r.Value.LossPct >= 5.0 || (r.Value.JitterMs ?? 0) >= 15))
                {
                    verdictEn = "Local Wi-Fi / Modem instability detected";
                    verdictFa = "ناپایداری داخلی است (وای‌فای یا مودم شما)";
                }
                else if (!g.AvgMs.HasValue || g.LossPct >= 5.0 || (g.JitterMs ?? 0) >= 25)
                {
                    verdictEn = "Modem OK · ISP / Internet unstable";
                    verdictFa = "مودم سالم · ناپایداری از اینترنت / ISP";
                }
                else if (g.LossPct == 0 && (g.JitterMs ?? 0) <= 12)
                {
                    verdictEn = "Rock-solid for gaming!";
                    verdictFa = "عالی و کاملاً پایدار برای گیم!";
                }
                else
                {
                    verdictEn = "Good line stability";
                    verdictFa = "پایداری خط مناسب است";
                }

                return new StabilityCheckResult(
                    Success: true,
                    SentCount: probes,
                    GlobalLossPct: g.LossPct,
                    GlobalAvgMs: g.AvgMs,
                    GlobalJitterMs: g.JitterMs,
                    RouterLossPct: r?.LossPct,
                    RouterAvgMs: r?.AvgMs,
                    RouterJitterMs: r?.JitterMs,
                    VerdictEn: verdictEn,
                    VerdictFa: verdictFa);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return new StabilityCheckResult(
                    false, probes, 100, null, null, null, null, null,
                    "Stability check failed", "خطا در اجرای تست پایداری");
            }
        }

        // ==================== HARDENED GITHUB AUTO-UPDATER (ADMIN-LOCKED STAGING + SHA256 + PE CHECK) ====================
        private static bool IsTrustedGitHubHttpsUrl(string? url, out Uri? uri)
        {
            uri = null;
            if (string.IsNullOrWhiteSpace(url)) return false;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) || parsed.Scheme != Uri.UriSchemeHttps)
                return false;
            if (!IsTrustedGitHubHost(parsed.Host))
                return false;
            uri = parsed;
            return true;
        }

        private static bool IsTrustedGitHubHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            return host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".github.com", StringComparison.OrdinalIgnoreCase)
                || host.Equals("githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
        }

        private static string? ParseExpectedSha256(string checksumText, string targetFileName)
        {
            var hex64 = new Regex(@"\b[a-fA-F0-9]{64}\b");
            var lines = checksumText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var raw in lines)
            {
                if (raw.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    var m = hex64.Match(raw);
                    if (m.Success) return m.Value.ToLowerInvariant();
                }
            }
            if (lines.Length == 1)
            {
                var m = hex64.Match(lines[0]);
                if (m.Success) return m.Value.ToLowerInvariant();
            }
            return null;
        }

        private async Task<string?> PrepareAdminOnlyUpdateDirectoryAsync(CancellationToken token)
        {
            string parentDir = Path.GetDirectoryName(_secureUpdatesDir)!;
            if (Directory.Exists(parentDir) && IsReparsePoint(parentDir))
                return null;
            if (Directory.Exists(_secureUpdatesDir) && IsReparsePoint(_secureUpdatesDir))
                return null;

            Directory.CreateDirectory(_secureUpdatesDir);

            // Lock NTFS ACL strictly to SYSTEM (*S-1-5-18) and Administrators (*S-1-5-32-544) — prevents TOCTOU LPE!
            var aclRes = await _runner.RunAsync("icacls", new[]
            {
                _secureUpdatesDir,
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(OI)(CI)F",
                "/grant:r", "*S-1-5-32-544:(OI)(CI)F"
            }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            if (!aclRes.IsSuccess)
                return null;

            // Clean any leftover update installers from prior runs
            foreach (var oldFile in Directory.GetFiles(_secureUpdatesDir, "update_*.exe"))
            {
                try { if (!IsReparsePoint(oldFile)) File.Delete(oldFile); } catch { }
            }

            return _secureUpdatesDir;
        }

        public async Task<(bool HasUpdate, string LatestVersion)> CheckLatestUpdateInfoAsync(string owner, string repo, CancellationToken token = default)
        {
            try
            {
                var rawVer = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 1, 0);
                var currentVer = new Version(Math.Max(0, rawVer.Major), Math.Max(0, rawVer.Minor), Math.Max(0, rawVer.Build));

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(8));

                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{owner}/{repo}/releases/latest");
                req.Headers.Accept.ParseAdd("application/vnd.github+json");
                using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    return (false, string.Empty);

                string json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                string tag = doc.RootElement.TryGetProperty("tag_name", out var tEl) ? tEl.GetString() ?? "" : "";
                if (!Version.TryParse(tag.TrimStart('v', 'V').Trim(), out var parsed) || parsed == null)
                    return (false, string.Empty);

                var latestVer = new Version(Math.Max(0, parsed.Major), Math.Max(0, parsed.Minor), Math.Max(0, parsed.Build));
                return latestVer > currentVer ? (true, latestVer.ToString()) : (false, string.Empty);
            }
            catch
            {
                return (false, string.Empty);
            }
        }

        public async Task<OperationResult> CheckAndInstallUpdateAsync(string owner, string repo, CancellationToken token = default)
        {
            string? stagedExe = null;
            try
            {
                var rawVer = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 1, 0);
                var currentVer = new Version(Math.Max(0, rawVer.Major), Math.Max(0, rawVer.Minor), Math.Max(0, rawVer.Build));

                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{owner}/{repo}/releases/latest");
                req.Headers.Accept.ParseAdd("application/vnd.github+json");
                using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    return new OperationResult(false, "You are on the latest version (or GitHub is unreachable).", "شما از آخرین نسخه استفاده می‌کنید (یا گیت‌هاب در دسترس نیست).");

                string json = await resp.Content.ReadAsStringAsync(token).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                string tag = doc.RootElement.TryGetProperty("tag_name", out var tEl) ? tEl.GetString() ?? "" : "";
                if (!Version.TryParse(tag.TrimStart('v', 'V').Trim(), out var parsed) || parsed == null)
                    return new OperationResult(false, "Could not read release version.", "نسخه انتشار قابل خواندن نیست.");

                var latestVer = new Version(Math.Max(0, parsed.Major), Math.Max(0, parsed.Minor), Math.Max(0, parsed.Build));
                if (latestVer <= currentVer)
                    return new OperationResult(false, $"You're up to date (v{currentVer}).", $"برنامه شما به‌روز است (نسخه {currentVer}).");

                string? exeName = null;
                string? dlUrl = null;
                string? checksumUrl = null;

                if (doc.RootElement.TryGetProperty("assets", out var assets))
                {
                    foreach (var a in assets.EnumerateArray())
                    {
                        string name = a.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? "" : "";
                        string? url = a.TryGetProperty("browser_download_url", out var uEl) ? uEl.GetString() : null;

                        if (dlUrl == null && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            exeName = name;
                            dlUrl = url;
                        }
                        else if (checksumUrl == null &&
                                 (name.Equals("checksums.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.Equals("sha256sums.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.Equals("sha256.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase)))
                        {
                            checksumUrl = url;
                        }
                    }
                }

                if (!IsTrustedGitHubHttpsUrl(dlUrl, out var dlUri) || dlUri == null || string.IsNullOrWhiteSpace(exeName))
                    return new OperationResult(false, "Update found, but no verified GitHub installer is attached.", "آپدیت جدید یافت شد اما فایل نصبی معتبر یافت نشد.");

                string? secureDir = await PrepareAdminOnlyUpdateDirectoryAsync(token).ConfigureAwait(false);
                if (string.IsNullOrEmpty(secureDir))
                    return new OperationResult(false, "Could not prepare secure admin-only update folder.", "ایجاد پوشه امن آپدیت با دسترسی ادمین ناموفق بود.");

                // Strictly hex-only filename inside Admin-locked ProgramData directory (zero untrusted chars, zero TOCTOU)
                stagedExe = Path.Combine(secureDir, $"update_{Guid.NewGuid():N}.exe");
                if (stagedExe.IndexOfAny(ForbiddenShellChars) >= 0)
                    return new OperationResult(false, "Blocked update: unsafe staging path.", "آپدیت متوقف شد: مسیر ذخیره‌سازی نامعتبر است.");

                using (var dlResp = await SharedHttp.GetAsync(dlUri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false))
                {
                    dlResp.EnsureSuccessStatusCode();

                    // Verify final post-redirect URI stayed on HTTPS + GitHub domain
                    var finalUri = dlResp.RequestMessage?.RequestUri;
                    if (finalUri == null || finalUri.Scheme != Uri.UriSchemeHttps || !IsTrustedGitHubHost(finalUri.Host))
                        return new OperationResult(false, "Update aborted: redirected outside trusted GitHub HTTPS.", "آپدیت متوقف شد: ریدایرکت خارج از سرور امن گیت‌هاب.");

                    if (dlResp.Content.Headers.ContentLength > MaxUpdaterBytes)
                        return new OperationResult(false, "Update aborted: installer exceeds 150 MB limit.", "آپدیت متوقف شد: حجم فایل بیش از سقف ۱۵۰ مگابایت است.");

                    await using var src = await dlResp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                    await using var dst = new FileStream(stagedExe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true);
                    byte[] buf = new byte[81920];
                    long total = 0;
                    int read;
                    while ((read = await src.ReadAsync(buf.AsMemory(), token).ConfigureAwait(false)) > 0)
                    {
                        total += read;
                        if (total > MaxUpdaterBytes)
                            throw new InvalidOperationException("Installer download exceeded 150 MB safety limit.");
                        await dst.WriteAsync(buf.AsMemory(0, read), token).ConfigureAwait(false);
                    }
                }

                // Validate minimum size and Windows PE magic header ('MZ')
                var fi = new FileInfo(stagedExe);
                if (fi.Length < 100 * 1024)
                {
                    try { File.Delete(stagedExe); } catch { }
                    return new OperationResult(false, "Downloaded installer appears incomplete.", "فایل آپدیت دانلودشده ناقص به نظر می‌رسد.");
                }

                byte[] header = new byte[2];
                using (var fs = File.OpenRead(stagedExe))
                {
                    if (fs.Read(header, 0, 2) < 2 || header[0] != 0x4D || header[1] != 0x5A)
                    {
                        fs.Close();
                        try { File.Delete(stagedExe); } catch { }
                        return new OperationResult(false, "Update aborted: downloaded file is not a valid Windows executable.", "آپدیت متوقف شد: فایل دانلودشده یک فایل اجرایی معتبر نیست.");
                    }
                }

                // Verify SHA256 if a checksum file is provided in the GitHub release
                if (IsTrustedGitHubHttpsUrl(checksumUrl, out var sumUri) && sumUri != null)
                {
                    using var sumResp = await SharedHttp.GetAsync(sumUri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                    sumResp.EnsureSuccessStatusCode();
                    var finalSumUri = sumResp.RequestMessage?.RequestUri;
                    if (finalSumUri == null || finalSumUri.Scheme != Uri.UriSchemeHttps || !IsTrustedGitHubHost(finalSumUri.Host))
                    {
                        try { File.Delete(stagedExe); } catch { }
                        return new OperationResult(false, "Update aborted: untrusted checksum redirect.", "آپدیت متوقف شد: منبع فایل چک‌سام نامعتبر است.");
                    }

                    string sumText = await sumResp.Content.ReadAsStringAsync(token).ConfigureAwait(false);
                    string? expectedHash = ParseExpectedSha256(sumText, exeName);
                    if (!string.IsNullOrEmpty(expectedHash))
                    {
                        string actualHash;
                        await using (var verifyStream = new FileStream(stagedExe, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
                        {
                            byte[] actualBytes = await SHA256.HashDataAsync(verifyStream, token).ConfigureAwait(false);
                            actualHash = Convert.ToHexString(actualBytes).ToLowerInvariant();
                        }

                        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                        {
                            try { File.Delete(stagedExe); } catch { }
                            return new OperationResult(false, "Update aborted: SHA256 checksum mismatch!", "آپدیت متوقف شد: عدم تطابق امضای امنیتی SHA256!");
                        }
                    }
                }

                string cmdPath = _runner.ResolveSystemExecutable("cmd.exe");
                string pingPath = _runner.ResolveSystemExecutable("ping.exe");
                string taskkillPath = _runner.ResolveSystemExecutable("taskkill.exe");

                // Use ping.exe instead of timeout.exe (timeout fails immediately in non-console GUI apps)
                // Wrap inner command in outer quotes so cmd.exe /c strips only the outer pair safely
                string innerCmd = $"\"{pingPath}\" -n 3 127.0.0.1 > NUL & \"{taskkillPath}\" /F /IM AionToolLite.exe > NUL 2>&1 & \"{pingPath}\" -n 2 127.0.0.1 > NUL & \"{stagedExe}\" /VERYSILENT /SUPPRESSMSGBOXES /FORCECLOSEAPPLICATIONS /NORESTART & del /f /q \"{stagedExe}\" > NUL 2>&1";
                Process.Start(new ProcessStartInfo
                {
                    FileName = cmdPath,
                    Arguments = $"/c \"{innerCmd}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                return new OperationResult(true, "READY_TO_UPDATE", "READY_TO_UPDATE");
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(stagedExe))
                {
                    try { if (File.Exists(stagedExe)) File.Delete(stagedExe); } catch { }
                }
                return new OperationResult(false, $"Update check failed: {ex.Message}", $"بررسی آپدیت ناموفق بود: {ex.Message}");
            }
        }

        // ==================== SETTINGS ====================
        public LiteSettings LoadSettings()
        {
            lock (_ioLock)
            {
                try
                {
                    string? json = ReadSmallJsonTextSafe(SettingsFilePath);
                    if (!string.IsNullOrEmpty(json))
                    {
                        var loaded = JsonSerializer.Deserialize<LiteSettings>(json);
                        if (loaded != null)
                        {
                            var safeCustom = (loaded.SavedCustomDns ?? new List<SavedCustomDnsEntry>())
                                .Where(c => c != null && !string.IsNullOrWhiteSpace(c.Id) && !string.IsNullOrWhiteSpace(c.Name) && LiteCatalog.IsSafeDnsIpv4(c.PrimaryIp))
                                .Take(5)
                                .ToList();
                            return loaded with
                            {
                                PinnedDnsIds = loaded.PinnedDnsIds ?? new List<string>(),
                                SavedCustomDns = safeCustom
                            };
                        }
                    }
                }
                catch { }
                return new LiteSettings(PinnedDnsIds: new List<string>(), SavedCustomDns: new List<SavedCustomDnsEntry>());
            }
        }

        public void SaveSettings(LiteSettings settings)
        {
            lock (_ioLock)
            {
                try
                {
                    Directory.CreateDirectory(_cfgDir);
                    string tmp = SettingsFilePath + ".tmp";
                    File.WriteAllText(tmp, JsonSerializer.Serialize(settings, JsonOpts), new UTF8Encoding(false));
                    if (File.Exists(SettingsFilePath))
                        File.Replace(tmp, SettingsFilePath, null, true);
                    else
                        File.Move(tmp, SettingsFilePath);
                }
                catch { }
            }
        }
    }
}
