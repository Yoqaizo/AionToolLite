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
using System.Security;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        private const long MaxChecksumBytes = 64 * 1024;
        private const long MaxSignatureBytes = 8 * 1024;
        private const int MaxBlocklistEntries = 200_000;

        // Offline RSA-3072 public key pinned automatically by Release-Manager.ps1 (private key never leaves developer PC)
        private const string PinnedReleaseRsaModulusBase64 = "yg2Zz+JUQi8F+Uzwih5Da8uXC057IGPqqOc1EGjIl1AzqAyI3Fl5CySI3Naz/WBdblSbZ4L7Wk6aD2p1NmZ3N8EcJs30Vajzm+Kumm5WJHN+TGklHF5iyEbIehajEQWHgJxRD0eJCjE1IDGtONAhd0YS7sHxSlJz88CPj1obNcrBmFuvUc8usScYNCA8be0aiNaBglw/LZ5I1/2l6VdBt/DkKxgmmNCK+53PKaZqZMg91/WmkFzwMx9aL9WtfeOc2st/DPWpLPcV6j6/vXLZcg7d2OUYDvVKNOWyv0ffnGcrA8aSvt7TLzOdBKI5udDbMiEKATZBecTYS1mLPFnzLjopWhCFaomrvlKHSyhNTbJrmj3SZDD9SO6qOfTY7N6P73v5dzy3/AZ8NoFK9Qe0Eejy7knSnIOXKUqqqikORc5WKsUNsyaUyhHKrOAC2Uiscx76+yhYPqkdeEzA/Q9AFat5ddWy2zYCV2NkBPEztFHOjRDBV1Gk/cN0NI0VTgXR";
        private const string PinnedReleaseRsaExponentBase64 = "AQAB";
        private const int MaxBackupsToKeep = 10;

        private readonly ProcessRunner _runner = new();
        private readonly object _ioLock = new();
        private readonly SemaphoreSlim _hostsLock = new(1, 1);
        private static readonly byte[] PingPayload = new byte[16];
        private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
        private readonly ConcurrentDictionary<string, (IPAddress Ip, DateTime ExpiresUtc)> _resolveCache = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HttpClient SharedHttp = CreateHttpClient(TimeSpan.FromSeconds(45));
        private static readonly HttpClient UpdaterDownloadHttp = CreateHttpClient(Timeout.InfiniteTimeSpan);

        private readonly string _cfgDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AionToolLite");
        private readonly string _secureStateDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AionToolLite", "State");
        private readonly string _secureUpdatesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AionToolLite", "Updates");
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
        private string GameModeStatePath => Path.Combine(_secureStateDir, "gamemode_state.json");
        private string HostsOriginalBackupPath => Path.Combine(_secureStateDir, "hosts.backup.original");
        private string HostsManualBackupPath => Path.Combine(_secureStateDir, "hosts.backup.manual");
        private string OriginalDnsBackupPath => Path.Combine(_secureStateDir, "dns_original_backup.json");

        private static HttpClient CreateHttpClient(TimeSpan timeout)
        {
            var handler = new SocketsHttpHandler
            {
                ConnectTimeout = TimeSpan.FromSeconds(15),
                PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                AutomaticDecompression = DecompressionMethods.All,
                MaxAutomaticRedirections = 8,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }
            };
            var c = new HttpClient(handler) { Timeout = timeout };
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            string uaVer = v != null ? $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}" : "1.1.1";
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

        private string? EnsureAdminOnlyStateDirectory()
        {
            try
            {
                string programFilesDir = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string appDir = Path.GetDirectoryName(_secureStateDir)!;

                if (!IsDirectoryOwnedAndLockedByAdmins(programFilesDir, strictAdminOnly: false))
                    return null;

                if (!Directory.Exists(appDir))
                {
                    FileSystemAclExtensions.CreateDirectory(BuildAdminOnlyDirectorySecurity(), appDir);
                }
                if (!IsDirectoryOwnedAndLockedByAdmins(appDir, strictAdminOnly: false))
                    return null;

                if (!Directory.Exists(_secureStateDir))
                {
                    FileSystemAclExtensions.CreateDirectory(BuildAdminOnlyDirectorySecurity(), _secureStateDir);
                }
                if (!IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true))
                    return null;

                return _secureStateDir;
            }
            catch
            {
                return null;
            }
        }

        private string? ReadAdminVerifiedSmallJsonTextSafe(string path)
        {
            if (!IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true))
                return null;
            if (!IsFileOwnedAndLockedByAdmins(path, strictAdminOnly: true))
                return null;
            return ReadSmallJsonTextSafe(path);
        }

        private bool AtomicWriteAdminOnlyText(string destPath, string content)
        {
            if (EnsureAdminOnlyStateDirectory() == null)
                return false;
            if (File.Exists(destPath) && !IsFileOwnedAndLockedByAdmins(destPath, strictAdminOnly: true))
                return false;

            string tmp = destPath + $".{Guid.NewGuid():N}.tmp";
            try
            {
                File.WriteAllText(tmp, content, new UTF8Encoding(false));
                if (!IsFileOwnedAndLockedByAdmins(tmp, strictAdminOnly: true))
                    return false;

                if (File.Exists(destPath))
                    File.Replace(tmp, destPath, null, true);
                else
                    File.Move(tmp, destPath);

                return IsFileOwnedAndLockedByAdmins(destPath, strictAdminOnly: true);
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
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

        // ==================== AUTOMATIC ORIGINAL DNS BACKUP (LOSSLESS IPv4 + LOOPBACK + IPv6) ====================
        private static (List<string> Ipv4, List<string> Ipv6) ReadInterfaceStaticDnsFromRegistry(string nicGuid)
        {
            var v4 = new List<string>();
            var v6 = new List<string>();

            try
            {
                using var key4 = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{nicGuid}", false);
                if (key4?.GetValue("NameServer") is string raw4 && !string.IsNullOrWhiteSpace(raw4))
                {
                    v4.AddRange(raw4
                        .Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .Where(LiteCatalog.IsValidBackupDnsIpv4)
                        .Distinct(StringComparer.OrdinalIgnoreCase));
                }
            }
            catch { }

            try
            {
                using var key6 = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{nicGuid}", false);
                if (key6?.GetValue("NameServer") is string raw6 && !string.IsNullOrWhiteSpace(raw6))
                {
                    v6.AddRange(raw6
                        .Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .Where(LiteCatalog.IsSafeDnsIpv6)
                        .Distinct(StringComparer.OrdinalIgnoreCase));
                }
            }
            catch { }

            return (v4, v6);
        }

        private void EnsureOriginalDnsBackupSaved(string interfaceName)
        {
            lock (_ioLock)
            {
                try
                {
                    if (EnsureAdminOnlyStateDirectory() == null)
                        return;

                    string? existingJson = ReadAdminVerifiedSmallJsonTextSafe(OriginalDnsBackupPath);
                    var map = !string.IsNullOrEmpty(existingJson)
                        ? JsonSerializer.Deserialize<Dictionary<string, OriginalDnsBackup>>(existingJson)
                          ?? new Dictionary<string, OriginalDnsBackup>(StringComparer.OrdinalIgnoreCase)
                        : new Dictionary<string, OriginalDnsBackup>(StringComparer.OrdinalIgnoreCase);

                    if (map.Keys.Any(k => k.Equals(interfaceName, StringComparison.OrdinalIgnoreCase)))
                        return;

                    var nic = NetworkInterface.GetAllNetworkInterfaces()
                        .FirstOrDefault(n => n.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

                    var (v4, v6) = nic != null
                        ? ReadInterfaceStaticDnsFromRegistry(nic.Id)
                        : (new List<string>(), new List<string>());

                    map[interfaceName] = new OriginalDnsBackup(
                        AdapterName: interfaceName,
                        WasDhcp: v4.Count == 0,
                        PrimaryIp: v4.Count > 0 ? v4[0] : string.Empty,
                        SecondaryIp: v4.Count > 1 ? v4[1] : string.Empty,
                        SavedAtUtc: DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                        WasDhcpIpv6: v6.Count == 0,
                        PrimaryIpv6: v6.Count > 0 ? v6[0] : string.Empty,
                        SecondaryIpv6: v6.Count > 1 ? v6[1] : string.Empty);

                    AtomicWriteAdminOnlyText(OriginalDnsBackupPath, JsonSerializer.Serialize(map, JsonOpts));
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
                    string? json = ReadAdminVerifiedSmallJsonTextSafe(OriginalDnsBackupPath);
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
            if (!TryValidateInterfaceName(interfaceName, out string iface))
                return new OperationResult(false, "Invalid or missing network adapter.", "کارت شبکه انتخاب‌شده نامعتبر است.");

            var backup = GetOriginalDnsBackup(iface);
            if (backup == null || (backup.WasDhcp && backup.WasDhcpIpv6))
            {
                return await DisconnectDnsToAutoAsync(iface, token).ConfigureAwait(false);
            }

            bool restoredV4Static = !backup.WasDhcp && LiteCatalog.IsValidBackupDnsIpv4(backup.PrimaryIp);
            bool restoredV6Static = !backup.WasDhcpIpv6 && LiteCatalog.IsSafeDnsIpv6(backup.PrimaryIpv6);

            if (!restoredV4Static && !restoredV6Static)
                return await DisconnectDnsToAutoAsync(iface, token).ConfigureAwait(false);

            var warnings = new List<string>();

            if (restoredV4Static)
            {
                var r1 = await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ip", "set", "dnsservers",
                    $"name={iface}", "source=static", $"address={backup.PrimaryIp.Trim()}", "validate=no"
                }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                if (!r1.IsSuccess)
                    return new OperationResult(false, $"Could not restore original IPv4 DNS ({backup.PrimaryIp}).", $"بازیابی دی‌ان‌اس قبلی ({backup.PrimaryIp}) ناموفق بود.");

                if (LiteCatalog.IsValidBackupDnsIpv4(backup.SecondaryIp) &&
                    !backup.SecondaryIp.Trim().Equals(backup.PrimaryIp.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    var r2 = await _runner.RunAsync("netsh", new[]
                    {
                        "interface", "ip", "add", "dnsservers",
                        $"name={iface}", $"address={backup.SecondaryIp.Trim()}", "index=2", "validate=no"
                    }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                    if (!r2.IsSuccess) warnings.Add("secondary IPv4");
                }
            }
            else
            {
                var rDhcp4 = await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ip", "set", "dnsservers", $"name={iface}", "source=dhcp"
                }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                if (!rDhcp4.IsSuccess) warnings.Add("IPv4 DHCP");
            }

            if (restoredV6Static)
            {
                var r6p = await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "set", "dnsservers",
                    $"name={iface}", "source=static", $"address={backup.PrimaryIpv6.Trim()}", "validate=no"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                if (!r6p.IsSuccess) warnings.Add("IPv6 DNS");

                if (LiteCatalog.IsSafeDnsIpv6(backup.SecondaryIpv6) &&
                    !backup.SecondaryIpv6.Trim().Equals(backup.PrimaryIpv6.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    var r6s = await _runner.RunAsync("netsh", new[]
                    {
                        "interface", "ipv6", "add", "dnsservers",
                        $"name={iface}", $"address={backup.SecondaryIpv6.Trim()}", "index=2", "validate=no"
                    }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    if (!r6s.IsSuccess) warnings.Add("secondary IPv6");
                }
            }
            else
            {
                await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "set", "dnsservers", $"name={iface}", "source=dhcp"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }

            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);

            string summaryTarget = restoredV4Static ? backup.PrimaryIp : backup.PrimaryIpv6;
            string warnSuffixEn = warnings.Count > 0 ? $" (partial: {string.Join(", ", warnings)})" : string.Empty;
            string warnSuffixFa = warnings.Count > 0 ? " (با هشدار جزئی)" : string.Empty;

            return new OperationResult(
                true,
                $"Restored original DNS ({summaryTarget}){warnSuffixEn}.",
                $"دی‌ان‌اس قبلی شما ({summaryTarget}) بازیابی شد{warnSuffixFa}.");
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

                var (ips4, ips6) = ReadInterfaceStaticDnsFromRegistry(nic.Id);
                if (ips4.Count == 0 && ips6.Count == 0)
                    return ActiveDnsStatus.Automatic;

                string primary = ips4.Count > 0 ? ips4[0] : string.Empty;
                string secondary = ips4.Count > 1 ? ips4[1] : string.Empty;
                string primary6 = ips6.Count > 0 ? ips6[0] : string.Empty;
                string secondary6 = ips6.Count > 1 ? ips6[1] : string.Empty;

                if (!string.IsNullOrEmpty(primary))
                {
                    var matched = LiteCatalog.DnsPresets.FirstOrDefault(p =>
                        !p.IsSmartAuto && p.PrimaryIp.Equals(primary, StringComparison.OrdinalIgnoreCase));
                    if (matched != null)
                        return new ActiveDnsStatus(true, primary, secondary, matched.Name, matched.Name, matched.Id, primary6, secondary6);

                    if (customEntries != null)
                    {
                        var customMatched = customEntries.FirstOrDefault(c =>
                            c.PrimaryIp.Equals(primary, StringComparison.OrdinalIgnoreCase));
                        if (customMatched != null)
                            return new ActiveDnsStatus(true, primary, secondary, customMatched.Name, customMatched.Name, customMatched.Id, primary6, secondary6);
                    }

                    if (primary.StartsWith("127.", StringComparison.Ordinal))
                        return new ActiveDnsStatus(true, primary, secondary, "Local Resolver", "سرور محلی (Loopback)", null, primary6, secondary6);

                    return new ActiveDnsStatus(true, primary, secondary, "Custom DNS", "دی‌ان‌اس دستی", null, primary6, secondary6);
                }

                var matchedV6 = LiteCatalog.DnsPresets.FirstOrDefault(p =>
                    !string.IsNullOrEmpty(p.PrimaryIpv6) && p.PrimaryIpv6.Equals(primary6, StringComparison.OrdinalIgnoreCase));
                if (matchedV6 != null)
                    return new ActiveDnsStatus(true, primary6, secondary6, matchedV6.Name, matchedV6.Name, matchedV6.Id, primary6, secondary6);

                return new ActiveDnsStatus(true, primary6, secondary6, "Custom IPv6 DNS", "دی‌ان‌اس دستی IPv6", null, primary6, secondary6);
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

                    if (!IsExecutableSafeForElevatedAutoStart(exePath))
                    {
                        return new OperationResult(
                            false,
                            "For security, Start with Windows is only allowed when AionToolLite is installed in an admin-protected Program Files folder (run the official Setup installer).",
                            "برای حفظ امنیت سیستم، شروع خودکار با دسترسی ادمین فقط زمانی مجاز است که برنامه از طریق فایل نصبی در پوشه محافظت‌شده Program Files نصب شده باشد.");
                    }

                    string? stateDir = EnsureAdminOnlyStateDirectory();
                    if (string.IsNullOrEmpty(stateDir))
                    {
                        return new OperationResult(
                            false,
                            "Could not prepare verified admin-only state folder for task registration.",
                            "آماده‌سازی پوشه امن ادمین برای ثبت تسک ناموفق بود.");
                    }

                    using var currentIdentity = WindowsIdentity.GetCurrent();
                    string? userSid = currentIdentity.User?.Value;
                    string escapedExe = SecurityElement.Escape(exePath) ?? exePath;
                    string userIdTag = !string.IsNullOrWhiteSpace(userSid)
                        ? $"      <UserId>{SecurityElement.Escape(userSid)}</UserId>\r\n"
                        : string.Empty;

                    string taskXml =
                        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                        "<Task version=\"1.3\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                        "  <RegistrationInfo>\r\n" +
                        "    <Description>Starts AionToolLite quietly in the System Tray on user logon.</Description>\r\n" +
                        "  </RegistrationInfo>\r\n" +
                        "  <Triggers>\r\n" +
                        "    <LogonTrigger>\r\n" +
                        "      <Enabled>true</Enabled>\r\n" +
                        userIdTag +
                        "    </LogonTrigger>\r\n" +
                        "  </Triggers>\r\n" +
                        "  <Principals>\r\n" +
                        "    <Principal id=\"Author\">\r\n" +
                        userIdTag +
                        "      <LogonType>InteractiveToken</LogonType>\r\n" +
                        "      <RunLevel>HighestAvailable</RunLevel>\r\n" +
                        "    </Principal>\r\n" +
                        "  </Principals>\r\n" +
                        "  <Settings>\r\n" +
                        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
                        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
                        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
                        "    <AllowHardTerminate>true</AllowHardTerminate>\r\n" +
                        "    <StartWhenAvailable>true</StartWhenAvailable>\r\n" +
                        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n" +
                        "    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n" +
                        "    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n" +
                        "    <Enabled>true</Enabled>\r\n" +
                        "    <Hidden>false</Hidden>\r\n" +
                        "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n" +
                        "    <WakeToRun>false</WakeToRun>\r\n" +
                        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n" +
                        "    <Priority>7</Priority>\r\n" +
                        "  </Settings>\r\n" +
                        "  <Actions Context=\"Author\">\r\n" +
                        "    <Exec>\r\n" +
                        $"      <Command>{escapedExe}</Command>\r\n" +
                        "      <Arguments>--minimized</Arguments>\r\n" +
                        "    </Exec>\r\n" +
                        "  </Actions>\r\n" +
                        "</Task>\r\n";

                    string xmlPath = Path.Combine(stateDir, $"autostart_{Guid.NewGuid():N}.xml");
                    ProcessResult res;
                    try
                    {
                        await File.WriteAllTextAsync(xmlPath, taskXml, Encoding.Unicode, token).ConfigureAwait(false);
                        res = await _runner.RunAsync("schtasks", new[]
                        {
                            "/Create",
                            "/TN", AutoStartTaskName,
                            "/XML", xmlPath,
                            "/F"
                        }, token, TimeSpan.FromSeconds(12)).ConfigureAwait(false);
                    }
                    finally
                    {
                        try { if (File.Exists(xmlPath)) File.Delete(xmlPath); } catch { }
                    }

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

                // Include Disabled physical hardware adapters cleanly via Windows Registry (100% locale-independent)
                try
                {
                    var activeGuids = new HashSet<string>(
                        NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Id),
                        StringComparer.OrdinalIgnoreCase);

                    foreach (var kv in nameToGuid)
                    {
                        string name = kv.Key;
                        string guid = kv.Value;

                        if (activeGuids.Contains(guid)) continue;
                        if (physicalMap.ContainsKey(name) || IsIgnoredAdapterText(name, null)) continue;

                        if (regByGuid.TryGetValue(guid, out var meta) &&
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

        private static readonly string[] IranIntranetTargets = { "www.arvancloud.ir", "parsvds.com", "salatingames.ir" };

        private async Task<long?> PingIranIntranetAsync()
        {
            foreach (var host in IranIntranetTargets)
            {
                long? ms = await PingHostFastAsync(host, 1100, 443).ConfigureAwait(false);
                if (ms.HasValue) return ms.Value;
            }
            return null;
        }

        public async Task<LiteTelemetry> CaptureTelemetryAsync(
            string interfaceName,
            IReadOnlyList<SavedCustomDnsEntry>? customEntries = null)
        {
            string routerIp = await Task.Run(() => DetectGatewayIp(interfaceName)).ConfigureAwait(false);

            var tRouter = !string.IsNullOrEmpty(routerIp)
                ? PingHostFastAsync(routerIp, 800, 80)
                : Task.FromResult<long?>(null);
            await Task.Delay(25).ConfigureAwait(false);
            var tIntranet = PingIranIntranetAsync();
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
            // Smart Auto only selects from neutral, unfiltered global resolvers
            var eligible = LiteCatalog.DnsPresets.Where(x => x.SmartAutoEligible).ToList();
            using var sem = new SemaphoreSlim(8);
            var tasks = eligible.Select(async preset =>
            {
                await sem.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    long? ms = await QueryDnsUdpMsAsync(preset.PrimaryIp, 950, token).ConfigureAwait(false);
                    return (Preset: preset, Latency: ms);
                }
                finally
                {
                    sem.Release();
                }
            });

            LiteDnsPreset? best = null;
            long bestMs = long.MaxValue;

            foreach (var (preset, ms) in await Task.WhenAll(tasks).ConfigureAwait(false))
            {
                if (ms.HasValue && ms.Value < bestMs)
                {
                    bestMs = ms.Value;
                    best = preset;
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

            var warningsEn = new List<string>();
            var warningsFa = new List<string>();

            if (cleanSecondary != null)
            {
                var r2 = await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ip", "add", "dnsservers",
                    $"name={iface}", $"address={cleanSecondary}", "index=2", "validate=no"
                }, token, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                if (!r2.IsSuccess)
                {
                    warningsEn.Add("secondary IPv4 failed");
                    warningsFa.Add("ثبت DNS دوم ناموفق بود");
                }
            }

            if (LiteCatalog.IsSafeDnsIpv6(primaryIpv6) && IPAddress.TryParse(primaryIpv6!.Trim(), out var v6p))
            {
                var r6p = await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "set", "dnsservers",
                    $"name={iface}", "source=static", $"address={v6p}", "validate=no"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

                if (!r6p.IsSuccess)
                {
                    warningsEn.Add("IPv6 DNS failed");
                    warningsFa.Add("ثبت IPv6 ناموفق بود");
                }
                else if (LiteCatalog.IsSafeDnsIpv6(secondaryIpv6) && IPAddress.TryParse(secondaryIpv6!.Trim(), out var v6s))
                {
                    var r6s = await _runner.RunAsync("netsh", new[]
                    {
                        "interface", "ipv6", "add", "dnsservers",
                        $"name={iface}", $"address={v6s}", "index=2", "validate=no"
                    }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    if (!r6s.IsSuccess)
                    {
                        warningsEn.Add("secondary IPv6 failed");
                        warningsFa.Add("ثبت IPv6 دوم ناموفق بود");
                    }
                }
            }
            else
            {
                await _runner.RunAsync("netsh", new[]
                {
                    "interface", "ipv6", "delete", "dnsservers",
                    $"name={iface}", "all"
                }, token, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

                bool hasActiveRouterIpv6Dns = false;
                try
                {
                    var nic = NetworkInterface.GetAllNetworkInterfaces()
                        .FirstOrDefault(n => n.Name.Equals(iface, StringComparison.OrdinalIgnoreCase));
                    if (nic != null)
                    {
                        hasActiveRouterIpv6Dns = nic.GetIPProperties().DnsAddresses
                            .Any(a => a.AddressFamily == AddressFamily.InterNetworkV6 && LiteCatalog.IsSafeDnsIpv6(a.ToString()));
                    }
                }
                catch { }

                if (hasActiveRouterIpv6Dns)
                {
                    warningsEn.Add("router IPv6 DNS active");
                    warningsFa.Add("هشدار: IPv6 DNS مودم فعال است");
                }
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
            string warnEn = warningsEn.Count > 0 ? $" (Warning: {string.Join("; ", warningsEn)})" : string.Empty;
            string warnFa = warningsFa.Count > 0 ? $" ({string.Join("، ", warningsFa)})" : string.Empty;
            return new OperationResult(
                true,
                $"Connected to {label} ({cleanPrimary}){dohSuffix}{warnEn}",
                $"متصل به {label} ({cleanPrimary}){dohSuffix}{warnFa}");
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
                await _runner.RunAsync("netsh", new[] { "interface", "ip", "delete", "arpcache" }, token).ConfigureAwait(false);

                // Scoped adapter restart only (do NOT run global `netsh int ip reset`, which wipes static IPs across all NICs)
                var disRes = await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=disabled" }, token).ConfigureAwait(false);
                if (disRes.IsSuccess)
                {
                    disabledAdapter = true;
                    await Task.Delay(2000, token).ConfigureAwait(false);

                    var enRes = await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=enabled" }, CancellationToken.None).ConfigureAwait(false);
                    if (!enRes.IsSuccess)
                        return new OperationResult(false, $"Adapter '{iface}' was disabled and could not be re-enabled automatically.", $"کارت شبکه «{iface}» غیرفعال شد اما فعال‌سازی خودکار آن ناموفق بود.");

                    disabledAdapter = false;
                    await Task.Delay(2000, token).ConfigureAwait(false);
                }

                await _runner.RunAsync("ipconfig", new[] { "/release", iface }, token).ConfigureAwait(false);
                await _runner.RunAsync("ipconfig", new[] { "/renew", iface }, token).ConfigureAwait(false);
                await _runner.RunAsync("ipconfig", new[] { "/registerdns" }, token).ConfigureAwait(false);
                await _runner.RunAsync("nbtstat", new[] { "-R" }, token).ConfigureAwait(false);
                await _runner.RunAsync("nbtstat", new[] { "-RR" }, token).ConfigureAwait(false);

                return new OperationResult(
                    true,
                    $"Adapter '{iface}' restarted & DHCP/caches refreshed!",
                    $"کارت شبکه «{iface}» ریستارت و کش شبکه/DHCP تازه‌سازی شد!");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Adapter reset error: {ex.Message}", $"خطا در ریست کارت شبکه: {ex.Message}");
            }
            finally
            {
                if (disabledAdapter)
                {
                    try { await _runner.RunAsync("netsh", new[] { "interface", "set", "interface", $"name={iface}", "admin=enabled" }, CancellationToken.None).ConfigureAwait(false); } catch { }
                }
            }
        }

        // ==================== SAFE GAME MODE TOGGLE (STRICT SERVICE ALLOWLIST + REBOOT DETECTION) ====================
        private static long GetCurrentSystemBootUtcTicks() =>
            DateTime.UtcNow.Ticks - (Environment.TickCount64 * TimeSpan.TicksPerMillisecond);

        private (bool IsActive, List<string> StoppedServices) ReadVerifiedGameModeState()
        {
            string? json = ReadAdminVerifiedSmallJsonTextSafe(GameModeStatePath);
            if (string.IsNullOrEmpty(json))
                return (false, new List<string>());

            try
            {
                var trimmed = json.TrimStart();
                if (trimmed.StartsWith("{", StringComparison.Ordinal))
                {
                    var rec = JsonSerializer.Deserialize<GameModeStateRecord>(json);
                    if (rec == null || rec.StoppedServices == null || rec.StoppedServices.Count == 0)
                        return (false, new List<string>());

                    long currentBoot = GetCurrentSystemBootUtcTicks();
                    if (Math.Abs(currentBoot - rec.BootUtcTicks) > TimeSpan.FromSeconds(60).Ticks)
                    {
                        try
                        {
                            if (IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true) &&
                                File.Exists(GameModeStatePath) && !IsReparsePoint(GameModeStatePath))
                            {
                                File.Delete(GameModeStatePath);
                            }
                        }
                        catch { }
                        return (false, new List<string>());
                    }

                    return (true, rec.StoppedServices);
                }

                var legacy = JsonSerializer.Deserialize<List<string>>(json);
                return legacy != null && legacy.Count > 0
                    ? (true, legacy)
                    : (false, new List<string>());
            }
            catch
            {
                return (false, new List<string>());
            }
        }

        public bool IsGameModeActive()
        {
            lock (_ioLock)
            {
                return ReadVerifiedGameModeState().IsActive;
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
                    var saveList = stopped.Count > 0 ? stopped : new List<string> { "_ACTIVE_MARKER_" };
                    var stateRec = new GameModeStateRecord(saveList, GetCurrentSystemBootUtcTicks());
                    AtomicWriteAdminOnlyText(GameModeStatePath, JsonSerializer.Serialize(stateRec, JsonOpts));
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
                    toRestore = ReadVerifiedGameModeState().StoppedServices;
                }

                int restored = 0;
                foreach (var s in toRestore.Where(x => AllowedGameModeServices.Contains(x)))
                {
                    var r = await _runner.RunAsync("net", new[] { "start", s }, token, TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                    if (r.IsSuccess) restored++;
                }

                lock (_ioLock)
                {
                    try
                    {
                        if (IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true) &&
                            File.Exists(GameModeStatePath) && !IsReparsePoint(GameModeStatePath))
                        {
                            File.Delete(GameModeStatePath);
                        }
                    }
                    catch { }
                }

                return new OperationResult(
                    true,
                    $"Game Mode OFF — restored {restored} service(s).",
                    $"حالت گیم خاموش شد — {restored} سرویس به حالت عادی برگشت.");
            }
        }

        // ==================== ATOMIC, SYMLINK-SAFE & LOCKED WINDOWS HOSTS MANAGER ====================
        private async Task AtomicWriteHostsUnlockedAsync(string content, CancellationToken token)
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

        public bool IsAdShieldActive() => IsBlocklistTagPresent(AdShieldTag);

        public bool IsBlocklistTagPresent(string tag)
        {
            try
            {
                if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath)) return false;
                string cleanTag = SanitizeHeaderToken(tag);
                foreach (var raw in File.ReadLines(_hostsPath))
                {
                    if (MatchesExactBlocklistBegin(raw.Trim(), cleanTag))
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

        private static void AtomicCopyFile(string sourcePath, string destPath)
        {
            if (File.Exists(destPath) && IsReparsePoint(destPath))
                throw new IOException("Refused to overwrite symbolic link or reparse point.");

            string tmp = destPath + $".{Guid.NewGuid():N}.tmp";
            try
            {
                File.Copy(sourcePath, tmp, overwrite: true);
                if (File.Exists(destPath))
                    File.Replace(tmp, destPath, null, true);
                else
                    File.Move(tmp, destPath);
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }

        public Task<OperationResult> BackupHostsAsync(bool isManual = true)
        {
            return Task.Run(() =>
            {
                lock (_ioLock)
                {
                    try
                    {
                        string? stateDir = EnsureAdminOnlyStateDirectory();
                        if (string.IsNullOrEmpty(stateDir))
                            return new OperationResult(false, "Could not prepare verified admin-only backup folder.", "ایجاد یا تایید امنیت پوشه پشتیبان ناموفق بود.");

                        if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath))
                            return new OperationResult(false, "Windows hosts file not found or unsafe.", "فایل hosts ویندوز پیدا نشد یا ایمن نیست.");

                        // Immutable original snapshot captured once before AionTool's first modification
                        if (!File.Exists(HostsOriginalBackupPath))
                        {
                            AtomicCopyFile(_hostsPath, HostsOriginalBackupPath);
                        }
                        if (!IsFileOwnedAndLockedByAdmins(HostsOriginalBackupPath, strictAdminOnly: true))
                        {
                            return new OperationResult(false, "Original hosts backup failed admin ownership/ACL verification.", "تایید امنیتی فایل پشتیبان اصلی hosts ناموفق بود.");
                        }

                        // Explicit user-triggered backup is stored separately so automatic pre-apply backups never shadow it
                        if (isManual)
                        {
                            if (File.Exists(HostsManualBackupPath) && !IsFileOwnedAndLockedByAdmins(HostsManualBackupPath, strictAdminOnly: true))
                                return new OperationResult(false, "Manual hosts backup failed admin ownership/ACL verification.", "تایید امنیتی فایل پشتیبان دستی hosts ناموفق بود.");

                            AtomicCopyFile(_hostsPath, HostsManualBackupPath);
                        }

                        string stamped = Path.Combine(stateDir, $"hosts.backup.{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}");
                        AtomicCopyFile(_hostsPath, stamped);

                        var oldBackups = Directory.GetFiles(stateDir, "hosts.backup.*")
                            .Where(p => !p.EndsWith(".original", StringComparison.OrdinalIgnoreCase)
                                     && !p.EndsWith(".manual", StringComparison.OrdinalIgnoreCase))
                            .OrderByDescending(File.GetLastWriteTimeUtc)
                            .Skip(MaxBackupsToKeep);
                        foreach (var old in oldBackups)
                        {
                            try { if (!IsReparsePoint(old)) File.Delete(old); } catch { }
                        }

                        return new OperationResult(
                            true,
                            isManual ? "Manual hosts backup saved!" : "Hosts backup saved!",
                            isManual ? "پشتیبان دستی فایل hosts ذخیره شد!" : "پشتیبان فایل hosts ذخیره شد!");
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
            bool restoredManual = false;
            if (!IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true))
                return new OperationResult(false, "No verified admin-protected hosts backup found yet.", "پشتیبان تاییدشده و محافظت‌شده‌ای از فایل hosts یافت نشد.");

            lock (_ioLock)
            {
                // Prefer an explicit user manual backup if present; otherwise restore the clean pre-modification original backup
                // (never restore an intermediate auto-backup from a second blocklist apply!)
                if (File.Exists(HostsManualBackupPath))
                {
                    target = HostsManualBackupPath;
                    restoredManual = true;
                }
                else if (File.Exists(HostsOriginalBackupPath))
                {
                    target = HostsOriginalBackupPath;
                }
                else if (Directory.Exists(_secureStateDir))
                {
                    target = Directory.GetFiles(_secureStateDir, "hosts.backup.*")
                        .OrderBy(File.GetLastWriteTimeUtc)
                        .FirstOrDefault();
                }
            }

            if (target == null || !IsFileOwnedAndLockedByAdmins(target, strictAdminOnly: true))
                return new OperationResult(false, "No verified admin-protected hosts backup found yet.", "پشتیبان تاییدشده و محافظت‌شده‌ای از فایل hosts یافت نشد.");

            try
            {
                var fi = new FileInfo(target);
                if (fi.Length > MaxBlocklistBytes)
                    return new OperationResult(false, "Backup file exceeds 12 MB safety cap.", "حجم فایل پشتیبان بیش از حد مجاز است.");

                string content = await File.ReadAllTextAsync(target, token).ConfigureAwait(false);
                if (content.IndexOf('\0') >= 0)
                    return new OperationResult(false, "Backup file is corrupted (binary data detected).", "فایل پشتیبان خراب است.");

                await _hostsLock.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    await AtomicWriteHostsUnlockedAsync(content, token).ConfigureAwait(false);
                }
                finally
                {
                    _hostsLock.Release();
                }
                await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
                return new OperationResult(
                    true,
                    restoredManual ? "Hosts restored from your manual backup!" : "Hosts restored to original pre-change backup!",
                    restoredManual ? "فایل hosts از پشتیبان دستی شما بازگردانی شد!" : "فایل hosts به نسخه اصلی پیش از تغییرات بازگردانی شد!");
            }
            catch (Exception ex)
            {
                return new OperationResult(false, $"Restore error: {ex.Message}", $"خطا در بازگردانی: {ex.Message}");
            }
        }

        public async Task<OperationResult> ResetHostsToDefaultAsync(CancellationToken token = default)
        {
            await _hostsLock.WaitAsync(token).ConfigureAwait(false);
            try
            {
                if (File.Exists(_hostsPath))
                {
                    var backupRes = await BackupHostsAsync(isManual: false).ConfigureAwait(false);
                    if (!backupRes.Success)
                    {
                        return new OperationResult(
                            false,
                            $"Reset aborted: could not save hosts backup first ({backupRes.MessageEn}).",
                            $"بازنشانی متوقف شد: ذخیره پشتیبان hosts ناموفق بود ({backupRes.MessageFa}).");
                    }
                }

                string defaultHosts =
                    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
                    "#\r\n" +
                    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
                    "# localhost name resolution is handled within DNS itself.\r\n" +
                    "#\t127.0.0.1       localhost\r\n" +
                    "#\t::1             localhost\r\n";

                await AtomicWriteHostsUnlockedAsync(defaultHosts, token).ConfigureAwait(false);
            }
            finally
            {
                _hostsLock.Release();
            }

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

                await _hostsLock.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    var backupRes = await BackupHostsAsync(isManual: false).ConfigureAwait(false);
                    if (!backupRes.Success)
                    {
                        return new OperationResult(
                            false,
                            $"Apply aborted: could not back up hosts first ({backupRes.MessageEn}).",
                            $"اعمال لیست متوقف شد: پشتیبان‌گیری از hosts ناموفق بود ({backupRes.MessageFa}).");
                    }

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

                    await AtomicWriteHostsUnlockedAsync(sb.ToString(), token).ConfigureAwait(false);
                }
                finally
                {
                    _hostsLock.Release();
                }
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
            await _hostsLock.WaitAsync(token).ConfigureAwait(false);
            try
            {
                if (!File.Exists(_hostsPath) || IsReparsePoint(_hostsPath))
                    return new OperationResult(false, "Windows hosts file not found or unsafe.", "فایل hosts ویندوز یافت نشد یا ایمن نیست.");

                var existing = (await File.ReadAllLinesAsync(_hostsPath, token).ConfigureAwait(false)).ToList();
                var cleaned = StripBlocklistTagSafe(existing, SanitizeHeaderToken(tag));

                if (cleaned.Count == existing.Count)
                    return new OperationResult(true, $"{label} was not installed.", $"{label} در فایل hosts وجود نداشت.");

                await AtomicWriteHostsUnlockedAsync(string.Join(Environment.NewLine, cleaned) + Environment.NewLine, token).ConfigureAwait(false);
            }
            finally
            {
                _hostsLock.Release();
            }

            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
            return new OperationResult(true, $"Removed {label} from hosts.", $"{label} از فایل hosts حذف شد.");
        }

        private static bool MatchesExactBlocklistBegin(string trimmedLine, string tag)
        {
            string aion = $"# AIONTOOL-BEGIN:{tag}";
            string aio = $"# AIOTOOL-BEGIN:{tag}";
            string legacy = $"# {tag}-BEGIN";

            return trimmedLine.Equals(aion, StringComparison.OrdinalIgnoreCase)
                || trimmedLine.StartsWith(aion + ":", StringComparison.OrdinalIgnoreCase)
                || trimmedLine.Equals(aio, StringComparison.OrdinalIgnoreCase)
                || trimmedLine.StartsWith(aio + ":", StringComparison.OrdinalIgnoreCase)
                || trimmedLine.Equals(legacy, StringComparison.OrdinalIgnoreCase);
        }

        private static List<string> StripBlocklistTagSafe(IReadOnlyList<string> lines, string tag)
        {
            string[] endExacts = { $"# AIONTOOL-END:{tag}", $"# AIOTOOL-END:{tag}", $"# {tag}-END" };

            var output = new List<string>(lines.Count);
            int i = 0;
            while (i < lines.Count)
            {
                string t = lines[i].Trim();
                if (MatchesExactBlocklistBegin(t, tag))
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

        private static List<string> StripAllManagedBlocklistsSafe(IReadOnlyList<string> lines)
        {
            var output = new List<string>(lines.Count);
            int i = 0;
            while (i < lines.Count)
            {
                string t = lines[i].Trim();
                if (t.StartsWith("# AIONTOOL-BEGIN:", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("# AIOTOOL-BEGIN:", StringComparison.OrdinalIgnoreCase))
                {
                    int colon1 = t.IndexOf(':');
                    string rest = colon1 >= 0 ? t[(colon1 + 1)..] : string.Empty;
                    int colon2 = rest.IndexOf(':');
                    string tag = colon2 >= 0 ? rest[..colon2] : rest;
                    string endAion = $"# AIONTOOL-END:{tag}";
                    string endAio = $"# AIOTOOL-END:{tag}";

                    int endIdx = -1;
                    for (int j = i + 1; j < lines.Count; j++)
                    {
                        string t2 = lines[j].Trim();
                        if (t2.Equals(endAion, StringComparison.OrdinalIgnoreCase) ||
                            t2.Equals(endAio, StringComparison.OrdinalIgnoreCase))
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

        // ==================== UNINSTALL CLEANUP (MEDIUM #10) ====================
        public async Task PerformUninstallCleanupAsync(CancellationToken token = default)
        {
            try
            {
                Dictionary<string, OriginalDnsBackup>? dnsMap = null;
                lock (_ioLock)
                {
                    string? json = ReadAdminVerifiedSmallJsonTextSafe(OriginalDnsBackupPath);
                    if (!string.IsNullOrEmpty(json))
                        dnsMap = JsonSerializer.Deserialize<Dictionary<string, OriginalDnsBackup>>(json);
                }

                if (dnsMap != null)
                {
                    foreach (var adapterName in dnsMap.Keys.ToList())
                    {
                        try { await RestoreOriginalDnsAsync(adapterName, token).ConfigureAwait(false); } catch { }
                    }
                }
            }
            catch { }

            try
            {
                bool restoredOriginal = false;
                if (IsDirectoryOwnedAndLockedByAdmins(_secureStateDir, strictAdminOnly: true) &&
                    File.Exists(HostsOriginalBackupPath) &&
                    IsFileOwnedAndLockedByAdmins(HostsOriginalBackupPath, strictAdminOnly: true))
                {
                    var fi = new FileInfo(HostsOriginalBackupPath);
                    if (fi.Length <= MaxBlocklistBytes)
                    {
                        string content = await File.ReadAllTextAsync(HostsOriginalBackupPath, token).ConfigureAwait(false);
                        if (content.IndexOf('\0') < 0)
                        {
                            await _hostsLock.WaitAsync(token).ConfigureAwait(false);
                            try { await AtomicWriteHostsUnlockedAsync(content, token).ConfigureAwait(false); }
                            finally { _hostsLock.Release(); }
                            restoredOriginal = true;
                        }
                    }
                }

                if (!restoredOriginal && File.Exists(_hostsPath) && !IsReparsePoint(_hostsPath))
                {
                    await _hostsLock.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        var existing = (await File.ReadAllLinesAsync(_hostsPath, token).ConfigureAwait(false)).ToList();
                        var cleaned = StripAllManagedBlocklistsSafe(existing);
                        if (cleaned.Count != existing.Count)
                        {
                            await AtomicWriteHostsUnlockedAsync(string.Join(Environment.NewLine, cleaned) + Environment.NewLine, token).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        _hostsLock.Release();
                    }
                }
            }
            catch { }

            try
            {
                if (IsGameModeActive())
                    await SetGameModeAsync(false, token).ConfigureAwait(false);
            }
            catch { }

            await FastFlushDnsCacheAsync(token).ConfigureAwait(false);
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

        private static void CleanTempDirectoryTreeSafely(
            string dirPath,
            DateTime cutoff,
            bool removeDirIfEmpty,
            int remainingDepth,
            ref int deletedFiles,
            ref int deletedDirs,
            ref long freedBytes)
        {
            if (remainingDepth < 0 || !Directory.Exists(dirPath) || IsReparsePoint(dirPath))
                return;

            // 1. Delete only individual files whose creation AND last-write timestamps are older than cutoff (never follows symlinks)
            try
            {
                foreach (var f in Directory.EnumerateFiles(dirPath))
                {
                    try
                    {
                        var fi = new FileInfo(f);
                        if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if (fi.LastWriteTimeUtc >= cutoff || fi.CreationTimeUtc >= cutoff) continue;
                        long len = fi.Length;
                        File.Delete(f);
                        deletedFiles++;
                        freedBytes += len;
                    }
                    catch { }
                }
            }
            catch { }

            // 2. Descend into non-reparse subdirectories safely (never uses recursive Directory.Delete!)
            try
            {
                foreach (var sub in Directory.EnumerateDirectories(dirPath))
                {
                    try
                    {
                        var di = new DirectoryInfo(sub);
                        if ((di.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        // Preserve .NET single-file native extraction cache folder
                        if (di.Name.Equals(".net", StringComparison.OrdinalIgnoreCase)) continue;

                        CleanTempDirectoryTreeSafely(sub, cutoff, removeDirIfEmpty: true, remainingDepth - 1, ref deletedFiles, ref deletedDirs, ref freedBytes);
                    }
                    catch { }
                }
            }
            catch { }

            // 3. Remove subdirectory ONLY if it is now completely empty and older than cutoff (non-recursive delete)
            if (removeDirIfEmpty)
            {
                try
                {
                    var di = new DirectoryInfo(dirPath);
                    if ((di.Attributes & FileAttributes.ReparsePoint) != 0) return;
                    if (di.LastWriteTimeUtc >= cutoff || di.CreationTimeUtc >= cutoff) return;
                    if (!Directory.EnumerateFileSystemEntries(dirPath).Any())
                    {
                        Directory.Delete(dirPath, recursive: false);
                        deletedDirs++;
                    }
                }
                catch { }
            }
        }

        public async Task<OperationResult> CleanOldTempFilesAsync()
        {
            int deletedFiles = 0;
            int deletedDirs = 0;
            long bytes = 0;
            DateTime cutoff = DateTime.UtcNow.AddHours(-24);

            await Task.Run(() =>
            {
                var roots = new[]
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
                }
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Select(d => Path.GetFullPath(d).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(d => Directory.Exists(d) && !IsReparsePoint(d));

                foreach (var dir in roots)
                {
                    CleanTempDirectoryTreeSafely(dir, cutoff, removeDirIfEmpty: false, remainingDepth: 16, ref deletedFiles, ref deletedDirs, ref bytes);
                }
            }).ConfigureAwait(false);

            double mb = Math.Round(bytes / 1048576.0, 1);
            return new OperationResult(
                true,
                $"Cleaned {deletedFiles} old files & {deletedDirs} empty folders (~{mb:F1} MB).",
                $"{deletedFiles} فایل قدیمی و {deletedDirs} پوشه خالی پاکسازی شد (~{mb:F1} مگابایت).");
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

                bool routerBlockedIcmp = r.HasValue && !r.Value.AvgMs.HasValue && r.Value.LossPct >= 99.9 && g.AvgMs.HasValue;
                bool routerPartialInstability = r.HasValue && r.Value.AvgMs.HasValue && (r.Value.LossPct >= 5.0 || (r.Value.JitterMs ?? 0) >= 15);
                bool bothOffline = r.HasValue && !r.Value.AvgMs.HasValue && !g.AvgMs.HasValue;

                string verdictEn;
                string verdictFa;

                if (bothOffline)
                {
                    verdictEn = "No reply from Modem or Internet (check connection)";
                    verdictFa = "پاسخی از مودم و اینترنت دریافت نشد (اتصال را چک کنید)";
                }
                else if (routerPartialInstability)
                {
                    verdictEn = "Local Wi-Fi / Modem instability detected";
                    verdictFa = "ناپایداری داخلی است (وای‌فای یا مودم شما)";
                }
                else if (!g.AvgMs.HasValue || g.LossPct >= 5.0 || (g.JitterMs ?? 0) >= 25)
                {
                    verdictEn = routerBlockedIcmp
                        ? "Modem blocks ping · ISP / Internet unstable"
                        : "Modem OK · ISP / Internet unstable";
                    verdictFa = routerBlockedIcmp
                        ? "پینگ مودم بسته است · ناپایداری از اینترنت / ISP"
                        : "مودم سالم · ناپایداری از اینترنت / ISP";
                }
                else if (g.LossPct == 0 && (g.JitterMs ?? 0) <= 12)
                {
                    verdictEn = routerBlockedIcmp
                        ? "Modem blocks ping · Internet rock-solid for gaming!"
                        : "Rock-solid for gaming!";
                    verdictFa = routerBlockedIcmp
                        ? "پینگ مودم بسته است · اینترنت عالی و پایدار برای گیم!"
                        : "عالی و کاملاً پایدار برای گیم!";
                }
                else
                {
                    verdictEn = routerBlockedIcmp
                        ? "Modem blocks ping · Good internet stability"
                        : "Good line stability";
                    verdictFa = routerBlockedIcmp
                        ? "پینگ مودم بسته است · پایداری اینترنت مناسب است"
                        : "پایداری خط مناسب است";
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
                    VerdictFa: verdictFa,
                    RouterBlockedIcmp: routerBlockedIcmp);
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

        private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WinTrustData pWVTData);

        private static bool VerifyAuthenticodeSignature(string filePath)
        {
            IntPtr pathPtr = IntPtr.Zero;
            IntPtr fileInfoPtr = IntPtr.Zero;
            try
            {
                pathPtr = Marshal.StringToCoTaskMemUni(filePath);
                var fileInfo = new WinTrustFileInfo
                {
                    cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                    pcwszFilePath = pathPtr,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var data = new WinTrustData
                {
                    cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,          // WTD_UI_NONE
                    fdwRevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN
                    dwUnionChoice = 1,       // WTD_CHOICE_FILE
                    pFile = fileInfoPtr,
                    dwStateAction = 1,       // WTD_STATEACTION_VERIFY
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0x00000040, // WTD_REVOCATION_CHECK_CHAIN
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                int status = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref data);
                data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                try { WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref data); } catch { }
                return status == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPtr);
                if (pathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPtr);
            }
        }

        private static string? TryGetAuthenticodeThumbprint(string filePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return null;
                using var baseCert = X509Certificate.CreateFromSignedFile(filePath);
                using var cert = new X509Certificate2(baseCert);
                return cert.Thumbprint;
            }
            catch
            {
                return null;
            }
        }

        private static bool HasPinnedReleasePublicKey() =>
            !string.IsNullOrWhiteSpace(PinnedReleaseRsaModulusBase64) &&
            !string.IsNullOrWhiteSpace(PinnedReleaseRsaExponentBase64);

        private static bool VerifyDetachedRsaSignature(byte[] payloadBytes, byte[] signatureAssetBytes)
        {
            if (!HasPinnedReleasePublicKey() || payloadBytes.Length == 0 || signatureAssetBytes.Length == 0)
                return false;

            try
            {
                byte[] sigBytes;
                string asText = Encoding.UTF8.GetString(signatureAssetBytes).Trim();
                if (asText.Length > 0 && asText.All(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || char.IsWhiteSpace(c)))
                {
                    sigBytes = Convert.FromBase64String(Regex.Replace(asText, @"\s+", string.Empty));
                }
                else
                {
                    sigBytes = signatureAssetBytes;
                }

                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Convert.FromBase64String(PinnedReleaseRsaModulusBase64),
                    Exponent = Convert.FromBase64String(PinnedReleaseRsaExponentBase64)
                });

                return rsa.VerifyData(payloadBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        private static async Task<(bool Ok, byte[] Data, string ErrorEn, string ErrorFa)> DownloadSmallTrustedGitHubAssetAsync(
            Uri uri, long maxBytes, CancellationToken token)
        {
            using var resp = await SharedHttp.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return (false, Array.Empty<byte>(), "Failed to download verification file from GitHub.", "دانلود فایل تایید امنیتی از گیت‌هاب ناموفق بود.");

            var finalUri = resp.RequestMessage?.RequestUri;
            if (finalUri == null || finalUri.Scheme != Uri.UriSchemeHttps || !IsTrustedGitHubHost(finalUri.Host))
                return (false, Array.Empty<byte>(), "Update aborted: untrusted verification redirect.", "آپدیت متوقف شد: ریدایرکت نامعتبر در فایل تایید امنیتی.");

            if (resp.Content.Headers.ContentLength > maxBytes)
                return (false, Array.Empty<byte>(), "Update aborted: verification file exceeds safety limit.", "آپدیت متوقف شد: حجم فایل تایید امنیتی بیش از حد مجاز است.");

            await using var stream = await resp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var ms = new MemoryStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int read;
            while ((read = await stream.ReadAsync(buf.AsMemory(), token).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    return (false, Array.Empty<byte>(), "Update aborted: verification file exceeds safety limit.", "آپدیت متوقف شد: حجم فایل تایید امنیتی بیش از حد مجاز است.");
                ms.Write(buf, 0, read);
            }
            return (true, ms.ToArray(), string.Empty, string.Empty);
        }

        private static byte[]? ParseExpectedSha256Bytes(string checksumText, string targetFileName, string checksumAssetName)
        {
            var exactHex64 = new Regex(@"^[a-fA-F0-9]{64}$");
            var lines = checksumText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var raw in lines)
            {
                string trimmed = raw.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#') continue;

                var parts = trimmed.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && exactHex64.IsMatch(parts[0]))
                {
                    string entryFile = parts[1].Trim().TrimStart('*');
                    if (entryFile.StartsWith("./", StringComparison.Ordinal) || entryFile.StartsWith(".\\", StringComparison.Ordinal))
                        entryFile = entryFile[2..];

                    if (entryFile.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) ||
                        Path.GetFileName(entryFile).Equals(targetFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        return Convert.FromHexString(parts[0]);
                    }
                }
            }

            // Allow a single bare 64-hex hash ONLY when the file is specifically named "<installer>.sha256"
            if (lines.Length == 1 &&
                checksumAssetName.Equals($"{targetFileName}.sha256", StringComparison.OrdinalIgnoreCase) &&
                exactHex64.IsMatch(lines[0].Trim()))
            {
                return Convert.FromHexString(lines[0].Trim());
            }

            return null;
        }

        private static readonly SecurityIdentifier LocalSystemSid = new(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier BuiltinAdminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier TrustedInstallerSid = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        private static readonly SecurityIdentifier CreatorOwnerSid = new(WellKnownSidType.CreatorOwnerSid, null);

        private static bool IsTrustedAdminSid(SecurityIdentifier? sid)
        {
            if (sid == null) return false;
            return sid.Equals(LocalSystemSid)
                || sid.Equals(BuiltinAdminsSid)
                || sid.Equals(TrustedInstallerSid);
        }

        private static DirectorySecurity BuildAdminOnlyDirectorySecurity()
        {
            var sec = new DirectorySecurity();
            sec.SetOwner(BuiltinAdminsSid);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            sec.AddAccessRule(new FileSystemAccessRule(
                LocalSystemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(
                BuiltinAdminsSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            return sec;
        }

        private static bool IsAclOwnedAndNonUserWritable(FileSystemSecurity sec, bool strictAdminOnly)
        {
            // 1. Owner MUST be SYSTEM, Builtin Administrators, or TrustedInstaller (prevents owner WRITE_DAC bypass!)
            var ownerSid = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!IsTrustedAdminSid(ownerSid))
                return false;

            // 2. Verify DACL grants no write/modify/delete/ownership/generic-write rights to any non-admin principal
            const FileSystemRights dangerousRights =
                FileSystemRights.WriteData |
                FileSystemRights.AppendData |
                FileSystemRights.WriteExtendedAttributes |
                FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.WriteAttributes |
                FileSystemRights.Delete |
                FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership;

            var rules = sec.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;

                var sid = rule.IdentityReference as SecurityIdentifier;
                if (IsTrustedAdminSid(sid))
                    continue;

                if (strictAdminOnly)
                    return false;

                // Standard Program Files includes an InheritOnly CREATOR OWNER ACE; ignore inherit-only CreatorOwner
                bool isInheritOnly = (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0;
                if (isInheritOnly && sid != null && sid.Equals(CreatorOwnerSid))
                    continue;

                int rawMask = unchecked((int)rule.FileSystemRights);
                bool hasGenericWrite = (rawMask & (0x10000000 | 0x40000000)) != 0; // GENERIC_ALL | GENERIC_WRITE
                if (hasGenericWrite || (rule.FileSystemRights & dangerousRights) != 0)
                    return false;
            }

            return true;
        }

        private static bool IsDirectoryOwnedAndLockedByAdmins(string dirPath, bool strictAdminOnly)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath) || IsReparsePoint(dirPath))
                    return false;

                var di = new DirectoryInfo(dirPath);
                var sec = di.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                return IsAclOwnedAndNonUserWritable(sec, strictAdminOnly);
            }
            catch
            {
                return false;
            }
        }

        private static bool IsFileOwnedAndLockedByAdmins(string filePath, bool strictAdminOnly = false)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath) || IsReparsePoint(filePath))
                    return false;

                var fi = new FileInfo(filePath);
                var sec = fi.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                return IsAclOwnedAndNonUserWritable(sec, strictAdminOnly);
            }
            catch
            {
                return false;
            }
        }

        private static string EnsureTrailingSeparator(string path)
        {
            string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return full + Path.DirectorySeparatorChar;
        }

        private static bool IsExecutableSafeForElevatedAutoStart(string exePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(exePath) || !Path.IsPathRooted(exePath) || exePath.StartsWith(@"\", StringComparison.Ordinal))
                    return false;

                string fullExe = Path.GetFullPath(exePath);
                if (!File.Exists(fullExe) || IsReparsePoint(fullExe))
                    return false;

                // 1. Must reside inside Program Files or Program Files (x86)
                string[] allowedRoots =
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };

                string? matchedRoot = null;
                foreach (var root in allowedRoots)
                {
                    if (string.IsNullOrWhiteSpace(root)) continue;
                    string rootWithSep = EnsureTrailingSeparator(root);
                    if (fullExe.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase))
                    {
                        matchedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        break;
                    }
                }

                if (string.IsNullOrEmpty(matchedRoot))
                    return false;

                // 2. Verify executable file itself is admin-owned and not writable by standard users
                if (!IsFileOwnedAndLockedByAdmins(fullExe, strictAdminOnly: false))
                    return false;

                // 3. Verify every directory from the exe's folder up through Program Files is admin-owned, non-symlink, and non-user-writable
                string? currentDir = Path.GetDirectoryName(fullExe);
                while (!string.IsNullOrEmpty(currentDir))
                {
                    string normalizedDir = Path.GetFullPath(currentDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    if (!IsDirectoryOwnedAndLockedByAdmins(normalizedDir, strictAdminOnly: false))
                        return false;

                    if (normalizedDir.Equals(matchedRoot, StringComparison.OrdinalIgnoreCase))
                        return true;

                    currentDir = Path.GetDirectoryName(normalizedDir);
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private string? PrepareAdminOnlyUpdateDirectory()
        {
            try
            {
                string programFilesDir = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string appDir = Path.GetDirectoryName(_secureUpdatesDir)!;

                // Verify Program Files itself is admin/TrustedInstaller-owned and not writable by standard users
                if (!IsDirectoryOwnedAndLockedByAdmins(programFilesDir, strictAdminOnly: false))
                    return null;

                // Ensure %ProgramFiles%\AionToolLite exists and is admin-owned / non-user-writable
                if (!Directory.Exists(appDir))
                {
                    FileSystemAclExtensions.CreateDirectory(BuildAdminOnlyDirectorySecurity(), appDir);
                }
                if (!IsDirectoryOwnedAndLockedByAdmins(appDir, strictAdminOnly: false))
                    return null;

                // Ensure %ProgramFiles%\AionToolLite\Updates exists with strict admin-only ACL & owner
                if (!Directory.Exists(_secureUpdatesDir))
                {
                    FileSystemAclExtensions.CreateDirectory(BuildAdminOnlyDirectorySecurity(), _secureUpdatesDir);
                }
                if (!IsDirectoryOwnedAndLockedByAdmins(_secureUpdatesDir, strictAdminOnly: true))
                    return null;

                // Clean leftover staging folders/files from prior runs
                foreach (var oldDir in Directory.GetDirectories(_secureUpdatesDir, "stage_*"))
                {
                    try { if (!IsReparsePoint(oldDir)) Directory.Delete(oldDir, recursive: true); } catch { }
                }
                foreach (var oldFile in Directory.GetFiles(_secureUpdatesDir, "update_*.exe"))
                {
                    try { if (!IsReparsePoint(oldFile)) File.Delete(oldFile); } catch { }
                }

                // Atomically create a fresh randomly named staging directory born with admin-only ACL & owner (zero TOCTOU)
                string stageDir = Path.Combine(_secureUpdatesDir, $"stage_{Guid.NewGuid():N}");
                FileSystemAclExtensions.CreateDirectory(BuildAdminOnlyDirectorySecurity(), stageDir);

                if (!IsDirectoryOwnedAndLockedByAdmins(stageDir, strictAdminOnly: true))
                {
                    try { Directory.Delete(stageDir, recursive: true); } catch { }
                    return null;
                }

                return stageDir;
            }
            catch
            {
                return null;
            }
        }

        public static bool OpenTrustedGitHubReleaseUrl(string? url)
        {
            if (!IsTrustedGitHubHttpsUrl(url, out var uri) || uri == null)
                return false;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = uri.AbsoluteUri,
                    UseShellExecute = true
                });
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static Version GetCurrentAppVersion()
        {
            var rawVer = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 1, 1);
            return new Version(Math.Max(0, rawVer.Major), Math.Max(0, rawVer.Minor), Math.Max(0, rawVer.Build));
        }

        private static async Task<string?> TryGetLatestTagViaRedirectFallbackAsync(string owner, string repo, CancellationToken token)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://github.com/{owner}/{repo}/releases/latest");
                using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                var finalUri = resp.RequestMessage?.RequestUri;
                if (finalUri == null || !IsTrustedGitHubHost(finalUri.Host))
                    return null;

                const string marker = "/releases/tag/";
                int idx = finalUri.AbsolutePath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return null;

                string tag = finalUri.AbsolutePath[(idx + marker.Length)..].Trim('/');
                return string.IsNullOrWhiteSpace(tag) ? null : Uri.UnescapeDataString(tag);
            }
            catch
            {
                return null;
            }
        }

        public async Task<(bool HasUpdate, string LatestVersion)> CheckLatestUpdateInfoAsync(string owner, string repo, CancellationToken token = default)
        {
            try
            {
                var currentVer = GetCurrentAppVersion();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(10));

                string? tag = null;
                using (var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{owner}/{repo}/releases/latest"))
                {
                    req.Headers.Accept.ParseAdd("application/vnd.github+json");
                    req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
                    using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        string json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                        using var doc = JsonDocument.Parse(json);
                        tag = doc.RootElement.TryGetProperty("tag_name", out var tEl) ? tEl.GetString() : null;
                    }
                    else if ((int)resp.StatusCode == 403 || (int)resp.StatusCode == 429)
                    {
                        tag = await TryGetLatestTagViaRedirectFallbackAsync(owner, repo, cts.Token).ConfigureAwait(false);
                    }
                }

                if (string.IsNullOrWhiteSpace(tag) ||
                    !Version.TryParse(tag.TrimStart('v', 'V').Trim(), out var parsed) || parsed == null)
                {
                    return (false, string.Empty);
                }

                var latestVer = new Version(Math.Max(0, parsed.Major), Math.Max(0, parsed.Minor), Math.Max(0, parsed.Build));
                return latestVer > currentVer ? (true, latestVer.ToString()) : (false, string.Empty);
            }
            catch
            {
                return (false, string.Empty);
            }
        }

        public async Task<OperationResult> CheckAndInstallUpdateAsync(
            string owner,
            string repo,
            IProgress<UpdateProgressInfo>? progress = null,
            CancellationToken token = default)
        {
            string? stageDir = null;
            string? stagedExe = null;
            bool launched = false;
            string releasesFallbackUrl = $"https://github.com/{owner}/{repo}/releases/latest";

            void Report(
                UpdateStage stage,
                string? ver,
                double pct,
                long dlBytes,
                long totalBytes,
                double speedBps,
                string en,
                string fa,
                string? releaseUrl = null)
            {
                progress?.Report(new UpdateProgressInfo(stage, ver, pct, dlBytes, totalBytes, speedBps, en, fa, releaseUrl));
            }

            try
            {
                var currentVer = GetCurrentAppVersion();
                Report(UpdateStage.Checking, null, -1, 0, 0, 0,
                    "Checking GitHub Releases...",
                    "در حال بررسی آخرین نسخه در گیت‌هاب...");

                using var apiCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                apiCts.CancelAfter(TimeSpan.FromSeconds(20));

                string json;
                using (var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{owner}/{repo}/releases/latest"))
                {
                    req.Headers.Accept.ParseAdd("application/vnd.github+json");
                    req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
                    using var resp = await SharedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, apiCts.Token).ConfigureAwait(false);

                    if ((int)resp.StatusCode == 404)
                    {
                        Report(UpdateStage.UpToDate, currentVer.ToString(), 100, 0, 0, 0,
                            $"You're up to date (v{currentVer}).",
                            $"برنامه شما به‌روز است (نسخه {currentVer}).");
                        return new OperationResult(false, $"You're up to date (v{currentVer}).", $"برنامه شما به‌روز است (نسخه {currentVer}).");
                    }

                    if ((int)resp.StatusCode == 403 || (int)resp.StatusCode == 429)
                    {
                        string? fallbackTag = await TryGetLatestTagViaRedirectFallbackAsync(owner, repo, apiCts.Token).ConfigureAwait(false);
                        if (!string.IsNullOrWhiteSpace(fallbackTag) &&
                            Version.TryParse(fallbackTag.TrimStart('v', 'V').Trim(), out var fbVer) && fbVer != null)
                        {
                            var cleanFb = new Version(Math.Max(0, fbVer.Major), Math.Max(0, fbVer.Minor), Math.Max(0, fbVer.Build));
                            if (cleanFb <= currentVer)
                            {
                                Report(UpdateStage.UpToDate, currentVer.ToString(), 100, 0, 0, 0,
                                    $"You're up to date (v{currentVer}).",
                                    $"برنامه شما به‌روز است (نسخه {currentVer}).");
                                return new OperationResult(false, $"You're up to date (v{currentVer}).", $"برنامه شما به‌روز است (نسخه {currentVer}).");
                            }

                            string tagUrl = $"https://github.com/{owner}/{repo}/releases/tag/{Uri.EscapeDataString(fallbackTag)}";
                            Report(UpdateStage.ManualRequired, cleanFb.ToString(), 0, 0, 0, 0,
                                $"v{cleanFb} is available (GitHub API rate limit reached).",
                                $"نسخه v{cleanFb} موجود است (محدودیت موقت API گیت‌هاب).",
                                tagUrl);
                            return new OperationResult(false,
                                $"Update v{cleanFb} found, but GitHub API is temporarily rate-limited. Open Releases to download.",
                                $"نسخه v{cleanFb} یافت شد اما API گیت‌هاب موقتاً محدود شده است. از صفحه گیت‌هاب دانلود کنید.");
                        }

                        Report(UpdateStage.Failed, null, 0, 0, 0, 0,
                            "GitHub API rate limit reached. Try again later.",
                            "محدودیت موقت API گیت‌هاب؛ کمی بعد دوباره تلاش کنید.",
                            releasesFallbackUrl);
                        return new OperationResult(false, "GitHub API rate limit reached. Please try again shortly.", "محدودیت موقت API گیت‌هاب. کمی بعد دوباره امتحان کنید.");
                    }

                    if (!resp.IsSuccessStatusCode)
                    {
                        Report(UpdateStage.Failed, null, 0, 0, 0, 0,
                            $"GitHub returned HTTP {(int)resp.StatusCode}.",
                            $"خطای سرور گیت‌هاب (کد {(int)resp.StatusCode}).");
                        return new OperationResult(false, $"Could not reach GitHub Releases (HTTP {(int)resp.StatusCode}).", $"اتصال به گیت‌هاب ناموفق بود (کد {(int)resp.StatusCode}).");
                    }

                    json = await resp.Content.ReadAsStringAsync(apiCts.Token).ConfigureAwait(false);
                }

                using var doc = JsonDocument.Parse(json);
                string tag = doc.RootElement.TryGetProperty("tag_name", out var tEl) ? tEl.GetString() ?? "" : "";
                string releaseHtmlUrl = doc.RootElement.TryGetProperty("html_url", out var hEl) ? hEl.GetString() ?? releasesFallbackUrl : releasesFallbackUrl;
                if (!IsTrustedGitHubHttpsUrl(releaseHtmlUrl, out _))
                    releaseHtmlUrl = releasesFallbackUrl;

                if (!Version.TryParse(tag.TrimStart('v', 'V').Trim(), out var parsed) || parsed == null)
                {
                    Report(UpdateStage.Failed, null, 0, 0, 0, 0, "Could not read release version.", "نسخه انتشار قابل خواندن نیست.");
                    return new OperationResult(false, "Could not read release version.", "نسخه انتشار قابل خواندن نیست.");
                }

                var latestVer = new Version(Math.Max(0, parsed.Major), Math.Max(0, parsed.Minor), Math.Max(0, parsed.Build));
                if (latestVer <= currentVer)
                {
                    Report(UpdateStage.UpToDate, currentVer.ToString(), 100, 0, 0, 0,
                        $"You're up to date (v{currentVer}).",
                        $"برنامه شما به‌روز است (نسخه {currentVer}).");
                    return new OperationResult(false, $"You're up to date (v{currentVer}).", $"برنامه شما به‌روز است (نسخه {currentVer}).");
                }

                bool hasPinnedRsa = HasPinnedReleasePublicKey();
                string? currentExeThumbprint = !string.IsNullOrWhiteSpace(Environment.ProcessPath) && VerifyAuthenticodeSignature(Environment.ProcessPath)
                    ? TryGetAuthenticodeThumbprint(Environment.ProcessPath)
                    : null;

                if (!hasPinnedRsa && string.IsNullOrEmpty(currentExeThumbprint))
                {
                    Report(UpdateStage.ManualRequired, latestVer.ToString(), 0, 0, 0, 0,
                        $"v{latestVer} available — manual download required for local dev builds.",
                        $"نسخه v{latestVer} آماده است — برای بیلدهای بدون کلید امضا دستی دانلود کنید.",
                        releaseHtmlUrl);
                    return new OperationResult(
                        false,
                        $"Update v{latestVer} is available, but silent admin install is disabled for unsigned builds. Download manually from GitHub Releases.",
                        $"نسخه v{latestVer} موجود است، اما نصب خودکار برای بیلدهای بدون امضای رمزنگاری غیرفعال است. لطفاً دستی از گیت‌هاب دانلود کنید.");
                }

                string? exeName = null;
                string? dlUrl = null;
                long expectedAssetSize = 0;
                string? checksumName = null;
                string? checksumUrl = null;
                string? sigUrl = null;

                if (doc.RootElement.TryGetProperty("assets", out var assets))
                {
                    foreach (var a in assets.EnumerateArray())
                    {
                        string name = a.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? "" : "";
                        string? url = a.TryGetProperty("browser_download_url", out var uEl) ? uEl.GetString() : null;
                        long sz = a.TryGetProperty("size", out var sEl) && sEl.TryGetInt64(out var parsedSz) ? parsedSz : 0;

                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            bool isSetup = name.Contains("Setup", StringComparison.OrdinalIgnoreCase);
                            if (dlUrl == null || (isSetup && !(exeName?.Contains("Setup", StringComparison.OrdinalIgnoreCase) ?? false)))
                            {
                                exeName = name;
                                dlUrl = url;
                                expectedAssetSize = sz;
                            }
                        }
                        else if (checksumUrl == null &&
                                 (name.Equals("checksums.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.Equals("sha256sums.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.Equals("sha256.txt", StringComparison.OrdinalIgnoreCase) ||
                                  name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase)))
                        {
                            checksumName = name;
                            checksumUrl = url;
                        }
                        else if (sigUrl == null &&
                                 (name.Equals("checksums.txt.sig", StringComparison.OrdinalIgnoreCase) ||
                                  name.Equals("sha256sums.txt.sig", StringComparison.OrdinalIgnoreCase) ||
                                  name.EndsWith(".sha256.sig", StringComparison.OrdinalIgnoreCase)))
                        {
                            sigUrl = url;
                        }
                    }
                }

                if (!IsTrustedGitHubHttpsUrl(dlUrl, out var dlUri) || dlUri == null || string.IsNullOrWhiteSpace(exeName))
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0,
                        "No verified installer attached to release.",
                        "فایل نصبی معتبری در انتشار گیت‌هاب یافت نشد.",
                        releaseHtmlUrl);
                    return new OperationResult(false, "Update found, but no verified GitHub installer is attached.", "آپدیت جدید یافت شد اما فایل نصبی معتبر یافت نشد.");
                }

                if (!IsTrustedGitHubHttpsUrl(checksumUrl, out var sumUri) || sumUri == null || string.IsNullOrWhiteSpace(checksumName))
                {
                    Report(UpdateStage.ManualRequired, latestVer.ToString(), 0, 0, 0, 0,
                        "Release is missing checksums.txt.",
                        "فایل الزامی checksums.txt در انتشار موجود نیست.",
                        releaseHtmlUrl);
                    return new OperationResult(false, "Update aborted: release is missing a required SHA256 checksum file.", "آپدیت متوقف شد: فایل الزامی چک‌سام SHA256 در انتشار وجود ندارد.");
                }

                Report(UpdateStage.VerifyingSignature, latestVer.ToString(), -1, 0, expectedAssetSize, 0,
                    $"Verifying v{latestVer} signature & checksum...",
                    $"در حال تایید امضای دیجیتال و چک‌سام نسخه v{latestVer}...");

                var sumDl = await DownloadSmallTrustedGitHubAssetAsync(sumUri, MaxChecksumBytes, token).ConfigureAwait(false);
                if (!sumDl.Ok)
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, sumDl.ErrorEn, sumDl.ErrorFa, releaseHtmlUrl);
                    return new OperationResult(false, sumDl.ErrorEn, sumDl.ErrorFa);
                }

                if (hasPinnedRsa)
                {
                    if (!IsTrustedGitHubHttpsUrl(sigUrl, out var sigUri) || sigUri == null)
                    {
                        Report(UpdateStage.ManualRequired, latestVer.ToString(), 0, 0, 0, 0,
                            "Release is missing cryptographic signature (.sig).",
                            "فایل امضای دیجیتال (.sig) در انتشار موجود نیست.",
                            releaseHtmlUrl);
                        return new OperationResult(false, "Update aborted: release is missing a required cryptographic signature (.sig).", "آپدیت متوقف شد: فایل امضای دیجیتال (.sig) در انتشار وجود ندارد.");
                    }

                    var sigDl = await DownloadSmallTrustedGitHubAssetAsync(sigUri, MaxSignatureBytes, token).ConfigureAwait(false);
                    if (!sigDl.Ok)
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, sigDl.ErrorEn, sigDl.ErrorFa, releaseHtmlUrl);
                        return new OperationResult(false, sigDl.ErrorEn, sigDl.ErrorFa);
                    }

                    if (!VerifyDetachedRsaSignature(sumDl.Data, sigDl.Data))
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0,
                            "Cryptographic signature verification failed!",
                            "تایید امضای دیجیتال انتشار ناموفق بود!");
                        return new OperationResult(false, "Update aborted: cryptographic release signature verification failed!", "آپدیت متوقف شد: تایید امضای دیجیتال انتشار ناموفق بود!");
                    }
                }

                string sumText = Encoding.UTF8.GetString(sumDl.Data);
                byte[]? expectedHashBytes = ParseExpectedSha256Bytes(sumText, exeName, checksumName);
                if (expectedHashBytes == null || expectedHashBytes.Length != 32)
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0,
                        "Checksum file has no valid SHA256 entry.",
                        "فایل چک‌سام فاقد هش SHA256 معتبر است.");
                    return new OperationResult(false, "Update aborted: checksum file has no valid SHA256 entry for this installer.", "آپدیت متوقف شد: فایل چک‌سام فاقد هش SHA256 معتبر برای این فایل نصبی است.");
                }

                stageDir = PrepareAdminOnlyUpdateDirectory();
                if (string.IsNullOrEmpty(stageDir))
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0,
                        "Could not prepare verified admin-owned update folder.",
                        "ایجاد یا تایید مالکیت ادمین پوشه امن آپدیت ناموفق بود.");
                    return new OperationResult(false, "Could not prepare verified admin-owned update folder.", "ایجاد یا تایید مالکیت ادمین پوشه امن آپدیت ناموفق بود.");
                }

                stagedExe = Path.Combine(stageDir, $"update_{Guid.NewGuid():N}.exe");
                if (stagedExe.IndexOfAny(ForbiddenShellChars) >= 0 || stageDir.IndexOfAny(ForbiddenShellChars) >= 0)
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Unsafe staging path.", "مسیر ذخیره‌سازی نامعتبر است.");
                    return new OperationResult(false, "Blocked update: unsafe staging path.", "آپدیت متوقف شد: مسیر ذخیره‌سازی نامعتبر است.");
                }

                Report(UpdateStage.Downloading, latestVer.ToString(), 0, 0, expectedAssetSize, 0,
                    $"Downloading v{latestVer} from GitHub...",
                    $"در حال دانلود نسخه v{latestVer} از گیت‌هاب...");

                byte[] streamedHashBytes;
                using (var dlReq = new HttpRequestMessage(HttpMethod.Get, dlUri))
                using (var headerCts = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    headerCts.CancelAfter(TimeSpan.FromSeconds(30));
                    using var dlResp = await UpdaterDownloadHttp.SendAsync(dlReq, HttpCompletionOption.ResponseHeadersRead, headerCts.Token).ConfigureAwait(false);
                    dlResp.EnsureSuccessStatusCode();

                    var finalUri = dlResp.RequestMessage?.RequestUri;
                    if (finalUri == null || finalUri.Scheme != Uri.UriSchemeHttps || !IsTrustedGitHubHost(finalUri.Host))
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Redirected outside trusted GitHub HTTPS.", "ریدایرکت خارج از سرور امن گیت‌هاب.");
                        return new OperationResult(false, "Update aborted: redirected outside trusted GitHub HTTPS.", "آپدیت متوقف شد: ریدایرکت خارج از سرور امن گیت‌هاب.");
                    }

                    long totalExpected = dlResp.Content.Headers.ContentLength ?? expectedAssetSize;
                    if (totalExpected > MaxUpdaterBytes)
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Installer exceeds 150 MB limit.", "حجم فایل بیش از سقف ۱۵۰ مگابایت است.");
                        return new OperationResult(false, "Update aborted: installer exceeds 150 MB limit.", "آپدیت متوقف شد: حجم فایل بیش از سقف ۱۵۰ مگابایت است.");
                    }

                    await using var src = await dlResp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                    var fsOpts = new FileStreamOptions
                    {
                        Mode = FileMode.CreateNew,
                        Access = FileAccess.Write,
                        Share = FileShare.None,
                        BufferSize = 131072,
                        Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                        PreallocationSize = totalExpected > 0 ? totalExpected : 0
                    };
                    await using var dst = new FileStream(stagedExe, fsOpts);
                    using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

                    byte[] buf = new byte[131072];
                    long totalRead = 0;
                    var speedSw = Stopwatch.StartNew();
                    long lastTickMs = 0;
                    long lastTickBytes = 0;
                    double smoothedBps = 0;

                    while (true)
                    {
                        int read;
                        using (var stallCts = CancellationTokenSource.CreateLinkedTokenSource(token))
                        {
                            stallCts.CancelAfter(TimeSpan.FromSeconds(30));
                            try
                            {
                                read = await src.ReadAsync(buf.AsMemory(), stallCts.Token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (!token.IsCancellationRequested)
                            {
                                throw new TimeoutException("Download stalled for 30 seconds without receiving data.");
                            }
                        }

                        if (read <= 0) break;

                        totalRead += read;
                        if (totalRead > MaxUpdaterBytes)
                            throw new InvalidOperationException("Installer download exceeded 150 MB safety limit.");

                        hasher.AppendData(buf, 0, read);
                        await dst.WriteAsync(buf.AsMemory(0, read), token).ConfigureAwait(false);

                        long nowMs = speedSw.ElapsedMilliseconds;
                        if (nowMs - lastTickMs >= 85 || (totalExpected > 0 && totalRead >= totalExpected))
                        {
                            double dtSec = Math.Max(0.05, (nowMs - lastTickMs) / 1000.0);
                            double instantBps = (totalRead - lastTickBytes) / dtSec;
                            smoothedBps = smoothedBps <= 0 ? instantBps : (smoothedBps * 0.65 + instantBps * 0.35);
                            lastTickMs = nowMs;
                            lastTickBytes = totalRead;

                            double pct = totalExpected > 0
                                ? Math.Min(99.5, (totalRead * 100.0) / totalExpected)
                                : -1;

                            Report(UpdateStage.Downloading, latestVer.ToString(), pct, totalRead, totalExpected, smoothedBps,
                                $"Downloading v{latestVer}...",
                                $"در حال دانلود نسخه v{latestVer}...");
                        }
                    }

                    await dst.FlushAsync(token).ConfigureAwait(false);
                    streamedHashBytes = hasher.GetHashAndReset();
                }

                Report(UpdateStage.VerifyingHash, latestVer.ToString(), 99.5, 0, 0, 0,
                    "Verifying SHA256 integrity...",
                    "در حال بررسی اصالت و هش SHA256...");

                var fi = new FileInfo(stagedExe);
                if (fi.Length < 100 * 1024)
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Downloaded installer is incomplete.", "فایل دانلودشده ناقص است.");
                    return new OperationResult(false, "Downloaded installer appears incomplete.", "فایل آپدیت دانلودشده ناقص به نظر می‌رسد.");
                }

                byte[] header = new byte[2];
                using (var fs = File.OpenRead(stagedExe))
                {
                    if (fs.Read(header, 0, 2) < 2 || header[0] != 0x4D || header[1] != 0x5A)
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "File is not a valid Windows executable.", "فایل اجرایی ویندوز معتبر نیست.");
                        return new OperationResult(false, "Update aborted: downloaded file is not a valid Windows executable.", "آپدیت متوقف شد: فایل دانلودشده یک فایل اجرایی معتبر نیست.");
                    }
                }

                byte[] diskHashBytes;
                await using (var verifyStream = new FileStream(stagedExe, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    diskHashBytes = await SHA256.HashDataAsync(verifyStream, token).ConfigureAwait(false);
                }

                if (!CryptographicOperations.FixedTimeEquals(streamedHashBytes, expectedHashBytes) ||
                    !CryptographicOperations.FixedTimeEquals(diskHashBytes, expectedHashBytes))
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "SHA256 checksum mismatch!", "عدم تطابق امضای امنیتی SHA256!");
                    return new OperationResult(false, "Update aborted: SHA256 checksum mismatch!", "آپدیت متوقف شد: عدم تطابق امضای امنیتی SHA256!");
                }

                if (!string.IsNullOrEmpty(currentExeThumbprint))
                {
                    string? newThumbprint = VerifyAuthenticodeSignature(stagedExe) ? TryGetAuthenticodeThumbprint(stagedExe) : null;
                    if (!string.Equals(newThumbprint, currentExeThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Authenticode publisher signature mismatch!", "عدم تطابق امضای دیجیتال ناشر!");
                        return new OperationResult(false, "Update aborted: installer Authenticode publisher signature mismatch!", "آپدیت متوقف شد: عدم تطابق امضای دیجیتال ناشر (Authenticode)!");
                    }
                }

                if (!IsDirectoryOwnedAndLockedByAdmins(stageDir, strictAdminOnly: true))
                {
                    Report(UpdateStage.Failed, latestVer.ToString(), 0, 0, 0, 0, "Staging folder ACL check failed.", "تایید امنیتی پوشه آپدیت ناموفق بود.");
                    return new OperationResult(false, "Update aborted: staging folder ownership/ACL verification failed.", "آپدیت متوقف شد: تایید امنیتی مالکیت پوشه آپدیت ناموفق بود.");
                }

                Report(UpdateStage.Installing, latestVer.ToString(), 100, fi.Length, fi.Length, 0,
                    $"Verified v{latestVer}! Launching installer...",
                    $"نسخه v{latestVer} تایید شد! در حال اجرای نصاب...");

                string cmdPath = _runner.ResolveSystemExecutable("cmd.exe");
                string pingPath = _runner.ResolveSystemExecutable("ping.exe");
                string taskkillPath = _runner.ResolveSystemExecutable("taskkill.exe");

                string innerCmd = $"\"{pingPath}\" -n 3 127.0.0.1 > NUL & \"{taskkillPath}\" /F /IM AionToolLite.exe > NUL 2>&1 & \"{pingPath}\" -n 2 127.0.0.1 > NUL & \"{stagedExe}\" /VERYSILENT /SUPPRESSMSGBOXES /FORCECLOSEAPPLICATIONS /NORESTART & rmdir /s /q \"{stageDir}\" > NUL 2>&1";
                Process.Start(new ProcessStartInfo
                {
                    FileName = cmdPath,
                    Arguments = $"/c \"{innerCmd}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                launched = true;
                return new OperationResult(true, "READY_TO_UPDATE", "READY_TO_UPDATE");
            }
            catch (OperationCanceledException)
            {
                Report(UpdateStage.Cancelled, null, 0, 0, 0, 0, "Update cancelled.", "بروزرسانی لغو شد.");
                return new OperationResult(false, "Update cancelled.", "بروزرسانی لغو شد.");
            }
            catch (Exception ex)
            {
                Report(UpdateStage.Failed, null, 0, 0, 0, 0, ex.Message, $"خطا در بروزرسانی: {ex.Message}", releasesFallbackUrl);
                return new OperationResult(false, $"Update check failed: {ex.Message}", $"بررسی آپدیت ناموفق بود: {ex.Message}");
            }
            finally
            {
                if (!launched)
                {
                    if (!string.IsNullOrEmpty(stageDir))
                    {
                        try { if (Directory.Exists(stageDir) && !IsReparsePoint(stageDir)) Directory.Delete(stageDir, recursive: true); } catch { }
                    }
                    else if (!string.IsNullOrEmpty(stagedExe))
                    {
                        try { if (File.Exists(stagedExe)) File.Delete(stagedExe); } catch { }
                    }
                }
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
