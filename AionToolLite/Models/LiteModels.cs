using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows.Media;

namespace AionToolLite.Models
{
    public enum DnsCategory
    {
        Auto,
        IranGame,
        Global,
        Security,
        Custom
    }

    public enum AdapterHealth
    {
        Connected = 0,
        Disconnected = 1,
        Disabled = 2
    }

    public enum PingChannelMode
    {
        Global = 0,
        Intranet = 1,
        Router = 2
    }

    public sealed class LiteAdapterItem
    {
        private static readonly SolidColorBrush GreenBrush = CreateFrozen("#10B981");
        private static readonly SolidColorBrush AmberBrush = CreateFrozen("#F59E0B");
        private static readonly SolidColorBrush RedBrush = CreateFrozen("#F43F5E");

        private static SolidColorBrush CreateFrozen(string hex)
        {
            var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }

        public string Name { get; init; } = string.Empty;
        public string HardwareDesc { get; init; } = string.Empty;
        public bool HasGateway { get; init; }
        public AdapterHealth Health { get; init; } = AdapterHealth.Connected;
        public string StatusLabel => Health switch
        {
            AdapterHealth.Connected => "Online",
            AdapterHealth.Disconnected => "Idle",
            _ => "Disabled"
        };

        public SolidColorBrush DotBrush => Health switch
        {
            AdapterHealth.Connected => GreenBrush,
            AdapterHealth.Disconnected => AmberBrush,
            _ => RedBrush
        };

        public override string ToString() => Name;
    }

    public sealed record LiteDnsPreset(
        string Id,
        string Name,
        string PrimaryIp,
        string SecondaryIp,
        DnsCategory Category,
        string TaglineEn,
        string TaglineFa,
        string BadgeHex,
        string? PrimaryIpv6 = null,
        string? SecondaryIpv6 = null,
        string? DohTemplate = null,
        bool SmartAutoEligible = false)
    {
        public bool IsSmartAuto => Category == DnsCategory.Auto;
        public bool IsCustom => Category == DnsCategory.Custom;
        public bool HasDoh => !string.IsNullOrWhiteSpace(DohTemplate);
    }

    public sealed record SavedCustomDnsEntry(
        string Id,
        string Name,
        string PrimaryIp,
        string SecondaryIp)
    {
        public LiteDnsPreset ToPreset() => new(
            Id,
            Name,
            PrimaryIp,
            SecondaryIp,
            DnsCategory.Custom,
            "Saved custom server",
            "سرور دستی ذخیره‌شده",
            "#E879F9");
    }

    public sealed record ActiveDnsStatus(
        bool IsStaticConnected,
        string PrimaryIp,
        string SecondaryIp,
        string DisplayNameEn,
        string DisplayNameFa,
        string? MatchedPresetId,
        string PrimaryIpv6 = "",
        string SecondaryIpv6 = "")
    {
        public static ActiveDnsStatus Automatic { get; } = new(false, string.Empty, string.Empty, string.Empty, string.Empty, null);
    }

    public sealed record OriginalDnsBackup(
        string AdapterName,
        bool WasDhcp,
        string PrimaryIp,
        string SecondaryIp,
        string SavedAtUtc,
        bool WasDhcpIpv6 = true,
        string PrimaryIpv6 = "",
        string SecondaryIpv6 = "");

    public sealed record GameModeStateRecord(
        List<string> StoppedServices,
        long BootUtcTicks);

    public sealed record StabilityCheckResult(
        bool Success,
        int SentCount,
        double GlobalLossPct,
        long? GlobalAvgMs,
        long? GlobalJitterMs,
        double? RouterLossPct,
        long? RouterAvgMs,
        long? RouterJitterMs,
        string VerdictEn,
        string VerdictFa,
        bool RouterBlockedIcmp = false);

    public sealed record LiteBlocklistItem(
        string Tag,
        string Name,
        string Category,
        string DownloadUrl,
        bool IsBuiltInCustom = false,
        bool IsLargeList = false)
    {
        public override string ToString() => $"{Name} — {Category}";
    }

    public sealed record HostsSummaryInfo(
        int TotalRules,
        List<string> InstalledListNames);

    public sealed record LiteTheme(
        int Id,
        string NameEn,
        string NameFa,
        string AccentHex,
        string SecondaryHex,
        string BgTopHex,
        string BgBottomHex,
        string CardHex,
        string CardHoverHex,
        string SurfaceSoftHex,
        string BorderHex,
        bool IsLight = false);

    public sealed record LiteSettings(
        int ThemeId = 1,
        string Language = "en",
        string SelectedDnsId = "smart_auto",
        string? PreferredAdapter = null,
        string CustomDns1 = "1.1.1.1",
        string CustomDns2 = "1.0.0.1",
        int PingChannel = 0,
        bool MinimizeToTray = true,
        List<string>? PinnedDnsIds = null,
        bool EnableNativeDoH = false,
        bool AutoConnectOnStartup = false,
        bool EnableGlobalHotkey = true,
        List<SavedCustomDnsEntry>? SavedCustomDns = null);

    public sealed record LiteTelemetry(
        bool HasInternet,
        long? GlobalPingMs,
        long? IntranetPingMs,
        long? RouterPingMs,
        string RouterIp,
        string AdapterName,
        bool AdapterFound,
        long BytesReceived,
        long BytesSent,
        ActiveDnsStatus ActiveDns);

    public sealed record OperationResult(
        bool Success,
        string MessageEn,
        string MessageFa);

    public enum UpdateStage
    {
        Checking,
        VerifyingSignature,
        Downloading,
        VerifyingHash,
        Installing,
        UpToDate,
        ManualRequired,
        Cancelled,
        Failed
    }

    public sealed record UpdateProgressInfo(
        UpdateStage Stage,
        string? TargetVersion,
        double Percent,
        long BytesDownloaded,
        long TotalBytes,
        double SpeedBytesPerSec,
        string StatusEn,
        string StatusFa,
        string? ReleasePageUrl = null);

    public static class LiteCatalog
    {
        private static readonly Regex StrictHostnameRegex = new(
            @"^([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])(\.([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))+\z",
            RegexOptions.Compiled);

        public static bool IsSafeDnsIpv4(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            string s = input.Trim();
            if (s.Length < 7 || s.Length > 15) return false;
            if (!IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            if (!string.Equals(ip.ToString(), s, StringComparison.Ordinal))
                return false;
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 0 || b[0] == 127 || b[0] >= 224) return false;
            if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return false;
            return true;
        }

        // Permits local loopback resolvers (e.g. 127.0.0.1 Pi-hole / AdGuard Home) for detection & lossless backup/restore
        public static bool IsValidBackupDnsIpv4(string? input)
        {
            if (IsSafeDnsIpv4(input)) return true;
            if (string.IsNullOrWhiteSpace(input)) return false;
            string s = input.Trim();
            if (!IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            if (!string.Equals(ip.ToString(), s, StringComparison.Ordinal))
                return false;
            return ip.GetAddressBytes()[0] == 127;
        }

        public static bool IsSafeDnsIpv6(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            string s = input.Trim();
            if (s.Contains('%') || s.Length < 2 || s.Length > 45) return false;
            if (!IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6)
                return false;
            if (ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast)
                return false;
            // Ignore Windows synthetic dummy site-local IPv6 DNS addresses (fec0:0:0:ffff::1..3)
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 0xFE && b[1] == 0xC0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0xFF && b[7] == 0xFF)
                return false;
            return true;
        }

        public static bool IsValidBlocklistHostname(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (host.Length < 3 || host.Length > 253) return false;
            if (IPAddress.TryParse(host, out _)) return false;
            if (host == "localhost" || host == "localhost.localdomain" ||
                host == "broadcasthost" || host == "ip6-localhost" || host == "ip6-loopback")
                return false;
            return StrictHostnameRegex.IsMatch(host);
        }

        public static IReadOnlyList<LiteDnsPreset> DnsPresets { get; } = new List<LiteDnsPreset>
        {
            new("smart_auto", "Smart Auto", "", "", DnsCategory.Auto,
                "Picks the fastest unfiltered global resolver",
                "انتخاب هوشمند سریع‌ترین سرور جهانی بدون فیلتر",
                "#818CF8"),

            // ==================== IRAN / GAMING (8) ====================
            new("shecan", "Shecan", "178.22.122.100", "185.51.200.2", DnsCategory.IranGame,
                "Anti-sanction smart DNS",
                "عبور از تحریم وب و اپ",
                "#FB923C",
                DohTemplate: "https://free.shecan.ir/dns-query"),

            new("electro", "Electro", "78.157.42.100", "78.157.42.101", DnsCategory.IranGame,
                "Low-ping gaming & bypass",
                "مخصوص گیم و پینگ پایین",
                "#FB923C"),

            new("radar", "Radar Game", "10.202.10.10", "10.202.10.11", DnsCategory.IranGame,
                "Iran gaming routing boost",
                "بهینه‌ساز مسیر بازی‌ها",
                "#FB923C"),

            new("403online", "403 Online", "10.202.10.202", "10.202.10.102", DnsCategory.IranGame,
                "Developer & app bypass",
                "رفع تحریم برنامه‌نویسان",
                "#FB923C"),

            new("begzar", "Begzar", "185.55.226.26", "185.55.225.25", DnsCategory.IranGame,
                "Stable sanction bypass",
                "دی‌ان‌اس پایدار رفع تحریم",
                "#FB923C"),

            new("shelter", "Shelter", "91.92.255.16", "91.92.255.24", DnsCategory.IranGame,
                "Gaming & download boost",
                "پایدارساز گیم و دانلود",
                "#FB923C"),

            new("shatel", "Shatel DNS", "85.15.1.14", "85.15.1.15", DnsCategory.IranGame,
                "Shatel fast domestic resolver",
                "دی‌ان‌اس پرسرعت داخلی شاتل",
                "#FB923C"),

            new("hostiran", "HostIran", "172.29.2.100", "172.29.0.100", DnsCategory.IranGame,
                "HostIran datacenter DNS",
                "دی‌ان‌اس دیتاسنتر هاست‌ایران",
                "#FB923C"),

            // ==================== GLOBAL (9) ====================
            new("cloudflare", "Cloudflare", "1.1.1.1", "1.0.0.1", DnsCategory.Global,
                "Ultra-fast global edge DNS",
                "سریع‌ترین سرور جهانی",
                "#38BDF8", "2606:4700:4700::1111", "2606:4700:4700::1001",
                "https://cloudflare-dns.com/dns-query",
                SmartAutoEligible: true),

            new("google", "Google DNS", "8.8.8.8", "8.8.4.4", DnsCategory.Global,
                "Reliable worldwide DNS",
                "پایدار و مطمئن جهانی",
                "#38BDF8", "2001:4860:4860::8888", "2001:4860:4860::8844",
                "https://dns.google/dns-query",
                SmartAutoEligible: true),

            new("opendns", "OpenDNS", "208.67.222.222", "208.67.220.220", DnsCategory.Global,
                "Cisco enterprise recursive DNS",
                "سرور قدرتمند سیسکو",
                "#38BDF8", "2620:119:35::35", "2620:119:53::53",
                "https://doh.opendns.com/dns-query",
                SmartAutoEligible: true),

            new("controld", "ControlD", "76.76.2.0", "76.76.10.0", DnsCategory.Global,
                "Modern fast anycast DNS",
                "سرور مدرن با سرعت بالا",
                "#38BDF8", "2606:1a40::", "2606:1a40:1::",
                "https://freedns.controld.com/p0",
                SmartAutoEligible: true),

            // Mullvad unfiltered uses 194.242.2.2 + 2a07:e340::2 only (no ad-blocking secondary)
            new("mullvad", "Mullvad DNS", "194.242.2.2", "", DnsCategory.Global,
                "Privacy-first zero-log unfiltered DNS",
                "حریم خصوصی بالا بدون لاگ و فیلتر",
                "#38BDF8", "2a07:e340::2", null,
                "https://dns.mullvad.net/dns-query",
                SmartAutoEligible: true),

            new("yandex", "Yandex DNS", "77.88.8.8", "77.88.8.1", DnsCategory.Global,
                "Fast Eurasia regional DNS",
                "پاسخ‌دهی سریع منطقه‌ای",
                "#38BDF8", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"),

            new("level3", "Level3", "4.2.2.4", "4.2.2.2", DnsCategory.Global,
                "Classic backbone resolver",
                "دی‌ان‌اس کلاسیک و کم‌پینگ",
                "#38BDF8",
                SmartAutoEligible: true),

            new("alidns", "AliDNS", "223.5.5.5", "223.6.6.6", DnsCategory.Global,
                "Alibaba Cloud global DNS",
                "دی‌ان‌اس جهانی علی‌بابا",
                "#38BDF8", "2400:3200::1", "2400:3200:baba::1",
                "https://dns.alidns.com/dns-query"),

            new("114dns", "114DNS", "114.114.114.114", "114.114.115.115", DnsCategory.Global,
                "Reliable Asian & Pacific DNS",
                "مسیر پایدار شرق آسیا",
                "#38BDF8"),

            // ==================== AD & SECURITY (8) ====================
            new("adguard", "AdGuard", "94.140.14.14", "94.140.15.15", DnsCategory.Security,
                "Blocks ads & trackers",
                "مسدودکننده تبلیغات و ردیاب",
                "#FACC15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
                "https://dns.adguard-dns.com/dns-query"),

            new("quad9", "Quad9", "9.9.9.9", "149.112.112.112", DnsCategory.Security,
                "Swiss malware & phishing shield",
                "محافظ سوئیسی در برابر بدافزار",
                "#FACC15", "2620:fe::fe", "2620:fe::9",
                "https://dns.quad9.net/dns-query"),

            new("cf_security", "Cloudflare Safe", "1.1.1.2", "1.0.0.2", DnsCategory.Security,
                "Fast DNS + malware blocking",
                "کلودفلر پرسرعت + مسدودساز بدافزار",
                "#FACC15", "2606:4700:4700::1112", "2606:4700:4700::1002",
                "https://security.cloudflare-dns.com/dns-query"),

            new("cf_family", "Cloudflare Family", "1.1.1.3", "1.0.0.3", DnsCategory.Security,
                "Blocks malware & adult sites",
                "سپر خانواده (بدافزار + محتوای نامناسب)",
                "#FACC15", "2606:4700:4700::1113", "2606:4700:4700::1003",
                "https://family.cloudflare-dns.com/dns-query"),

            new("cleanbrowsing", "CleanBrowsing", "185.228.168.9", "185.228.169.9", DnsCategory.Security,
                "Blocks malicious & phishing domains",
                "فیلتر امنیتی سایت‌های مخرب",
                "#FACC15", "2a0d:2a00:1::2", "2a0d:2a00:2::2",
                "https://doh.cleanbrowsing.org/doh/security-filter/"),

            new("dns0eu", "dns0.eu", "193.110.81.0", "185.253.5.0", DnsCategory.Security,
                "European privacy & threat shield",
                "دی‌ان‌اس امن و حریم خصوصی اروپا",
                "#FACC15", "2a0f:fc80::", "2a0f:fc81::",
                "https://dns0.eu/"),

            new("comodo", "Comodo Secure", "8.26.56.26", "8.20.247.20", DnsCategory.Security,
                "Cloud malware & web protection",
                "محافظ ابری کومودو",
                "#FACC15"),

            new("alternate", "Alternate DNS", "76.76.19.19", "76.223.122.150", DnsCategory.Security,
                "Lightweight ad & tracker filter",
                "فیلتر سبک تبلیغات و ردیاب‌ها",
                "#FACC15")
        };

        public static IReadOnlyList<LiteBlocklistItem> Blocklists { get; } = new List<LiteBlocklistItem>
        {
            new("TeamSpeak-Blocked",       "TeamSpeak Fix (Custom)",         "Custom Rule (9)",          "local://teamspeak", IsBuiltInCustom: true, IsLargeList: false),
            new("PeterLowe-AdServers",     "Peter Lowe Ad Servers",          "Lightweight Ads (~3.5k)",  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", IsLargeList: false),
            new("Pollock-SomeoneWhoCares", "Dan Pollock Zero-Route",         "Medium Shield (~16k)",     "https://someonewhocares.org/hosts/zero/hosts", IsLargeList: false),
            new("StevenBlack-Base",        "StevenBlack Ads & Malware",      "Large (~80k+)",            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", IsLargeList: true),
            new("StevenBlack-Social",      "StevenBlack Ads + Social",       "Very Large (~100k+)",      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts", IsLargeList: true),
            new("StevenBlack-Gambling",    "StevenBlack Gambling Filter",    "Large (~85k+)",            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts", IsLargeList: true),
            new("StevenBlack-Porn",        "StevenBlack Family Shield",      "Very Large (~120k+)",      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts", IsLargeList: true)
        };

        public static IReadOnlyList<LiteTheme> Themes { get; } = new List<LiteTheme>
        {
            new(1, "Aion Lavender", "یاسی آیون",
                "#B57BFF", "#67E8F9", "#0D091A", "#160F2E", "#1E153D", "#291D52", "#120C26", "#3B2B6E"),

            new(2, "Cosmic Blurple", "بنفش کیهانی",
                "#6366F1", "#38BDF8", "#0B0E17", "#111626", "#161C2E", "#1F2842", "#0E1220", "#26314D"),

            new(3, "Emerald Pulse", "زمردی نئون",
                "#10B981", "#34D399", "#06120E", "#0B1F18", "#102820", "#17382D", "#081712", "#1F473A"),

            new(4, "Crimson Glow", "قرمز یاقوتی",
                "#F43F5E", "#FB7185", "#14080C", "#1F0D14", "#29121B", "#381825", "#190A10", "#4A2131"),

            new(5, "Ocean Cyber", "آبی اقیانوسی",
                "#06B6D4", "#818CF8", "#060F17", "#0B1B29", "#102436", "#17324A", "#08141F", "#1E3F5C"),

            new(6, "Clean Daylight", "روشن روز",
                "#4F46E5", "#0EA5E9", "#F1F5F9", "#E2E8F0", "#FFFFFF", "#F8FAFC", "#F1F5F9", "#CBD5E1", IsLight: true)
        };
    }
}
