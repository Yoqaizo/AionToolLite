using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;
using AionToolLite.Models;
using AionToolLite.Services;
using AionToolLite.Themes;

namespace AionToolLite
{
    public partial class MainWindow : Window
    {
        private enum OrbVisualState { Idle, Connecting, Disconnecting, Connected }

        private readonly LiteNetworkService _service = new();
        private readonly DispatcherTimer _telemetryTimer = new() { Interval = TimeSpan.FromSeconds(2.2) };
        private readonly NetworkAddressChangedEventHandler _netChangeHandler;
        private TrayManager? _tray;

        private LiteSettings _settings = new(PinnedDnsIds: new List<string>());
        private LiteTheme _currentTheme = LiteCatalog.Themes[0];
        private LiteDnsPreset _selectedPreset = LiteCatalog.DnsPresets[0];
        private LiteDnsPreset? _fastestWinner;
        private long? _fastestWinnerMs;
        private ActiveDnsStatus _activeDns = ActiveDnsStatus.Automatic;
        private string _selectedAdapter = string.Empty;
        private string _dnsFilter = "All";
        private OrbVisualState _orbState = OrbVisualState.Idle;
        private PingChannelMode _pingMode = PingChannelMode.Global;
        private LiteTelemetry? _lastTelemetry;
        private string _lastPublicIp = string.Empty;

        private readonly Dictionary<string, long?> _dnsLatencies = new(StringComparer.OrdinalIgnoreCase);
        private CancellationTokenSource? _toastCts;
        private CancellationTokenSource? _netChangeDebounceCts;

        private bool _isReady;
        private bool _isBusy;
        private bool _isClosing;
        private bool _shownTrayTipOnce;
        private bool _isTelemetryTickRunning;

        private long _lastRx;
        private long _lastTx;
        private DateTime _lastTrafficTick = DateTime.MinValue;

        private static readonly Color EmeraldStart = (Color)ColorConverter.ConvertFromString("#10B981");
        private static readonly Color EmeraldEnd = (Color)ColorConverter.ConvertFromString("#34D399");
        private static readonly Color AmberStart = (Color)ColorConverter.ConvertFromString("#F59E0B");
        private static readonly Color AmberEnd = (Color)ColorConverter.ConvertFromString("#FBBF24");
        private static readonly Color GoldCol = (Color)ColorConverter.ConvertFromString("#FACC15");
        private static readonly Color RedCol = (Color)ColorConverter.ConvertFromString("#F43F5E");
        private static readonly SolidColorBrush FrozenGreen = Freeze(new SolidColorBrush(EmeraldStart));
        private static readonly SolidColorBrush FrozenAmber = Freeze(new SolidColorBrush(AmberStart));
        private static readonly SolidColorBrush FrozenGold = Freeze(new SolidColorBrush(GoldCol));
        private static readonly SolidColorBrush FrozenRed = Freeze(new SolidColorBrush(RedCol));
        private static readonly SolidColorBrush FrozenDotDim = Freeze(new SolidColorBrush((Color)ColorConverter.ConvertFromString("#475569")));

        private static SolidColorBrush Freeze(SolidColorBrush b)
        {
            b.Freeze();
            return b;
        }

        private bool IsFa => _settings.Language == "fa";
        private string L(string en, string fa) => IsFa ? fa : en;
        private List<string> PinnedIds => _settings.PinnedDnsIds ?? new List<string>();

        public MainWindow()
        {
            InitializeComponent();

            if (App.StartMinimized)
            {
                ShowInTaskbar = false;
                Opacity = 0;
            }

            _netChangeHandler = (_, _) =>
            {
                if (_isClosing) return;
                Dispatcher.InvokeAsync(ScheduleDebouncedNetworkChangeAsync);
            };
            NetworkChange.NetworkAddressChanged += _netChangeHandler;

            StateChanged += (_, _) =>
            {
                if (!_isClosing && _isReady && IsVisible && WindowState != WindowState.Minimized)
                    _ = RefreshTelemetryAsync();
            };

            _telemetryTimer.Tick += async (_, _) => await RefreshTelemetryAsync();
            Loaded += MainWindow_Loaded;
        }

        // ==================== SYSTEM TRAY INITIALIZATION & RESTORE ====================
        private void InitializeTray()
        {
            try
            {
                _tray = new TrayManager();
                _tray.ShowRequested += () => Dispatcher.InvokeAsync(RestoreFromTray);
                _tray.ToggleConnectRequested += () => Dispatcher.InvokeAsync(ToggleConnectFromTrayAsync);
                _tray.QuickSwitchDnsRequested += preset => Dispatcher.InvokeAsync(() => QuickSwitchFromTrayAsync(preset));
                _tray.ExitRequested += () => Dispatcher.InvokeAsync(ExitApplicationCompletely);
                RefreshTrayState();
            }
            catch (Exception ex)
            {
                App.WriteCrashLog("TrayInit", ex);
            }
        }

        private void RefreshTrayState()
        {
            if (_tray == null || _isClosing) return;

            var pinned = PinnedIds;
            var quickList = LiteCatalog.DnsPresets
                .OrderBy(p => p.IsSmartAuto ? 0 : pinned.Contains(p.Id, StringComparer.OrdinalIgnoreCase) ? 1 : 2)
                .Take(7)
                .ToList();

            string activeName = L(_activeDns.DisplayNameEn, _activeDns.DisplayNameFa);
            _tray.UpdateState(IsFa, _activeDns.IsStaticConnected, activeName, _activeDns.PrimaryIp, quickList);
        }

        public void RestoreFromTray()
        {
            if (_isClosing) return;
            ShowInTaskbar = true;
            if (!IsVisible) Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Opacity = 1;
            LaunchScale.ScaleX = 1;
            LaunchScale.ScaleY = 1;
            Activate();
            Topmost = true;
            Topmost = false;
            Focus();
            _ = RefreshTelemetryAsync();
        }

        private void HideToTray()
        {
            Hide();
            ShowInTaskbar = false;
            if (!_shownTrayTipOnce)
            {
                _shownTrayTipOnce = true;
                _tray?.ShowBalloon(
                    "AionToolLite",
                    L("Running quietly in the System Tray. Click the icon to open or right-click for quick DNS controls.",
                      "برنامه در پس‌زمینه کنار ساعت فعال است. برای باز کردن کلیک کنید یا برای تغییر سریع DNS کلیک‌راست کنید."));
            }
        }

        private void ExitApplicationCompletely()
        {
            Close();
            Application.Current?.Shutdown();
        }

        private async Task ToggleConnectFromTrayAsync()
        {
            if (_isBusy || _isClosing) return;
            _isBusy = true;
            try
            {
                if (_orbState == OrbVisualState.Connected)
                {
                    SetOrbState(OrbVisualState.Disconnecting);
                    var res = await _service.DisconnectDnsToAutoAsync(_selectedAdapter);
                    _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                    SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                    UpdateSelectedDnsHomeCard();
                    RebuildDnsCards();
                    RefreshTrayState();
                    _tray?.ShowBalloon("AionToolLite", L(res.MessageEn, res.MessageFa));
                }
                else
                {
                    await ConnectPresetAsync(_selectedPreset);
                    _tray?.ShowBalloon("AionToolLite",
                        _activeDns.IsStaticConnected
                            ? L($"Connected to {_activeDns.DisplayNameEn}", $"متصل به {_activeDns.DisplayNameFa}")
                            : L("Connection failed.", "اتصال ناموفق بود."));
                }
            }
            catch (Exception ex)
            {
                App.WriteCrashLog("TrayToggle", ex);
            }
            finally
            {
                _isBusy = false;
            }
        }

        private async Task QuickSwitchFromTrayAsync(LiteDnsPreset preset)
        {
            if (_isBusy || _isClosing) return;
            _isBusy = true;
            try
            {
                _selectedPreset = preset;
                _settings = _settings with { SelectedDnsId = preset.Id };
                _service.SaveSettings(_settings);
                await ConnectPresetAsync(preset);
                _tray?.ShowBalloon("AionToolLite",
                    _activeDns.IsStaticConnected
                        ? L($"Switched to {_activeDns.DisplayNameEn} ({_activeDns.PrimaryIp})", $"متصل به {_activeDns.DisplayNameFa} ({_activeDns.PrimaryIp})")
                        : L("Could not switch DNS.", "تغییر سرور ناموفق بود."));
            }
            catch (Exception ex)
            {
                App.WriteCrashLog("TraySwitch", ex);
            }
            finally
            {
                _isBusy = false;
            }
        }

        // ==================== LIFECYCLE & NETWORK DEBOUNCE ====================
        private async void ScheduleDebouncedNetworkChangeAsync()
        {
            try
            {
                _netChangeDebounceCts?.Cancel();
                _netChangeDebounceCts?.Dispose();
                _netChangeDebounceCts = new CancellationTokenSource();
                var token = _netChangeDebounceCts.Token;

                await Task.Delay(550, token);
                if (_isClosing) return;

                await LoadAdaptersAsync(preserveSelection: true);
                await RefreshTelemetryAsync();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                App.WriteCrashLog("NetworkChange", ex);
            }
        }

        private async Task RunSafeAsync(Func<Task> action, string context)
        {
            try
            {
                await action();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                App.WriteCrashLog(context, ex);
                ShowToast(ex.Message, isError: true);
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await RunSafeAsync(async () =>
            {
                if (!App.StartMinimized)
                    PlayLaunchEntranceAnimation();

                _settings = await Task.Run(() => _service.LoadSettings());
                _currentTheme = LiteCatalog.Themes.FirstOrDefault(t => t.Id == _settings.ThemeId) ?? LiteCatalog.Themes[0];
                _selectedPreset = LiteCatalog.DnsPresets.FirstOrDefault(p => p.Id == _settings.SelectedDnsId) ?? LiteCatalog.DnsPresets[0];
                _pingMode = Enum.IsDefined(typeof(PingChannelMode), _settings.PingChannel)
                    ? (PingChannelMode)_settings.PingChannel
                    : PingChannelMode.Global;

                TxtCustomDns1.Text = string.IsNullOrWhiteSpace(_settings.CustomDns1) ? "1.1.1.1" : _settings.CustomDns1;
                TxtCustomDns2.Text = string.IsNullOrWhiteSpace(_settings.CustomDns2) ? "1.0.0.1" : _settings.CustomDns2;

                ComboHostsBlocklist.ItemsSource = LiteCatalog.Blocklists;
                ComboHostsBlocklist.SelectedIndex = 0;

                var asmVer = Assembly.GetExecutingAssembly().GetName().Version;
                string verLabel = asmVer != null ? $"{asmVer.Major}.{asmVer.Minor}.{Math.Max(0, asmVer.Build)}" : "1.2.3";
                TxtAppFooterVersion.Text = $"AionToolLite v{verLabel}  ·  Created by Yoqaizo";

                LiteThemeManager.Apply(_currentTheme);
                BuildThemeDots();
                ApplyLanguage();

                ToggleMinToTray.IsChecked = _settings.MinimizeToTray;

                var stateTask = Task.Run(() => (Game: _service.IsGameModeActive(), AdShield: _service.IsAdShieldActive()));
                var autoStartTask = _service.IsAutoStartEnabledAsync();
                await Task.WhenAll(stateTask, autoStartTask);

                ToggleGameMode.IsChecked = stateTask.Result.Game;
                ToggleAdShield.IsChecked = stateTask.Result.AdShield;
                ToggleAutoStart.IsChecked = autoStartTask.Result;

                await LoadAdaptersAsync(preserveSelection: false);
                await RefreshHostsUiAsync();

                _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                _isReady = true;

                SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                UpdateSelectedDnsHomeCard();
                RebuildDnsCards();
                RenderPingCard();

                InitializeTray();

                if (App.StartMinimized)
                {
                    Hide();
                    ShowInTaskbar = false;
                }

                _telemetryTimer.Start();
                await RefreshTelemetryAsync();
            }, "Startup");
        }

        protected override void OnClosed(EventArgs e)
        {
            _isClosing = true;
            try
            {
                _telemetryTimer.Stop();
                _toastCts?.Cancel();
                _toastCts?.Dispose();
                _netChangeDebounceCts?.Cancel();
                _netChangeDebounceCts?.Dispose();
                NetworkChange.NetworkAddressChanged -= _netChangeHandler;
                _tray?.Dispose();
            }
            catch { }
            base.OnClosed(e);
        }

        // ==================== SMOOTH ANIMATIONS & TOAST ====================
        private void PlayLaunchEntranceAnimation()
        {
            Opacity = 0;
            var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
            var sx = new DoubleAnimation(0.95, 1.0, TimeSpan.FromMilliseconds(280)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
            var sy = new DoubleAnimation(0.95, 1.0, TimeSpan.FromMilliseconds(280)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
            BeginAnimation(OpacityProperty, fade);
            LaunchScale.BeginAnimation(ScaleTransform.ScaleXProperty, sx);
            LaunchScale.BeginAnimation(ScaleTransform.ScaleYProperty, sy);
        }

        private void PlayViewTransition()
        {
            var fade = new DoubleAnimation(0.25, 1.0, TimeSpan.FromMilliseconds(210)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
            var slide = new DoubleAnimation(14, 0, TimeSpan.FromMilliseconds(230)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
            AnimatedViewHost.BeginAnimation(OpacityProperty, fade);
            ViewSlideTransform.BeginAnimation(TranslateTransform.YProperty, slide);
        }

        private async void ShowToast(string message, bool isError = false)
        {
            if (_isClosing) return;
            try
            {
                _toastCts?.Cancel();
                _toastCts?.Dispose();
                _toastCts = new CancellationTokenSource();
                var token = _toastCts.Token;

                TxtToastMessage.Text = message;
                ToastBanner.BorderBrush = isError ? FrozenRed : FrozenGreen;

                ToastBanner.BeginAnimation(OpacityProperty, new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(180)));
                ToastSlide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(220))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                });

                await Task.Delay(2600, token);
                if (_isClosing) return;

                ToastBanner.BeginAnimation(OpacityProperty, new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(240)));
                ToastSlide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(-16, TimeSpan.FromMilliseconds(240)));
            }
            catch (OperationCanceledException) { }
        }

        private void SetOrbState(OrbVisualState state)
        {
            _orbState = state;
            var sonar = (Storyboard)FindResource("SonarPulseStoryboard");
            var spinner = (Storyboard)FindResource("SpinnerStoryboard");

            Color targetStart, targetEnd, ambient;

            if (state == OrbVisualState.Connected)
            {
                targetStart = EmeraldStart;
                targetEnd = EmeraldEnd;
                ambient = EmeraldStart;

                spinner.Stop(this);
                SpinnerRing.BeginAnimation(OpacityProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(180)));
                sonar.Begin(this, true);

                string activeName = L(_activeDns.DisplayNameEn, _activeDns.DisplayNameFa);
                TxtHeroState.Text = L("Connected", "متصل هستید");
                TxtHeroSubtitle.Text = L("Tap the orb anytime to disconnect", "برای قطع اتصال، روی دکمه وسط بزنید");
                TxtOrbAction.Text = L("DISCONNECT", "قطع اتصال");

                if (_activeDns.IsStaticConnected)
                {
                    TxtConnectedDnsBadge.Text = string.IsNullOrEmpty(_activeDns.SecondaryIp)
                        ? $"{activeName}  ·  {_activeDns.PrimaryIp}"
                        : $"{activeName}  ·  {_activeDns.PrimaryIp} , {_activeDns.SecondaryIp}";
                    ConnectedDnsPill.Visibility = Visibility.Visible;
                    ConnectedDnsPill.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(240)));
                }
            }
            else if (state == OrbVisualState.Connecting || state == OrbVisualState.Disconnecting)
            {
                targetStart = AmberStart;
                targetEnd = AmberEnd;
                ambient = AmberStart;

                sonar.Stop(this);
                SonarRing1.Opacity = 0;
                SonarRing2.Opacity = 0;
                ConnectedDnsPill.Visibility = Visibility.Collapsed;

                SpinnerRing.BeginAnimation(OpacityProperty, new DoubleAnimation(0.95, TimeSpan.FromMilliseconds(180)));
                spinner.Begin(this, true);

                if (state == OrbVisualState.Connecting)
                {
                    TxtHeroState.Text = L("Connecting...", "در حال اتصال...");
                    TxtHeroSubtitle.Text = L("Applying optimized DNS & refreshing cache", "در حال تنظیم بهینه دی‌ان‌اس و پاکسازی کش");
                    TxtOrbAction.Text = L("WAIT", "صبر...");
                }
                else
                {
                    TxtHeroState.Text = L("Disconnecting...", "در حال قطع اتصال...");
                    TxtHeroSubtitle.Text = L("Removing DNS & flushing Windows cache", "در حال حذف دی‌ان‌اس و پاکسازی سریع کش");
                    TxtOrbAction.Text = L("CLEARING", "پاکسازی...");
                }
            }
            else
            {
                targetStart = (Color)ColorConverter.ConvertFromString(_currentTheme.AccentHex);
                targetEnd = (Color)ColorConverter.ConvertFromString(_currentTheme.SecondaryHex);
                ambient = targetStart;

                sonar.Stop(this);
                spinner.Stop(this);
                SonarRing1.Opacity = 0;
                SonarRing2.Opacity = 0;
                ConnectedDnsPill.Visibility = Visibility.Collapsed;
                SpinnerRing.BeginAnimation(OpacityProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(180)));

                TxtHeroState.Text = L("Ready to Connect", "آماده اتصال");
                TxtHeroSubtitle.Text = L("Tap the button for faster, cleaner internet", "برای اینترنت سریع‌تر و تمیزتر لمس کنید");
                TxtOrbAction.Text = L("CONNECT", "اتصال");
            }

            var dur = TimeSpan.FromMilliseconds(320);
            OrbGradStart.BeginAnimation(GradientStop.ColorProperty, new ColorAnimation(targetStart, dur));
            OrbGradEnd.BeginAnimation(GradientStop.ColorProperty, new ColorAnimation(targetEnd, dur));
            OrbGlowShadow.BeginAnimation(DropShadowEffect.ColorProperty, new ColorAnimation(ambient, dur));
            AmbientGlowColorStop.BeginAnimation(GradientStop.ColorProperty, new ColorAnimation(ambient, TimeSpan.FromMilliseconds(420)));
            RefreshTrayState();
        }

        // ==================== WINDOW CHROME & NAVIGATION ====================
        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                try { DragMove(); } catch { }
            }
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            if (_settings.MinimizeToTray && _tray != null)
            {
                HideToTray();
                return;
            }
            ExitApplicationCompletely();
        }

        private async void BottomNav_Checked(object sender, RoutedEventArgs e)
        {
            if (!_isReady || sender is not RadioButton rb || rb.Tag is not string tag) return;

            ViewHome.Visibility = tag == "Home" ? Visibility.Visible : Visibility.Collapsed;
            ViewDns.Visibility = tag == "Dns" ? Visibility.Visible : Visibility.Collapsed;
            ViewBoost.Visibility = tag == "Boost" ? Visibility.Visible : Visibility.Collapsed;
            ViewUtilities.Visibility = tag == "Utilities" ? Visibility.Visible : Visibility.Collapsed;
            ViewSettings.Visibility = tag == "Settings" ? Visibility.Visible : Visibility.Collapsed;

            PlayViewTransition();

            if (tag == "Utilities")
                await RunSafeAsync(RefreshHostsUiAsync, "RefreshHosts");
        }

        private void BtnHomeOpenDns_Click(object sender, RoutedEventArgs e) => NavDns.IsChecked = true;

        // ==================== CLICKABLE 3-MODE PING CARD ====================
        private void BtnPingCycle_Click(object sender, RoutedEventArgs e)
        {
            _pingMode = _pingMode switch
            {
                PingChannelMode.Global => PingChannelMode.Intranet,
                PingChannelMode.Intranet => PingChannelMode.Router,
                _ => PingChannelMode.Global
            };

            _settings = _settings with { PingChannel = (int)_pingMode };
            _service.SaveSettings(_settings);

            var fade = new DoubleAnimation(0.3, 1.0, TimeSpan.FromMilliseconds(180))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            PingCardContent.BeginAnimation(OpacityProperty, fade);
            RenderPingCard();
        }

        private void RenderPingCard()
        {
            var accentBrush = (Brush)FindResource("AccentBrush");
            PingDot0.Fill = _pingMode == PingChannelMode.Global ? accentBrush : FrozenDotDim;
            PingDot1.Fill = _pingMode == PingChannelMode.Intranet ? accentBrush : FrozenDotDim;
            PingDot2.Fill = _pingMode == PingChannelMode.Router ? accentBrush : FrozenDotDim;

            if (_pingMode == PingChannelMode.Global)
            {
                LblHomePingTitle.Text = L("GLOBAL · 4.2.2.4", "جهانی · 4.2.2.4");
                ApplyPingMetric(_lastTelemetry?.GlobalPingMs, isRouter: false, goodMax: 65, warnMax: 130);
            }
            else if (_pingMode == PingChannelMode.Intranet)
            {
                LblHomePingTitle.Text = L("IRAN · ARVAN", "داخلی · آروان");
                ApplyPingMetric(_lastTelemetry?.IntranetPingMs, isRouter: false, goodMax: 35, warnMax: 85);
            }
            else
            {
                string gw = _lastTelemetry?.RouterIp ?? "";
                LblHomePingTitle.Text = string.IsNullOrEmpty(gw)
                    ? L("PC ↔ MODEM", "پینگ مودم")
                    : L($"MODEM · {gw}", $"مودم · {gw}");
                ApplyPingMetric(_lastTelemetry?.RouterPingMs, isRouter: true, goodMax: 3, warnMax: 12);
            }
        }

        private void ApplyPingMetric(long? msOpt, bool isRouter, long goodMax, long warnMax)
        {
            if (_lastTelemetry == null)
            {
                TxtHomePingValue.Text = "-- ms";
                TxtHomePingRating.Text = "";
                return;
            }

            if (msOpt.HasValue)
            {
                long ms = msOpt.Value;
                TxtHomePingValue.Text = (isRouter && ms == 0) ? "<1 ms" : $"{ms} ms";
                if (ms <= goodMax)
                {
                    PingQualityDot.Fill = FrozenGreen;
                    TxtHomePingRating.Foreground = FrozenGreen;
                    TxtHomePingRating.Text = L("Great", "عالی");
                }
                else if (ms <= warnMax)
                {
                    PingQualityDot.Fill = FrozenAmber;
                    TxtHomePingRating.Foreground = FrozenAmber;
                    TxtHomePingRating.Text = L("Good", "خوب");
                }
                else
                {
                    PingQualityDot.Fill = FrozenRed;
                    TxtHomePingRating.Foreground = FrozenRed;
                    TxtHomePingRating.Text = isRouter ? L("Lag", "تاخیر") : L("High", "بالا");
                }
            }
            else
            {
                TxtHomePingValue.Text = "-- ms";
                PingQualityDot.Fill = FrozenRed;
                TxtHomePingRating.Foreground = FrozenRed;
                TxtHomePingRating.Text = isRouter && string.IsNullOrEmpty(_lastTelemetry.RouterIp)
                    ? L("N/A", "ندارد")
                    : L("Offline", "قطع");
            }
        }

        // ==================== HERO POWER ORB ====================
        private async void BtnPowerOrb_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            _isBusy = true;

            try
            {
                if (_orbState == OrbVisualState.Connected)
                {
                    SetOrbState(OrbVisualState.Disconnecting);
                    var sw = Stopwatch.StartNew();

                    var res = await _service.DisconnectDnsToAutoAsync(_selectedAdapter);

                    int remaining = 380 - (int)sw.ElapsedMilliseconds;
                    if (remaining > 0) await Task.Delay(remaining);

                    _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                    if (res.Success && !_activeDns.IsStaticConnected)
                    {
                        SetOrbState(OrbVisualState.Idle);
                        UpdateSelectedDnsHomeCard();
                        RebuildDnsCards();
                        ShowToast(L(res.MessageEn, res.MessageFa));
                    }
                    else
                    {
                        SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                        ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                    }
                    await RefreshTelemetryAsync();
                    return;
                }

                await ConnectPresetAsync(_selectedPreset);
            }
            catch (Exception ex)
            {
                App.WriteCrashLog("PowerOrb", ex);
                SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                ShowToast(ex.Message, isError: true);
            }
            finally
            {
                _isBusy = false;
            }
        }

        private async Task ConnectPresetAsync(LiteDnsPreset preset)
        {
            SetOrbState(OrbVisualState.Connecting);
            var sw = Stopwatch.StartNew();
            LiteDnsPreset target = preset;

            if (preset.IsSmartAuto)
            {
                TxtHeroSubtitle.Text = L("Finding the fastest DNS for your line...", "در حال یافتن سریع‌ترین سرور برای اینترنت شما...");
                var (best, ms) = await _service.FindFastestPresetAsync();
                if (best != null)
                {
                    target = best;
                    if (ms.HasValue) _dnsLatencies[best.Id] = ms.Value;
                }
                else
                {
                    target = LiteCatalog.DnsPresets.First(p => p.Id == "cloudflare");
                }
            }

            var res = await _service.ApplyDnsAsync(
                _selectedAdapter,
                target.PrimaryIp,
                target.SecondaryIp,
                target.Name,
                target.PrimaryIpv6,
                target.SecondaryIpv6);

            int remaining = 380 - (int)sw.ElapsedMilliseconds;
            if (remaining > 0) await Task.Delay(remaining);

            if (res.Success)
            {
                _activeDns = new ActiveDnsStatus(true, target.PrimaryIp, target.SecondaryIp, target.Name, target.Name, target.Id);
                SetOrbState(OrbVisualState.Connected);
                UpdateSelectedDnsHomeCard();
                RebuildDnsCards();
                ShowToast(L(res.MessageEn, res.MessageFa));
            }
            else
            {
                _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: true);
            }

            await RefreshTelemetryAsync();
        }

        // ==================== DNS VIEW, PINNING & ONE-TAP FASTEST WINNER ====================
        private void UpdateSelectedDnsHomeCard()
        {
            if (_orbState == OrbVisualState.Connected && _activeDns.IsStaticConnected)
            {
                LblHomeServerCaption.Text = L("ACTIVE DNS", "دی‌ان‌اس فعال");
                TxtHomeSelectedDns.Text = L(_activeDns.DisplayNameEn, _activeDns.DisplayNameFa);
                TxtHomeSelectedIp.Text = string.IsNullOrEmpty(_activeDns.SecondaryIp)
                    ? _activeDns.PrimaryIp
                    : $"{_activeDns.PrimaryIp}  ·  {_activeDns.SecondaryIp}";
                return;
            }

            LblHomeServerCaption.Text = L("SELECTED SERVER", "سرور انتخاب‌شده");
            TxtHomeSelectedDns.Text = _selectedPreset.IsSmartAuto
                ? L("Smart Auto (Recommended)", "انتخاب هوشمند (پیشنهادی)")
                : _selectedPreset.Name;

            TxtHomeSelectedIp.Text = _selectedPreset.IsSmartAuto
                ? L(_selectedPreset.TaglineEn, _selectedPreset.TaglineFa)
                : $"{_selectedPreset.PrimaryIp}  ·  {_selectedPreset.SecondaryIp}";
        }

        private void DnsFilterChip_Checked(object sender, RoutedEventArgs e)
        {
            if (!_isReady || sender is not RadioButton rb || rb.Tag is not string filter) return;
            _dnsFilter = filter;
            RebuildDnsCards();
        }

        private void TogglePinDns(LiteDnsPreset preset)
        {
            var pins = new List<string>(PinnedIds);
            bool nowPinned;
            if (pins.Any(x => x.Equals(preset.Id, StringComparison.OrdinalIgnoreCase)))
            {
                pins.RemoveAll(x => x.Equals(preset.Id, StringComparison.OrdinalIgnoreCase));
                nowPinned = false;
            }
            else
            {
                pins.Add(preset.Id);
                nowPinned = true;
            }

            _settings = _settings with { PinnedDnsIds = pins };
            _service.SaveSettings(_settings);
            RebuildDnsCards();
            RefreshTrayState();
            ShowToast(nowPinned
                ? L($"Pinned {preset.Name} to top", $"{preset.Name} به بالای لیست پین شد")
                : L($"Unpinned {preset.Name}", $"پین {preset.Name} برداشته شد"));
        }

        private void RebuildDnsCards()
        {
            DnsCardsPanel.Children.Clear();
            var pins = PinnedIds;

            IEnumerable<LiteDnsPreset> items = LiteCatalog.DnsPresets;
            if (_dnsFilter == "IranGame") items = items.Where(p => p.Category == DnsCategory.IranGame);
            else if (_dnsFilter == "Global") items = items.Where(p => p.Category == DnsCategory.Global);
            else if (_dnsFilter == "Security") items = items.Where(p => p.Category == DnsCategory.Security);

            // Order: Smart Auto -> Pinned Favorites -> Fastest measured latency
            var ordered = items
                .OrderBy(p => p.IsSmartAuto ? 0 : pins.Contains(p.Id, StringComparer.OrdinalIgnoreCase) ? 1 : 2)
                .ThenBy(p => _dnsLatencies.TryGetValue(p.Id, out var ms) && ms.HasValue ? ms.Value : long.MaxValue)
                .ToList();

            foreach (var p in ordered)
            {
                bool isPinned = !p.IsSmartAuto && pins.Contains(p.Id, StringComparer.OrdinalIgnoreCase);
                bool isSelected = p.Id == _selectedPreset.Id;
                bool isActiveNow = _orbState == OrbVisualState.Connected &&
                                   _activeDns.IsStaticConnected &&
                                   !string.IsNullOrEmpty(p.PrimaryIp) &&
                                   string.Equals(p.PrimaryIp, _activeDns.PrimaryIp, StringComparison.OrdinalIgnoreCase);

                var dotColor = (Color)ColorConverter.ConvertFromString(p.BadgeHex);
                var dotBrush = Freeze(new SolidColorBrush(dotColor));

                var cardGrid = new Grid();
                cardGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                cardGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                cardGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var dot = new Ellipse
                {
                    Width = 10,
                    Height = 10,
                    Fill = isActiveNow ? FrozenGreen : dotBrush,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 11, 0)
                };
                Grid.SetColumn(dot, 0);

                var infoStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
                titleRow.Children.Add(new TextBlock
                {
                    Text = p.IsSmartAuto ? L("⚡ Smart Auto", "⚡ انتخاب هوشمند") : p.Name,
                    FontSize = 13.5,
                    FontWeight = FontWeights.Bold,
                    Foreground = (Brush)FindResource("PrimaryTextBrush")
                });
                if (isActiveNow)
                {
                    titleRow.Children.Add(new TextBlock
                    {
                        Text = L("  ✓ Active", "  ✓ فعال"),
                        FontSize = 11,
                        FontWeight = FontWeights.Bold,
                        Foreground = FrozenGreen,
                        VerticalAlignment = VerticalAlignment.Center
                    });
                }

                infoStack.Children.Add(titleRow);
                infoStack.Children.Add(new TextBlock
                {
                    Text = p.IsSmartAuto ? L(p.TaglineEn, p.TaglineFa) : $"{L(p.TaglineEn, p.TaglineFa)}  ·  {p.PrimaryIp}",
                    FontSize = 10.5,
                    Foreground = (Brush)FindResource("MutedTextBrush"),
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Margin = new Thickness(0, 2, 0, 0)
                });
                Grid.SetColumn(infoStack, 1);

                var pillText = new TextBlock
                {
                    FontSize = 10.5,
                    FontWeight = FontWeights.Bold,
                    FontFamily = new FontFamily("Consolas"),
                    VerticalAlignment = VerticalAlignment.Center
                };
                var pillBorder = new Border
                {
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(8, 3, 8, 3),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(6, 0, p.IsSmartAuto ? 0 : 30, 0),
                    Child = pillText
                };

                if (p.IsSmartAuto)
                {
                    pillText.Text = L("AUTO", "هوشمند");
                    pillText.Foreground = (Brush)FindResource("AccentBrush");
                    pillBorder.Background = (Brush)FindResource("AccentSoftBrush");
                }
                else if (_dnsLatencies.TryGetValue(p.Id, out var ms))
                {
                    if (ms.HasValue)
                    {
                        pillText.Text = $"{ms.Value}ms";
                        pillText.Foreground = ms.Value <= 50 ? FrozenGreen : ms.Value <= 120 ? FrozenAmber : FrozenRed;
                        pillBorder.Background = (Brush)FindResource("SurfaceSoftBrush");
                    }
                    else
                    {
                        pillText.Text = L("Slow", "کند");
                        pillText.Foreground = FrozenRed;
                        pillBorder.Background = (Brush)FindResource("SurfaceSoftBrush");
                    }
                }
                else
                {
                    pillText.Text = isSelected ? "●" : "›";
                    pillText.Foreground = isSelected ? (Brush)FindResource("AccentBrush") : (Brush)FindResource("MutedTextBrush");
                }
                Grid.SetColumn(pillBorder, 2);

                cardGrid.Children.Add(dot);
                cardGrid.Children.Add(infoStack);
                cardGrid.Children.Add(pillBorder);

                var mainBtn = new Button
                {
                    Style = (Style)FindResource("CardButtonStyle"),
                    Content = cardGrid,
                    Padding = new Thickness(14, 11, 10, 11),
                    Tag = p
                };

                if (isActiveNow || isSelected)
                    mainBtn.BorderBrush = isActiveNow ? FrozenGreen : (Brush)FindResource("AccentBrush");

                mainBtn.Click += async (s, _) =>
                {
                    if (_isBusy || s is not Button b || b.Tag is not LiteDnsPreset chosen) return;
                    _selectedPreset = chosen;
                    _settings = _settings with { SelectedDnsId = chosen.Id };
                    _service.SaveSettings(_settings);
                    UpdateSelectedDnsHomeCard();
                    NavHome.IsChecked = true;

                    _isBusy = true;
                    try { await RunSafeAsync(() => ConnectPresetAsync(chosen), "ConnectPreset"); }
                    finally { _isBusy = false; }
                };

                // Sibling container so clicking the star NEVER triggers mainBtn.Click
                var rowHost = new Grid { Margin = new Thickness(0, 0, 0, 8) };
                rowHost.Children.Add(mainBtn);

                if (!p.IsSmartAuto)
                {
                    var starBtn = new Button
                    {
                        Style = (Style)FindResource("StarPinBtnStyle"),
                        Content = isPinned ? "★" : "☆",
                        Foreground = isPinned ? FrozenGold : (Brush)FindResource("MutedTextBrush"),
                        HorizontalAlignment = HorizontalAlignment.Right,
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(0, 0, 8, 0),
                        ToolTip = isPinned ? L("Unpin favorite", "برداشتن پین") : L("Pin to top", "پین کردن به بالا"),
                        Tag = p
                    };
                    starBtn.Click += (s, _) =>
                    {
                        if (s is Button sb && sb.Tag is LiteDnsPreset target)
                            TogglePinDns(target);
                    };
                    rowHost.Children.Add(starBtn);
                }

                DnsCardsPanel.Children.Add(rowHost);
            }
        }

        private void UpdateFastestWinnerBanner()
        {
            if (_fastestWinner == null || !_fastestWinnerMs.HasValue)
            {
                FastestResultBanner.Visibility = Visibility.Collapsed;
                return;
            }
            TxtFastestWinnerTitle.Text = L("⚡ FASTEST SERVER FOUND", "⚡ سریع‌ترین سرور پیدا شد");
            TxtFastestWinnerInfo.Text = $"{_fastestWinner.Name}  ·  {_fastestWinnerMs.Value} ms";
            BtnConnectFastestWinner.Content = L("Connect", "اتصال");
            FastestResultBanner.Visibility = Visibility.Visible;
        }

        private async void BtnFindFastest_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            _isBusy = true;
            BtnFindFastest.IsEnabled = false;
            DnsTestProgress.Visibility = Visibility.Visible;

            await RunSafeAsync(async () =>
            {
                var results = await _service.BenchmarkAllPresetsAsync();
                foreach (var kv in results)
                    _dnsLatencies[kv.Key] = kv.Value;

                RebuildDnsCards();

                var fastest = results
                    .Where(kv => kv.Value.HasValue)
                    .OrderBy(kv => kv.Value!.Value)
                    .FirstOrDefault();

                if (!string.IsNullOrEmpty(fastest.Key))
                {
                    _fastestWinner = LiteCatalog.DnsPresets.First(x => x.Id == fastest.Key);
                    _fastestWinnerMs = fastest.Value;
                    UpdateFastestWinnerBanner();
                    ShowToast(L($"Fastest: {_fastestWinner.Name} ({fastest.Value} ms)", $"سریع‌ترین: {_fastestWinner.Name} ({fastest.Value} میلی‌ثانیه)"));
                }
                else
                {
                    _fastestWinner = null;
                    _fastestWinnerMs = null;
                    UpdateFastestWinnerBanner();
                    ShowToast(L("No server responded. Check internet.", "سروری پاسخ نداد. اینترنت را چک کنید."), isError: true);
                }
            }, "DnsBenchmark");

            DnsTestProgress.Visibility = Visibility.Collapsed;
            BtnFindFastest.IsEnabled = true;
            _isBusy = false;
        }

        private async void BtnConnectFastestWinner_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy || _fastestWinner == null) return;
            var winner = _fastestWinner;
            _selectedPreset = winner;
            _settings = _settings with { SelectedDnsId = winner.Id };
            _service.SaveSettings(_settings);
            UpdateSelectedDnsHomeCard();
            NavHome.IsChecked = true;

            _isBusy = true;
            try { await RunSafeAsync(() => ConnectPresetAsync(winner), "ConnectFastest"); }
            finally { _isBusy = false; }
        }

        private async void BtnApplyCustomDns_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            string d1 = TxtCustomDns1.Text.Trim();
            string d2 = TxtCustomDns2.Text.Trim();

            if (!LiteCatalog.IsSafeDnsIpv4(d1))
            {
                ShowToast(L("Enter a valid Primary IPv4 (e.g. 1.1.1.1)", "آدرس DNS اول معتبر نیست (مثلاً 1.1.1.1)"), isError: true);
                return;
            }
            if (!string.IsNullOrEmpty(d2) && !LiteCatalog.IsSafeDnsIpv4(d2))
            {
                ShowToast(L("Secondary IPv4 is invalid.", "آدرس DNS دوم معتبر نیست."), isError: true);
                return;
            }

            _settings = _settings with { CustomDns1 = d1, CustomDns2 = d2 };
            _service.SaveSettings(_settings);

            _isBusy = true;
            NavHome.IsChecked = true;
            SetOrbState(OrbVisualState.Connecting);
            var sw = Stopwatch.StartNew();

            await RunSafeAsync(async () =>
            {
                var res = await _service.ApplyDnsAsync(_selectedAdapter, d1, string.IsNullOrEmpty(d2) ? null : d2, "Custom DNS");
                int remaining = 380 - (int)sw.ElapsedMilliseconds;
                if (remaining > 0) await Task.Delay(remaining);

                if (res.Success)
                {
                    _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                    if (!_activeDns.IsStaticConnected)
                        _activeDns = new ActiveDnsStatus(true, d1, d2, "Custom DNS", "دی‌ان‌اس دستی", null);

                    SetOrbState(OrbVisualState.Connected);
                    UpdateSelectedDnsHomeCard();
                    RebuildDnsCards();
                    ShowToast(L(res.MessageEn, res.MessageFa));
                }
                else
                {
                    _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                    SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                    ShowToast(L(res.MessageEn, res.MessageFa), isError: true);
                }
                await RefreshTelemetryAsync();
            }, "CustomDns");

            _isBusy = false;
        }

        // ==================== BOOST, QUICK FIX & FULL ADAPTER RESET ====================
        private async void ToggleGameMode_Click(object sender, RoutedEventArgs e)
        {
            bool target = ToggleGameMode.IsChecked == true;
            ToggleGameMode.IsEnabled = false;
            await RunSafeAsync(async () =>
            {
                var res = await _service.SetGameModeAsync(target);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "GameMode");
            ToggleGameMode.IsChecked = await Task.Run(() => _service.IsGameModeActive());
            ToggleGameMode.IsEnabled = true;
        }

        private async void ToggleAdShield_Click(object sender, RoutedEventArgs e)
        {
            bool target = ToggleAdShield.IsChecked == true;
            ToggleAdShield.IsEnabled = false;
            ShowToast(target
                ? L("Enabling Ad Shield...", "در حال فعال‌سازی سپر تبلیغات...")
                : L("Disabling Ad Shield...", "در حال خاموش کردن سپر تبلیغات..."));
            await RunSafeAsync(async () =>
            {
                var res = await _service.SetAdShieldAsync(target);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshHostsUiAsync();
            }, "AdShield");
            ToggleAdShield.IsChecked = await Task.Run(() => _service.IsAdShieldActive());
            ToggleAdShield.IsEnabled = true;
        }

        private async void BtnQuickFix_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            BtnQuickFix.IsEnabled = false;
            TxtQuickFixBadge.Text = "...";
            await RunSafeAsync(async () =>
            {
                var res = await _service.QuickNetworkRefreshAsync(_selectedAdapter);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshTelemetryAsync();
            }, "QuickFix");
            TxtQuickFixBadge.Text = L("Run", "اجرا");
            BtnQuickFix.IsEnabled = true;
        }

        private async void BtnFullFix_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (MessageBox.Show(
                    L($"Fully reset network adapter '{_selectedAdapter}'?\n\nYour internet will disconnect for ~5 seconds while the adapter restarts and renews its IP.",
                      $"آیا کارت شبکه «{_selectedAdapter}» به صورت کامل ریست شود؟\n\nاینترنت شما حدود ۵ ثانیه قطع شده و پس از ریست کارت شبکه و تجدید IP مجدداً وصل می‌شود."),
                    "AionToolLite",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;

            _isBusy = true;
            BtnFullFix.IsEnabled = false;
            BtnQuickFix.IsEnabled = false;
            FullFixProgress.Visibility = Visibility.Visible;
            TxtFullFixBadge.Text = "...";
            ShowToast(L("Resetting network adapter...", "در حال ریست کامل کارت شبکه..."));

            await RunSafeAsync(async () =>
            {
                var res = await _service.FullAdapterResetAsync(_selectedAdapter);
                await LoadAdaptersAsync(preserveSelection: true);
                await RefreshTelemetryAsync();
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "FullFix");

            FullFixProgress.Visibility = Visibility.Collapsed;
            TxtFullFixBadge.Text = L("Reset", "ریست");
            BtnFullFix.IsEnabled = true;
            BtnQuickFix.IsEnabled = true;
            _isBusy = false;
        }

        private async void BtnQuickSpeed_Click(object sender, RoutedEventArgs e)
        {
            BtnQuickSpeed.IsEnabled = false;
            SpeedCheckProgress.Visibility = Visibility.Visible;
            TxtSpeedCheckBadge.Text = "...";
            TxtSpeedCheckResult.Text = L("Testing download speed (6s)...", "در حال اندازه‌گیری سرعت دانلود...");

            await RunSafeAsync(async () =>
            {
                var (ok, _, en, fa) = await _service.RunQuickSpeedCheckAsync();
                TxtSpeedCheckResult.Text = L(en, fa);
                ShowToast(L(en, fa), isError: !ok);
            }, "SpeedCheck");

            SpeedCheckProgress.Visibility = Visibility.Collapsed;
            TxtSpeedCheckBadge.Text = L("Start", "شروع");
            BtnQuickSpeed.IsEnabled = true;
        }

        // ==================== UTILITIES: WINDOWS HOSTS & QUICK TOOLS ====================
        private async Task RefreshHostsUiAsync()
        {
            var info = await _service.GetHostsSummaryAsync();
            bool adActive = await Task.Run(() => _service.IsAdShieldActive());
            if (_isClosing) return;

            ToggleAdShield.IsChecked = adActive;
            TxtHostsRuleCount.Text = L($"{info.TotalRules:N0} rules", $"{info.TotalRules:N0} قانون");
            TxtHostsInstalledLists.Text = info.InstalledListNames.Count > 0
                ? string.Join(" · ", info.InstalledListNames)
                : L("Clean default Windows hosts", "فایل hosts پیش‌فرض و تمیز");
        }

        private async void BtnHostsApplyList_Click(object sender, RoutedEventArgs e)
        {
            if (ComboHostsBlocklist.SelectedItem is not LiteBlocklistItem item) return;
            BtnHostsApplyList.IsEnabled = false;
            BtnHostsRemoveList.IsEnabled = false;
            HostsProgress.Visibility = Visibility.Visible;
            ShowToast(L($"Applying {item.Name}...", $"در حال اعمال {item.Name}..."));

            await RunSafeAsync(async () =>
            {
                var res = await _service.ApplyBlocklistAsync(item);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshHostsUiAsync();
            }, "ApplyBlocklist");

            HostsProgress.Visibility = Visibility.Collapsed;
            BtnHostsApplyList.IsEnabled = true;
            BtnHostsRemoveList.IsEnabled = true;
        }

        private async void BtnHostsRemoveList_Click(object sender, RoutedEventArgs e)
        {
            if (ComboHostsBlocklist.SelectedItem is not LiteBlocklistItem item) return;
            BtnHostsApplyList.IsEnabled = false;
            BtnHostsRemoveList.IsEnabled = false;

            await RunSafeAsync(async () =>
            {
                var res = await _service.RemoveBlocklistByTagAsync(item.Tag, item.Name);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshHostsUiAsync();
            }, "RemoveBlocklist");

            BtnHostsApplyList.IsEnabled = true;
            BtnHostsRemoveList.IsEnabled = true;
        }

        private async void BtnHostsBackup_Click(object sender, RoutedEventArgs e)
        {
            await RunSafeAsync(async () =>
            {
                var res = await _service.BackupHostsAsync();
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "BackupHosts");
        }

        private async void BtnHostsRestore_Click(object sender, RoutedEventArgs e)
        {
            await RunSafeAsync(async () =>
            {
                var res = await _service.RestoreHostsAsync();
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshHostsUiAsync();
            }, "RestoreHosts");
        }

        private void BtnHostsNotepad_Click(object sender, RoutedEventArgs e)
        {
            try { _service.OpenHostsInNotepad(); }
            catch (Exception ex) { ShowToast(ex.Message, isError: true); }
        }

        private async void BtnHostsReset_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(
                    L("Reset Windows hosts file to factory default? A backup will be saved first.",
                      "فایل hosts ویندوز به حالت پیش‌فرض برگردد؟ قبل از ریست، یک پشتیبان ذخیره می‌شود."),
                    "AionToolLite",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;

            await RunSafeAsync(async () =>
            {
                var res = await _service.ResetHostsToDefaultAsync();
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
                await RefreshHostsUiAsync();
            }, "ResetHosts");
        }

        private async void BtnPublicIpCheck_Click(object sender, RoutedEventArgs e)
        {
            BtnPublicIpCheck.IsEnabled = false;
            TxtPublicIpLabel.Text = L("🌍  Checking Public IP...", "🌍  در حال دریافت آی‌پی عمومی...");

            await RunSafeAsync(async () =>
            {
                var (ok, ip, en, fa) = await _service.GetPublicIpAsync();
                if (ok)
                {
                    _lastPublicIp = ip;
                    TxtPublicIpLabel.Text = $"🌍  {L(en, fa)}";
                    try { Clipboard.SetText(ip); } catch { }
                    ShowToast(L($"Public IP copied: {ip}", $"آی‌پی عمومی کپی شد: {ip}"));
                }
                else
                {
                    TxtPublicIpLabel.Text = L("🌍  Check My Public IP", "🌍  بررسی آی‌پی اینترنت من");
                    ShowToast(L(en, fa), isError: true);
                }
            }, "PublicIp");

            BtnPublicIpCheck.IsEnabled = true;
        }

        private async void BtnCleanTemp_Click(object sender, RoutedEventArgs e)
        {
            BtnCleanTemp.IsEnabled = false;
            await RunSafeAsync(async () =>
            {
                var res = await _service.CleanOldTempFilesAsync();
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "CleanTemp");
            BtnCleanTemp.IsEnabled = true;
        }

        // ==================== SETTINGS, STARTUP, TRAY & THEMES ====================
        private async void ToggleAutoStart_Click(object sender, RoutedEventArgs e)
        {
            bool target = ToggleAutoStart.IsChecked == true;
            ToggleAutoStart.IsEnabled = false;
            await RunSafeAsync(async () =>
            {
                var res = await _service.SetAutoStartAsync(target);
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "AutoStart");
            bool active = await _service.IsAutoStartEnabledAsync();
            if (!_isClosing)
            {
                ToggleAutoStart.IsChecked = active;
                ToggleAutoStart.IsEnabled = true;
            }
        }

        private void ToggleMinToTray_Click(object sender, RoutedEventArgs e)
        {
            bool enabled = ToggleMinToTray.IsChecked == true;
            _settings = _settings with { MinimizeToTray = enabled };
            _service.SaveSettings(_settings);
            ShowToast(enabled
                ? L("Close button will minimize to System Tray.", "دکمه بستن، برنامه را کنار ساعت مخفی می‌کند.")
                : L("Close button will exit the app completely.", "دکمه بستن، برنامه را کاملاً می‌بندد."));
        }

        private void BuildThemeDots()
        {
            ThemeDotsPanel.Children.Clear();
            foreach (var theme in LiteCatalog.Themes)
            {
                bool active = theme.Id == _currentTheme.Id;
                var c1 = (Color)ColorConverter.ConvertFromString(theme.AccentHex);
                var c2 = (Color)ColorConverter.ConvertFromString(theme.SecondaryHex);
                var grad = new LinearGradientBrush(c1, c2, new Point(0, 0), new Point(1, 1));
                grad.Freeze();

                var dot = new Border
                {
                    Width = 34,
                    Height = 34,
                    CornerRadius = new CornerRadius(17),
                    Background = grad,
                    BorderBrush = active ? Brushes.White : Brushes.Transparent,
                    BorderThickness = new Thickness(active ? 2.5 : 0),
                    Cursor = Cursors.Hand,
                    Margin = new Thickness(0, 0, 10, 0),
                    ToolTip = L(theme.NameEn, theme.NameFa),
                    Tag = theme
                };

                if (theme.IsLight)
                {
                    dot.Background = Brushes.WhiteSmoke;
                    dot.BorderBrush = active ? FrozenGreen : (Brush)FindResource("BorderBrushSoft");
                    dot.BorderThickness = new Thickness(2);
                }

                dot.MouseLeftButtonDown += (s, _) =>
                {
                    if (s is Border b && b.Tag is LiteTheme chosen)
                    {
                        _currentTheme = chosen;
                        _settings = _settings with { ThemeId = chosen.Id };
                        _service.SaveSettings(_settings);
                        LiteThemeManager.Apply(chosen);
                        BuildThemeDots();
                        TxtActiveThemeName.Text = L(chosen.NameEn, chosen.NameFa);
                        if (_orbState == OrbVisualState.Idle) SetOrbState(OrbVisualState.Idle);
                        RenderPingCard();
                        RebuildDnsCards();
                    }
                };

                ThemeDotsPanel.Children.Add(dot);
            }
            TxtActiveThemeName.Text = L(_currentTheme.NameEn, _currentTheme.NameFa);
        }

        private void BtnQuickLang_Click(object sender, RoutedEventArgs e) => SetLanguage(IsFa ? "en" : "fa");
        private void BtnLangEn_Click(object sender, RoutedEventArgs e) => SetLanguage("en");
        private void BtnLangFa_Click(object sender, RoutedEventArgs e) => SetLanguage("fa");

        private void SetLanguage(string lang)
        {
            _settings = _settings with { Language = lang };
            _service.SaveSettings(_settings);
            ApplyLanguage();
            RebuildDnsCards();
            UpdateFastestWinnerBanner();
            UpdateSelectedDnsHomeCard();
            RenderPingCard();
            SetOrbState(_orbState);
            BuildThemeDots();
            RefreshTrayState();
            _ = RefreshHostsUiAsync();
        }

        private void ApplyLanguage()
        {
            bool fa = IsFa;
            BtnQuickLang.Content = fa ? "EN" : "FA";

            LblNavHome.Text = L("Home", "خانه");
            LblNavDns.Text = L("DNS", "سرورها");
            LblNavBoost.Text = L("Boost", "تقویت");
            LblNavUtilities.Text = L("Tools", "ابزارها");
            LblNavSettings.Text = L("Settings", "تنظیمات");

            LblHomeTrafficTitle.Text = L("LIVE TRAFFIC", "مصرف لحظه‌ای");

            LblDnsTitle.Text = L("Choose a Server", "انتخاب سرور دی‌ان‌اس");
            LblDnsSubtitle.Text = L("Tap to connect · ★ to pin favorite", "برای اتصال بزنید · ★ برای پین کردن");
            BtnFindFastest.Content = L("⚡ Test Speed", "⚡ تست سرعت");
            ChipAll.Content = L("All", "همه");
            ChipIran.Content = L("Iran / Game", "ایران و گیم");
            ChipGlobal.Content = L("Global", "جهانی");
            ChipSecurity.Content = L("Ad & Safe", "امن و ضدتبلیغ");
            LblCustomDnsHeader.Text = L("Custom DNS (Optional)", "دی‌ان‌اس دستی (اختیاری)");
            BtnApplyCustomDns.Content = L("Apply Custom DNS", "اعمال دی‌ان‌اس دستی");

            LblBoostTitle.Text = L("Boost & Repair", "تقویت و تعمیر");
            LblBoostSubtitle.Text = L("Simple one-tap tools — safe and reversible", "ابزارهای تک‌کلیکی، کاملاً ایمن و قابل بازگشت");
            LblGameModeTitle.Text = L("Game Mode", "حالت بازی (Game Mode)");
            LblGameModeDesc.Text = L("Pauses background Windows clutter while gaming", "سرویس‌های مزاحم پس‌زمینه را حین بازی متوقف می‌کند");
            LblAdShieldTitle.Text = L("Ad & Tracker Shield", "سپر تبلیغات و ردیاب");
            LblAdShieldDesc.Text = L("Blocks ads & trackers across all apps", "مسدودسازی سرورهای تبلیغاتی در کل ویندوز");
            LblQuickFixTitle.Text = L("Quick Network Fix", "تازه‌سازی سریع شبکه");
            LblQuickFixDesc.Text = L("Clears DNS cache & refreshes connection", "پاکسازی کش دی‌ان‌اس و رفع گیر کردن اینترنت");
            TxtQuickFixBadge.Text = L("Run", "اجرا");
            LblFullFixTitle.Text = L("Full Network Fix", "تعمیر کامل کارت شبکه");
            LblFullFixDesc.Text = L("Full adapter reset, IP renew & TCP/IP repair", "ریست کامل کارت شبکه، تجدید IP و تعمیر TCP/IP");
            if (TxtFullFixBadge.Text != "...")
                TxtFullFixBadge.Text = L("Reset", "ریست");
            LblSpeedCheckTitle.Text = L("Speed Check", "تست سرعت اینترنت");
            if (TxtSpeedCheckBadge.Text != "...")
                TxtSpeedCheckBadge.Text = L("Start", "شروع");

            LblUtilTitle.Text = L("Utilities & Hosts", "ابزارها و فایل هاست");
            LblUtilSubtitle.Text = L("Windows hosts, blocklists & handy tools", "مدیریت hosts ویندوز، لیست‌های مسدودساز و ابزارها");
            LblHostsCardTitle.Text = L("Windows Hosts Manager", "مدیریت فایل Hosts ویندوز");
            BtnHostsApplyList.Content = L("➕ Apply List", "➕ اعمال لیست");
            BtnHostsRemoveList.Content = L("➖ Remove", "➖ حذف لیست");
            BtnHostsBackup.Content = L("💾 Backup", "💾 پشتیبان");
            BtnHostsRestore.Content = L("↺ Restore", "↺ بازگردانی");
            BtnHostsNotepad.Content = L("📝 Notepad", "📝 نوت‌پد");
            BtnHostsReset.Content = L("🧹 Default", "🧹 پیش‌فرض");
            LblExtraToolsTitle.Text = L("Quick System Tools", "ابزارهای سریع سیستم");
            if (string.IsNullOrEmpty(_lastPublicIp))
                TxtPublicIpLabel.Text = L("🌍  Check My Public IP", "🌍  بررسی آی‌پی اینترنت من");
            TxtCleanTempLabel.Text = L("🧹  Clean Old Temp Files (>24h)", "🧹  پاکسازی فایل‌های موقت قدیمی");

            LblSettingsTitle.Text = L("Settings", "تنظیمات");
            LblSettingsSubtitle.Text = L("Customize look, behavior & updates", "شخصی‌سازی ظاهر، رفتار و بروزرسانی");
            LblThemeSection.Text = L("Appearance Theme", "پوسته و رنگ برنامه");
            LblLangSection.Text = L("Language / زبان", "زبان برنامه / Language");
            LblBehaviorSection.Text = L("Startup & System Tray", "شروع خودکار و نوار ساعت");
            LblAutoStartTitle.Text = L("Start with Windows", "شروع خودکار با ویندوز");
            LblAutoStartDesc.Text = L("Launch quietly in Tray on logon", "اجرای بی‌صدا در کنار ساعت هنگام بالا آمدن ویندوز");
            LblMinToTrayTitle.Text = L("Minimize to Tray on Close", "مخفی شدن کنار ساعت با دکمه بستن");
            LblMinToTrayDesc.Text = L("Keep quick controls in taskbar corner", "دسترسی سریع به تغییر DNS از کنار ساعت");
            LblAdapterSection.Text = L("Network Adapter", "کارت شبکه فعال");
            BtnCheckUpdates.Content = L("🔄 Check for Updates", "🔄 بررسی بروزرسانی");
            BtnResetAll.Content = L("↺ Restore Original DNS & Defaults", "↺ بازگردانی DNS قبلی و پیش‌فرض‌ها");

            BtnLangEn.BorderBrush = !fa ? (Brush)FindResource("AccentBrush") : (Brush)FindResource("BorderBrushSoft");
            BtnLangFa.BorderBrush = fa ? (Brush)FindResource("AccentBrush") : (Brush)FindResource("BorderBrushSoft");
        }

        private async Task LoadAdaptersAsync(bool preserveSelection)
        {
            string prev = preserveSelection ? _selectedAdapter : (_settings.PreferredAdapter ?? _selectedAdapter);
            var list = await _service.ScanAdaptersAsync();
            if (_isClosing) return;

            ComboAdapters.ItemsSource = list;
            if (list.Count == 0)
            {
                _selectedAdapter = string.Empty;
                return;
            }

            var match = (!string.IsNullOrWhiteSpace(prev)
                            ? list.FirstOrDefault(a => a.Name.Equals(prev, StringComparison.OrdinalIgnoreCase))
                            : null)
                        ?? list.FirstOrDefault(a => a.Health == AdapterHealth.Connected && a.HasGateway)
                        ?? list.FirstOrDefault(a => a.Health == AdapterHealth.Connected)
                        ?? list[0];

            ComboAdapters.SelectedItem = match;
            _selectedAdapter = match.Name;
        }

        private async void ComboAdapters_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ComboAdapters.SelectedItem is not LiteAdapterItem item) return;
            _selectedAdapter = item.Name;
            _lastTrafficTick = DateTime.MinValue;
            if (_isReady)
            {
                _settings = _settings with { PreferredAdapter = item.Name };
                _service.SaveSettings(_settings);
                await RunSafeAsync(async () =>
                {
                    await SyncActiveDnsFromSystemAsync();
                    await RefreshTelemetryAsync();
                }, "SwitchAdapter");
            }
        }

        private async void BtnRefreshAdapters_Click(object sender, RoutedEventArgs e)
        {
            await RunSafeAsync(async () =>
            {
                await LoadAdaptersAsync(preserveSelection: true);
                await SyncActiveDnsFromSystemAsync();
                ShowToast(L("Adapters refreshed.", "لیست کارت‌های شبکه بروز شد."));
            }, "RefreshAdapters");
        }

        private async void BtnCheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            BtnCheckUpdates.IsEnabled = false;
            BtnCheckUpdates.Content = L("Checking GitHub...", "در حال بررسی گیت‌هاب...");
            await RunSafeAsync(async () =>
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                var res = await _service.CheckAndInstallUpdateAsync("Yoqaizo", "AionToolLite", cts.Token);
                if (res.Success && res.MessageEn == "READY_TO_UPDATE")
                {
                    ExitApplicationCompletely();
                    return;
                }
                ShowToast(L(res.MessageEn, res.MessageFa), isError: !res.Success);
            }, "CheckUpdates");

            if (!_isClosing)
            {
                BtnCheckUpdates.IsEnabled = true;
                BtnCheckUpdates.Content = L("🔄 Check for Updates", "🔄 بررسی بروزرسانی");
            }
        }

        private async void BtnResetAll_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            var origBackup = _service.GetOriginalDnsBackup(_selectedAdapter);
            string dnsNoteEn = origBackup != null && !origBackup.WasDhcp
                ? $"Restore your original DNS ({origBackup.PrimaryIp})"
                : "Reset DNS to Automatic";
            string dnsNoteFa = origBackup != null && !origBackup.WasDhcp
                ? $"بازیابی دی‌ان‌اس قبلی شما ({origBackup.PrimaryIp})"
                : "بازگرداندن دی‌ان‌اس به حالت خودکار";

            if (MessageBox.Show(
                    L($"{dnsNoteEn}, turn OFF Ad Shield and restore Game Mode services?",
                      $"{dnsNoteFa}، خاموش کردن سپر تبلیغات و بازیابی سرویس‌های حالت گیم؟"),
                    "AionToolLite",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;

            _isBusy = true;
            BtnResetAll.IsEnabled = false;
            await RunSafeAsync(async () =>
            {
                var dnsRes = await _service.RestoreOriginalDnsAsync(_selectedAdapter);
                if (_service.IsAdShieldActive()) await _service.SetAdShieldAsync(false);
                if (_service.IsGameModeActive()) await _service.SetGameModeAsync(false);

                ToggleAdShield.IsChecked = false;
                ToggleGameMode.IsChecked = false;
                _activeDns = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
                SetOrbState(_activeDns.IsStaticConnected ? OrbVisualState.Connected : OrbVisualState.Idle);
                UpdateSelectedDnsHomeCard();
                RebuildDnsCards();
                await RefreshHostsUiAsync();
                ShowToast(L(dnsRes.MessageEn, dnsRes.MessageFa), isError: !dnsRes.Success);
                await RefreshTelemetryAsync();
            }, "ResetAll");

            BtnResetAll.IsEnabled = true;
            _isBusy = false;
        }

        // ==================== LIVE TELEMETRY & AUTOMATIC SYSTEM DNS SYNC ====================
        private async Task SyncActiveDnsFromSystemAsync()
        {
            if (_isBusy || _isClosing) return;
            var detected = await _service.DetectActiveStaticDnsAsync(_selectedAdapter);
            ApplyDetectedDnsState(detected);
        }

        private void ApplyDetectedDnsState(ActiveDnsStatus detected)
        {
            if (_isBusy || _isClosing) return;

            bool changed = detected.IsStaticConnected != _activeDns.IsStaticConnected
                        || !string.Equals(detected.PrimaryIp, _activeDns.PrimaryIp, StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(detected.SecondaryIp, _activeDns.SecondaryIp, StringComparison.OrdinalIgnoreCase);

            if (!changed) return;

            _activeDns = detected;
            if (detected.IsStaticConnected)
            {
                SetOrbState(OrbVisualState.Connected);
            }
            else if (_orbState == OrbVisualState.Connected)
            {
                SetOrbState(OrbVisualState.Idle);
            }

            UpdateSelectedDnsHomeCard();
            RebuildDnsCards();
            RefreshTrayState();
        }

        private async Task RefreshTelemetryAsync()
        {
            if (_isTelemetryTickRunning || _isClosing || !IsVisible || WindowState == WindowState.Minimized)
                return;

            _isTelemetryTickRunning = true;
            try
            {
                var snap = await _service.CaptureTelemetryAsync(_selectedAdapter);
                if (_isClosing) return;

                _lastTelemetry = snap;

                NetStatusDot.Fill = snap.HasInternet ? FrozenGreen : FrozenRed;
                TxtHeaderNetState.Text = snap.HasInternet ? L("Online", "آنلاین") : L("Offline", "آفلاین");

                RenderPingCard();

                if (snap.AdapterFound)
                {
                    if (_lastTrafficTick != DateTime.MinValue)
                    {
                        double secs = (DateTime.Now - _lastTrafficTick).TotalSeconds;
                        if (secs > 0.1)
                        {
                            double dl = Math.Max(0, snap.BytesReceived - _lastRx) / secs;
                            double ul = Math.Max(0, snap.BytesSent - _lastTx) / secs;
                            TxtHomeDlSpeed.Text = $"⬇ {FormatRate(dl)}";
                            TxtHomeUlSpeed.Text = $"⬆ {FormatRate(ul)}";
                        }
                    }
                    _lastRx = snap.BytesReceived;
                    _lastTx = snap.BytesSent;
                    _lastTrafficTick = DateTime.Now;
                }

                ApplyDetectedDnsState(snap.ActiveDns);
            }
            catch { }
            finally
            {
                _isTelemetryTickRunning = false;
            }
        }

        private static string FormatRate(double bytesPerSec)
        {
            if (bytesPerSec <= 0) return "0 KB/s";
            if (bytesPerSec >= 1048576) return $"{bytesPerSec / 1048576.0:F1} MB/s";
            return $"{bytesPerSec / 1024.0:F0} KB/s";
        }
    }
}
