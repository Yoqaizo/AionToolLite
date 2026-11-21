using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using AionToolLite.Models;

namespace AionToolLite.Services
{
    public sealed class TrayManager : IDisposable
    {
        private readonly NotifyIcon _notifyIcon;
        private readonly ContextMenuStrip _menu;
        private readonly Icon? _appIcon;
        private readonly Font _boldFont;
        private bool _disposed;

        public event Action? ShowRequested;
        public event Action? ToggleConnectRequested;
        public event Action<LiteDnsPreset>? QuickSwitchDnsRequested;
        public event Action? ExitRequested;

        public TrayManager()
        {
            _appIcon = LoadEmbeddedIcon();
            _menu = new ContextMenuStrip
            {
                ShowImageMargin = false,
                RenderMode = ToolStripRenderMode.Professional,
                Renderer = new DarkMenuRenderer(),
                BackColor = Color.FromArgb(22, 28, 46),
                ForeColor = Color.FromArgb(248, 250, 252)
            };
            _boldFont = new Font(_menu.Font, FontStyle.Bold);

            _notifyIcon = new NotifyIcon
            {
                Icon = _appIcon ?? SystemIcons.Shield,
                Text = "AionToolLite",
                ContextMenuStrip = _menu,
                Visible = true
            };

            _notifyIcon.MouseClick += (_, e) =>
            {
                if (e.Button == MouseButtons.Left)
                    ShowRequested?.Invoke();
            };
            _notifyIcon.DoubleClick += (_, _) => ShowRequested?.Invoke();
        }

        private static Icon? LoadEmbeddedIcon()
        {
            try
            {
                var uri = new Uri("pack://application:,,,/AionToolp.ico", UriKind.Absolute);
                var info = System.Windows.Application.GetResourceStream(uri);
                if (info?.Stream != null)
                {
                    using var stream = info.Stream;
                    return new Icon(stream);
                }
            }
            catch { }
            return null;
        }

        private void ClearMenuItemsSafely()
        {
            while (_menu.Items.Count > 0)
            {
                var item = _menu.Items[0];
                _menu.Items.RemoveAt(0);
                item.Dispose();
            }
        }

        public void UpdateState(
            bool isFa,
            bool isConnected,
            string activeLabel,
            string activeIp,
            IReadOnlyList<LiteDnsPreset> quickPresets)
        {
            if (_disposed) return;

            string tooltip = isConnected
                ? $"AionToolLite — {(isFa ? "متصل" : "Connected")}: {activeLabel}"
                : $"AionToolLite — {(isFa ? "آماده اتصال" : "Ready")}";
            _notifyIcon.Text = tooltip.Length > 63 ? tooltip[..63] : tooltip;

            ClearMenuItemsSafely();

            string statusText = isConnected
                ? $"● {(isFa ? "متصل به" : "Connected:")} {activeLabel} ({activeIp})"
                : $"○ {(isFa ? "قطع (DNS خودکار)" : "Disconnected (Auto DNS)")}";

            var headerItem = new ToolStripMenuItem(statusText)
            {
                Enabled = false,
                ForeColor = isConnected ? Color.FromArgb(16, 185, 129) : Color.FromArgb(148, 163, 184)
            };
            _menu.Items.Add(headerItem);
            _menu.Items.Add(new ToolStripSeparator());

            var toggleItem = new ToolStripMenuItem(isConnected
                ? (isFa ? "⏹  قطع اتصال و پاکسازی کش" : "⏹  Disconnect & Flush Cache")
                : (isFa ? "⚡  اتصال سریع" : "⚡  Quick Connect"));
            toggleItem.Click += (_, _) => ToggleConnectRequested?.Invoke();
            _menu.Items.Add(toggleItem);

            var switchMenu = new ToolStripMenuItem(isFa ? "🌐  تغییر سریع سرور DNS" : "🌐  Switch DNS Server");
            foreach (var preset in quickPresets)
            {
                string label = preset.IsSmartAuto
                    ? (isFa ? "⚡ انتخاب هوشمند" : "⚡ Smart Auto")
                    : $"{preset.Name} ({preset.PrimaryIp})";
                var sub = new ToolStripMenuItem(label);
                var captured = preset;
                sub.Click += (_, _) => QuickSwitchDnsRequested?.Invoke(captured);
                switchMenu.DropDownItems.Add(sub);
            }
            _menu.Items.Add(switchMenu);

            _menu.Items.Add(new ToolStripSeparator());

            var openItem = new ToolStripMenuItem(isFa ? "📱  باز کردن AionToolLite" : "📱  Open AionToolLite")
            {
                Font = _boldFont
            };
            openItem.Click += (_, _) => ShowRequested?.Invoke();
            _menu.Items.Add(openItem);

            var exitItem = new ToolStripMenuItem(isFa ? "✕  خروج کامل" : "✕  Exit");
            exitItem.Click += (_, _) => ExitRequested?.Invoke();
            _menu.Items.Add(exitItem);
        }

        public void ShowBalloon(string title, string message)
        {
            if (_disposed) return;
            try
            {
                _notifyIcon.ShowBalloonTip(2200, title, message, ToolTipIcon.Info);
            }
            catch { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                ClearMenuItemsSafely();
                _menu.Dispose();
                _boldFont.Dispose();
                _appIcon?.Dispose();
            }
            catch { }
        }

        private sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
        {
            public DarkMenuRenderer() : base(new DarkColorTable()) { }

            protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
            {
                if (!e.Item.Enabled)
                    e.TextColor = Color.FromArgb(148, 163, 184);
                else
                    e.TextColor = Color.FromArgb(248, 250, 252);
                base.OnRenderItemText(e);
            }
        }

        private sealed class DarkColorTable : ProfessionalColorTable
        {
            private static readonly Color Bg = Color.FromArgb(22, 28, 46);
            private static readonly Color Hover = Color.FromArgb(38, 49, 77);
            private static readonly Color Border = Color.FromArgb(51, 65, 102);

            public override Color ToolStripDropDownBackground => Bg;
            public override Color MenuBorder => Border;
            public override Color MenuItemBorder => Hover;
            public override Color MenuItemSelected => Hover;
            public override Color MenuItemSelectedGradientBegin => Hover;
            public override Color MenuItemSelectedGradientEnd => Hover;
            public override Color ImageMarginGradientBegin => Bg;
            public override Color ImageMarginGradientMiddle => Bg;
            public override Color ImageMarginGradientEnd => Bg;
            public override Color SeparatorDark => Border;
            public override Color SeparatorLight => Border;
        }
    }
}
