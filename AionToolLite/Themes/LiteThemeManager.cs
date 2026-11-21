using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using AionToolLite.Models;

namespace AionToolLite.Themes
{
    public static class LiteThemeManager
    {
        public static void Apply(LiteTheme theme)
        {
            var res = Application.Current.Resources;

            Color bgTop = Parse(theme.BgTopHex);
            Color bgBottom = Parse(theme.BgBottomHex);
            Color card = Parse(theme.CardHex);
            Color cardHover = Parse(theme.CardHoverHex);
            Color soft = Parse(theme.SurfaceSoftHex);
            Color border = Parse(theme.BorderHex);
            Color accent = Parse(theme.AccentHex);
            Color secondary = Parse(theme.SecondaryHex);
            Color primaryText = Parse(theme.IsLight ? "#0F172A" : "#F8FAFC");
            Color mutedText = Parse(theme.IsLight ? "#64748B" : "#94A3B8");

            AnimateBrush(res, "BgTopBrush", bgTop);
            AnimateBrush(res, "BgBottomBrush", bgBottom);
            AnimateBrush(res, "CardBrush", card);
            AnimateBrush(res, "CardHoverBrush", cardHover);
            AnimateBrush(res, "SurfaceSoftBrush", soft);
            AnimateBrush(res, "BorderBrushSoft", border);
            AnimateBrush(res, "AccentBrush", accent);
            AnimateBrush(res, "SecondaryAccentBrush", secondary);
            AnimateBrush(res, "PrimaryTextBrush", primaryText);
            AnimateBrush(res, "MutedTextBrush", mutedText);

            var softAccent = Color.FromArgb(theme.IsLight ? (byte)32 : (byte)42, accent.R, accent.G, accent.B);
            AnimateBrush(res, "AccentSoftBrush", softAccent);

            var grad = new LinearGradientBrush(accent, secondary, new Point(0, 0), new Point(1, 1));
            grad.Freeze();
            res["AccentGradientBrush"] = grad;

            var shellGrad = new LinearGradientBrush(bgTop, bgBottom, new Point(0, 0), new Point(0, 1));
            shellGrad.Freeze();
            res["ShellBackgroundBrush"] = shellGrad;
        }

        private static Color Parse(string hex) => (Color)ColorConverter.ConvertFromString(hex);

        private static void AnimateBrush(ResourceDictionary res, string key, Color target)
        {
            if (res[key] is SolidColorBrush existing && !existing.IsFrozen)
            {
                var anim = new ColorAnimation(target, TimeSpan.FromMilliseconds(240))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                existing.BeginAnimation(SolidColorBrush.ColorProperty, anim);
            }
            else
            {
                res[key] = new SolidColorBrush(target);
            }
        }
    }
}
