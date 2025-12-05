using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Converters
{
    public class TrafficIntensityColorConverter : IValueConverter
    {
        // Traffic intensity uses 5-group color system from theme:
        // <0.1% = TrafficNone (Gray)
        // <1% = TrafficLow (Blue)
        // <5% = TrafficMedium (Green)
        // <10% = TrafficHigh (Orange)
        // >=10% = TrafficCritical (Red)

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is not double percentage)
                return ThemeColorHelper.GetTrafficIntensityBrush(0);

            return ThemeColorHelper.GetTrafficIntensityBrush(percentage);
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class TrafficIntensityGradientConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is not double percentage)
                return new LinearGradientBrush();

            // For 0% or very small values, return transparent to hide the bar
            if (percentage < 0.01)
            {
                return new SolidColorBrush(Colors.Transparent);
            }

            // Get base color from theme
            Color baseColor = ThemeColorHelper.GetTrafficIntensityColor(percentage);

            // Create a subtle gradient from the base color
            var startColor = baseColor;
            var endColor = Color.FromArgb(
                baseColor.A,
                (byte)Math.Min(255, baseColor.R + 30),
                (byte)Math.Min(255, baseColor.G + 30),
                (byte)Math.Min(255, baseColor.B + 30)
            );

            return new LinearGradientBrush
            {
                StartPoint = new Avalonia.RelativePoint(0, 0, Avalonia.RelativeUnit.Relative),
                EndPoint = new Avalonia.RelativePoint(1, 0, Avalonia.RelativeUnit.Relative),
                GradientStops = new GradientStops
                {
                    new GradientStop(startColor, 0),
                    new GradientStop(endColor, 1)
                }
            };
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}