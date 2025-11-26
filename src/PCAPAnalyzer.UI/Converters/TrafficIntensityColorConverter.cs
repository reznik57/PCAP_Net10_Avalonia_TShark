using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Converters
{
    public class TrafficIntensityColorConverter : IValueConverter
    {
        // Define consistent 5-group color system for traffic intensity
        // <0.1% = Gray (#6B7280)
        // <1% = Blue (#3B82F6)
        // <5% = Green (#10B981)
        // <10% = Yellow/Orange (#F59E0B)
        // >=10% = Red (#EF4444)
        
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is not double percentage)
                return new SolidColorBrush(Color.FromRgb(107, 114, 128)); // Default gray
            
            // Create color based on 5-group system
            Color color = percentage switch
            {
                < 0.1 => Color.FromRgb(107, 114, 128),  // Gray for <0.1%
                < 1 => Color.FromRgb(59, 130, 246),     // Blue for <1%
                < 5 => Color.FromRgb(16, 185, 129),     // Green for <5%
                < 10 => Color.FromRgb(245, 158, 11),    // Orange for <10%
                _ => Color.FromRgb(239, 68, 68)         // Red for >=10%
            };
            
            return new SolidColorBrush(color);
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
            
            // Create gradient based on 5-group system
            Color baseColor = percentage switch
            {
                < 0.1 => Color.FromRgb(107, 114, 128),  // Gray
                < 1 => Color.FromRgb(59, 130, 246),     // Blue
                < 5 => Color.FromRgb(16, 185, 129),     // Green
                < 10 => Color.FromRgb(245, 158, 11),    // Orange
                _ => Color.FromRgb(239, 68, 68)         // Red
            };
            
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