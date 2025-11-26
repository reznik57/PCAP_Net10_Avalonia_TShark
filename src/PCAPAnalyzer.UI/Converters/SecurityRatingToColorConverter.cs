using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Converters;

public class SecurityRatingToColorConverter : IValueConverter
{
    private static readonly IBrush SecureBrush = new SolidColorBrush(Color.Parse("#4CAF50")); // Green
    private static readonly IBrush LowBrush = new SolidColorBrush(Color.Parse("#8BC34A"));     // Light Green  
    private static readonly IBrush MediumBrush = new SolidColorBrush(Color.Parse("#FFA726")); // Orange
    private static readonly IBrush HighBrush = new SolidColorBrush(Color.Parse("#EF5350"));   // Red
    private static readonly IBrush CriticalBrush = new SolidColorBrush(Color.Parse("#B71C1C")); // Dark Red
    private static readonly IBrush UnknownBrush = new SolidColorBrush(Color.Parse("#9E9E9E")); // Gray

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string rating)
        {
            return rating.ToUpperInvariant() switch
            {
                "SECURE" => SecureBrush,
                "LOW" => LowBrush,
                "MEDIUM" => MediumBrush,
                "HIGH" => HighBrush,
                "CRITICAL" => CriticalBrush,
                _ => UnknownBrush
            };
        }

        return UnknownBrush;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}