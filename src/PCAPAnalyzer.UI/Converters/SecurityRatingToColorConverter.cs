using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Converters;

public class SecurityRatingToColorConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string rating)
        {
            return ThemeColorHelper.GetSecurityRatingBrush(rating);
        }

        return ThemeColorHelper.GetSecurityRatingBrush("unknown");
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}