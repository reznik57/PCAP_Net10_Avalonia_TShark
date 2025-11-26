using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts boolean to opacity value for filtered stat display.
/// True (filter active) = 0.5 opacity (dimmed)
/// False (no filter) = 1.0 opacity (full brightness)
/// </summary>
public class BoolToOpacityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isFiltered)
        {
            return isFiltered ? 0.5 : 1.0;
        }
        return 1.0; // Default to full opacity
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
