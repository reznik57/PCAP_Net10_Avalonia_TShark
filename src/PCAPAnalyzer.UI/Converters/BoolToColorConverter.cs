using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Converters;

public class BoolToColorConverter : IValueConverter
{
    public static readonly BoolToColorConverter Instance = new();

    /// <summary>
    /// Converter for countdown background: red when active, default dark when not
    /// </summary>
    public static readonly IValueConverter CountdownBackground = new FuncValueConverter<bool, IBrush>(
        isActive => isActive
            ? new SolidColorBrush(Color.FromArgb(0xE0, 0xB9, 0x1C, 0x1C)) // Dark red background (#B91C1C with transparency)
            : new SolidColorBrush(Color.Parse("#0D1117")));

    /// <summary>
    /// Converter for countdown border: bright red when active, blue when not
    /// </summary>
    public static readonly IValueConverter CountdownBorder = new FuncValueConverter<bool, IBrush>(
        isActive => isActive
            ? new SolidColorBrush(Color.Parse("#DC2626")) // Bright red border
            : new SolidColorBrush(Color.Parse("#58A6FF"))); // Blue border

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isActive)
        {
            return isActive ? "#EF4444" : "#10B981"; // Red if active (threat detected), Green if not
        }
        return "#6B7280"; // Gray default
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}