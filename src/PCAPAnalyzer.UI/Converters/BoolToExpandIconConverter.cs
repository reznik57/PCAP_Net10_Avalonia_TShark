using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts boolean IsExpanded value to expand/collapse icon.
/// True (expanded) = "▼" (down arrow)
/// False (collapsed) = "▶" (right arrow)
/// </summary>
public class BoolToExpandIconConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isExpanded)
            return isExpanded ? "▼" : "▶";

        return "▶"; // Default to collapsed icon
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException("BoolToExpandIconConverter does not support ConvertBack");
    }
}
