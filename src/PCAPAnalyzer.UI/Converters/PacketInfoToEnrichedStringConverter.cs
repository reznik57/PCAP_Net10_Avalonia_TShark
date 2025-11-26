using System;
using System.Globalization;
using Avalonia.Data.Converters;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts PacketInfo to enriched INFO string with TCP state labels
/// </summary>
public class PacketInfoToEnrichedStringConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is PacketInfo packet)
        {
            return packet.GetEnrichedInfo();
        }

        return string.Empty;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
