using System;
using System.Globalization;
using Avalonia.Data.Converters;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Converters
{
    public class ByteSizeConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            switch (value)
            {
                case long longBytes:
                    return NumberFormatter.FormatBytes(longBytes);
                case int intBytes:
                    return NumberFormatter.FormatBytes(intBytes);
                case double doubleBytes:
                    return NumberFormatter.FormatBytes((long)doubleBytes);
                case float floatBytes:
                    return NumberFormatter.FormatBytes((long)floatBytes);
                default:
                    return "0 B";
            }
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            return null;
        }
    }
}
