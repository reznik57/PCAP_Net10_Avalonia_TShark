using System;
using System.Globalization;
using Avalonia.Data.Converters;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Converters
{
    public class ByteFormatConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                return NumberFormatter.FormatBytes(bytes);
            }
            else if (value is int intBytes)
            {
                return NumberFormatter.FormatBytes(intBytes);
            }
            else if (value is double doubleBytes)
            {
                return NumberFormatter.FormatBytes((long)doubleBytes);
            }
            return "0 B";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}