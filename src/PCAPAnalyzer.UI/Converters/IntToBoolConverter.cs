using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters
{
    /// <summary>
    /// Converts an integer to a boolean.
    /// Returns true if the integer is greater than 0, false otherwise.
    /// </summary>
    public class IntToBoolConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is int intValue)
            {
                return intValue > 0;
            }

            if (value is long longValue)
            {
                return longValue > 0;
            }

            if (value is double doubleValue)
            {
                return doubleValue > 0;
            }

            return false;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                return boolValue ? 1 : 0;
            }

            return 0;
        }
    }
}
