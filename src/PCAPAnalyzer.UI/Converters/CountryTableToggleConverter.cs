using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters
{
    public class CountryTableToggleConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showTop100)
            {
                return showTop100 ? "Top 25" : "Top 100";
            }
            return "Top 100";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            return null;
        }
    }
}