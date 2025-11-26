using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters
{
    public class ListToStringConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is IEnumerable enumerable && !(value is string))
            {
                var items = enumerable.Cast<object>().Take(5).ToList();
                var result = string.Join(", ", items);
                
                var totalCount = enumerable.Cast<object>().Count();
                if (totalCount > 5)
                {
                    result += $" (+{totalCount - 5} more)";
                }
                
                return result;
            }
            
            return value?.ToString() ?? string.Empty;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}