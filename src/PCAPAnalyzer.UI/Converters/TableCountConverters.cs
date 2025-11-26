using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters
{
    public class PortTimelineCountConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showTop10)
            {
                return showTop10 ? "Top 10" : "Top 5";
            }
            return "Top 5";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class PortTableCountConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showTop25)
            {
                return showTop25 ? "Top 25" : "Top 10";
            }
            return "Top 10";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class OtherTableCountConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showTop25)
            {
                return showTop25 ? "Top 25" : "Top 10";
            }
            return "Top 10";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class ConnectionTableCountConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showTop25)
            {
                return showTop25 ? "Top 25" : "Top 10";
            }
            return "Top 10";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}