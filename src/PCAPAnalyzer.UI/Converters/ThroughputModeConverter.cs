using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters
{
    public class ThroughputModeConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showThroughput)
            {
                return showThroughput ? "Throughput/s" : "Packets/s";
            }
            return "Packets/s";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class PortActivityModeConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is bool showThroughput)
            {
                return showThroughput ? "Throughput/Second per Port" : "Packets/Second per Port";
            }
            return "Packets/Second per Port";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}