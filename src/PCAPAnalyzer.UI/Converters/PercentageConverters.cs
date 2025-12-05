using System;
using System.Collections.Generic;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Converters
{
    public class PercentageToGradientConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is double percentage)
            {
                var brush = new LinearGradientBrush();
                brush.StartPoint = new Avalonia.RelativePoint(0, 0, Avalonia.RelativeUnit.Relative);
                brush.EndPoint = new Avalonia.RelativePoint(1, 0, Avalonia.RelativeUnit.Relative);

                var (startColor, endColor) = ThemeColorHelper.GetPercentageGradientColors(percentage);
                brush.GradientStops.Add(new GradientStop(startColor, 0));
                brush.GradientStops.Add(new GradientStop(endColor, 1));

                return brush;
            }
            return new SolidColorBrush(ThemeColorHelper.PercentageTrackColor);
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class PercentageToWidthConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is double percentage)
            {
                // Get max width from parameter or use default
                double maxWidth = 150; // Default max width for percentage bars
                if (parameter is string widthStr && double.TryParse(widthStr, out double paramWidth))
                {
                    maxWidth = paramWidth;
                }
                
                // Return 0 width for 0% to prevent showing colored bars
                if (percentage < 0.01) // Less than 0.01% should show no bar
                    return 0.0;
                    
                // Calculate proportional width based on percentage
                // Ensure very small non-zero percentages remain visible for readability
                var width = (percentage / 100.0) * maxWidth;
                if (width <= 0)
                    return 0.0;

                const double minimumVisibleWidth = 3.0;
                return Math.Max(minimumVisibleWidth, width);
            }
            return 0.0;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class PercentageToScaleConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is double percentage)
            {
                // Convert percentage to scale (0 to 1)
                return Math.Max(0.01, percentage / 100.0);
            }
            return 0.01;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class PercentageToColorConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is double percentage)
            {
                var isStart = parameter?.ToString() == "Start";
                var (startColor, endColor) = ThemeColorHelper.GetPercentageGradientColors(percentage);
                return isStart ? startColor : endColor;
            }
            return ThemeColorHelper.PercentageTrackColor;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    public class PercentageToPixelWidthConverter : IMultiValueConverter
    {
        public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
        {
            if (values.Count >= 2 &&
                values[0] is double percentageValue &&
                values[1] is double containerWidthValue)
            {
                var percentage = Math.Max(0, Math.Min(100, percentageValue));
                var availableWidth = double.IsNaN(containerWidthValue) ? 0 : Math.Max(0, containerWidthValue);

                if (parameter is string paddingText && double.TryParse(paddingText, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsedPadding))
                {
                    availableWidth = Math.Max(0, availableWidth - parsedPadding);
                }
                else if (parameter is double paddingDouble && !double.IsNaN(paddingDouble))
                {
                    availableWidth = Math.Max(0, availableWidth - paddingDouble);
                }

                var width = availableWidth * (percentage / 100.0);
                return width <= 0 ? 0.0 : width;
            }

            return 0.0;
        }

        public object?[] ConvertBack(object? value, Type[] targetTypes, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
