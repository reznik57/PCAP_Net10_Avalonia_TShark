using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Compares enum value to parameter for equality.
/// Used to show/hide elements based on enum state (e.g., AnalysisStageState).
/// Usage: IsVisible="{Binding State, Converter={StaticResource EnumEqualsConverter}, ConverterParameter={x:Static components:AnalysisStageState.Completed}}"
/// </summary>
public class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value == null || parameter == null)
            return false;

        // Both must be enums or convertible to same type
        try
        {
            // Direct equality comparison
            if (value.Equals(parameter))
                return true;

            // Try converting parameter to value's type if different
            if (value.GetType() != parameter.GetType())
            {
                var convertedParam = System.Convert.ChangeType(parameter, value.GetType());
                return value.Equals(convertedParam);
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException("EnumEqualsConverter does not support ConvertBack");
    }
}
