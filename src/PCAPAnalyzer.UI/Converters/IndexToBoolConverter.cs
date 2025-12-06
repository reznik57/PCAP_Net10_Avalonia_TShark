using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Two-way converter for binding an integer index to a RadioButton's IsChecked property.
/// Convert: Returns true if the current index equals the ConverterParameter.
/// ConvertBack: Returns the ConverterParameter value when IsChecked becomes true.
/// </summary>
public class IndexToBoolConverter : IValueConverter
{
    public static readonly IndexToBoolConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not int currentIndex)
            return false;

        var targetIndex = GetTargetIndex(parameter);
        return currentIndex == targetIndex;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is true)
            return GetTargetIndex(parameter);

        // Return binding DoNothing to avoid setting value when unchecked
        return Avalonia.Data.BindingOperations.DoNothing;
    }

    private static int GetTargetIndex(object? parameter)
    {
        return parameter switch
        {
            int i => i,
            string s when int.TryParse(s, out var parsed) => parsed,
            _ => -1
        };
    }
}
