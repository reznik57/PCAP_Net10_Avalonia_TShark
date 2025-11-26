using System;
using System.Collections.Generic;
using System.Globalization;
using Avalonia.Data.Converters;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Converters;

public class StageProgressVisibilityConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count >= 2 &&
            values[0] is AnalysisStageState state &&
            values[1] is bool showProgress)
        {
            return showProgress && state == AnalysisStageState.Active;
        }

        return false;
    }

    public object[] ConvertBack(object? value, Type[] targetTypes, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
