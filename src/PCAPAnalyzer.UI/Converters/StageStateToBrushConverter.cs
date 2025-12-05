using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Converters;

public class StageStateToBrushConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var mode = parameter as string;

        if (value is not AnalysisStageState state)
        {
            return mode == "Text"
                ? ThemeColorHelper.GetStageTextBrush("pending")
                : ThemeColorHelper.GetStageFillBrush("pending");
        }

        var stateStr = state.ToString().ToLowerInvariant();
        return mode == "Text"
            ? ThemeColorHelper.GetStageTextBrush(stateStr)
            : ThemeColorHelper.GetStageFillBrush(stateStr);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
