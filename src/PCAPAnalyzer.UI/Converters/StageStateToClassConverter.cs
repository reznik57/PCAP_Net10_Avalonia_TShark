using Avalonia.Data.Converters;
using PCAPAnalyzer.UI.ViewModels.Components;
using System;
using System.Globalization;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts AnalysisStageState enum to CSS class names for styling.
/// Used to apply different visual styles based on stage state (pending, active, completed, error).
/// </summary>
public class StageStateToClassConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is AnalysisStageState state)
        {
            return state switch
            {
                AnalysisStageState.Pending => "stage-card",
                AnalysisStageState.Active => "stage-card active",
                AnalysisStageState.Completed => "stage-card completed",
                AnalysisStageState.Error => "stage-card error",
                _ => "stage-card"
            };
        }

        return "stage-card";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
