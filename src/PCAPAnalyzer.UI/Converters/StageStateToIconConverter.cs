using System;
using System.Globalization;
using Avalonia.Data.Converters;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts AnalysisStageState to icon path data for visual indicators
/// </summary>
public class StageStateToIconConverter : IValueConverter
{
    // Circle outline for pending stages
    private const string PendingIcon = "M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20A8,8 0 0,0 20,12A8,8 0 0,0 12,4Z";

    // Rotating spinner arc for active stages
    private const string ActiveIcon = "M12,4V2A10,10 0 0,1 22,12H20A8,8 0 0,0 12,4Z";

    // Checkmark for completed stages
    private const string CompletedIcon = "M9,20.42L2.79,14.21L5.62,11.38L9,14.77L18.88,4.88L21.71,7.71L9,20.42Z";

    // X mark for error stages
    private const string ErrorIcon = "M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z";

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not AnalysisStageState state)
        {
            return PendingIcon;
        }

        return state switch
        {
            AnalysisStageState.Pending => PendingIcon,
            AnalysisStageState.Active => ActiveIcon,
            AnalysisStageState.Completed => CompletedIcon,
            AnalysisStageState.Error => ErrorIcon,
            _ => PendingIcon
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
