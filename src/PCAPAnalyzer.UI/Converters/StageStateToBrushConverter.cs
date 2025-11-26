using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Converters;

public class StageStateToBrushConverter : IValueConverter
{
    private static readonly IBrush DefaultFillBrush = new SolidColorBrush(Color.Parse("#4B5563"));
    private static readonly IBrush ActiveFillBrush = new SolidColorBrush(Color.Parse("#3B82F6"));
    private static readonly IBrush CompletedFillBrush = new SolidColorBrush(Color.Parse("#22C55E"));
    private static readonly IBrush ErrorFillBrush = new SolidColorBrush(Color.Parse("#EF4444"));

    private static readonly IBrush DefaultTextBrush = new SolidColorBrush(Color.Parse("#D1D5DB"));
    private static readonly IBrush ActiveTextBrush = new SolidColorBrush(Color.Parse("#93C5FD"));
    private static readonly IBrush CompletedTextBrush = new SolidColorBrush(Color.Parse("#22C55E"));
    private static readonly IBrush ErrorTextBrush = new SolidColorBrush(Color.Parse("#EF4444"));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var mode = parameter as string;

        if (value is not AnalysisStageState state)
        {
            return mode == "Text" ? DefaultTextBrush : DefaultFillBrush;
        }

        return mode == "Text" ? GetTextBrush(state) : GetFillBrush(state);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();

    private static IBrush GetFillBrush(AnalysisStageState state) => state switch
    {
        AnalysisStageState.Active => ActiveFillBrush,
        AnalysisStageState.Completed => CompletedFillBrush,
        AnalysisStageState.Error => ErrorFillBrush,
        _ => DefaultFillBrush
    };

    private static IBrush GetTextBrush(AnalysisStageState state) => state switch
    {
        AnalysisStageState.Active => ActiveTextBrush,
        AnalysisStageState.Completed => CompletedTextBrush,
        AnalysisStageState.Error => ErrorTextBrush,
        _ => DefaultTextBrush
    };
}
