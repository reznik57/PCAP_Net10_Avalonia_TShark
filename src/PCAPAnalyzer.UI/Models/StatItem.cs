using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a single statistic metric for display in StatsBarControl.
/// Tab-specific stats are created by ViewModels and passed to the control.
/// </summary>
public partial class StatItem : ObservableObject
{
    /// <summary>
    /// Display label for the statistic (e.g., "TOTAL PACKETS", "AVG LATENCY")
    /// </summary>
    [ObservableProperty]
    private string _label = string.Empty;

    /// <summary>
    /// Formatted value to display (e.g., "1,106,728", "287.35 MB", "42.5 ms")
    /// </summary>
    [ObservableProperty]
    private string _value = string.Empty;

    /// <summary>
    /// Optional emoji icon (e.g., "📦", "🔍", "💾", "⚠️")
    /// </summary>
    [ObservableProperty]
    private string _icon = string.Empty;

    /// <summary>
    /// Color for the value text (e.g., "#58A6FF", "#3FB950", "#F85149")
    /// </summary>
    [ObservableProperty]
    private string _valueColor = "#58A6FF";

    /// <summary>
    /// Optional secondary text (e.g., percentage, threshold indicator)
    /// </summary>
    [ObservableProperty]
    private string _secondaryText = string.Empty;

    /// <summary>
    /// Color for secondary text
    /// </summary>
    [ObservableProperty]
    private string _secondaryColor = "#6E7681";
}
