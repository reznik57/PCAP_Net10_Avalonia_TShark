using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for StatsBarControl - manages tab-specific statistics display
/// </summary>
public partial class StatsBarControlViewModel : ObservableObject
{
    /// <summary>
    /// Section title displayed above stats (e.g., "PACKET ANALYSIS OVERVIEW", "QUALITY STATISTICS")
    /// </summary>
    [ObservableProperty]
    private string _sectionTitle = "STATISTICS";

    /// <summary>
    /// Accent color for the vertical bar (matches tab theme)
    /// </summary>
    [ObservableProperty]
    private string _accentColor = ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF");

    /// <summary>
    /// Number of columns in the grid (auto-responsive)
    /// Default: 4 columns for most tabs
    /// </summary>
    [ObservableProperty]
    private int _columnCount = 4;

    /// <summary>
    /// Collection of statistics to display
    /// Populated by parent ViewModel with tab-specific metrics
    /// </summary>
    public ObservableCollection<StatItem> Stats { get; } = new();

    /// <summary>
    /// Helper method to add a stat item
    /// </summary>
    public void AddStat(string label, string value, string icon = "", string? valueColor = null, string secondaryText = "", string? secondaryColor = null)
    {
        Stats.Add(new StatItem
        {
            Label = label,
            Value = value,
            Icon = icon,
            ValueColor = valueColor ?? ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF"),
            SecondaryText = secondaryText,
            SecondaryColor = secondaryColor ?? ThemeColorHelper.GetColorHex("TextMuted", "#6E7681")
        });
    }

    /// <summary>
    /// Clear all stats (useful for refresh/rebuild)
    /// </summary>
    public void ClearStats()
    {
        Stats.Clear();
    }
}
