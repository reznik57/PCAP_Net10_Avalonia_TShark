using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Models;

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
    private string _accentColor = "#58A6FF";

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
    public void AddStat(string label, string value, string icon = "", string valueColor = "#58A6FF", string secondaryText = "", string secondaryColor = "#6E7681")
    {
        Stats.Add(new StatItem
        {
            Label = label,
            Value = value,
            Icon = icon,
            ValueColor = valueColor,
            SecondaryText = secondaryText,
            SecondaryColor = secondaryColor
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
