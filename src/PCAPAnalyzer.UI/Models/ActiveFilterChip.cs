using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents an active filter chip in the summary row.
/// </summary>
public class ActiveFilterChip
{
    public required string DisplayLabel { get; init; }
    public required string Value { get; init; }
    public required FilterCategory Category { get; init; }
    public required bool IsInclude { get; init; }
    public required ICommand RemoveCommand { get; init; }

    /// <summary>
    /// Format: "Protocol:TCP" or "IP:192.168.1.1" or "Port:443"
    /// </summary>
    public string TypedLabel => Category switch
    {
        FilterCategory.Protocol => DisplayLabel,
        FilterCategory.IP => DisplayLabel,
        FilterCategory.Port => $"Port:{DisplayLabel}",
        FilterCategory.QuickFilter => DisplayLabel,
        FilterCategory.Severity => DisplayLabel,
        FilterCategory.ThreatCategory => DisplayLabel,
        _ => DisplayLabel
    };
}
