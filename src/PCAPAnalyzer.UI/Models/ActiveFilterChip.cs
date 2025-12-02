using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents an active filter chip in the summary row.
/// Can represent either an individual filter or an AND-grouped filter.
/// </summary>
public class ActiveFilterChip
{
    public required string DisplayLabel { get; init; }
    public required string Value { get; init; }
    public required FilterCategory Category { get; init; }
    public required bool IsInclude { get; init; }
    public required ICommand RemoveCommand { get; init; }

    /// <summary>True if this chip represents an AND-grouped filter</summary>
    public bool IsGroup { get; init; }

    /// <summary>Group ID for group chips (used for removal)</summary>
    public int GroupId { get; init; }

    /// <summary>
    /// Format: "Protocol:TCP" or "IP:192.168.1.1" or "Port:443" or "GROUP: X AND Y"
    /// </summary>
    public string TypedLabel => IsGroup ? DisplayLabel : Category switch
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
