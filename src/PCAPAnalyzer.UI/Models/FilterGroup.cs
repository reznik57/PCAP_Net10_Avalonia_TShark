using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a grouped filter with AND logic between all fields.
/// Used when user selects AND mode and clicks Apply - creates a single chip with all active fields.
/// Example: "Dest IP: 8.8.8.8 AND Port: 53"
/// </summary>
public partial class FilterGroup : ObservableObject
{
    /// <summary>Unique identifier for this filter group</summary>
    [ObservableProperty]
    private int _groupId;

    /// <summary>Display label shown in the chip (e.g., "Dest IP: 8.8.8.8 AND Port: 53")</summary>
    [ObservableProperty]
    private string _displayLabel = string.Empty;

    /// <summary>True if this is an AND group, false if individual OR chips</summary>
    [ObservableProperty]
    private bool _isAndGroup;

    /// <summary>True if this is a NOT/EXCLUDE group</summary>
    [ObservableProperty]
    private bool _isExcludeGroup;

    // Filter criteria - only populated fields contribute to the group
    [ObservableProperty]
    private string? _sourceIP;

    [ObservableProperty]
    private string? _destinationIP;

    [ObservableProperty]
    private string? _portRange;

    [ObservableProperty]
    private string? _protocol;

    /// <summary>Command to remove this entire filter group</summary>
    public IRelayCommand? RemoveCommand { get; set; }

    public FilterGroup()
    {
    }

    public FilterGroup(int groupId, string displayLabel, bool isAndGroup, bool isExcludeGroup)
    {
        GroupId = groupId;
        DisplayLabel = displayLabel;
        IsAndGroup = isAndGroup;
        IsExcludeGroup = isExcludeGroup;
    }

    /// <summary>
    /// Checks if this filter group has any populated criteria
    /// </summary>
    public bool HasCriteria()
    {
        return !string.IsNullOrWhiteSpace(SourceIP) ||
               !string.IsNullOrWhiteSpace(DestinationIP) ||
               !string.IsNullOrWhiteSpace(PortRange) ||
               !string.IsNullOrWhiteSpace(Protocol);
    }

    /// <summary>
    /// Gets a list of all non-empty field descriptions for this group
    /// </summary>
    public List<string> GetFieldDescriptions()
    {
        var descriptions = new List<string>();

        if (!string.IsNullOrWhiteSpace(SourceIP))
            descriptions.Add($"Src IP: {SourceIP}");

        if (!string.IsNullOrWhiteSpace(DestinationIP))
            descriptions.Add($"Dest IP: {DestinationIP}");

        if (!string.IsNullOrWhiteSpace(PortRange))
            descriptions.Add($"Port: {PortRange}");

        if (!string.IsNullOrWhiteSpace(Protocol))
            descriptions.Add($"Protocol: {Protocol}");

        return descriptions;
    }

    /// <summary>
    /// Builds and sets the DisplayLabel based on populated filter fields.
    /// Should be called after setting filter properties.
    /// </summary>
    public void BuildDisplayLabel()
    {
        var descriptions = GetFieldDescriptions();

        if (descriptions.Count == 0)
        {
            DisplayLabel = "(empty filter)";
            return;
        }

        // Join with " AND " for AND groups, ", " for OR mode
        var separator = IsAndGroup ? " AND " : ", ";
        DisplayLabel = string.Join(separator, descriptions);
    }
}
