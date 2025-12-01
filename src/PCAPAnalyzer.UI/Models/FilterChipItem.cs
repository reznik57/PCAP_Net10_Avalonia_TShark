using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a single filter chip for OR mode filtering.
/// Used when user selects OR mode and clicks Apply - creates separate chips for each field.
/// Example: Individual chips "Dest IP: 8.8.8.8" and "Port: 53" (shown as OR logic)
/// </summary>
public partial class FilterChipItem : ObservableObject
{
    /// <summary>Unique identifier for this chip</summary>
    [ObservableProperty]
    private int _chipId;

    /// <summary>Field name (e.g., "Source IP", "Destination IP", "Port", "Protocol")</summary>
    [ObservableProperty]
    private string _fieldName = string.Empty;

    /// <summary>Filter value (e.g., "8.8.8.8", "53", "TCP")</summary>
    [ObservableProperty]
    private string _value = string.Empty;

    /// <summary>True if this is an EXCLUDE/NOT filter</summary>
    [ObservableProperty]
    private bool _isExclude;

    /// <summary>
    /// If set, this chip was created from a quick filter toggle.
    /// Used to sync chip removal back to toggle state.
    /// E.g., "Retransmissions", "ZeroWindow", "CleartextAuth"
    /// </summary>
    [ObservableProperty]
    private string? _quickFilterCodeName;

    /// <summary>Display label shown in the chip (e.g., "Port: 53")</summary>
    [ObservableProperty]
    private string _displayLabel = string.Empty;

    /// <summary>Command to remove this individual filter chip</summary>
    public IRelayCommand? RemoveCommand { get; set; }

    public FilterChipItem()
    {
    }

    public FilterChipItem(int chipId, string fieldName, string value, bool isExclude)
    {
        ChipId = chipId;
        FieldName = fieldName;
        Value = value;
        IsExclude = isExclude;
        DisplayLabel = $"{fieldName}: {value}";
    }

    /// <summary>
    /// Creates a chip from a quick filter toggle.
    /// </summary>
    /// <param name="chipId">Unique chip identifier</param>
    /// <param name="displayName">Human-readable name (e.g., "Retransmissions", "Zero Window")</param>
    /// <param name="codeName">Code name for toggle sync (e.g., "Retransmissions", "ZeroWindow")</param>
    /// <param name="isExclude">True if this is an exclude/hide filter</param>
    public FilterChipItem(int chipId, string displayName, string codeName, bool isExclude, bool isQuickFilter)
    {
        ChipId = chipId;
        FieldName = "⚡ Quick";
        Value = displayName;
        IsExclude = isExclude;
        QuickFilterCodeName = codeName;
        // Prefix with mode indicator for clarity
        DisplayLabel = isExclude ? $"🚫 {displayName}" : $"✓ {displayName}";
    }

    // ==================== COMPUTED COLOR PROPERTIES ====================

    /// <summary>
    /// Background color based on filter mode.
    /// INCLUDE = Green tint (#1A3D1A), EXCLUDE = Red tint (#3D1A1A)
    /// </summary>
    public string ChipBackgroundColor => IsExclude ? "#3D1A1A" : "#1A3D1A";

    /// <summary>
    /// Border color based on filter mode.
    /// INCLUDE = Green (#2EA043), EXCLUDE = Red (#F85149)
    /// </summary>
    public string ChipBorderColor => IsExclude ? "#F85149" : "#2EA043";

    /// <summary>
    /// Text color based on filter mode.
    /// INCLUDE = Light Green (#7EE787), EXCLUDE = Light Red (#FF7B72)
    /// </summary>
    public string ChipTextColor => IsExclude ? "#FF7B72" : "#7EE787";

    /// <summary>
    /// Mode prefix for display label.
    /// INCLUDE = "+", EXCLUDE = "-"
    /// </summary>
    public string ModePrefix => IsExclude ? "−" : "+";

    /// <summary>
    /// Full display with mode indicator.
    /// </summary>
    public string DisplayWithMode => $"[{ModePrefix}] {FieldName}: {Value}";
}
