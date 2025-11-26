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
}
