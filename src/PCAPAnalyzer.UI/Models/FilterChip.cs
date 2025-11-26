using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a filter chip displayed in the active filters section.
/// Used for visual display of applied INCLUDE and EXCLUDE filters with remove functionality.
/// </summary>
public partial class FilterChip : ObservableObject
{
    [ObservableProperty]
    private string _label = string.Empty;

    public IRelayCommand? RemoveCommand { get; set; }

    public FilterChip(string label, IRelayCommand removeCommand)
    {
        Label = label;
        RemoveCommand = removeCommand;
    }
}
