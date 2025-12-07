using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Represents a node in the protocol tree hierarchy.
/// Supports expandable/collapsible tree structure for protocol layer breakdown.
/// </summary>
public partial class ProtocolTreeItemViewModel : ObservableObject
{
    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] private string _value = string.Empty;
    [ObservableProperty] private bool _isExpanded;
    [ObservableProperty] private bool _hasChildren;
    [ObservableProperty] private int _level;
    [ObservableProperty] private string _displayText = string.Empty;

    public ObservableCollection<ProtocolTreeItemViewModel> Children { get; } = [];

    /// <summary>
    /// Creates a protocol tree item
    /// </summary>
    public ProtocolTreeItemViewModel(string name, string value, int level = 0)
    {
        Name = name;
        Value = value;
        Level = level;
        UpdateDisplayText();
    }

    /// <summary>
    /// Adds a child item to this node
    /// </summary>
    public void AddChild(ProtocolTreeItemViewModel child)
    {
        Children.Add(child);
        HasChildren = true;
        IsExpanded = true; // Auto-expand nodes with children
    }

    /// <summary>
    /// Updates the display text based on name and value
    /// </summary>
    private void UpdateDisplayText()
    {
        DisplayText = string.IsNullOrEmpty(Value) ? Name : $"{Name}: {Value}";
    }

    partial void OnNameChanged(string value)
    {
        UpdateDisplayText();
    }

    partial void OnValueChanged(string value)
    {
        UpdateDisplayText();
    }
}
