using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Filter chip with LOCAL pending state. Does NOT update GlobalFilterState directly.
/// Name = internal key for filter matching, DisplayName = UI label.
/// </summary>
public partial class FilterChipViewModel : ObservableObject
{
    /// <summary>Internal key used for filter matching in SmartFilterBuilderService</summary>
    public string Name { get; }

    /// <summary>User-friendly display label (e.g., "TLS v1.0" instead of "TlsV10")</summary>
    public string DisplayName { get; }

    [ObservableProperty] private bool _isSelected;

    // For visual state in XAML
    public bool IsIncluded => IsSelected && _mode == FilterChipMode.Include;
    public bool IsExcluded => IsSelected && _mode == FilterChipMode.Exclude;

    private FilterChipMode _mode = FilterChipMode.Include;

    public FilterChipViewModel(string name) : this(name, name) { }

    public FilterChipViewModel(string name, string displayName)
    {
        Name = name;
        DisplayName = displayName;
    }

    public void SetMode(FilterChipMode mode)
    {
        var wasSelected = IsSelected;
        _mode = mode;
        if (wasSelected)
        {
            OnPropertyChanged(nameof(IsIncluded));
            OnPropertyChanged(nameof(IsExcluded));
        }
    }

    [RelayCommand]
    private void Toggle()
    {
        IsSelected = !IsSelected;
        OnPropertyChanged(nameof(IsIncluded));
        OnPropertyChanged(nameof(IsExcluded));
    }

    public void Reset()
    {
        IsSelected = false;
        OnPropertyChanged(nameof(IsIncluded));
        OnPropertyChanged(nameof(IsExcluded));
    }
}

public enum FilterChipMode { Include, Exclude }
