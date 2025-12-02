using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Filter chip with LOCAL pending state. Does NOT update GlobalFilterState directly.
/// </summary>
public partial class FilterChipViewModel : ObservableObject
{
    public string Name { get; }

    [ObservableProperty] private bool _isSelected;

    // For visual state in XAML
    public bool IsIncluded => IsSelected && _mode == FilterChipMode.Include;
    public bool IsExcluded => IsSelected && _mode == FilterChipMode.Exclude;

    private FilterChipMode _mode = FilterChipMode.Include;

    public FilterChipViewModel(string name)
    {
        Name = name;
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
