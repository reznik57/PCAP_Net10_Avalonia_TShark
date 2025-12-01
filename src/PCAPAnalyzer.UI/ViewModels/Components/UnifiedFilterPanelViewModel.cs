using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class UnifiedFilterPanelViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    public FilterSummaryViewModel Summary { get; }

    [ObservableProperty] private int _selectedTabIndex;

    public bool IsIncludeMode => _filterState.CurrentMode == FilterMode.Include;

    public event Action? ApplyFiltersRequested;

    public UnifiedFilterPanelViewModel(GlobalFilterState filterState, FilterSummaryViewModel summary)
    {
        _filterState = filterState;
        Summary = summary;
        _filterState.OnFilterChanged += () => OnPropertyChanged(nameof(IsIncludeMode));
    }

    [RelayCommand]
    private void SetIncludeMode()
    {
        _filterState.CurrentMode = FilterMode.Include;
        OnPropertyChanged(nameof(IsIncludeMode));
    }

    [RelayCommand]
    private void SetExcludeMode()
    {
        _filterState.CurrentMode = FilterMode.Exclude;
        OnPropertyChanged(nameof(IsIncludeMode));
    }

    [RelayCommand]
    private void ApplyFilters()
    {
        ApplyFiltersRequested?.Invoke();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        _filterState.Clear();
    }
}
