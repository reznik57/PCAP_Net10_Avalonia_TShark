using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class UnifiedFilterPanelViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    public FilterSummaryViewModel Summary { get; }
    public GeneralFilterTabViewModel GeneralTab { get; }
    public ThreatsFilterTabViewModel ThreatsTab { get; }
    public VoiceQoSFilterTabViewModel VoiceQoSTab { get; }
    public CountryFilterTabViewModel CountryTab { get; }

    [ObservableProperty] private int _selectedTabIndex;

    public bool IsIncludeMode => _filterState.CurrentMode == FilterMode.Include;
    public bool IsExcludeMode => _filterState.CurrentMode == FilterMode.Exclude;

    public event Action? ApplyFiltersRequested;

    public UnifiedFilterPanelViewModel(
        GlobalFilterState filterState,
        FilterSummaryViewModel summary,
        GeneralFilterTabViewModel generalTab,
        ThreatsFilterTabViewModel threatsTab,
        VoiceQoSFilterTabViewModel voiceQoSTab,
        CountryFilterTabViewModel countryTab)
    {
        _filterState = filterState;
        Summary = summary;
        GeneralTab = generalTab;
        ThreatsTab = threatsTab;
        VoiceQoSTab = voiceQoSTab;
        CountryTab = countryTab;
        _filterState.OnFilterChanged += OnFilterStateChanged;
    }

    private void OnFilterStateChanged()
    {
        OnPropertyChanged(nameof(IsIncludeMode));
        OnPropertyChanged(nameof(IsExcludeMode));
    }

    [RelayCommand]
    private void SetIncludeMode()
    {
        _filterState.CurrentMode = FilterMode.Include;
        OnFilterStateChanged();
    }

    [RelayCommand]
    private void SetExcludeMode()
    {
        _filterState.CurrentMode = FilterMode.Exclude;
        OnFilterStateChanged();
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
