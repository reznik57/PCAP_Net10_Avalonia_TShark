using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class ThreatsFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _searchInput = "";

    // Observable chip collections with state tracking
    public ObservableCollection<FilterChipViewModel> SeverityChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> ThreatCategoryChips { get; } = new();

    public ThreatsFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        InitializeChips();
    }

    private void InitializeChips()
    {
        // Severity chips
        var severities = new[] { "Critical", "High", "Medium", "Low" };
        foreach (var s in severities)
            SeverityChips.Add(new FilterChipViewModel(s, _filterState, FilterCategory.Severity));

        // Threat category chips
        var categories = new[] { "Network", "Application", "Crypto", "Exfiltration", "IoT", "VoIP" };
        foreach (var c in categories)
            ThreatCategoryChips.Add(new FilterChipViewModel(c, _filterState, FilterCategory.ThreatCategory));
    }

    [RelayCommand]
    private void Search()
    {
        if (string.IsNullOrWhiteSpace(SearchInput)) return;

        // Add search term as threat category filter (flexible search)
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeThreatCategory(SearchInput.Trim());
        else
            _filterState.AddExcludeThreatCategory(SearchInput.Trim());

        SearchInput = "";
    }
}
