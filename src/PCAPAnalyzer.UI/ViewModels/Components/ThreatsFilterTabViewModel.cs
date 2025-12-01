using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class ThreatsFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _searchInput = "";

    // Predefined severity chips
    public static readonly string[] SeverityChips =
        { "Critical", "High", "Medium", "Low" };

    // Predefined threat category chips
    public static readonly string[] ThreatCategoryChips =
        { "Network", "Application", "Crypto", "Exfiltration", "IoT", "VoIP" };

    public ThreatsFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
    }

    [RelayCommand]
    private void ToggleSeverity(string severity)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Severities.Contains(severity))
        {
            _filterState.RemoveIncludeFilter(severity, FilterCategory.Severity);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Severities.Contains(severity))
        {
            _filterState.RemoveExcludeFilter(severity, FilterCategory.Severity);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeSeverity(severity);
        else
            _filterState.AddExcludeSeverity(severity);
    }

    [RelayCommand]
    private void ToggleThreatCategory(string category)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.ThreatCategories.Contains(category))
        {
            _filterState.RemoveIncludeFilter(category, FilterCategory.ThreatCategory);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.ThreatCategories.Contains(category))
        {
            _filterState.RemoveExcludeFilter(category, FilterCategory.ThreatCategory);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeThreatCategory(category);
        else
            _filterState.AddExcludeThreatCategory(category);
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

    // Helper to check chip state for UI styling
    public ChipState GetSeverityChipState(string severity)
    {
        if (_filterState.IncludeFilters.Severities.Contains(severity))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Severities.Contains(severity))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetThreatCategoryChipState(string category)
    {
        if (_filterState.IncludeFilters.ThreatCategories.Contains(category))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.ThreatCategories.Contains(category))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }
}
