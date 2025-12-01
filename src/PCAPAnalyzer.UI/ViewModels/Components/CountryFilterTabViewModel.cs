using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class CountryFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _countrySearchInput = "";

    // Predefined direction chips
    public static readonly string[] DirectionChips =
        { "Inbound", "Outbound", "Internal" };

    // Predefined region chips
    public static readonly string[] RegionChips =
        { "North America", "Europe", "Asia", "Middle East", "Africa", "South America", "Oceania" };

    // Common country chips (2-letter ISO codes)
    public static readonly string[] CommonCountryChips =
        { "US", "CN", "RU", "DE", "GB", "FR", "JP", "IN", "BR", "AU" };

    public CountryFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
    }

    [RelayCommand]
    private void AddCountry()
    {
        if (string.IsNullOrWhiteSpace(CountrySearchInput)) return;

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeCountry(CountrySearchInput.Trim());
        else
            _filterState.AddExcludeCountry(CountrySearchInput.Trim());

        CountrySearchInput = "";
    }

    [RelayCommand]
    private void ToggleDirection(string direction)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Directions.Contains(direction))
        {
            _filterState.RemoveIncludeFilter(direction, FilterCategory.Direction);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Directions.Contains(direction))
        {
            _filterState.RemoveExcludeFilter(direction, FilterCategory.Direction);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeDirection(direction);
        else
            _filterState.AddExcludeDirection(direction);
    }

    [RelayCommand]
    private void ToggleRegion(string region)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Regions.Contains(region))
        {
            _filterState.RemoveIncludeFilter(region, FilterCategory.Region);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Regions.Contains(region))
        {
            _filterState.RemoveExcludeFilter(region, FilterCategory.Region);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeRegion(region);
        else
            _filterState.AddExcludeRegion(region);
    }

    [RelayCommand]
    private void ToggleCountry(string country)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Countries.Contains(country))
        {
            _filterState.RemoveIncludeFilter(country, FilterCategory.Country);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Countries.Contains(country))
        {
            _filterState.RemoveExcludeFilter(country, FilterCategory.Country);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeCountry(country);
        else
            _filterState.AddExcludeCountry(country);
    }

    // Helper to check chip state for UI styling
    public ChipState GetDirectionChipState(string direction)
    {
        if (_filterState.IncludeFilters.Directions.Contains(direction))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Directions.Contains(direction))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetRegionChipState(string region)
    {
        if (_filterState.IncludeFilters.Regions.Contains(region))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Regions.Contains(region))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetCountryChipState(string country)
    {
        if (_filterState.IncludeFilters.Countries.Contains(country))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Countries.Contains(country))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }
}
