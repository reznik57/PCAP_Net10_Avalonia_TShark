using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class CountryFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _countrySearchInput = "";

    // Observable chip collections with state tracking
    public ObservableCollection<FilterChipViewModel> DirectionChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> RegionChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> CountryChips { get; } = new();

    public CountryFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        InitializeChips();
    }

    private void InitializeChips()
    {
        // Direction chips
        var directions = new[] { "Inbound", "Outbound", "Internal" };
        foreach (var d in directions)
            DirectionChips.Add(new FilterChipViewModel(d, _filterState, FilterCategory.Direction));

        // Region chips
        var regions = new[] { "North America", "Europe", "Asia", "Middle East", "Africa", "South America", "Oceania" };
        foreach (var r in regions)
            RegionChips.Add(new FilterChipViewModel(r, _filterState, FilterCategory.Region));

        // Common country chips (2-letter ISO codes)
        var countries = new[] { "US", "CN", "RU", "DE", "GB", "FR", "JP", "IN", "BR", "AU" };
        foreach (var c in countries)
            CountryChips.Add(new FilterChipViewModel(c, _filterState, FilterCategory.Country));
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
}
