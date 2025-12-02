using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class CountryFilterTabViewModel : ObservableObject
{
    [ObservableProperty] private string _countrySearchInput = "";

    public ObservableCollection<FilterChipViewModel> DirectionChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> RegionChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> CountryChips { get; } = new();

    public CountryFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var directions = new[] { "Inbound", "Outbound", "Internal" };
        foreach (var d in directions)
            DirectionChips.Add(new FilterChipViewModel(d));

        var regions = new[] { "North America", "Europe", "Asia", "Middle East", "Africa", "South America", "Oceania" };
        foreach (var r in regions)
            RegionChips.Add(new FilterChipViewModel(r));

        var countries = new[] { "US", "CN", "RU", "DE", "GB", "FR", "JP", "IN", "BR", "AU" };
        foreach (var c in countries)
            CountryChips.Add(new FilterChipViewModel(c));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in DirectionChips) chip.SetMode(mode);
        foreach (var chip in RegionChips) chip.SetMode(mode);
        foreach (var chip in CountryChips) chip.SetMode(mode);
    }

    public (List<string> Directions, List<string> Regions, List<string> Countries) GetPendingFilters()
    {
        return (
            DirectionChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            RegionChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            CountryChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in DirectionChips) chip.Reset();
        foreach (var chip in RegionChips) chip.Reset();
        foreach (var chip in CountryChips) chip.Reset();
        CountrySearchInput = "";
    }
}
