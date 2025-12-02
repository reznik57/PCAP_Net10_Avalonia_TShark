using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class ThreatsFilterTabViewModel : ObservableObject
{
    [ObservableProperty] private string _searchInput = "";

    public ObservableCollection<FilterChipViewModel> SeverityChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> ThreatCategoryChips { get; } = new();

    public ThreatsFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var severities = new[] { "Critical", "High", "Medium", "Low" };
        foreach (var s in severities)
            SeverityChips.Add(new FilterChipViewModel(s));

        var categories = new[] { "Network", "Application", "Crypto", "Exfiltration", "IoT", "VoIP" };
        foreach (var c in categories)
            ThreatCategoryChips.Add(new FilterChipViewModel(c));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in SeverityChips) chip.SetMode(mode);
        foreach (var chip in ThreatCategoryChips) chip.SetMode(mode);
    }

    public (List<string> Severities, List<string> Categories) GetPendingFilters()
    {
        return (
            SeverityChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            ThreatCategoryChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in SeverityChips) chip.Reset();
        foreach (var chip in ThreatCategoryChips) chip.Reset();
        SearchInput = "";
    }
}
