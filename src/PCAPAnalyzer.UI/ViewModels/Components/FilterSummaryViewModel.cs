using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for the active filter summary rows.
/// Displays include/exclude chips with remove functionality.
/// </summary>
public partial class FilterSummaryViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    public ObservableCollection<ActiveFilterChip> IncludeChips { get; } = new();
    public ObservableCollection<ActiveFilterChip> ExcludeChips { get; } = new();

    [ObservableProperty] private bool _hasIncludeFilters;
    [ObservableProperty] private bool _hasExcludeFilters;

    public FilterSummaryViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        _filterState.OnFilterChanged += RefreshChips;
        RefreshChips();
    }

    private void RefreshChips()
    {
        RefreshIncludeChips();
        RefreshExcludeChips();
    }

    private void RefreshIncludeChips()
    {
        IncludeChips.Clear();

        foreach (var p in _filterState.IncludeFilters.Protocols)
            IncludeChips.Add(CreateChip(p, p, FilterCategory.Protocol, true));
        foreach (var ip in _filterState.IncludeFilters.IPs)
            IncludeChips.Add(CreateChip(ip, ip, FilterCategory.IP, true));
        foreach (var port in _filterState.IncludeFilters.Ports)
            IncludeChips.Add(CreateChip(port, port, FilterCategory.Port, true));
        foreach (var qf in _filterState.IncludeFilters.QuickFilters)
            IncludeChips.Add(CreateChip(qf, qf, FilterCategory.QuickFilter, true));
        foreach (var sev in _filterState.IncludeFilters.Severities)
            IncludeChips.Add(CreateChip(sev, sev, FilterCategory.Severity, true));
        foreach (var cat in _filterState.IncludeFilters.ThreatCategories)
            IncludeChips.Add(CreateChip(cat, cat, FilterCategory.ThreatCategory, true));
        foreach (var tls in _filterState.IncludeFilters.TlsVersions)
            IncludeChips.Add(CreateChip(tls, tls, FilterCategory.TlsVersion, true));
        foreach (var country in _filterState.IncludeFilters.Countries)
            IncludeChips.Add(CreateChip(country, country, FilterCategory.Country, true));

        HasIncludeFilters = IncludeChips.Count > 0;
    }

    private void RefreshExcludeChips()
    {
        ExcludeChips.Clear();

        foreach (var p in _filterState.ExcludeFilters.Protocols)
            ExcludeChips.Add(CreateChip(p, p, FilterCategory.Protocol, false));
        foreach (var ip in _filterState.ExcludeFilters.IPs)
            ExcludeChips.Add(CreateChip(ip, ip, FilterCategory.IP, false));
        foreach (var port in _filterState.ExcludeFilters.Ports)
            ExcludeChips.Add(CreateChip(port, port, FilterCategory.Port, false));
        foreach (var qf in _filterState.ExcludeFilters.QuickFilters)
            ExcludeChips.Add(CreateChip(qf, qf, FilterCategory.QuickFilter, false));
        foreach (var sev in _filterState.ExcludeFilters.Severities)
            ExcludeChips.Add(CreateChip(sev, sev, FilterCategory.Severity, false));
        foreach (var cat in _filterState.ExcludeFilters.ThreatCategories)
            ExcludeChips.Add(CreateChip(cat, cat, FilterCategory.ThreatCategory, false));
        foreach (var tls in _filterState.ExcludeFilters.TlsVersions)
            ExcludeChips.Add(CreateChip(tls, tls, FilterCategory.TlsVersion, false));
        foreach (var country in _filterState.ExcludeFilters.Countries)
            ExcludeChips.Add(CreateChip(country, country, FilterCategory.Country, false));

        HasExcludeFilters = ExcludeChips.Count > 0;
    }

    private ActiveFilterChip CreateChip(string label, string value, FilterCategory category, bool isInclude)
    {
        return new ActiveFilterChip
        {
            DisplayLabel = label,
            Value = value,
            Category = category,
            IsInclude = isInclude,
            RemoveCommand = new RelayCommand(() =>
            {
                if (isInclude)
                    _filterState.RemoveIncludeFilter(value, category);
                else
                    _filterState.RemoveExcludeFilter(value, category);
            })
        };
    }
}
