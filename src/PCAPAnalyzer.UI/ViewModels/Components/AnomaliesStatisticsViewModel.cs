using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages KPIs and ranked table data for the Anomalies tab.
/// </summary>
public partial class AnomaliesStatisticsViewModel : ObservableObject
{
    // KPIs
    [ObservableProperty] private int _totalAnomalies;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private int _uniqueSourceIPs;
    [ObservableProperty] private int _uniqueTargetIPs;
    [ObservableProperty] private string _timeSpanFormatted = "--";

    // Filtered state
    [ObservableProperty] private bool _isFiltered;
    [ObservableProperty] private int _filteredTotalAnomalies;

    // Ranked tables
    public ObservableCollection<AnomalyEndpointViewModel> TopSources { get; } = [];
    public ObservableCollection<AnomalyEndpointViewModel> TopTargets { get; } = [];
    public ObservableCollection<AnomalyPortViewModel> TopPorts { get; } = [];
    public ObservableCollection<AnomalyCategoryViewModel> CategoryBreakdown { get; } = [];

    public void UpdateKPIs(AnomalyKPIs kpis)
    {
        TotalAnomalies = kpis.TotalAnomalies;
        CriticalCount = kpis.CriticalCount;
        HighCount = kpis.HighCount;
        MediumCount = kpis.MediumCount;
        LowCount = kpis.LowCount;
        UniqueSourceIPs = kpis.UniqueSourceIPs;
        UniqueTargetIPs = kpis.UniqueTargetIPs;

        if (kpis.TimeSpan.TotalSeconds > 0)
        {
            TimeSpanFormatted = kpis.TimeSpan.TotalHours >= 1
                ? $"{kpis.TimeSpan.Hours}h {kpis.TimeSpan.Minutes}m"
                : kpis.TimeSpan.TotalMinutes >= 1
                    ? $"{kpis.TimeSpan.Minutes}m {kpis.TimeSpan.Seconds}s"
                    : $"{kpis.TimeSpan.Seconds}s";
        }
        else
        {
            TimeSpanFormatted = "--";
        }
    }

    public void UpdateTopSources(IEnumerable<AnomalyEndpointViewModel> sources)
    {
        TopSources.Clear();
        foreach (var source in sources.Take(20))
            TopSources.Add(source);
    }

    public void UpdateTopTargets(IEnumerable<AnomalyEndpointViewModel> targets)
    {
        TopTargets.Clear();
        foreach (var target in targets.Take(20))
            TopTargets.Add(target);
    }

    public void UpdateTopPorts(IEnumerable<AnomalyPortViewModel> ports)
    {
        TopPorts.Clear();
        foreach (var port in ports.Take(15))
            TopPorts.Add(port);
    }

    public void UpdateCategoryBreakdown(IEnumerable<AnomalyCategoryViewModel> categories)
    {
        CategoryBreakdown.Clear();
        foreach (var cat in categories.OrderByDescending(c => c.Count))
            CategoryBreakdown.Add(cat);
    }

    public void SetFilteredState(bool isFiltered, int filteredCount)
    {
        IsFiltered = isFiltered;
        FilteredTotalAnomalies = filteredCount;
    }

    public void Clear()
    {
        TotalAnomalies = 0;
        CriticalCount = 0;
        HighCount = 0;
        MediumCount = 0;
        LowCount = 0;
        UniqueSourceIPs = 0;
        UniqueTargetIPs = 0;
        TimeSpanFormatted = "--";
        IsFiltered = false;
        FilteredTotalAnomalies = 0;
        TopSources.Clear();
        TopTargets.Clear();
        TopPorts.Clear();
        CategoryBreakdown.Clear();
    }
}
