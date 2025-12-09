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
/// Uses fingerprinting to skip redundant UI updates when data is unchanged.
/// </summary>
public partial class AnomaliesStatisticsViewModel : ObservableObject
{
    // Fingerprints for early-exit optimization
    private string? _lastKPIsFingerprint;
    private string? _lastSourcesFingerprint;
    private string? _lastTargetsFingerprint;
    private string? _lastPortsFingerprint;
    private string? _lastCategoriesFingerprint;

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
        // Fingerprint check for early-exit
        var fingerprint = $"{kpis.TotalAnomalies}|{kpis.CriticalCount}|{kpis.HighCount}|{kpis.MediumCount}|{kpis.LowCount}|{kpis.UniqueSourceIPs}|{kpis.UniqueTargetIPs}|{kpis.TimeSpan.Ticks}";
        if (fingerprint == _lastKPIsFingerprint)
            return;
        _lastKPIsFingerprint = fingerprint;

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
        var sourceList = sources.Take(20).ToList();
        // Fingerprint: IP + count for each source
        var fingerprint = string.Join(";", sourceList.Select(s => $"{s.IpAddress}:{s.AnomalyCount}"));
        if (fingerprint == _lastSourcesFingerprint)
            return;
        _lastSourcesFingerprint = fingerprint;

        TopSources.Clear();
        foreach (var source in sourceList)
            TopSources.Add(source);
    }

    public void UpdateTopTargets(IEnumerable<AnomalyEndpointViewModel> targets)
    {
        var targetList = targets.Take(20).ToList();
        var fingerprint = string.Join(";", targetList.Select(t => $"{t.IpAddress}:{t.AnomalyCount}"));
        if (fingerprint == _lastTargetsFingerprint)
            return;
        _lastTargetsFingerprint = fingerprint;

        TopTargets.Clear();
        foreach (var target in targetList)
            TopTargets.Add(target);
    }

    public void UpdateTopPorts(IEnumerable<AnomalyPortViewModel> ports)
    {
        var portList = ports.Take(15).ToList();
        var fingerprint = string.Join(";", portList.Select(p => $"{p.Port}:{p.AnomalyCount}"));
        if (fingerprint == _lastPortsFingerprint)
            return;
        _lastPortsFingerprint = fingerprint;

        TopPorts.Clear();
        foreach (var port in portList)
            TopPorts.Add(port);
    }

    public void UpdateCategoryBreakdown(IEnumerable<AnomalyCategoryViewModel> categories)
    {
        // Categories already sorted by caller - no need to re-sort
        var categoryList = categories.ToList();
        var fingerprint = string.Join(";", categoryList.Select(c => $"{c.Category}:{c.Count}"));
        if (fingerprint == _lastCategoriesFingerprint)
            return;
        _lastCategoriesFingerprint = fingerprint;

        CategoryBreakdown.Clear();
        foreach (var cat in categoryList)
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

        // Reset fingerprints to allow fresh population
        _lastKPIsFingerprint = null;
        _lastSourcesFingerprint = null;
        _lastTargetsFingerprint = null;
        _lastPortsFingerprint = null;
        _lastCategoriesFingerprint = null;
    }
}
