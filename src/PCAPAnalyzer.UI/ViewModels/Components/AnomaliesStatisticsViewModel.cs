using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
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

    // Filtered state and Total/Filtered display pattern
    [ObservableProperty] private bool _isFiltered;
    [ObservableProperty] private int _filteredTotalAnomalies;

    // ==================== PACKET-LEVEL FILTERED STATISTICS ====================

    /// <summary>
    /// Filtered packet count (from global filter application)
    /// </summary>
    [ObservableProperty] private long _filteredTotalPackets;

    /// <summary>
    /// Unfiltered packet count (stored on first load)
    /// </summary>
    [ObservableProperty] private long _unfilteredTotalPackets;

    /// <summary>
    /// Indicates if global filter is active (packet-level)
    /// </summary>
    [ObservableProperty] private bool _isPacketFilterActive;

    /// <summary>
    /// Percentage of packets shown after filtering
    /// </summary>
    public double FilteredPacketsPercentage => UnfilteredTotalPackets > 0
        ? (FilteredTotalPackets * 100.0 / UnfilteredTotalPackets)
        : 100;

    // Unfiltered totals (stored on initial load, before any filters)
    [ObservableProperty] private int _totalAnomaliesAll;
    [ObservableProperty] private int _criticalCountAll;
    [ObservableProperty] private int _highCountAll;
    [ObservableProperty] private int _mediumCountAll;
    [ObservableProperty] private int _lowCountAll;

    // Percentage calculations for Total/Filtered display
    public double TotalAnomaliesPercentage => TotalAnomaliesAll > 0 ? (TotalAnomalies * 100.0 / TotalAnomaliesAll) : 0;
    public double CriticalCountPercentage => CriticalCountAll > 0 ? (CriticalCount * 100.0 / CriticalCountAll) : 0;
    public double HighCountPercentage => HighCountAll > 0 ? (HighCount * 100.0 / HighCountAll) : 0;
    public double MediumCountPercentage => MediumCountAll > 0 ? (MediumCount * 100.0 / MediumCountAll) : 0;
    public double LowCountPercentage => LowCountAll > 0 ? (LowCount * 100.0 / LowCountAll) : 0;

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
        NotifyPercentageChanges();
    }

    /// <summary>
    /// Stores unfiltered totals for Total/Filtered display pattern.
    /// Call this when data is first loaded before any filters are applied.
    /// </summary>
    public void StoreUnfilteredTotals(AnomalyKPIs kpis)
    {
        TotalAnomaliesAll = kpis.TotalAnomalies;
        CriticalCountAll = kpis.CriticalCount;
        HighCountAll = kpis.HighCount;
        MediumCountAll = kpis.MediumCount;
        LowCountAll = kpis.LowCount;
    }

    /// <summary>
    /// Notifies UI of percentage property changes (computed properties don't auto-notify).
    /// </summary>
    private void NotifyPercentageChanges()
    {
        OnPropertyChanged(nameof(TotalAnomaliesPercentage));
        OnPropertyChanged(nameof(CriticalCountPercentage));
        OnPropertyChanged(nameof(HighCountPercentage));
        OnPropertyChanged(nameof(MediumCountPercentage));
        OnPropertyChanged(nameof(LowCountPercentage));
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

    // ==================== PACKET-LEVEL FILTERED STATE METHODS ====================

    /// <summary>
    /// Stores unfiltered packet totals for Total/Filtered display pattern.
    /// Call this when data is first loaded, before any filters are applied.
    /// </summary>
    public void StoreUnfilteredPacketTotals(long packetCount)
    {
        UnfilteredTotalPackets = packetCount;
        FilteredTotalPackets = packetCount;
        IsPacketFilterActive = false;
        DebugLogger.Log($"[AnomaliesStatisticsViewModel] Stored unfiltered packet totals: {UnfilteredTotalPackets:N0} packets");
    }

    /// <summary>
    /// Sets packet-level filtered state for Total/Filtered display pattern.
    /// Call this when global filters are applied.
    /// </summary>
    public void SetPacketFilteredState(long filteredPacketCount, bool isFiltered)
    {
        FilteredTotalPackets = filteredPacketCount;
        IsPacketFilterActive = isFiltered;
        OnPropertyChanged(nameof(FilteredPacketsPercentage));
        DebugLogger.Log($"[AnomaliesStatisticsViewModel] SetPacketFilteredState: {filteredPacketCount:N0} packets (isFiltered={isFiltered}, {FilteredPacketsPercentage:F1}%)");
    }

    /// <summary>
    /// Clears packet-level filtered state, restoring unfiltered display.
    /// Call when filters are cleared.
    /// </summary>
    public void ClearPacketFilteredState()
    {
        FilteredTotalPackets = UnfilteredTotalPackets;
        IsPacketFilterActive = false;
        OnPropertyChanged(nameof(FilteredPacketsPercentage));
        DebugLogger.Log("[AnomaliesStatisticsViewModel] Cleared packet filtered state");
    }
}
