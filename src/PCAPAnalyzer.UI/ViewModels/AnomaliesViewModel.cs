using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Main ViewModel for the Anomalies tab.
/// Orchestrates component ViewModels and manages anomaly data.
/// </summary>
public partial class AnomaliesViewModel : ObservableObject, ITabPopulationTarget, IDisposable
{
    private readonly IDispatcherService _dispatcher;
    private readonly IAnomalyFrameIndexService _frameIndexService;
    private readonly GlobalFilterState _globalFilterState;
    private readonly IGeoIPService _geoIPService;
    private readonly ILogger<AnomaliesViewModel> _logger;

    private List<NetworkAnomaly> _allAnomalies = [];
    private List<NetworkAnomaly> _filteredAnomalies = [];
    private List<PacketInfo> _allPackets = [];
    private CancellationTokenSource? _filterCts;
    private bool _disposed;

    // Component ViewModels
    public AnomaliesStatisticsViewModel Statistics { get; }
    public AnomaliesChartsViewModel Charts { get; }
    public AnomaliesDrillDownViewModel DrillDown { get; }
    public AnomaliesFilterViewModel Filters { get; }
    public AnomaliesPacketTableViewModel PacketTable { get; }

    // Loading state
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _hasData;
    [ObservableProperty] private string _loadingMessage = "Loading anomalies...";

    // Filter progress
    [ObservableProperty] private bool _isFiltering;
    [ObservableProperty] private double _filterProgress;

    // ITabPopulationTarget implementation
    public string TabName => "Anomalies";

    public AnomaliesViewModel(
        IDispatcherService dispatcher,
        IAnomalyFrameIndexService frameIndexService,
        GlobalFilterState globalFilterState,
        IGeoIPService geoIPService,
        ILogger<AnomaliesViewModel> logger)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _frameIndexService = frameIndexService;
        _globalFilterState = globalFilterState;
        _geoIPService = geoIPService;
        _logger = logger;

        // Initialize component ViewModels
        Statistics = new();
        Charts = new();
        DrillDown = new();
        Filters = new AnomaliesFilterViewModel(globalFilterState);
        PacketTable = new();

        // Subscribe to filter changes
        Filters.FiltersChanged += OnFiltersChanged;
        _globalFilterState.PropertyChanged += OnGlobalFilterStateChanged;
        _globalFilterState.OnFilterChanged += OnGlobalFilterGroupsChanged;
    }

    /// <summary>
    /// ITabPopulationTarget implementation - populate from cached analysis result.
    /// </summary>
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        _logger.LogInformation("PopulateFromCacheAsync called with {Count} anomalies", result.Anomalies?.Count ?? 0);

        if (result.Anomalies is null || result.Anomalies.Count == 0)
        {
            _logger.LogWarning("No anomalies in AnalysisResult");
            HasData = false;
            return;
        }

        // Store packets for packet table
        _allPackets = result.AllPackets ?? new List<PacketInfo>();

        await LoadFromAnalysisResultAsync(result.Anomalies);
    }

    public async Task LoadFromAnalysisResultAsync(List<NetworkAnomaly> anomalies)
    {
        if (anomalies is null)
        {
            _logger.LogWarning("LoadFromAnalysisResultAsync called with null anomalies");
            HasData = false;
            return;
        }

        IsLoading = true;
        LoadingMessage = "Loading anomalies...";

        try
        {
            _allAnomalies = anomalies.ToList();
            _filteredAnomalies = _allAnomalies;

            // Build frame index for cross-tab filtering
            _frameIndexService.BuildIndex(_allAnomalies);

            // Populate available detectors in filter panel
            Filters.SetAvailableDetectors(_frameIndexService.GetDetectorNames());

            await UpdateAllComponentsAsync();

            HasData = _allAnomalies.Count > 0;
            _logger.LogInformation("Loaded {Count} anomalies", _allAnomalies.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading anomalies");
            HasData = false;
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task UpdateAllComponentsAsync()
    {
        await Task.Run(() =>
        {
            var kpis = CalculateKPIs(_filteredAnomalies);
            var timePoints = BuildTimelineSeries(_filteredAnomalies);
            var sources = BuildRankedSources(_filteredAnomalies);
            var targets = BuildRankedTargets(_filteredAnomalies);
            var ports = BuildPortBreakdown(_filteredAnomalies);
            var categories = BuildCategoryBreakdown(_filteredAnomalies);

            _dispatcher.Post(() =>
            {
                Statistics.UpdateKPIs(kpis);
                Statistics.UpdateTopSources(sources);
                Statistics.UpdateTopTargets(targets);
                Statistics.UpdateTopPorts(ports);
                Statistics.UpdateCategoryBreakdown(categories);
                Statistics.SetFilteredState(
                    _filteredAnomalies.Count != _allAnomalies.Count,
                    _filteredAnomalies.Count);

                Charts.UpdateTimeline(timePoints);
                Charts.UpdateCategoryDonut(categories);
                Charts.UpdatePortsBar(ports);

                // Update packet table with filtered anomalies
                PacketTable.LoadPackets(_allPackets, _filteredAnomalies);
            });
        });
    }

    private AnomalyKPIs CalculateKPIs(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new AnomalyKPIs();

        var timestamps = anomalies
            .Select(a => a.DetectedAt)
            .OrderBy(t => t)
            .ToList();

        return new AnomalyKPIs
        {
            TotalAnomalies = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            UniqueSourceIPs = anomalies.Select(a => a.SourceIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            UniqueTargetIPs = anomalies.Select(a => a.DestinationIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            FirstAnomalyTime = timestamps.FirstOrDefault(),
            LastAnomalyTime = timestamps.LastOrDefault(),
            TimeSpan = timestamps.Count > 1 ? timestamps.Last() - timestamps.First() : TimeSpan.Zero
        };
    }

    private List<AnomalyTimePoint> BuildTimelineSeries(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyTimePoint>();

        // Group by second for fine-grained timeline
        var grouped = anomalies
            .GroupBy(a => new DateTime(
                a.DetectedAt.Year, a.DetectedAt.Month, a.DetectedAt.Day,
                a.DetectedAt.Hour, a.DetectedAt.Minute, a.DetectedAt.Second))
            .OrderBy(g => g.Key);

        return grouped.Select(g => new AnomalyTimePoint
        {
            Timestamp = g.Key,
            CriticalCount = g.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = g.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = g.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = g.Count(a => a.Severity == AnomalySeverity.Low)
        }).ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedSources(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.SourceIP))
            .GroupBy(a => a.SourceIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedTargets(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.DestinationIP))
            .GroupBy(a => a.DestinationIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private AnomalyEndpointViewModel BuildEndpointViewModel(string ip, List<NetworkAnomaly> anomalies)
    {
        var total = _filteredAnomalies.Count > 0 ? _filteredAnomalies.Count : 1;
        // GetLocationAsync is async, but we're in a sync method. For now, use sync wrapper or defaults.
        // TODO: Refactor to async if needed for GeoIP enrichment
        var geoInfo = Task.Run(() => _geoIPService.GetLocationAsync(ip)).GetAwaiter().GetResult();

        return new AnomalyEndpointViewModel
        {
            IpAddress = ip,
            AnomalyCount = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            HighestSeverity = anomalies.Max(a => a.Severity),
            Percentage = (double)anomalies.Count / total * 100,
            Country = geoInfo?.CountryName ?? "Unknown",
            CountryCode = geoInfo?.CountryCode ?? "",
            Categories = anomalies.Select(a => a.Category).Distinct().ToList(),
            AffectedFrames = anomalies.SelectMany(a => a.AffectedFrames ?? Enumerable.Empty<long>()).Distinct().ToList()
        };
    }

    private List<AnomalyPortViewModel> BuildPortBreakdown(List<NetworkAnomaly> anomalies)
    {
        var portAnomalies = anomalies
            .Where(a => a.DestinationPort > 0)
            .GroupBy(a => a.DestinationPort)
            .Select(g => new AnomalyPortViewModel
            {
                Port = g.Key,
                ServiceName = ThreatDisplayHelpers.GetServiceName(g.Key),
                AnomalyCount = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100,
                HighestSeverity = g.Max(a => a.Severity),
                AffectedFrames = g.SelectMany(a => a.AffectedFrames ?? Enumerable.Empty<long>()).Distinct().ToList()
            })
            .OrderByDescending(p => p.AnomalyCount)
            .Take(15)
            .Select((p, i) => { p.Rank = i + 1; return p; })
            .ToList();

        return portAnomalies;
    }

    private List<AnomalyCategoryViewModel> BuildCategoryBreakdown(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyCategoryViewModel>();

        return anomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100
            })
            .OrderByDescending(c => c.Count)
            .ToList();
    }

    private void OnFiltersChanged(object? sender, EventArgs e)
    {
        _ = ApplyFiltersAsync();
    }

    private void OnGlobalFilterStateChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // React to anomaly filter changes
        if (e.PropertyName is "AnomalySeverityFilter" or "AnomalyCategoryFilter" or "AnomalyDetectorFilter")
        {
            _ = ApplyFiltersAsync();
        }
    }

    /// <summary>
    /// Handles GlobalFilterState.OnFilterChanged - when filter groups are added/removed from UnifiedFilterPanel.
    /// </summary>
    private void OnGlobalFilterGroupsChanged()
    {
        _logger.LogDebug("[AnomaliesViewModel] GlobalFilterState groups changed - reapplying filters");
        _ = ApplyFiltersAsync();
    }

    [RelayCommand]
    private async Task ApplyFiltersAsync()
    {
        _filterCts?.Cancel();
        _filterCts = new();
        var token = _filterCts.Token;

        IsFiltering = true;
        FilterProgress = 0;

        try
        {
            _filteredAnomalies = await Task.Run(() =>
            {
                var result = _frameIndexService.GetFilteredAnomalies(
                    _globalFilterState.AnomalySeverityFilter.Count > 0 ? _globalFilterState.AnomalySeverityFilter : null,
                    _globalFilterState.AnomalyCategoryFilter.Count > 0 ? _globalFilterState.AnomalyCategoryFilter : null,
                    _globalFilterState.AnomalyDetectorFilter.Count > 0 ? _globalFilterState.AnomalyDetectorFilter : null);

                // Apply IP filters from IncludeFilters/ExcludeFilters if set
                var filtered = result.AsEnumerable();

                if (_globalFilterState.IncludeFilters.IPs.Count > 0)
                {
                    filtered = filtered.Where(a =>
                        _globalFilterState.IncludeFilters.IPs.Contains(a.SourceIP) ||
                        _globalFilterState.IncludeFilters.IPs.Contains(a.DestinationIP));
                }

                if (_globalFilterState.ExcludeFilters.IPs.Count > 0)
                {
                    filtered = filtered.Where(a =>
                        !_globalFilterState.ExcludeFilters.IPs.Contains(a.SourceIP) &&
                        !_globalFilterState.ExcludeFilters.IPs.Contains(a.DestinationIP));
                }

                // Apply FilterGroups from UnifiedFilterPanel (Include groups - OR'd together)
                if (_globalFilterState.IncludeGroups.Count > 0)
                {
                    filtered = filtered.Where(a => MatchesAnyIncludeGroup(a));
                }

                // Apply FilterGroups from UnifiedFilterPanel (Exclude groups - packets NOT matching)
                if (_globalFilterState.ExcludeGroups.Count > 0)
                {
                    filtered = filtered.Where(a => !MatchesAnyExcludeGroup(a));
                }

                return filtered.ToList();
            }, token);

            FilterProgress = 50;

            if (!token.IsCancellationRequested)
            {
                await UpdateAllComponentsAsync();
                FilterProgress = 100;
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Filter operation cancelled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error applying filters");
        }
        finally
        {
            IsFiltering = false;
        }
    }

    /// <summary>
    /// Checks if an anomaly matches ANY of the include groups (OR logic between groups).
    /// </summary>
    private bool MatchesAnyIncludeGroup(NetworkAnomaly anomaly)
    {
        foreach (var group in _globalFilterState.IncludeGroups)
        {
            if (MatchesFilterGroup(anomaly, group))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if an anomaly matches ANY of the exclude groups (OR logic between groups).
    /// </summary>
    private bool MatchesAnyExcludeGroup(NetworkAnomaly anomaly)
    {
        foreach (var group in _globalFilterState.ExcludeGroups)
        {
            if (MatchesFilterGroup(anomaly, group))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if an anomaly matches ALL criteria in a filter group (AND logic within group).
    /// </summary>
    private static bool MatchesFilterGroup(NetworkAnomaly anomaly, FilterGroup group)
    {
        // Source IP filter
        if (!string.IsNullOrWhiteSpace(group.SourceIP))
        {
            if (!Core.Services.NetworkHelper.MatchesIpPattern(anomaly.SourceIP, group.SourceIP))
                return false;
        }

        // Destination IP filter
        if (!string.IsNullOrWhiteSpace(group.DestinationIP))
        {
            if (!Core.Services.NetworkHelper.MatchesIpPattern(anomaly.DestinationIP, group.DestinationIP))
                return false;
        }

        // Port range filter
        if (!string.IsNullOrWhiteSpace(group.PortRange))
        {
            if (!MatchesPortRange(anomaly.SourcePort, anomaly.DestinationPort, group.PortRange))
                return false;
        }

        // Protocol filter (comma-separated list)
        if (!string.IsNullOrWhiteSpace(group.Protocol))
        {
            var protocols = group.Protocol.Split(',', StringSplitOptions.RemoveEmptyEntries);
            var anomalyProtocol = anomaly.Protocol ?? "";
            if (!protocols.Any(p => anomalyProtocol.Equals(p.Trim(), StringComparison.OrdinalIgnoreCase)))
                return false;
        }

        // Anomaly severity filter (from Anomalies filter tab)
        if (group.AnomalySeverities?.Count > 0)
        {
            var severityStr = anomaly.Severity.ToString();
            if (!group.AnomalySeverities.Any(s => s.Equals(severityStr, StringComparison.OrdinalIgnoreCase)))
                return false;
        }

        // Anomaly category filter (from Anomalies filter tab)
        if (group.AnomalyCategories?.Count > 0)
        {
            var categoryStr = anomaly.Category.ToString();
            if (!group.AnomalyCategories.Any(c => c.Equals(categoryStr, StringComparison.OrdinalIgnoreCase)))
                return false;
        }

        // Anomaly detector filter (from Anomalies filter tab)
        if (group.AnomalyDetectors?.Count > 0)
        {
            if (!group.AnomalyDetectors.Contains(anomaly.DetectorName))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Checks if source or destination port matches a port range (e.g., "80", "80-443").
    /// </summary>
    private static bool MatchesPortRange(int sourcePort, int destPort, string portRange)
    {
        if (int.TryParse(portRange, out var singlePort))
        {
            return sourcePort == singlePort || destPort == singlePort;
        }

        if (portRange.Contains('-', StringComparison.Ordinal))
        {
            var parts = portRange.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out var start) && int.TryParse(parts[1], out var end))
            {
                return (sourcePort >= start && sourcePort <= end) ||
                       (destPort >= start && destPort <= end);
            }
        }

        return true; // If port range is invalid, don't filter
    }

    [RelayCommand]
    private void ShowSourceDrillDown(AnomalyEndpointViewModel source)
    {
        var sourceAnomalies = _filteredAnomalies
            .Where(a => a.SourceIP == source.IpAddress)
            .ToList();

        DrillDown.ShowSourceDetail(source.IpAddress, sourceAnomalies);

        // Filter packet table to show packets from this source
        PacketTable.FilterBySource(source.IpAddress);
    }

    [RelayCommand]
    private void ShowTargetDrillDown(AnomalyEndpointViewModel target)
    {
        var targetAnomalies = _filteredAnomalies
            .Where(a => a.DestinationIP == target.IpAddress)
            .ToList();

        DrillDown.ShowTargetDetail(target.IpAddress, targetAnomalies);

        // Filter packet table to show packets to this target
        PacketTable.FilterByTarget(target.IpAddress);
    }

    [RelayCommand]
    private void ShowPortDrillDown(AnomalyPortViewModel port)
    {
        var portAnomalies = _filteredAnomalies
            .Where(a => a.DestinationPort == port.Port)
            .ToList();

        var serviceName = string.IsNullOrEmpty(port.ServiceName) ? port.Port.ToString() : $"{port.Port} ({port.ServiceName})";
        DrillDown.ShowPortDetail(serviceName, portAnomalies);

        // Filter packet table to show packets on this port
        PacketTable.FilterByPort(port.Port);
    }

    [RelayCommand]
    private void ShowTimeSliceDrillDown(DateTime timestamp)
    {
        DrillDown.ShowTimeSliceDrillDown(timestamp, TimeSpan.FromMinutes(5), _filteredAnomalies);

        // Filter packet table to show packets in this time window
        PacketTable.FilterByTimeWindow(timestamp, TimeSpan.FromMinutes(5));
    }

    [RelayCommand]
    private void ShowTimePointDetails(DateTime timestamp)
    {
        // Show detailed popup for anomalies at this time point (±30 seconds window)
        DrillDown.ShowTimePointDetails(timestamp, TimeSpan.FromSeconds(30), _filteredAnomalies);

        // Filter packet table to show packets in this time window
        PacketTable.FilterByTimeWindow(timestamp, TimeSpan.FromSeconds(30));
    }

    [RelayCommand]
    private void ShowCategoryDrillDown(AnomalyCategoryViewModel category)
    {
        var categoryAnomalies = _filteredAnomalies
            .Where(a => a.Category == category.Category)
            .ToList();

        DrillDown.ShowCategoryDetail(category.Category.ToString(), categoryAnomalies);

        // Filter packet table to show packets of this category
        PacketTable.FilterByCategory(category.Category);
    }

    public void Clear()
    {
        _allAnomalies.Clear();
        _filteredAnomalies.Clear();
        _allPackets.Clear();
        _frameIndexService.ClearIndex();
        Statistics.Clear();
        Charts.Clear();
        DrillDown.Clear();
        PacketTable.Clear();
        HasData = false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Filters.FiltersChanged -= OnFiltersChanged;
        _globalFilterState.PropertyChanged -= OnGlobalFilterStateChanged;
        _globalFilterState.OnFilterChanged -= OnGlobalFilterGroupsChanged;
        _filterCts?.Cancel();
        _filterCts?.Dispose();
    }
}
