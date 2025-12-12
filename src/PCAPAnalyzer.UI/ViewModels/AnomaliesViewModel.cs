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
using PCAPAnalyzer.UI.Utilities;
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
    private CancellationTokenSource? _geoIPCts;
    private bool _disposed;

    // GeoIP throttling: max 5 concurrent lookups to avoid overwhelming the service
    private static readonly SemaphoreSlim _geoIPThrottle = new(5, 5);

    /// <summary>
    /// Maps UI detector chip names to actual anomaly Type values.
    /// UI shows user-friendly attack names; data contains full type strings.
    /// </summary>
    private static readonly Dictionary<string, HashSet<string>> DetectorTypeMapping =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Network anomalies
            ["SYN Flood"] = ["SYN Flood Attack", "SYN Flood"],
            ["ARP Spoofing"] = ["ARP Spoofing"],
            ["ICMP Flood"] = ["ICMP Flood"],

            // Application anomalies
            ["DNS Tunneling"] = ["DNS Tunneling"],
            ["Beaconing"] = ["Beaconing"],

            // Security anomalies
            ["Cryptomining"] = ["Cryptomining", "Cryptomining Pool Scanning", "Stratum Mining Protocol"],
            ["Data Exfiltration"] = ["Data Exfiltration", "Slow Data Exfiltration",
                                      "Encoded Data Transfer", "Unusual Outbound Traffic"],

            // TCP anomalies
            ["TCP Retransmission"] = ["TCP Retransmission"],
            ["Duplicate ACK"] = ["TCP Duplicate ACK"],

            // VoIP anomalies
            ["VoIP Flooding"] = ["VoIP SIP Flooding"],

            // IoT anomalies
            ["IoT Flooding"] = ["IoT MQTT Flooding", "IoT CoAP Amplification"]
        };

    // Component ViewModels
    public AnomaliesStatisticsViewModel Statistics { get; }
    public AnomaliesChartsViewModel Charts { get; }
    public AnomaliesDrillDownViewModel DrillDown { get; }
    public AnomaliesFilterViewModel Filters { get; }
    public AnomaliesPacketTableViewModel PacketTable { get; }

    // StatsBarControl for unified statistics display
    public StatsBarControlViewModel AnomaliesStatsBar { get; } = new()
    {
        SectionTitle = "ANOMALY OVERVIEW",
        AccentColor = ThemeColorHelper.GetColorHex("SlackDanger", "#DA3633"),
        ColumnCount = 6
    };

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
        ArgumentNullException.ThrowIfNull(dispatcher);
        _dispatcher = dispatcher;
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
        // NOTE: Using OnFiltersApplied (not OnFilterChanged) to avoid auto-apply on chip removal
        _globalFilterState.OnFiltersApplied += OnGlobalFilterGroupsChanged;
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

        // Store unfiltered packet totals for Total/Filtered display pattern
        Statistics.StoreUnfilteredPacketTotals(result.AllPackets?.Count ?? 0);
    }

    /// <summary>
    /// Sets the filtered packet set and re-filters anomalies based on filtered packet frame numbers.
    /// Called by MainWindowViewModel when global filters are applied.
    /// Unlike Threats/VoiceQoS which re-analyze, anomalies are pre-calculated so we filter by frame numbers.
    /// </summary>
    /// <param name="filteredPackets">The filtered packet list from PacketManager</param>
    public async Task SetFilteredPacketsAsync(IReadOnlyList<PacketInfo> filteredPackets)
    {
        _logger.LogInformation("SetFilteredPacketsAsync called with {Count} filtered packets", filteredPackets.Count);

        if (_allAnomalies.Count == 0)
        {
            _logger.LogWarning("SetFilteredPacketsAsync called but no anomalies loaded");
            return;
        }

        IsLoading = true;
        LoadingMessage = "Filtering anomalies...";

        try
        {
            // Build set of frame numbers from filtered packets for O(1) lookup
            var filteredFrameNumbers = new HashSet<long>(filteredPackets.Select(p => (long)p.FrameNumber));

            // Filter anomalies: keep only those whose affected frames overlap with filtered packets
            _filteredAnomalies = await Task.Run(() =>
            {
                return _allAnomalies
                    .Where(a =>
                    {
                        // If anomaly has no affected frames, check if source/dest IPs are in filtered packets
                        if (a.AffectedFrames is null || a.AffectedFrames.Count == 0)
                        {
                            return filteredPackets.Any(p =>
                                p.SourceIP == a.SourceIP || p.DestinationIP == a.SourceIP ||
                                p.SourceIP == a.DestinationIP || p.DestinationIP == a.DestinationIP);
                        }

                        // Anomaly has affected frames - check if any overlap with filtered packets
                        return a.AffectedFrames.Any(f => filteredFrameNumbers.Contains(f));
                    })
                    .ToList();
            });

            _logger.LogInformation("Filtered from {AllCount} to {FilteredCount} anomalies based on {PacketCount} filtered packets",
                _allAnomalies.Count, _filteredAnomalies.Count, filteredPackets.Count);

            // Update Statistics component with filtered packet count for Total/Filtered header display
            Statistics.SetPacketFilteredState(filteredPackets.Count, isFiltered: true);

            // Update all UI components with filtered data
            await UpdateAllComponentsAsync();

            HasData = _filteredAnomalies.Count > 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error filtering anomalies");
        }
        finally
        {
            IsLoading = false;
        }
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

            // Store unfiltered totals for Total/Filtered display pattern
            var unfilteredKPIs = CalculateKPIs(_allAnomalies);
            Statistics.StoreUnfilteredTotals(unfilteredKPIs);

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
        // Cancel any pending GeoIP enrichment from previous update
        _geoIPCts?.Cancel();
        _geoIPCts = new CancellationTokenSource();
        var geoIPToken = _geoIPCts.Token;

        var (kpis, timePoints, sources, targets, ports, categories) = await Task.Run(() =>
        {
            var k = CalculateKPIs(_filteredAnomalies);
            var t = BuildTimelineSeries(_filteredAnomalies);
            var s = BuildRankedSources(_filteredAnomalies);
            var tg = BuildRankedTargets(_filteredAnomalies);
            var p = BuildPortBreakdown(_filteredAnomalies);
            var c = BuildCategoryBreakdown(_filteredAnomalies);
            return (k, t, s, tg, p, c);
        });

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

            // Update unified stats bar
            UpdateAnomaliesStatsBar();

            Charts.UpdateTimeline(timePoints);
            Charts.UpdateCategoryDonut(categories);
            Charts.UpdatePortsBar(ports);

            // Update packet table with filtered anomalies
            PacketTable.LoadPackets(_allPackets, _filteredAnomalies);
        });

        // Batch GeoIP enrichment with throttling (tracked, not fire-and-forget)
        var allEndpoints = sources.Concat(targets).ToList();
        if (allEndpoints.Count > 0)
        {
            _ = EnrichEndpointsGeoIPBatchAsync(allEndpoints, geoIPToken);
        }
    }

    /// <summary>
    /// Batch GeoIP enrichment with SemaphoreSlim throttling.
    /// Max 5 concurrent requests to avoid overwhelming the GeoIP service.
    /// </summary>
    private async Task EnrichEndpointsGeoIPBatchAsync(
        List<AnomalyEndpointViewModel> endpoints,
        CancellationToken cancellationToken)
    {
        try
        {
            var tasks = endpoints.Select(async endpoint =>
            {
                await _geoIPThrottle.WaitAsync(cancellationToken);
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;

                    var geoInfo = await _geoIPService.GetLocationAsync(endpoint.IpAddress);

                    // Update on UI thread
                    _dispatcher.Post(() =>
                    {
                        endpoint.Country = geoInfo?.CountryName ?? "Unknown";
                        endpoint.CountryCode = geoInfo?.CountryCode ?? "";
                    });
                }
                catch (OperationCanceledException)
                {
                    // Expected when filter changes rapidly
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "GeoIP lookup failed for {IP}", endpoint.IpAddress);
                    _dispatcher.Post(() =>
                    {
                        endpoint.Country = "Unknown";
                        endpoint.CountryCode = "";
                    });
                }
                finally
                {
                    _geoIPThrottle.Release();
                }
            });

            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("GeoIP batch enrichment cancelled");
        }
    }

    /// <summary>
    /// Calculates KPIs using single-pass aggregation.
    /// Previous: 9 collection traversals. Now: 1 traversal with HashSets.
    /// </summary>
    private static AnomalyKPIs CalculateKPIs(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new AnomalyKPIs();

        // Single-pass aggregation with severity buckets
        int critical = 0, high = 0, medium = 0, low = 0;
        var sourceIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var targetIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var minTime = DateTime.MaxValue;
        var maxTime = DateTime.MinValue;

        foreach (var anomaly in anomalies)
        {
            // Count by severity
            switch (anomaly.Severity)
            {
                case AnomalySeverity.Critical: critical++; break;
                case AnomalySeverity.High: high++; break;
                case AnomalySeverity.Medium: medium++; break;
                case AnomalySeverity.Low: low++; break;
            }

            // Track unique IPs
            if (!string.IsNullOrEmpty(anomaly.SourceIP))
                sourceIPs.Add(anomaly.SourceIP);
            if (!string.IsNullOrEmpty(anomaly.DestinationIP))
                targetIPs.Add(anomaly.DestinationIP);

            // Track time range
            if (anomaly.DetectedAt < minTime) minTime = anomaly.DetectedAt;
            if (anomaly.DetectedAt > maxTime) maxTime = anomaly.DetectedAt;
        }

        return new AnomalyKPIs
        {
            TotalAnomalies = anomalies.Count,
            CriticalCount = critical,
            HighCount = high,
            MediumCount = medium,
            LowCount = low,
            UniqueSourceIPs = sourceIPs.Count,
            UniqueTargetIPs = targetIPs.Count,
            FirstAnomalyTime = minTime == DateTime.MaxValue ? default : minTime,
            LastAnomalyTime = maxTime == DateTime.MinValue ? default : maxTime,
            TimeSpan = minTime < maxTime ? maxTime - minTime : TimeSpan.Zero
        };
    }

    /// <summary>
    /// Builds timeline series using single-pass per group.
    /// Previous: 4 Count() calls per group. Now: 1 pass with severity buckets.
    /// </summary>
    private static List<AnomalyTimePoint> BuildTimelineSeries(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return [];

        // Use Dictionary for O(1) lookup instead of GroupBy + OrderBy
        var buckets = new SortedDictionary<DateTime, (int Critical, int High, int Medium, int Low)>();

        foreach (var anomaly in anomalies)
        {
            // Truncate to second - use date math instead of constructor
            var key = anomaly.DetectedAt.AddTicks(-(anomaly.DetectedAt.Ticks % TimeSpan.TicksPerSecond));

            if (!buckets.TryGetValue(key, out var counts))
                counts = (0, 0, 0, 0);

            counts = anomaly.Severity switch
            {
                AnomalySeverity.Critical => (counts.Critical + 1, counts.High, counts.Medium, counts.Low),
                AnomalySeverity.High => (counts.Critical, counts.High + 1, counts.Medium, counts.Low),
                AnomalySeverity.Medium => (counts.Critical, counts.High, counts.Medium + 1, counts.Low),
                AnomalySeverity.Low => (counts.Critical, counts.High, counts.Medium, counts.Low + 1),
                _ => counts
            };

            buckets[key] = counts;
        }

        return buckets.Select(kvp => new AnomalyTimePoint
        {
            Timestamp = kvp.Key,
            CriticalCount = kvp.Value.Critical,
            HighCount = kvp.Value.High,
            MediumCount = kvp.Value.Medium,
            LowCount = kvp.Value.Low
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

    /// <summary>
    /// Builds endpoint view model for anomaly display.
    /// GeoIP enrichment is handled separately via EnrichEndpointsGeoIPBatchAsync.
    /// </summary>
    private AnomalyEndpointViewModel BuildEndpointViewModel(string ip, List<NetworkAnomaly> anomalies)
    {
        var total = _filteredAnomalies.Count > 0 ? _filteredAnomalies.Count : 1;

        // Single-pass severity counting instead of 4 separate Count() calls
        int critical = 0, high = 0, medium = 0, low = 0;
        var highestSeverity = AnomalySeverity.Low;

        foreach (var a in anomalies)
        {
            switch (a.Severity)
            {
                case AnomalySeverity.Critical: critical++; break;
                case AnomalySeverity.High: high++; break;
                case AnomalySeverity.Medium: medium++; break;
                case AnomalySeverity.Low: low++; break;
            }
            if (a.Severity > highestSeverity)
                highestSeverity = a.Severity;
        }

        return new AnomalyEndpointViewModel
        {
            IpAddress = ip,
            AnomalyCount = anomalies.Count,
            CriticalCount = critical,
            HighCount = high,
            MediumCount = medium,
            LowCount = low,
            HighestSeverity = highestSeverity,
            Percentage = (double)anomalies.Count / total * 100,
            Country = "Loading...",  // Will be enriched by EnrichEndpointsGeoIPBatchAsync
            CountryCode = "",
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
        // NOTE: UI chips use attack type names (e.g., "SYN Flood"), but anomaly.DetectorName
        // contains detector class names (e.g., "Network Anomaly Detector").
        // We check both anomaly.Type (preferred) and DetectorName for flexibility.
        if (group.AnomalyDetectors?.Count > 0)
        {
            if (!MatchesAnyDetectorType(anomaly, group.AnomalyDetectors))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Checks if an anomaly matches any of the specified detector/type filters.
    /// Supports both UI chip names (mapped to Types) and actual DetectorName values.
    /// </summary>
    private static bool MatchesAnyDetectorType(NetworkAnomaly anomaly, List<string> detectorFilters)
    {
        foreach (var filter in detectorFilters)
        {
            // First, try mapping UI chip name → actual Type values
            if (DetectorTypeMapping.TryGetValue(filter, out var typeMatches))
            {
                // Check if anomaly.Type matches any of the mapped types
                if (typeMatches.Any(t => anomaly.Type.Equals(t, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }

            // Fallback: direct match on DetectorName (for dynamically populated detector lists)
            if (anomaly.DetectorName.Equals(filter, StringComparison.OrdinalIgnoreCase))
                return true;

            // Fallback: contains match on Type (for partial matches like "SYN" in "SYN Flood Attack")
            if (anomaly.Type.Contains(filter, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
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

    /// <summary>
    /// Updates AnomaliesStatsBar with unified Total/Filtered display pattern.
    /// Call after updating KPIs or when filters change.
    /// </summary>
    private void UpdateAnomaliesStatsBar()
    {
        AnomaliesStatsBar.ClearStats();

        // Determine filter state
        var hasFilter = Statistics.IsFiltered ||
            _globalFilterState.HasActiveFilters;

        // Total Anomalies
        TabStatsHelper.AddNumericStat(AnomaliesStatsBar, "ANOMALIES", "🔍",
            Statistics.TotalAnomaliesAll, Statistics.TotalAnomalies, hasFilter,
            ThemeColorHelper.GetColorHex("AccentPrimary", "#58A6FF"));

        // Critical
        TabStatsHelper.AddNumericStat(AnomaliesStatsBar, "CRITICAL", "🔴",
            Statistics.CriticalCountAll, Statistics.CriticalCount, hasFilter,
            ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"));

        // High
        TabStatsHelper.AddNumericStat(AnomaliesStatsBar, "HIGH", "🟠",
            Statistics.HighCountAll, Statistics.HighCount, hasFilter,
            ThemeColorHelper.GetColorHex("ColorOrange", "#F97316"));

        // Unique Sources
        TabStatsHelper.AddSimpleStat(AnomaliesStatsBar, "SOURCES", "📤",
            Statistics.UniqueSourceIPs.ToString("N0"),
            ThemeColorHelper.GetColorHex("SlackInfo", "#58A6FF"));

        // Unique Targets
        TabStatsHelper.AddSimpleStat(AnomaliesStatsBar, "TARGETS", "🎯",
            Statistics.UniqueTargetIPs.ToString("N0"),
            ThemeColorHelper.GetColorHex("SlackDanger", "#DA3633"));

        // Time Span
        TabStatsHelper.AddSimpleStat(AnomaliesStatsBar, "TIME SPAN", "⏱️",
            Statistics.TimeSpanFormatted,
            ThemeColorHelper.GetColorHex("AccentSecondary", "#A371F7"));
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
        _globalFilterState.OnFiltersApplied -= OnGlobalFilterGroupsChanged;
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        _geoIPCts?.Cancel();
        _geoIPCts?.Dispose();
    }
}
