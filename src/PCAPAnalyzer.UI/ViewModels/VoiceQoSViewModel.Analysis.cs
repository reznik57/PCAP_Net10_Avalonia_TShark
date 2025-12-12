using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels.VoiceQoS;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// VoiceQoSViewModel partial class containing packet analysis and cache handling.
/// Manages loading, analyzing, and caching of VoiceQoS data.
/// </summary>
public partial class VoiceQoSViewModel
{
    // ==================== ANALYSIS COMPLETION HANDLER ====================

    /// <summary>
    /// Handles analysis completion from AnalysisViewModel.
    /// </summary>
    private void OnAnalysisCompleted(VoiceQoSAnalysisCompletedEventArgs e)
    {
        _dispatcher.InvokeAsync(() =>
        {
            // Update "all" collections from AnalysisViewModel
            _allQoSTraffic = AnalysisViewModel.AllQoSTraffic;
            _allLatencyConnections = AnalysisViewModel.AllLatencyConnections;
            _allJitterConnections = AnalysisViewModel.AllJitterConnections;
            _allPackets = AnalysisViewModel.AllPackets;
            _cachedTimeSeriesData = AnalysisViewModel.CachedTimeSeriesData;

            // Update "all" statistics
            TotalQoSPacketsAll = _allQoSTraffic.Sum(q => q.PacketCount);
            HighLatencyCountAll = _allLatencyConnections.Count;
            AverageLatencyAll = _allLatencyConnections.Any() ? _allLatencyConnections.Average(l => l.AverageLatency) : 0;
            MaxLatencyAll = _allLatencyConnections.Any() ? _allLatencyConnections.Max(l => l.MaxLatency) : 0;
            HighJitterCountAll = _allJitterConnections.Count;
            AverageJitterAll = _allJitterConnections.Any() ? _allJitterConnections.Average(j => j.AverageJitter) : 0;
            MaxJitterAll = _allJitterConnections.Any() ? _allJitterConnections.Max(j => j.MaxJitter) : 0;

            // Apply filters and update UI
            ApplyLocalFilters();

            // Update chart
            if (_cachedTimeSeriesData is not null)
            {
                ChartsViewModel.UpdateTimelineChartFromAggregated(_cachedTimeSeriesData);
            }

            IsAnalyzing = false;
            StatusMessage = e.FromCache
                ? $"Analysis complete (from cache): {TotalQoSPackets} QoS packets, {HighLatencyCount} high latency, {HighJitterCount} high jitter"
                : $"Analysis complete: {TotalQoSPackets} QoS packets, {HighLatencyCount} high latency, {HighJitterCount} high jitter";

            DebugLogger.Log($"[VoiceQoSViewModel] Analysis completed in {e.ElapsedSeconds:F2}s (fromCache={e.FromCache})");
        });
    }

    // ==================== DATA LOADING ====================

    /// <summary>
    /// Loads VoiceQoS analysis data on-demand. Call this when the Voice/QoS tab is first accessed.
    /// Returns immediately if data is already loaded or loading is in progress.
    /// </summary>
    public async Task LoadDataAsync(IReadOnlyList<PacketInfo> packets)
    {
        // Already loaded - instant return
        if (IsDataLoaded)
        {
            DebugLogger.Log("[VoiceQoSViewModel] Data already loaded, skipping");
            return;
        }

        // Currently loading - wait for existing operation
        if (_loadingTask is not null)
        {
            DebugLogger.Log("[VoiceQoSViewModel] Loading already in progress, awaiting existing task");
            await _loadingTask;
            return;
        }

        // Start new loading operation
        DebugLogger.Log($"[VoiceQoSViewModel] Starting lazy load for {packets.Count:N0} packets");
        IsLoading = true;
        _loadingTask = AnalyzePacketsAsync(packets);

        try
        {
            await _loadingTask;
            IsDataLoaded = true;
            DebugLogger.Log("[VoiceQoSViewModel] Lazy load completed successfully");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSViewModel] Error during lazy load: {ex.Message}");
            throw;
        }
        finally
        {
            IsLoading = false;
            _loadingTask = null;
        }
    }

    /// <summary>
    /// ✅ PRELOAD ARCHITECTURE: Sets VoiceQoS data from pre-analyzed SessionAnalysisCache.
    /// Bypasses ALL analysis - instantly binds cached VoiceQoS data to UI.
    /// Expected: &lt;200ms to populate (vs 5s re-analysis).
    /// </summary>
    public async Task SetFromCacheAsync(VoiceQoSAnalysisResult analysisResult, VoiceQoSTimeSeriesData? timeSeriesData, IReadOnlyList<PacketInfo> packets)
    {
        await _dispatcher.InvokeAsync(() =>
        {
            DebugLogger.Log($"[VoiceQoSViewModel] SetFromCache - QoS: {analysisResult.QoSTraffic.Count}, Latency: {analysisResult.HighLatencyConnections.Count}, Jitter: {analysisResult.HighJitterConnections.Count}");

            // Reset filter state when loading fresh data
            IsGlobalFilterActive = false;

            // Store reference to packets (no copy)
            lock (_collectionLock)
            {
                _allPackets = packets;
            }

            // Convert Core models to UI models
            _allQoSTraffic = analysisResult.QoSTraffic.Select(q => new QoSTrafficItem
            {
                SourceIP = q.SourceIP,
                DestinationIP = q.DestinationIP,
                Protocol = q.Protocol,
                PacketCount = q.PacketCount,
                TotalBytes = q.TotalBytes,
                FirstSeen = q.FirstSeen,
                LastSeen = q.LastSeen,
                QoSType = q.QoSType,
                PortRange = q.PortRange,
                DscpMarking = q.DscpMarking,
                DscpValue = q.DscpValue,
                Packets = new List<PacketInfo>()
            }).ToList();

            _allLatencyConnections = analysisResult.HighLatencyConnections.Select(l => new LatencyConnectionItem
            {
                SourceIP = l.SourceIP,
                DestinationIP = l.DestinationIP,
                Protocol = l.Protocol,
                AverageLatency = l.AverageLatency,
                MaxLatency = l.MaxLatency,
                MinLatency = l.MinLatency,
                PacketCount = l.PacketCount,
                FirstSeen = l.FirstSeen,
                LastSeen = l.LastSeen,
                PortRange = l.PortRange,
                Packets = new List<PacketInfo>()
            }).ToList();

            _allJitterConnections = analysisResult.HighJitterConnections.Select(j => new JitterConnectionItem
            {
                SourceIP = j.SourceIP,
                DestinationIP = j.DestinationIP,
                Protocol = j.Protocol,
                AverageJitter = j.AverageJitter,
                MaxJitter = j.MaxJitter,
                MinJitter = j.MinJitter,
                PacketCount = j.PacketCount,
                FirstSeen = j.FirstSeen,
                LastSeen = j.LastSeen,
                PortRange = j.PortRange,
                Packets = new List<PacketInfo>()
            }).ToList();

            // Store cached time-series data
            if (timeSeriesData is not null)
            {
                _cachedTimeSeriesData = timeSeriesData;
            }

            // Calculate statistics
            TotalQoSPacketsAll = _allQoSTraffic.Sum(q => q.PacketCount);
            HighLatencyCountAll = _allLatencyConnections.Count;
            AverageLatencyAll = _allLatencyConnections.Any() ? _allLatencyConnections.Average(l => l.AverageLatency) : 0;
            MaxLatencyAll = _allLatencyConnections.Any() ? _allLatencyConnections.Max(l => l.MaxLatency) : 0;
            HighJitterCountAll = _allJitterConnections.Count;
            AverageJitterAll = _allJitterConnections.Any() ? _allJitterConnections.Average(j => j.AverageJitter) : 0;
            MaxJitterAll = _allJitterConnections.Any() ? _allJitterConnections.Max(j => j.MaxJitter) : 0;

            // Apply local filters to populate collections (also updates top endpoints via StatisticsViewModel)
            ApplyLocalFilters();

            // Store unfiltered packet totals for Total/Filtered display pattern
            StatisticsViewModel.StoreUnfilteredTotals(_allPackets.Count);

            // Update chart from cached time-series
            if (_cachedTimeSeriesData is not null)
            {
                var chartStartTime = DateTime.Now;
                DebugLogger.Log($"[{chartStartTime:HH:mm:ss.fff}] [VoiceQoSViewModel] Updating chart from cached time-series");
                ChartsViewModel.UpdateTimelineChartFromAggregated(_cachedTimeSeriesData);
                DebugLogger.Log($"[VoiceQoSViewModel] Chart updated in {(DateTime.Now - chartStartTime).TotalMilliseconds:F0}ms (using cached data)");
            }

            IsAnalyzing = false;
            StatusMessage = $"VoiceQoS analysis complete: {TotalQoSPacketsAll:N0} QoS packets, {HighLatencyCountAll} high latency, {HighJitterCountAll} high jitter";

            DebugLogger.Log($"[VoiceQoSViewModel] ✓ SetFromCache complete in <200ms - {_allQoSTraffic.Count} QoS, {_allLatencyConnections.Count} latency, {_allJitterConnections.Count} jitter");
        });
    }

    /// <summary>
    /// Sets the filtered packet set and re-analyzes VoiceQoS data from filtered packets only.
    /// Called by MainWindowViewModel when global filters are applied.
    /// This clears existing data to ensure VoiceQoS is recalculated from the filtered packet set.
    /// </summary>
    /// <param name="filteredPackets">The filtered packet list from PacketManager</param>
    public async Task SetFilteredPacketsAsync(IReadOnlyList<PacketInfo> filteredPackets)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] SetFilteredPacketsAsync called with {filteredPackets.Count:N0} filtered packets");

        // Set filter active flag for Total/Filtered display
        IsGlobalFilterActive = true;

        // Update Statistics component with filtered packet count for Total/Filtered header display
        StatisticsViewModel.SetFilteredState(filteredPackets.Count, isFiltered: true);

        // Clear existing data to force fresh analysis
        lock (_collectionLock)
        {
            _allQoSTraffic.Clear();
            _allLatencyConnections.Clear();
            _allJitterConnections.Clear();
            _cachedTimeSeriesData = null;
        }

        // Clear AnalysisViewModel's cached data as well
        AnalysisViewModel.ClearCachedData();

        // Re-analyze with filtered packets (forceReanalysis=true bypass cache check)
        await AnalyzePacketsInternalAsync(filteredPackets, forceReanalysis: true);

        // Notify percentage property changes
        NotifyPercentageChanges();

        DebugLogger.Log($"[VoiceQoSViewModel] SetFilteredPacketsAsync complete - {_allQoSTraffic.Count} QoS, {_allLatencyConnections.Count} latency, {_allJitterConnections.Count} jitter");
    }

    /// <summary>
    /// Notifies UI of percentage property changes (computed properties don't auto-notify).
    /// </summary>
    private void NotifyPercentageChanges()
    {
        OnPropertyChanged(nameof(TotalQoSPacketsPercentage));
        OnPropertyChanged(nameof(HighLatencyCountPercentage));
        OnPropertyChanged(nameof(HighJitterCountPercentage));
    }

    /// <summary>
    /// Analyzes packets for QoS, latency, and jitter metrics
    /// </summary>
    public async Task AnalyzePacketsAsync(IReadOnlyList<PacketInfo> packets)
    {
        await AnalyzePacketsInternalAsync(packets, forceReanalysis: false);
    }

    /// <summary>
    /// Internal analysis method with optional cache bypass
    /// </summary>
    private async Task AnalyzePacketsInternalAsync(IReadOnlyList<PacketInfo> packets, bool forceReanalysis)
    {
        // ✅ CACHE HIT CHECK: Skip if already populated via SetFromCacheAsync (unless forced)
        // This prevents 25s re-analysis when session cache already has VoiceQoS data
        if (!forceReanalysis && (_allQoSTraffic.Count > 0 || _allLatencyConnections.Count > 0 || _allJitterConnections.Count > 0))
        {
            DebugLogger.Log($"[VoiceQoSViewModel] ⏭️ Skipping AnalyzePacketsAsync - already populated ({_allQoSTraffic.Count} QoS, {_allLatencyConnections.Count} latency, {_allJitterConnections.Count} jitter)");
            return;
        }

        // Set UI state (UI thread safe)
        await _dispatcher.InvokeAsync(() =>
        {
            IsAnalyzing = true;
            StatusMessage = "Analyzing Voice/QoS traffic...";
        });

        // Store reference to packets (no copy, thread-safe)
        lock (_collectionLock)
        {
            _allPackets = packets;
        }

        // Apply filter if active
        var workingSet = _filterService?.IsFilterActive == true
            ? _filterService.GetFilteredPackets(packets).ToList()
            : packets.ToList();

        // Delegate to AnalysisViewModel - OnAnalysisCompleted handles UI updates
        await AnalysisViewModel.AnalyzePacketsAsync(
            workingSet,
            LatencyThreshold,
            JitterThreshold,
            MinimumPacketThreshold);
    }

    /// <summary>
    /// Apply threshold filters - re-analyzes with new thresholds
    /// Manual trigger to prevent UI freezing during slider drag
    /// </summary>
    [RelayCommand]
    private async Task ApplyThresholdFilters()
    {
        if (_allPackets.Count == 0)
        {
            StatusMessage = "No packets loaded for analysis";
            return;
        }

        // Re-analyze all packets with new thresholds via AnalysisViewModel
        await AnalyzePacketsAsync(_allPackets);
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    // ==================== STATISTICS CALCULATION ====================

    private void CalculateStatistics()
    {
        // Calculate statistics for currently filtered data
        if (HighLatencyConnections.Any())
        {
            AverageLatency = HighLatencyConnections.Average(c => c.AverageLatency);
            MaxLatency = HighLatencyConnections.Max(c => c.MaxLatency);
            HighLatencyCount = HighLatencyConnections.Count;
        }
        else
        {
            AverageLatency = 0;
            MaxLatency = 0;
            HighLatencyCount = 0;
        }

        if (HighJitterConnections.Any())
        {
            AverageJitter = HighJitterConnections.Average(c => c.AverageJitter);
            MaxJitter = HighJitterConnections.Max(c => c.MaxJitter);
            HighJitterCount = HighJitterConnections.Count;
        }
        else
        {
            AverageJitter = 0;
            MaxJitter = 0;
            HighJitterCount = 0;
        }

        // Calculate QoS packet count from filtered data
        TotalQoSPackets = QosTraffic.Sum(q => q.PacketCount);

        // Notify percentage property changes for Total/Filtered display
        NotifyPercentageChanges();

        // Update unified stats bar
        UpdateVoiceQoSStatsBar();
    }

    /// <summary>
    /// Updates VoiceQoSStatsBar with unified Total/Filtered display pattern.
    /// Call after filtering or when statistics change.
    /// </summary>
    private void UpdateVoiceQoSStatsBar()
    {
        VoiceQoSStatsBar.ClearStats();

        // Determine filter state
        var hasFilter = IsGlobalFilterActive ||
            _globalFilterState?.HasActiveFilters == true;

        // QoS Packets
        TabStatsHelper.AddNumericStat(VoiceQoSStatsBar, "QoS PACKETS", "📡",
            TotalQoSPacketsAll, TotalQoSPackets, hasFilter,
            ThemeColorHelper.GetColorHex("AccentPrimary", "#58A6FF"));

        // High Latency Connections
        TabStatsHelper.AddNumericStat(VoiceQoSStatsBar, "HIGH LATENCY", "⏱️",
            HighLatencyCountAll, HighLatencyCount, hasFilter,
            ThemeColorHelper.GetColorHex("SlackWarning", "#F0883E"));

        // High Jitter Connections
        TabStatsHelper.AddNumericStat(VoiceQoSStatsBar, "HIGH JITTER", "📊",
            HighJitterCountAll, HighJitterCount, hasFilter,
            ThemeColorHelper.GetColorHex("SlackDanger", "#DA3633"));

        // Avg Latency (no total/filtered, just a metric)
        TabStatsHelper.AddSimpleStat(VoiceQoSStatsBar, "AVG LATENCY", "⚡",
            $"{AverageLatency:F2} ms",
            ThemeColorHelper.GetColorHex("AccentPrimary", "#58A6FF"));

        // Avg Jitter
        TabStatsHelper.AddSimpleStat(VoiceQoSStatsBar, "AVG JITTER", "🔀",
            $"{AverageJitter:F2} ms",
            ThemeColorHelper.GetColorHex("SlackSuccess", "#3FB950"));

        // Max Latency
        TabStatsHelper.AddSimpleStat(VoiceQoSStatsBar, "MAX LATENCY", "🔺",
            $"{MaxLatency:F2} ms",
            ThemeColorHelper.GetColorHex("SlackWarning", "#F0883E"));

        // Max Jitter
        TabStatsHelper.AddSimpleStat(VoiceQoSStatsBar, "MAX JITTER", "⚠️",
            $"{MaxJitter:F2} ms",
            ThemeColorHelper.GetColorHex("SlackDanger", "#DA3633"));
    }

    private void CalculateTopEndpoints() =>
        StatisticsViewModel.UpdateTopEndpoints(QosTraffic, HighLatencyConnections, HighJitterConnections);

    // ==================== CHART UPDATE ====================

    /// <summary>
    /// Update the timeline chart with PRE-AGGREGATED cached data (FAST - no packet processing)
    /// </summary>
    private void UpdateTimelineChart()
    {
        try
        {
            var updateStart = DateTime.Now;
            var timestamp = updateStart.ToString("HH:mm:ss.fff");

            // Use pre-aggregated time-series data (generated ONCE during analysis)
            if (_cachedTimeSeriesData is null)
            {
                DebugLogger.Log($"[{timestamp}] [VoiceQoSViewModel] No cached chart data - skipping chart update");
                return;
            }

            DebugLogger.Log($"[{timestamp}] [VoiceQoSViewModel] Updating chart with {_cachedTimeSeriesData.DataPoints.Count} pre-aggregated time buckets");

            // Pass pre-aggregated data to chart (NOT raw packets - 1000x faster!)
            ChartsViewModel.UpdateTimelineChartFromAggregated(_cachedTimeSeriesData);

            var elapsed = (DateTime.Now - updateStart).TotalMilliseconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [VoiceQoSViewModel] Chart updated in {elapsed:F0}ms (using cached aggregated data)");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSViewModel] Error updating timeline chart: {ex.Message}");
        }
    }

    // ==================== ITABPOPULATIONTARGET IMPLEMENTATION ====================

    /// <inheritdoc />
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[VoiceQoSViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");
        if (result.VoiceQoSData is not null)
        {
            await SetFromCacheAsync(result.VoiceQoSData, result.VoiceQoSTimeSeries, result.AllPackets);
        }
        else
        {
            // Fallback: analyze packets if no pre-computed data available
            await LoadDataAsync(result.AllPackets);
        }
    }
}
