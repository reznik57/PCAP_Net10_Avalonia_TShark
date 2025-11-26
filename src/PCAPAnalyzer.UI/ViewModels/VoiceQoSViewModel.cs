using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.ViewModels.VoiceQoS;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Base;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for Voice/QoS traffic analysis tab.
/// Displays QoS-marked traffic, connections with high latency, and connections with high jitter.
/// </summary>
public partial class VoiceQoSViewModel : SmartFilterableTab, IDisposable, ILazyLoadableTab
{
    private readonly ITabFilterService? _filterService;
    private readonly PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? _cacheService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly object _collectionLock = new(); // Thread-safety lock
    private readonly DebouncedAction _filterDebouncer; // Debouncer for IP filter TextBoxes
    private bool _disposed; // Track disposal state
    private List<PacketInfo> _allPackets = new();
    private string? _currentFilePath;

    // Storage for unfiltered collections (for local QoS/DSCP filtering)
    private List<QoSTrafficItem> _allQoSTraffic = new();
    private List<LatencyConnectionItem> _allLatencyConnections = new();
    private List<JitterConnectionItem> _allJitterConnections = new();

    // Collections for the three main lists
    [ObservableProperty] private ObservableCollection<QoSTrafficItem> _qosTraffic = new();
    [ObservableProperty] private ObservableCollection<LatencyConnectionItem> _highLatencyConnections = new();
    [ObservableProperty] private ObservableCollection<JitterConnectionItem> _highJitterConnections = new();

    // Statistics - All Data
    [ObservableProperty] private int _totalQoSPackets;
    [ObservableProperty] private int _totalQoSPacketsAll;
    [ObservableProperty] private int _highLatencyCount;
    [ObservableProperty] private int _highLatencyCountAll;
    [ObservableProperty] private int _highJitterCount;
    [ObservableProperty] private int _highJitterCountAll;
    [ObservableProperty] private double _averageLatency;
    [ObservableProperty] private double _averageLatencyAll;
    [ObservableProperty] private double _averageJitter;
    [ObservableProperty] private double _averageJitterAll;
    [ObservableProperty] private double _maxLatency;
    [ObservableProperty] private double _maxLatencyAll;
    [ObservableProperty] private double _maxJitter;
    [ObservableProperty] private double _maxJitterAll;

    // Filter/search
    [ObservableProperty] private string _searchFilter = "";
    [ObservableProperty] private double _latencyThreshold = 100.0; // ms (default)
    [ObservableProperty] private double _jitterThreshold = 30.0; // ms (default)
    [ObservableProperty] private int _minimumPacketThreshold = 10; // Minimum packets for statistical reliability (default: 10)
    [ObservableProperty] private string? _selectedQoSType = null;
    [ObservableProperty] private string? _selectedDscpMarking = null;
    [ObservableProperty] private string _sourceIPFilter = ""; // NEW: Source IP filter
    [ObservableProperty] private string _destinationIPFilter = ""; // NEW: Destination IP filter

    // ==================== UNIVERSAL FILTER PROPERTIES ====================

    [ObservableProperty] private string _filterSourceIP = "";
    [ObservableProperty] private string _filterDestinationIP = "";
    [ObservableProperty] private string _filterPortRange = "";
    [ObservableProperty] private string _filterProtocolType = "";

    partial void OnFilterSourceIPChanged(string value) => ApplyFilters();
    partial void OnFilterDestinationIPChanged(string value) => ApplyFilters();
    partial void OnFilterPortRangeChanged(string value) => ApplyFilters();
    partial void OnFilterProtocolTypeChanged(string value) => ApplyFilters();

    // ==================== FILTERABLE TAB IMPLEMENTATION ====================

    /// <summary>
    /// Common filters for protocol, source IP, and destination IP
    /// Using forwarding properties to avoid breaking existing code
    /// </summary>
    public new CommonFilterViewModel CommonFilters { get; } = new();

    /// <summary>
    /// Unique tab identifier for FilterCopyService
    /// </summary>
    public override string TabName => TabNames.VoiceQoS;

    /// <summary>
    /// IFilterableTab implementation - applies common and tab-specific filters
    /// </summary>
    public new void ApplyFilters()
    {
        ApplyLocalFilters();
    }

    /// <summary>
    /// Applies the sophisticated PacketFilter to VoiceQoS tab's call data
    /// </summary>
    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Apply filter to _allQoSTraffic, _allLatencyConnections, _allJitterConnections
        ApplyLocalFilters();
        DebugLogger.Log($"[{TabName}] Smart filters applied to VoiceQoS data");
    }

    [RelayCommand]
    private void ApplyFilter()
    {
        ApplyFilters();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        ClearLocalFilters();
    }

    /// <summary>
    /// Indicates whether any filters are currently active (non-default values)
    /// </summary>
    public bool HasActiveFilters =>
        CommonFilters.HasActiveFilters ||
        MinimumPacketThreshold != 10 ||
        LatencyThreshold != 100.0 ||
        JitterThreshold != 30.0 ||
        !string.IsNullOrWhiteSpace(SearchFilter) ||
        !string.IsNullOrWhiteSpace(SourceIPFilter) ||
        !string.IsNullOrWhiteSpace(DestinationIPFilter) ||
        SelectedQoSType != null ||
        SelectedDscpMarking != null;

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

    // Available filter options
    public ObservableCollection<string> AvailableQoSTypes { get; } = new() { "All", "RTP (Voice/Video)", "SIP (Signaling)", "RTP/Media", "QoS Marked" };
    public ObservableCollection<string> AvailableDscpMarkings { get; } = new() { "All", "EF (46)", "AF41 (34)", "AF31 (26)", "AF21 (18)", "AF11 (10)", "CS5 (40)", "CS3 (24)", "BE (0)" };

    // UI state
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private string _statusMessage = "No data loaded";

    // PAGINATION: Controls for three main tables (QoS Traffic, High Latency, High Jitter)
    [ObservableProperty] private int _qosTrafficPageSize = 30;
    [ObservableProperty] private int _qosTrafficCurrentPage = 1;
    [ObservableProperty] private int _qosTrafficTotalPages = 1;
    [ObservableProperty] private int _qosTrafficTotalItems;

    [ObservableProperty] private int _latencyPageSize = 30;
    [ObservableProperty] private int _latencyCurrentPage = 1;
    [ObservableProperty] private int _latencyTotalPages = 1;
    [ObservableProperty] private int _latencyTotalItems;

    [ObservableProperty] private int _jitterPageSize = 30;
    [ObservableProperty] private int _jitterCurrentPage = 1;
    [ObservableProperty] private int _jitterTotalPages = 1;
    [ObservableProperty] private int _jitterTotalItems;

    // Lazy loading support
    [ObservableProperty] private bool _isDataLoaded = false;
    [ObservableProperty] private bool _isLoading = false;
    private Task? _loadingTask;

    // Charts ViewModel for timeline
    [ObservableProperty] private VoiceQoSChartsViewModel _chartsViewModel = new();

    // Popup ViewModel for detail dialogs
    [ObservableProperty] private VoiceQoSPopupViewModel _popupViewModel = new();

    // Statistics ViewModel for top endpoints
    [ObservableProperty] private VoiceQoSStatisticsViewModel _statisticsViewModel = new();

    // Analysis ViewModel for packet analysis and caching
    [ObservableProperty] private VoiceQoSAnalysisViewModel _analysisViewModel;

    // Cached pre-aggregated chart data (generated ONCE during analysis, reused for filtering)
    private Core.Models.VoiceQoSTimeSeriesData? _cachedTimeSeriesData;

    // PAGINATION COMMANDS - QoS Traffic
    public void QosTrafficNextPage()
    {
        if (QosTrafficCurrentPage < QosTrafficTotalPages)
        {
            QosTrafficCurrentPage++;
            ApplyLocalFilters();
        }
    }

    public void QosTrafficPreviousPage()
    {
        if (QosTrafficCurrentPage > 1)
        {
            QosTrafficCurrentPage--;
            ApplyLocalFilters();
        }
    }

    public void QosTrafficFirstPage()
    {
        QosTrafficCurrentPage = 1;
        ApplyLocalFilters();
    }

    public void QosTrafficLastPage()
    {
        QosTrafficCurrentPage = QosTrafficTotalPages;
        ApplyLocalFilters();
    }

    public void QosTrafficJumpForward10()
    {
        QosTrafficCurrentPage = Math.Min(QosTrafficCurrentPage + 10, QosTrafficTotalPages);
        ApplyLocalFilters();
    }

    public void QosTrafficJumpBackward10()
    {
        QosTrafficCurrentPage = Math.Max(QosTrafficCurrentPage - 10, 1);
        ApplyLocalFilters();
    }

    public void QosTrafficSetPageSize(int pageSize)
    {
        QosTrafficPageSize = pageSize;
        QosTrafficCurrentPage = 1; // Reset to first page
        ApplyLocalFilters();
    }

    // PAGINATION COMMANDS - High Latency
    public void LatencyNextPage()
    {
        if (LatencyCurrentPage < LatencyTotalPages)
        {
            LatencyCurrentPage++;
            ApplyLocalFilters();
        }
    }

    public void LatencyPreviousPage()
    {
        if (LatencyCurrentPage > 1)
        {
            LatencyCurrentPage--;
            ApplyLocalFilters();
        }
    }

    public void LatencyFirstPage()
    {
        LatencyCurrentPage = 1;
        ApplyLocalFilters();
    }

    public void LatencyLastPage()
    {
        LatencyCurrentPage = LatencyTotalPages;
        ApplyLocalFilters();
    }

    public void LatencyJumpForward10()
    {
        LatencyCurrentPage = Math.Min(LatencyCurrentPage + 10, LatencyTotalPages);
        ApplyLocalFilters();
    }

    public void LatencyJumpBackward10()
    {
        LatencyCurrentPage = Math.Max(LatencyCurrentPage - 10, 1);
        ApplyLocalFilters();
    }

    public void LatencySetPageSize(int pageSize)
    {
        LatencyPageSize = pageSize;
        LatencyCurrentPage = 1;
        ApplyLocalFilters();
    }

    // PAGINATION COMMANDS - High Jitter
    public void JitterNextPage()
    {
        if (JitterCurrentPage < JitterTotalPages)
        {
            JitterCurrentPage++;
            ApplyLocalFilters();
        }
    }

    public void JitterPreviousPage()
    {
        if (JitterCurrentPage > 1)
        {
            JitterCurrentPage--;
            ApplyLocalFilters();
        }
    }

    public void JitterFirstPage()
    {
        JitterCurrentPage = 1;
        ApplyLocalFilters();
    }

    public void JitterLastPage()
    {
        JitterCurrentPage = JitterTotalPages;
        ApplyLocalFilters();
    }

    public void JitterJumpForward10()
    {
        JitterCurrentPage = Math.Min(JitterCurrentPage + 10, JitterTotalPages);
        ApplyLocalFilters();
    }

    public void JitterJumpBackward10()
    {
        JitterCurrentPage = Math.Max(JitterCurrentPage - 10, 1);
        ApplyLocalFilters();
    }

    public void JitterSetPageSize(int pageSize)
    {
        JitterPageSize = pageSize;
        JitterCurrentPage = 1;
        ApplyLocalFilters();
    }

    public VoiceQoSViewModel()
        : base(App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService())
    {
        _filterService = new TabFilterService("Voice/QoS", new FilterServiceCore());
        _cacheService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
        _filterCopyService = App.Services?.GetService<FilterCopyService>();

        // Initialize AnalysisViewModel with cache service
        _analysisViewModel = new VoiceQoSAnalysisViewModel(_cacheService);

        // Subscribe to analysis completion to update UI
        _analysisViewModel.AnalysisCompleted += OnAnalysisCompleted;

        // Initialize debouncer for IP filter TextBoxes (2000ms delay for better UX with large datasets)
        _filterDebouncer = new DebouncedAction(2000);

        // Subscribe to filter changes
        if (_filterService != null)
        {
            _filterService.FilterChanged += OnFilterServiceChanged;
        }

        // Subscribe to CommonFilters property changes and forward to existing SourceIP/DestIP filters
        CommonFilters.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(CommonFilters.SourceIPFilter))
                SourceIPFilter = CommonFilters.SourceIPFilter ?? "";
            else if (e.PropertyName == nameof(CommonFilters.DestinationIPFilter))
                DestinationIPFilter = CommonFilters.DestinationIPFilter ?? "";
            else if (e.PropertyName == nameof(CommonFilters.ProtocolFilter))
                ApplyLocalFilters();
        };

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        DebugLogger.Log("[VoiceQoSViewModel] Initialized with cache service and filter support");
    }

    /// <summary>
    /// Handles analysis completion from AnalysisViewModel.
    /// </summary>
    private void OnAnalysisCompleted(VoiceQoSAnalysisCompletedEventArgs e)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
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
            if (_cachedTimeSeriesData != null)
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

    /// <summary>
    /// Sets the current file path for cache key generation.
    /// Call this when loading a new PCAP file to enable result caching.
    /// </summary>
    public void SetCurrentFile(string filePath)
    {
        _currentFilePath = filePath;
        AnalysisViewModel.SetCurrentFile(filePath);
        DebugLogger.Log($"[VoiceQoSViewModel] Current file set for caching: {filePath}");
    }

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        // FIX: Don't auto-regenerate on every filter change if data is already loaded
        // Only apply local filters to existing data to prevent infinite retry loop
        if (IsDataLoaded && _cachedTimeSeriesData != null && _allQoSTraffic.Count > 0)
        {
            DebugLogger.Log("[VoiceQoSViewModel] Filter changed - applying local filters only (no regeneration)");
            ApplyLocalFilters();
            return;
        }

        // Only regenerate if no data loaded yet
        List<PacketInfo> packetSnapshot;
        lock (_collectionLock)
        {
            packetSnapshot = _allPackets.ToList();
        }

        if (packetSnapshot.Count > 0)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await AnalyzePacketsAsync(packetSnapshot);
                    DebugLogger.Log("[VoiceQoSViewModel] Data updated after filter change");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[VoiceQoSViewModel] Error updating after filter change: {ex.Message}");
                    IsAnalyzing = false; // CRITICAL: Stop retry loop on any error
                }
            });
        }
    }

    /// <summary>
    /// Analyzes packets for QoS, latency, and jitter metrics
    /// </summary>
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
        if (_loadingTask != null)
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
    /// Expected: <200ms to populate (vs 5s re-analysis).
    /// </summary>
    public async Task SetFromCacheAsync(VoiceQoSAnalysisResult analysisResult, VoiceQoSTimeSeriesData? timeSeriesData, IReadOnlyList<PacketInfo> packets)
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            DebugLogger.Log($"[VoiceQoSViewModel] SetFromCache - QoS: {analysisResult.QoSTraffic.Count}, Latency: {analysisResult.HighLatencyConnections.Count}, Jitter: {analysisResult.HighJitterConnections.Count}");

            // Store packets
            lock (_collectionLock)
            {
                _allPackets = packets.ToList();
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
            if (timeSeriesData != null)
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

            // Update chart from cached time-series
            if (_cachedTimeSeriesData != null)
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

    public async Task AnalyzePacketsAsync(IReadOnlyList<PacketInfo> packets)
    {
        // Set UI state (UI thread safe)
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            IsAnalyzing = true;
            StatusMessage = "Analyzing Voice/QoS traffic...";
        });

        // Store local copy for filtering (thread-safe)
        var packetList = packets as List<PacketInfo> ?? packets.ToList();
        lock (_collectionLock)
        {
            _allPackets = packetList;
        }

        // Apply filter if active
        var workingSet = _filterService?.IsFilterActive == true
            ? _filterService.GetFilteredPackets(packetList).ToList()
            : packetList;

        // Delegate to AnalysisViewModel - OnAnalysisCompleted handles UI updates
        await AnalysisViewModel.AnalyzePacketsAsync(
            workingSet,
            LatencyThreshold,
            JitterThreshold,
            MinimumPacketThreshold);
    }

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
    }

    private void CalculateTopEndpoints() =>
        StatisticsViewModel.UpdateTopEndpoints(QosTraffic, HighLatencyConnections, HighJitterConnections);

    [RelayCommand]
    private void ClearLocalFilters()
    {
        // Clear common filters
        CommonFilters.Clear();

        // Clear tab-specific filters
        SearchFilter = "";
        LatencyThreshold = 100.0;
        JitterThreshold = 30.0;
        MinimumPacketThreshold = 10;
        SelectedQoSType = null;
        SelectedDscpMarking = null;
        SourceIPFilter = "";
        DestinationIPFilter = "";
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    /// <summary>
    /// Shows packet details for a selected QoS traffic entry
    /// </summary>
    [RelayCommand]
    private void ShowQoSDetails(QoSTrafficItem item) => PopupViewModel.ShowQoSDetails(item);

    /// <summary>
    /// Shows packet details for a selected high latency connection
    /// </summary>
    [RelayCommand]
    private void ShowLatencyDetails(LatencyConnectionItem item) => PopupViewModel.ShowLatencyDetails(item);

    /// <summary>
    /// Shows packet details for a selected high jitter connection
    /// </summary>
    [RelayCommand]
    private void ShowJitterDetails(JitterConnectionItem item) => PopupViewModel.ShowJitterDetails(item);

    /// <summary>
    /// Shows packet details for a selected Top Endpoint entry
    /// </summary>
    [RelayCommand]
    private void ShowTopEndpointDetails(TopEndpointItem item)
    {
        if (item == null) return;

        // Gather related packets based on metric type
        var relatedPackets = GatherRelatedPacketsForEndpoint(item);
        PopupViewModel.ShowTopEndpointDetails(item, relatedPackets);
    }

    /// <summary>
    /// Gathers all packets related to an endpoint based on its metric type
    /// </summary>
    private IEnumerable<PacketInfo> GatherRelatedPacketsForEndpoint(TopEndpointItem item)
    {
        var packets = new List<PacketInfo>();

        if (item.MetricType.Contains("QoS", StringComparison.Ordinal))
        {
            var flows = QosTraffic.Where(q => q.SourceIP == item.IPAddress || q.DestinationIP == item.IPAddress);
            foreach (var flow in flows)
                packets.AddRange(flow.Packets);
        }
        else if (item.MetricType.Contains("Latency", StringComparison.Ordinal))
        {
            var connections = HighLatencyConnections.Where(c => c.SourceIP == item.IPAddress || c.DestinationIP == item.IPAddress);
            foreach (var conn in connections)
                packets.AddRange(conn.Packets);
        }
        else if (item.MetricType.Contains("Jitter", StringComparison.Ordinal))
        {
            var connections = HighJitterConnections.Where(c => c.SourceIP == item.IPAddress || c.DestinationIP == item.IPAddress);
            foreach (var conn in connections)
                packets.AddRange(conn.Packets);
        }

        return packets;
    }

    /// <summary>
    /// Closes the packet details dialog
    /// </summary>
    [RelayCommand]
    private void CloseDetailDialog() => PopupViewModel.CloseDetailDialog();

    partial void OnSearchFilterChanged(string value)
    {
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSelectedQoSTypeChanged(string? value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] QoS Type filter changed to: {value}");
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSelectedDscpMarkingChanged(string? value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] DSCP Marking filter changed to: {value}");
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSourceIPFilterChanged(string value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] Source IP filter changed to: {value} (debounced)");
        _filterDebouncer.Debounce(() =>
        {
            ApplyLocalFilters();
            OnPropertyChanged(nameof(HasActiveFilters));
        });
    }

    partial void OnDestinationIPFilterChanged(string value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] Destination IP filter changed to: {value} (debounced)");
        _filterDebouncer.Debounce(() =>
        {
            ApplyLocalFilters();
            OnPropertyChanged(nameof(HasActiveFilters));
        });
    }

    partial void OnMinimumPacketThresholdChanged(int value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnLatencyThresholdChanged(double value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnJitterThresholdChanged(double value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    /// <summary>
    /// Applies local QoS Type and DSCP Marking filters to the cached collections
    /// </summary>
    private void ApplyLocalFilters()
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            // Snapshot collections first to avoid enumeration errors
            var qosSnapshot = _allQoSTraffic.ToList();
            var latencySnapshot = _allLatencyConnections.ToList();
            var jitterSnapshot = _allJitterConnections.ToList();

            // Apply filters using extracted helper methods
            var filteredQoS = ApplyQoSFilters(qosSnapshot);
            var filteredLatency = ApplyLatencyJitterFilters(latencySnapshot);
            var filteredJitter = ApplyLatencyJitterFilters(jitterSnapshot);

            // PAGINATION: Sort and apply pagination to filtered results
            var sortedQoS = filteredQoS.OrderByDescending(q => q.PacketCount).ToList();
            var sortedLatency = filteredLatency.OrderByDescending(l => l.AverageLatency).ToList();
            var sortedJitter = filteredJitter.OrderByDescending(j => j.AverageJitter).ToList();

            // Update total items and calculate total pages
            QosTrafficTotalItems = sortedQoS.Count;
            LatencyTotalItems = sortedLatency.Count;
            JitterTotalItems = sortedJitter.Count;

            QosTrafficTotalPages = Math.Max(1, (int)Math.Ceiling((double)QosTrafficTotalItems / QosTrafficPageSize));
            LatencyTotalPages = Math.Max(1, (int)Math.Ceiling((double)LatencyTotalItems / LatencyPageSize));
            JitterTotalPages = Math.Max(1, (int)Math.Ceiling((double)JitterTotalItems / JitterPageSize));

            // Clamp current pages to valid range
            QosTrafficCurrentPage = Math.Max(1, Math.Min(QosTrafficCurrentPage, QosTrafficTotalPages));
            LatencyCurrentPage = Math.Max(1, Math.Min(LatencyCurrentPage, LatencyTotalPages));
            JitterCurrentPage = Math.Max(1, Math.Min(JitterCurrentPage, JitterTotalPages));

            // Calculate pagination offsets
            var qosSkip = (QosTrafficCurrentPage - 1) * QosTrafficPageSize;
            var latencySkip = (LatencyCurrentPage - 1) * LatencyPageSize;
            var jitterSkip = (JitterCurrentPage - 1) * JitterPageSize;

            // Apply pagination: Skip + Take with row numbering
            var pagedQoS = sortedQoS.Skip(qosSkip).Take(QosTrafficPageSize).ToList();
            var pagedLatency = sortedLatency.Skip(latencySkip).Take(LatencyPageSize).ToList();
            var pagedJitter = sortedJitter.Skip(jitterSkip).Take(JitterPageSize).ToList();

            // Calculate row numbers for each item
            for (int i = 0; i < pagedQoS.Count; i++)
            {
                pagedQoS[i].RowNumber = qosSkip + i + 1;
            }
            for (int i = 0; i < pagedLatency.Count; i++)
            {
                pagedLatency[i].RowNumber = latencySkip + i + 1;
            }
            for (int i = 0; i < pagedJitter.Count; i++)
            {
                pagedJitter[i].RowNumber = jitterSkip + i + 1;
            }

            lock (_collectionLock)
            {
                QosTraffic.Clear();
                foreach (var item in pagedQoS)
                {
                    QosTraffic.Add(item);
                }

                HighLatencyConnections.Clear();
                foreach (var item in pagedLatency)
                {
                    HighLatencyConnections.Add(item);
                }

                HighJitterConnections.Clear();
                foreach (var item in pagedJitter)
                {
                    HighJitterConnections.Add(item);
                }
            }

            // Recalculate filtered statistics AND top endpoints
            CalculateStatistics();
            CalculateTopEndpoints();

            // Update timeline chart with filtered data
            UpdateTimelineChart();

            DebugLogger.Log($"[VoiceQoSViewModel] Local filters applied - QoS: {QosTraffic.Count}, Latency: {HighLatencyConnections.Count}, Jitter: {HighJitterConnections.Count}");
        });
    }

    /// <summary>
    /// Apply QoS-specific filters (QoS Type, DSCP Marking, IP filters)
    /// </summary>
    private IEnumerable<QoSTrafficItem> ApplyQoSFilters(List<QoSTrafficItem> items)
    {
        var filtered = items.AsEnumerable();

        // Common protocol filter
        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            filtered = filtered.Where(q => q.Protocol.Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase));

        // QoS Type filter
        if (!string.IsNullOrEmpty(SelectedQoSType) && SelectedQoSType != "All")
            filtered = filtered.Where(q => q.QoSType.Contains(SelectedQoSType, StringComparison.OrdinalIgnoreCase));

        // DSCP Marking filter
        if (!string.IsNullOrEmpty(SelectedDscpMarking) && SelectedDscpMarking != "All")
            filtered = ApplyDscpFilter(filtered);

        // IP filters
        filtered = ApplyIPFilters(filtered, q => q.SourceIP, q => q.DestinationIP);

        return filtered;
    }

    /// <summary>
    /// Apply DSCP marking filter with name and value matching
    /// </summary>
    private IEnumerable<QoSTrafficItem> ApplyDscpFilter(IEnumerable<QoSTrafficItem> items)
    {
        var dscpName = SelectedDscpMarking!.Split('(')[0].Trim();
        var dscpValue = ExtractDscpValue(SelectedDscpMarking);

        return items.Where(q =>
            q.DscpMarking.Equals(dscpName, StringComparison.OrdinalIgnoreCase) ||
            q.DscpDisplay.Contains(SelectedDscpMarking, StringComparison.OrdinalIgnoreCase) ||
            (dscpValue >= 0 && q.DscpValue == dscpValue));
    }

    /// <summary>
    /// Extract DSCP numeric value from marking string "EF (46)" -> 46
    /// </summary>
    private static int ExtractDscpValue(string dscpMarking)
    {
        var startParen = dscpMarking.IndexOf('(', StringComparison.Ordinal);
        var endParen = dscpMarking.IndexOf(')', StringComparison.Ordinal);

        if (startParen > 0 && endParen > startParen)
        {
            var valueStr = dscpMarking.Substring(startParen + 1, endParen - startParen - 1).Trim();
            if (int.TryParse(valueStr, out var parsedValue))
                return parsedValue;
        }

        return -1;
    }

    /// <summary>
    /// Apply protocol and IP filters to latency/jitter connections
    /// </summary>
    private IEnumerable<T> ApplyLatencyJitterFilters<T>(List<T> items) where T : class
    {
        var filtered = items.AsEnumerable();

        // Common protocol filter
        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            filtered = filtered.Where(item => GetProtocol(item).Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase));

        // IP filters
        filtered = ApplyIPFilters(filtered, item => GetSourceIP(item), item => GetDestinationIP(item));

        return filtered;
    }

    /// <summary>
    /// Apply source and destination IP filters using generic selectors
    /// </summary>
    private IEnumerable<T> ApplyIPFilters<T>(IEnumerable<T> items, Func<T, string> sourceSelector, Func<T, string> destSelector)
    {
        var filtered = items;

        if (!string.IsNullOrWhiteSpace(SourceIPFilter))
            filtered = filtered.Where(item => sourceSelector(item).Contains(SourceIPFilter, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(DestinationIPFilter))
            filtered = filtered.Where(item => destSelector(item).Contains(DestinationIPFilter, StringComparison.OrdinalIgnoreCase));

        return filtered;
    }

    /// <summary>
    /// Get Protocol property from generic item (reflection-free)
    /// </summary>
    private static string GetProtocol<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.Protocol,
            JitterConnectionItem j => j.Protocol,
            _ => ""
        };
    }

    /// <summary>
    /// Get SourceIP property from generic item (reflection-free)
    /// </summary>
    private static string GetSourceIP<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.SourceIP,
            JitterConnectionItem j => j.SourceIP,
            _ => ""
        };
    }

    /// <summary>
    /// Get DestinationIP property from generic item (reflection-free)
    /// </summary>
    private static string GetDestinationIP<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.DestinationIP,
            JitterConnectionItem j => j.DestinationIP,
            _ => ""
        };
    }

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
            if (_cachedTimeSeriesData == null)
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

    #region IDisposable Implementation

    /// <summary>
    /// Disposes managed resources including event subscriptions and debouncer timer.
    /// Prevents memory leaks from filter service event handlers and active timers.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Unsubscribe from filter service events
        if (_filterService != null)
        {
            _filterService.FilterChanged -= OnFilterServiceChanged;
        }

        // Unregister from filter copy service
        _filterCopyService?.UnregisterTab(TabName);

        // Dispose debouncer (cancels active timers)
        _filterDebouncer?.Dispose();

        DebugLogger.Log("[VoiceQoSViewModel] Disposed - cleaned up event handlers and timers");
    }

    #endregion

    // ==================== ITabPopulationTarget IMPLEMENTATION ====================

    /// <inheritdoc />
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[VoiceQoSViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");
        if (result.VoiceQoSData != null)
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
