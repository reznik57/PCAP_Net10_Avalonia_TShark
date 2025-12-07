using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
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
///
/// Partial class structure:
/// - VoiceQoSViewModel.cs (this file) - Core properties, constructor, commands, IDisposable
/// - VoiceQoSViewModel.Filtering.cs - Filter application and filter change handlers
/// - VoiceQoSViewModel.Analysis.cs - Packet analysis, caching, and statistics
/// </summary>
public partial class VoiceQoSViewModel : SmartFilterableTab, IDisposable, ILazyLoadableTab
{
    private readonly IDispatcherService _dispatcher;
    private readonly ITabFilterService? _filterService;
    private readonly PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? _cacheService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly GlobalFilterState? _globalFilterState;
    private readonly Lock _collectionLock = new(); // Thread-safety lock
    private readonly DebouncedAction _filterDebouncer; // Debouncer for IP filter TextBoxes
    private bool _disposed; // Track disposal state
    private IReadOnlyList<PacketInfo> _allPackets = Array.Empty<PacketInfo>(); // Reference to cache (NOT a copy)
    private string? _currentFilePath;

    // Storage for unfiltered collections (for local QoS/DSCP filtering)
    private List<QoSTrafficItem> _allQoSTraffic = [];
    private List<LatencyConnectionItem> _allLatencyConnections = [];
    private List<JitterConnectionItem> _allJitterConnections = [];

    // Collections for the three main lists
    [ObservableProperty] private ObservableCollection<QoSTrafficItem> _qosTraffic = [];
    [ObservableProperty] private ObservableCollection<LatencyConnectionItem> _highLatencyConnections = [];
    [ObservableProperty] private ObservableCollection<JitterConnectionItem> _highJitterConnections = [];

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
    [ObservableProperty] private string _sourceIPFilter = ""; // Source IP filter
    [ObservableProperty] private string _destinationIPFilter = ""; // Destination IP filter

    // Universal filter properties
    [ObservableProperty] private string _filterSourceIP = "";
    [ObservableProperty] private string _filterDestinationIP = "";
    [ObservableProperty] private string _filterPortRange = "";
    [ObservableProperty] private string _filterProtocolType = "";

    partial void OnFilterSourceIPChanged(string value) => ApplyFilters();
    partial void OnFilterDestinationIPChanged(string value) => ApplyFilters();
    partial void OnFilterPortRangeChanged(string value) => ApplyFilters();
    partial void OnFilterProtocolTypeChanged(string value) => ApplyFilters();

    // Available filter options
    public ObservableCollection<string> AvailableQoSTypes { get; } = new() { "All", "RTP (Voice/Video)", "SIP (Signaling)", "RTP/Media", "QoS Marked" };
    public ObservableCollection<string> AvailableDscpMarkings { get; } = new() { "All", "EF (46)", "AF41 (34)", "AF31 (26)", "AF21 (18)", "AF11 (10)", "CS5 (40)", "CS3 (24)", "BE (0)" };

    // UI state
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private string _statusMessage = "No data loaded";

    // PAGINATION: Reusable pagination components for three main tables
    [ObservableProperty] private PaginationViewModel _qosTrafficPagination;
    [ObservableProperty] private PaginationViewModel _latencyPagination;
    [ObservableProperty] private PaginationViewModel _jitterPagination;

    // Lazy loading support
    [ObservableProperty] private bool _isDataLoaded = false;
    [ObservableProperty] private bool _isLoading = false;
    private Task? _loadingTask;

    // Component ViewModels
    [ObservableProperty] private VoiceQoSChartsViewModel _chartsViewModel = new();
    [ObservableProperty] private VoiceQoSPopupViewModel _popupViewModel = new();
    [ObservableProperty] private VoiceQoSStatisticsViewModel _statisticsViewModel = new();
    [ObservableProperty] private VoiceQoSAnalysisViewModel _analysisViewModel;

    // Cached pre-aggregated chart data (generated ONCE during analysis, reused for filtering)
    private Core.Models.VoiceQoSTimeSeriesData? _cachedTimeSeriesData;

    // ==================== FILTERABLE TAB IMPLEMENTATION ====================

    /// <summary>
    /// Common filters for protocol, source IP, and destination IP
    /// </summary>
    public new CommonFilterViewModel CommonFilters { get; } = new CommonFilterViewModel();

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
        SelectedQoSType is not null ||
        SelectedDscpMarking is not null;

    // Legacy pagination property accessors for XAML compatibility
    public int QosTrafficCurrentPage => QosTrafficPagination.CurrentPage;
    public int QosTrafficTotalPages => QosTrafficPagination.TotalPages;
    public int QosTrafficTotalItems => QosTrafficPagination.TotalItems;
    public int LatencyCurrentPage => LatencyPagination.CurrentPage;
    public int LatencyTotalPages => LatencyPagination.TotalPages;
    public int LatencyTotalItems => LatencyPagination.TotalItems;
    public int JitterCurrentPage => JitterPagination.CurrentPage;
    public int JitterTotalPages => JitterPagination.TotalPages;
    public int JitterTotalItems => JitterPagination.TotalItems;

    // ==================== CONSTRUCTOR ====================

    public VoiceQoSViewModel()
        : this(App.Services?.GetService<IDispatcherService>() ?? throw new InvalidOperationException("IDispatcherService not registered"))
    {
    }

    public VoiceQoSViewModel(IDispatcherService dispatcher)
        : base(App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService())
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _filterService = new TabFilterService("Voice/QoS", new FilterServiceCore());
        _cacheService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
        _filterCopyService = App.Services?.GetService<FilterCopyService>();
        _globalFilterState = App.Services?.GetService<GlobalFilterState>();

        // Initialize pagination components with callback to apply filters
        _qosTrafficPagination = new PaginationViewModel(ApplyLocalFilters);
        _latencyPagination = new PaginationViewModel(ApplyLocalFilters);
        _jitterPagination = new PaginationViewModel(ApplyLocalFilters);

        // Initialize AnalysisViewModel with cache service
        _analysisViewModel = new VoiceQoSAnalysisViewModel(_cacheService);

        // Subscribe to analysis completion to update UI
        _analysisViewModel.AnalysisCompleted += OnAnalysisCompleted;

        // Initialize debouncer for IP filter TextBoxes (2000ms delay for better UX with large datasets)
        _filterDebouncer = new DebouncedAction(2000);

        // Subscribe to filter changes
        if (_filterService is not null)
        {
            _filterService.FilterChanged += OnFilterServiceChanged;
        }

        // Subscribe to GlobalFilterState changes for tab-specific filtering (codec, quality, issues)
        if (_globalFilterState is not null)
        {
            _globalFilterState.OnFilterChanged += OnGlobalFilterChanged;
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

    // ==================== FILE PATH ====================

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

    // ==================== EVENT HANDLERS ====================

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        // FIX: Don't auto-regenerate on every filter change if data is already loaded
        if (IsDataLoaded && _cachedTimeSeriesData is not null && _allQoSTraffic.Count > 0)
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
    /// Handles GlobalFilterState changes - re-applies tab-specific filters to VoiceQoS data.
    /// </summary>
    private void OnGlobalFilterChanged()
    {
        if (_allQoSTraffic.Count > 0 || _allLatencyConnections.Count > 0 || _allJitterConnections.Count > 0)
        {
            _dispatcher.InvokeAsync(() =>
            {
                ApplyLocalFilters();
                DebugLogger.Log($"[VoiceQoSViewModel] VoiceQoS data updated after global filter change");
            });
        }
    }

    // ==================== COMMANDS ====================

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
        if (item is null) return;

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

    // ==================== IDISPOSABLE ====================

    /// <summary>
    /// Disposes managed resources including event subscriptions and debouncer timer.
    /// Prevents memory leaks from filter service event handlers and active timers.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Unsubscribe from GlobalFilterState to prevent memory leaks
        if (_globalFilterState is not null)
        {
            _globalFilterState.OnFilterChanged -= OnGlobalFilterChanged;
        }

        // Unsubscribe from filter service events
        if (_filterService is not null)
        {
            _filterService.FilterChanged -= OnFilterServiceChanged;
        }

        // Unregister from filter copy service
        _filterCopyService?.UnregisterTab(TabName);

        // Dispose debouncer (cancels active timers)
        _filterDebouncer?.Dispose();

        DebugLogger.Log("[VoiceQoSViewModel] Disposed - cleaned up event handlers and timers");
    }
}
