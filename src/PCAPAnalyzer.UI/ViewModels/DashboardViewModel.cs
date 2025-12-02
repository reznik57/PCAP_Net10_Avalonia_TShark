using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Refactored DashboardViewModel using composition pattern.
/// Delegates responsibilities to specialized component ViewModels.
/// Reduced from 4,254 lines to ~800 lines.
/// </summary>
[SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Orchestrator ViewModel coordinates multiple services and components by design")]
public partial class DashboardViewModel : SmartFilterableTab, IDisposable, ITabPopulationTarget
{
    // ==================== COMPONENT VIEWMODELS ====================

    /// <summary>
    /// Manages all chart visualizations (throughput, protocols, ports, etc.)
    /// </summary>
    public DashboardChartsViewModel Charts { get; }

    /// <summary>
    /// Manages all statistics display and data tables
    /// </summary>
    public DashboardStatisticsViewModel Statistics { get; }

    /// <summary>
    /// Manages popup windows and detail views
    /// </summary>
    public DashboardPopupViewModel Popups { get; }

    /// <summary>
    /// Manages anomaly summary widget for Security Overview
    /// </summary>
    public AnomalySummaryViewModel AnomalySummary { get; }

    /// <summary>
    /// Manages drill-down detail popup for IPs, Ports, Connections
    /// </summary>
    public DrillDownPopupViewModel DrillDown { get; }

    // ==================== SERVICES ====================

    private readonly IStatisticsService _statisticsService;
    private readonly IUnifiedAnomalyDetectionService _anomalyService;
    private readonly ITabFilterService? _filterService;
    private readonly IDashboardFilterService _dashboardFilterService;
    private readonly ICsvExportService? _csvExportService;
    private readonly IFileDialogService? _fileDialogService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly IFilterPresetService? _filterPresetService;
    private readonly GlobalFilterState? _globalFilterState;
    private readonly IAnomalyFrameIndexService? _anomalyFrameIndexService;
    private readonly Action<string>? _navigateToTab;

    // Anomaly frame number caches for efficient filtering
    private HashSet<long> _anomalyFrameNumbers = new();
    private HashSet<long> _highSeverityFrames = new();  // Critical + High severity
    private HashSet<long> _tcpAnomalyFrames = new();
    private HashSet<long> _networkAnomalyFrames = new();

    // Filter cancellation and progress tracking
    private CancellationTokenSource? _filterCancellationTokenSource;
    private PropertyChangedEventHandler? _commonFiltersHandler;

    // Current chip-based PacketFilter from SmartFilterableTab
    // This is the authoritative filter built from INCLUDE/EXCLUDE chips
    private PacketFilter? _currentChipBasedFilter;

    // ==================== FILTERABLE TAB IMPLEMENTATION ====================

    /// <summary>
    /// Common filters for protocol, source IP, and destination IP
    /// </summary>
    public new CommonFilterViewModel CommonFilters { get; } = new();

    /// <summary>
    /// Tab-specific filter: Traffic type (All/TCP/UDP/ICMP/Other)
    /// </summary>
    [ObservableProperty] private string _trafficTypeFilter = "All";

    /// <summary>
    /// Tab-specific filter: Port range filter
    /// </summary>
    [ObservableProperty] private string _portRangeFilter = "";

    /// <summary>
    /// Unique tab identifier for FilterCopyService
    /// </summary>
    public override string TabName => TabNames.Dashboard;

    // ==================== DATA STATE ====================

    private NetworkStatistics? _currentStatistics;
    private NetworkStatistics? _unfilteredStatistics; // For Quick Stats (all packets)
    private NetworkStatistics? _filteredStatistics;   // For Filtered Stats
    private IReadOnlyList<PacketInfo>? _allPackets;   // Reference to SessionAnalysisCache packets (NOT a copy)
    private List<PacketInfo>? _filteredPackets;       // Materialized filtered result (null when no filter active)
    private NetworkStatistics? _nextStatisticsOverride;

    public NetworkStatistics? CurrentStatistics => _currentStatistics;

    /// <summary>
    /// Exposes current packets for DrillDown popup time-slice analysis.
    /// Returns filtered packets if filter is active, otherwise all packets.
    /// </summary>
    public IEnumerable<PacketInfo> CurrentPackets => _filteredPackets ?? _allPackets ?? Enumerable.Empty<PacketInfo>();

    // ==================== CONFIGURATION ====================

    private const int LargeCaptureThreshold = 1_000_000;
    private const int MaxDetailedPacketSample = 750_000;

    [ObservableProperty] private bool _usingStatisticsSample;
    [ObservableProperty] private int _statisticsSampleSize;

    // ==================== UPDATE CONTROL ====================

    private readonly object _updateLock = new();
    private bool _isUpdating;
    private bool _isDisposed;

    // ==================== FILTER PROPERTIES ====================

    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _isFilterActive;
    [ObservableProperty] private DateTime? _filterStartTime;
    [ObservableProperty] private DateTime? _filterEndTime;
    [ObservableProperty] private string _filterProtocol = "All";
    [ObservableProperty] private string _filterSeverity = "All";

    // ==================== SMART FILTER LOGIC CONTROLS ====================

    [ObservableProperty] private bool _filterUseAndMode = true;

    public bool FilterUseOrMode
    {
        get => !FilterUseAndMode;
        set => FilterUseAndMode = !value;
    }

    [ObservableProperty] private bool _filterUseNotMode = false;

    // ==================== NETWORK/TRAFFIC/SECURITY FILTERS ====================
    // These are INHERITED from SmartFilterableTab which delegates to NetworkQuickFilters.
    // DO NOT add [ObservableProperty] here - that would HIDE the base class properties
    // and break the single source of truth architecture.
    //
    // Inherited properties (via SmartFilterableTab wrappers → NetworkQuickFilters):
    //   FilterRfc1918Toggle, FilterPublicIpToggle, FilterIPv4Toggle, FilterIPv6Toggle,
    //   FilterMulticastToggle, FilterInsecureToggle, FilterAnomaliesToggle,
    //   FilterSuspiciousToggle, FilterTcpIssuesToggle, FilterPortScansToggle,
    //   FilterPrivateToPublicToggle, FilterPublicToPrivateToggle, FilterJumboFramesToggle,
    //   FilterLoopbackToggle, FilterLinkLocalToggle

    // ==================== L7 PROTOCOL FILTERS ====================

    [ObservableProperty] private bool _filterTlsV10Toggle = false;
    [ObservableProperty] private bool _filterTlsV11Toggle = false;
    [ObservableProperty] private bool _filterTlsV12Toggle = false;
    [ObservableProperty] private bool _filterTlsV13Toggle = false;
    [ObservableProperty] private bool _filterHttpToggle = false;
    [ObservableProperty] private bool _filterHttpsToggle = false;
    [ObservableProperty] private bool _filterDnsToggle = false;
    [ObservableProperty] private bool _filterSnmpToggle = false;
    [ObservableProperty] private bool _filterSshToggle = false;
    [ObservableProperty] private bool _filterFtpToggle = false;
    [ObservableProperty] private bool _filterSmtpToggle = false;
    [ObservableProperty] private bool _filterStunToggle = false;
    [ObservableProperty] private bool _filterDhcpServerToggle = false;

    // ==================== VPN PROTOCOL FILTERS ====================

    [ObservableProperty] private bool _filterWireGuardToggle = false;
    [ObservableProperty] private bool _filterOpenVpnToggle = false;
    [ObservableProperty] private bool _filterIkeV2Toggle = false;
    [ObservableProperty] private bool _filterIpsecToggle = false;
    [ObservableProperty] private bool _filterL2tpToggle = false;
    [ObservableProperty] private bool _filterPptpToggle = false;

    // ==================== ADDITIONAL FILTERS ====================
    // JumboFrames, PrivateToPublic, PublicToPrivate, LinkLocal, Loopback,
    // Suspicious, TcpIssues, DnsAnomalies, PortScans are all inherited from
    // SmartFilterableTab (which delegates to NetworkQuickFilters).
    // See comment at line 160 for the full list of inherited properties.

    // ==================== UNIVERSAL FILTER PROPERTIES ====================

    [ObservableProperty] private string _filterSourceIP = "";
    [ObservableProperty] private string _filterDestinationIP = "";
    [ObservableProperty] private string _filterPortRange = "";
    [ObservableProperty] private string _filterProtocolType = "";

    partial void OnFilterSourceIPChanged(string value) => ApplyFilters();
    partial void OnFilterDestinationIPChanged(string value) => ApplyFilters();
    partial void OnFilterPortRangeChanged(string value) => ApplyFilters();
    partial void OnFilterProtocolTypeChanged(string value) => ApplyFilters();

    // ==================== GEOGRAPHIC DATA ====================

    [ObservableProperty] private Dictionary<string, double> _countryMapData = new();
    [ObservableProperty] private ObservableCollection<string> _excludedCountries = new();
    [ObservableProperty] private int _itemsCount = 0;

    [ObservableProperty] private int _uniqueCountries;
    [ObservableProperty] private string _topCountry = "N/A";
    [ObservableProperty] private bool _hasInternationalTraffic;

    // ==================== TCP HEALTH ====================

    [ObservableProperty] private int _tcpAnomalyCount;
    [ObservableProperty] private string _tcpHealthStatus = "Unknown";
    [ObservableProperty] private string _tcpHealthColor = "#6B7280";

    // ==================== FILTERING STATE ====================

    [ObservableProperty] private bool _isFilteringInProgress = false;
    [ObservableProperty] private double _filterProgress = 0.0;

    // ==================== CSV EXPORT ====================

    [ObservableProperty] private bool _isExporting = false;
    [ObservableProperty] private string? _exportStatusMessage;
    [ObservableProperty] private string _exportStatusColor = "#10B981"; // Default success green
    private System.Threading.CancellationTokenSource? _exportStatusCts;

    // ==================== FILTER PRESETS ====================

    [ObservableProperty] private ObservableCollection<FilterPreset> _availablePresets = new();
    [ObservableProperty] private FilterPreset? _selectedPreset;
    [ObservableProperty] private bool _isLoadingPresets = false;

    // ==================== ACTIVE FILTER DESCRIPTIONS ====================

    [ObservableProperty] private ObservableCollection<string> _activeFilterDescriptions = new();

    // ==================== CONSTRUCTORS ====================

    public DashboardViewModel()
        : this(
            App.Services?.GetRequiredService<IStatisticsService>() ?? throw new InvalidOperationException("IStatisticsService not registered"),
            App.Services?.GetService<IUnifiedAnomalyDetectionService>() ?? new UnifiedAnomalyDetectionService(),
            new TabFilterService("Dashboard", new FilterServiceCore()),
            App.Services?.GetService<IDashboardFilterService>() ?? new DashboardFilterService(),
            App.Services?.GetService<ICsvExportService>(),
            App.Services?.GetService<IFileDialogService>(),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
            App.Services?.GetService<IFilterPresetService>(),
            App.Services?.GetService<GlobalFilterState>(),
            App.Services?.GetService<IAnomalyFrameIndexService>())
    {
    }

    public DashboardViewModel(
        IStatisticsService statisticsService,
        IUnifiedAnomalyDetectionService anomalyService,
        ITabFilterService? filterService,
        IDashboardFilterService? dashboardFilterService = null,
        ICsvExportService? csvExportService = null,
        IFileDialogService? fileDialogService = null,
        ISmartFilterBuilder? filterBuilder = null,
        IFilterPresetService? filterPresetService = null,
        GlobalFilterState? globalFilterState = null,
        IAnomalyFrameIndexService? anomalyFrameIndexService = null,
        Action<string>? navigateToTab = null)
        : base(filterBuilder ?? new SmartFilterBuilderService())
    {
        _statisticsService = statisticsService;
        _anomalyService = anomalyService;
        _filterService = filterService;
        _dashboardFilterService = dashboardFilterService ?? new DashboardFilterService();
        _csvExportService = csvExportService;
        _fileDialogService = fileDialogService;
        _filterCopyService = App.Services?.GetService<FilterCopyService>();
        _filterPresetService = filterPresetService;
        _globalFilterState = globalFilterState;
        _anomalyFrameIndexService = anomalyFrameIndexService;
        _navigateToTab = navigateToTab;

        // Initialize component ViewModels
        Charts = new DashboardChartsViewModel();
        Statistics = new DashboardStatisticsViewModel();
        Popups = new DashboardPopupViewModel(this);

        // Initialize anomaly summary with navigation callback
        AnomalySummary = new AnomalySummaryViewModel(tabName =>
        {
            _navigateToTab?.Invoke(tabName);
        });

        // Initialize drill-down popup with navigation callback and GeoIP service
        var geoIPService = App.Services?.GetService<IGeoIPService>();
        DrillDown = new DrillDownPopupViewModel((tabName, filter) =>
        {
            _navigateToTab?.Invoke($"{tabName}?{filter}");
        }, geoIPService);

        // Subscribe to component property changes for backward compatibility
        Statistics.PropertyChanged += OnStatisticsPropertyChanged;
        Charts.PropertyChanged += OnChartsPropertyChanged;

        // Subscribe to filter changes
        if (_filterService != null)
        {
            _filterService.FilterChanged += OnFilterServiceChanged;
        }

        // Subscribe to CommonFilters property changes (stored handler for proper cleanup)
        _commonFiltersHandler = (s, e) => _ = ApplyFiltersAsync();
        CommonFilters.PropertyChanged += _commonFiltersHandler;

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        // Load filter presets
        _ = LoadPresetsAsync();

        DebugLogger.Log("[DashboardViewModel] Initialized with composition pattern and async filter support");
    }

    // ==================== PUBLIC UPDATE METHODS ====================

    /// <summary>
    /// Main entry point for updating dashboard with new packet data.
    /// Coordinates updates across all component ViewModels.
    /// </summary>
    public async Task UpdateStatisticsAsync(IReadOnlyList<PacketInfo> packets)
    {
        var methodStart = DateTime.Now;
        DebugLogger.Log($"[{methodStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] ========== METHOD START ==========");

        if (packets == null || packets.Count == 0)
        {
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] No packets to update");
            return;
        }

        // Prevent concurrent updates
        lock (_updateLock)
        {
            if (_isUpdating)
            {
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Update already in progress, skipping");
                return;
            }
            _isUpdating = true;
        }

        try
        {
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Updating with {packets.Count:N0} packets");

            Statistics.IsLoadingStats = true;

            // Store packet data and clear any cached filter results
            _allPackets = packets;
            _filteredPackets = null;

            // Calculate statistics
            NetworkStatistics statistics;

            if (_nextStatisticsOverride != null)
            {
                var overrideStart = DateTime.Now;
                statistics = _nextStatisticsOverride;
                _nextStatisticsOverride = null;
                var overrideElapsed = (DateTime.Now - overrideStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Using pre-calculated statistics override in {overrideElapsed:F3}s - TotalPackets: {statistics.TotalPackets:N0}, UniquePortCount: {statistics.UniquePortCount}");
            }
            else if (packets.Count > LargeCaptureThreshold)
            {
                // For very large captures, use sampling
                var samplingStart = DateTime.Now;
                DebugLogger.Log($"[{samplingStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Large capture detected ({packets.Count:N0} packets), using sampling");
                var sampleSize = Math.Min(MaxDetailedPacketSample, packets.Count);
                var sampledPackets = SamplePackets(packets, sampleSize);

                var calcStart = DateTime.Now;
                statistics = await Task.Run(() => _statisticsService.CalculateStatistics(sampledPackets));
                var calcElapsed = (DateTime.Now - calcStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Sampled statistics calculated in {calcElapsed:F3}s");

                UsingStatisticsSample = true;
                StatisticsSampleSize = sampleSize;
            }
            else
            {
                var calcStart = DateTime.Now;
                DebugLogger.Log($"[{calcStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Calculating statistics for {packets.Count:N0} packets");
                statistics = await Task.Run(() => _statisticsService.CalculateStatistics(packets));
                var calcElapsed = (DateTime.Now - calcStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Statistics calculated in {calcElapsed:F3}s - TotalPackets: {statistics.TotalPackets:N0}, UniquePortCount: {statistics.UniquePortCount}");
                UsingStatisticsSample = false;
                StatisticsSampleSize = 0;
            }

            _currentStatistics = statistics;
            _unfilteredStatistics = statistics;

            var componentsStart = DateTime.Now;
            DebugLogger.Log($"[{componentsStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] About to update all components with statistics");

            // Update all component ViewModels
            await UpdateAllComponents(statistics, packets);

            var componentsElapsed = (DateTime.Now - componentsStart).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Components updated in {componentsElapsed:F3}s");

            var totalElapsed = (DateTime.Now - methodStart).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] ========== METHOD COMPLETE in {totalElapsed:F3}s ==========");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] ERROR: {ex.Message}");
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Stack trace: {ex.StackTrace}");
        }
        finally
        {
            Statistics.IsLoadingStats = false;
            lock (_updateLock)
            {
                _isUpdating = false;
            }
        }
    }

    /// <summary>
    /// Updates all component ViewModels with new statistics.
    /// </summary>
    private async Task UpdateAllComponents(NetworkStatistics? statistics, IReadOnlyList<PacketInfo>? packets)
    {
        var updateStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] UpdateAllComponents starting - statistics null: {statistics == null}, packets: {packets?.Count ?? 0}");

        if (statistics == null || packets == null)
        {
            DebugLogger.Log($"[DashboardViewModel] Cannot update components - statistics or packets is null");
            return;
        }

        // Update Charts component
        var chartsStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating Charts component...");
        await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            Charts.UpdateAllCharts(statistics);
        });
        var chartsElapsed = (DateTime.Now - chartsStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] Charts component updated in {chartsElapsed:F2}s");

        // Update Statistics component
        var statsStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating Statistics component...");
        await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            Statistics.UpdateAllStatistics(statistics, isFiltered: false);

            // Update extended collections for dashboard tables
            UpdateExtendedCollections();

            // Update Port Activity Timeline chart
            UpdatePortActivityTimeline();
        });
        var statsElapsed = (DateTime.Now - statsStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] Statistics component updated in {statsElapsed:F2}s");

        // Update Popups component with data context
        var popupsStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating Popups component...");
        Popups.UpdateDataContext(statistics, packets);
        var popupsElapsed = (DateTime.Now - popupsStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] Popups component updated in {popupsElapsed:F2}s");

        // Update geographic data
        var geoStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating geographic data...");
        UpdateGeographicData(statistics, packets);
        var geoElapsed = (DateTime.Now - geoStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] Geographic data updated in {geoElapsed:F2}s");

        // Update TCP health
        var tcpStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating TCP health...");
        UpdateTCPHealth(statistics);
        var tcpElapsed = (DateTime.Now - tcpStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] TCP health updated in {tcpElapsed:F2}s");

        var totalElapsed = (DateTime.Now - updateStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] UpdateAllComponents completed in {totalElapsed:F2}s (Charts: {chartsElapsed:F2}s, Stats: {statsElapsed:F2}s, Popups: {popupsElapsed:F2}s, Geo: {geoElapsed:F2}s, TCP: {tcpElapsed:F2}s)");
    }

    /// <summary>
    /// Sets pre-calculated statistics to avoid recalculation.
    /// Useful when statistics are already available from another source.
    /// </summary>
    public void SetStatisticsOverride(NetworkStatistics statistics)
    {
        _nextStatisticsOverride = statistics;
    }

    /// <summary>
    /// Update the anomaly summary widget with detected anomalies.
    /// Called after PCAP analysis completes.
    /// </summary>
    public void UpdateAnomalySummary(IReadOnlyList<NetworkAnomaly>? anomalies)
    {
        DebugLogger.Log($"[DashboardViewModel] Updating anomaly summary: {anomalies?.Count ?? 0} anomalies");
        AnomalySummary.UpdateFromAnomalies(anomalies);

        // Build frame number caches for efficient anomaly filtering by category
        var anomalyList = anomalies?.ToList() ?? new List<NetworkAnomaly>();

        _anomalyFrameNumbers = anomalyList
            .SelectMany(a => a.AffectedFrames)
            .ToHashSet();

        _highSeverityFrames = anomalyList
            .Where(a => a.Severity == AnomalySeverity.Critical || a.Severity == AnomalySeverity.High)
            .SelectMany(a => a.AffectedFrames)
            .ToHashSet();

        _tcpAnomalyFrames = anomalyList
            .Where(a => a.Category == AnomalyCategory.TCP)
            .SelectMany(a => a.AffectedFrames)
            .ToHashSet();

        _networkAnomalyFrames = anomalyList
            .Where(a => a.Category == AnomalyCategory.Network || a.Category == AnomalyCategory.Security)
            .SelectMany(a => a.AffectedFrames)
            .ToHashSet();

        DebugLogger.Log($"[DashboardViewModel] Cached anomaly frames - All: {_anomalyFrameNumbers.Count}, High+: {_highSeverityFrames.Count}, TCP: {_tcpAnomalyFrames.Count}, Network: {_networkAnomalyFrames.Count}");
    }

    // ==================== FILTER COMMANDS ====================

    /// <summary>
    /// IFilterableTab implementation - applies common and tab-specific filters (sync wrapper)
    /// </summary>
    public new void ApplyFilters()
    {
        _ = ApplyFiltersAsync();
    }

    /// <summary>
    /// Async version of ApplyFilters with progress reporting and cancellation.
    /// </summary>
    public async Task ApplyFiltersAsync()
    {
        await UpdateFilteredStatisticsAsync();
    }

    /// <summary>
    /// Applies the sophisticated PacketFilter to Dashboard's displayed packets
    /// </summary>
    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Store the chip-based filter for use in filtering
        _currentChipBasedFilter = filter;

        // Apply filter to _displayedPackets and update Dashboard visualizations
        _ = ApplyChipBasedFilterAsync();
        DebugLogger.Log($"[{TabName}] Smart filters applied from chips (IsEmpty={filter?.IsEmpty ?? true})");
    }

    /// <summary>
    /// Applies the chip-based PacketFilter to packets and updates statistics.
    /// This is the NEW filter path that respects INCLUDE/EXCLUDE chips.
    /// </summary>
    private async Task ApplyChipBasedFilterAsync()
    {
        _filterCancellationTokenSource?.Cancel();
        _filterCancellationTokenSource = new CancellationTokenSource();
        var cancellationToken = _filterCancellationTokenSource.Token;

        try
        {
            if (_allPackets == null || _allPackets.Count == 0)
            {
                DebugLogger.Log("[DashboardViewModel] No packets available for chip-based filtering");
                return;
            }

            IsFilteringInProgress = true;
            FilterProgress = 0.0;

            var startTime = DateTime.Now;
            var filter = _currentChipBasedFilter;

            // Check if filter is empty or null
            IsFilterActive = filter != null && !filter.IsEmpty;

            if (!IsFilterActive)
            {
                _filteredPackets = null;
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                {
                    // CRITICAL: Set statistics FIRST, before any chart updates
                    _currentStatistics = _unfilteredStatistics;

                    Statistics.ClearFilteredStatistics();
                    // CRITICAL: Update charts with full unfiltered data when filters are cleared
                    if (_unfilteredStatistics != null)
                    {
                        Statistics.UpdateAllStatistics(_unfilteredStatistics, isFiltered: false);
                        Charts.UpdateAllCharts(_unfilteredStatistics);
                        DebugLogger.Log("[DashboardViewModel] Charts restored to unfiltered data");
                    }
                    // CRITICAL: Refresh extended collections (with ranking) for UI bindings
                    UpdateExtendedCollections();

                    // CRITICAL: Update Port Activity Timeline LAST to ensure _currentStatistics is set
                    UpdatePortActivityTimeline();
                });
                DebugLogger.Log("[DashboardViewModel] No chip filters active, using unfiltered packets");
                return;
            }

            DebugLogger.Log($"[DashboardViewModel] Applying chip-based filter to {_allPackets.Count:N0} packets");
            FilterProgress = 0.2;

            // Apply the chip-based filter using PacketFilter.MatchesPacket()
            var filteredList = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = new List<PacketInfo>();

                foreach (var packet in _allPackets)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (filter!.MatchesPacket(packet))
                    {
                        result.Add(packet);
                    }
                }

                return result;
            }, cancellationToken);

            FilterProgress = 0.6;
            cancellationToken.ThrowIfCancellationRequested();

            // Apply global anomaly filters if active
            if (_globalFilterState != null && _globalFilterState.HasAnomalyFilters && _anomalyFrameIndexService != null)
            {
                var matchingFrames = _anomalyFrameIndexService.GetFramesMatchingFilters(
                    _globalFilterState.AnomalySeverityFilter,
                    _globalFilterState.AnomalyCategoryFilter,
                    _globalFilterState.AnomalyDetectorFilter);

                if (matchingFrames.Count > 0)
                {
                    filteredList = filteredList.Where(p => matchingFrames.Contains(p.FrameNumber)).ToList();
                    DebugLogger.Log($"[DashboardViewModel] Applied anomaly filters: {filteredList.Count:N0} packets match anomaly criteria");
                }
            }

            FilterProgress = 0.7;
            cancellationToken.ThrowIfCancellationRequested();

            // Calculate statistics on filtered data
            var filteredStats = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return _statisticsService.CalculateStatistics(filteredList);
            }, cancellationToken);

            FilterProgress = 0.95;

            // Update UI
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                _filteredPackets = filteredList;
                _filteredStatistics = filteredStats;
                _currentStatistics = filteredStats;
                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
                Charts.UpdateAllCharts(filteredStats);

                // CRITICAL: Update Extended collections that XAML binds to!
                // Statistics.UpdateAllStatistics updates the underlying collections,
                // but the UI binds to TopSourcesExtended, TopDestinationsExtended, etc.
                UpdateExtendedCollections();

                UpdatePortActivityTimeline();
            });

            FilterProgress = 1.0;
            var elapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardViewModel] Chip-based filter complete in {elapsed:F2}s: {filteredList.Count:N0}/{_allPackets.Count:N0} packets");
        }
        catch (OperationCanceledException)
        {
            DebugLogger.Log("[DashboardViewModel] Chip-based filter cancelled");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error in chip-based filtering: {ex.Message}");
        }
        finally
        {
            IsFilteringInProgress = false;
        }
    }

    [RelayCommand]
    private async Task ApplyFilterAsync()
    {
        await ApplyFiltersAsync();
    }

    /// <summary>
    /// Populates Dashboard filters based on a connection (for Quick Win filtering from Details window)
    /// </summary>
    [RelayCommand]
    public void FilterByConnection(object? parameter)
    {
        if (parameter is ConversationViewModel connection)
        {
            FilterSourceIP = connection.SourceAddress;
            FilterDestinationIP = connection.DestinationAddress;
            FilterPortRange = $"{connection.SourcePort},{connection.DestinationPort}";

            // Map protocol to string (free-text now, not index)
            FilterProtocolType = connection.Protocol;

            ExportStatusMessage = $"🔍 Filtered by: {connection.SourceDisplay} ↔ {connection.DestinationDisplay}";
            ExportStatusColor = "#3B82F6";
            _ = AutoClearExportStatusAsync();
        }
    }

    [RelayCommand]
    private void ClearFilter()
    {
        // Clear common filters
        CommonFilters.Clear();

        // Clear tab-specific filters
        TrafficTypeFilter = "All";
        PortRangeFilter = "";

        // Clear legacy filters
        FilterText = "";
        FilterStartTime = null;
        FilterEndTime = null;
        FilterProtocol = "All";
        FilterSeverity = "All";

        // ==================== CLEAR SHARED FILTERS ====================
        // These are stored in NetworkQuickFilters (single source of truth)
        NetworkQuickFilters.ClearAll();

        // ==================== CLEAR DASHBOARD-ONLY FILTERS ====================
        // L7 Protocol Filters
        FilterTlsV10Toggle = false;
        FilterTlsV11Toggle = false;
        FilterTlsV12Toggle = false;
        FilterTlsV13Toggle = false;
        FilterHttpToggle = false;
        FilterHttpsToggle = false;
        FilterDnsToggle = false;
        FilterSnmpToggle = false;
        FilterSshToggle = false;
        FilterFtpToggle = false;
        FilterSmtpToggle = false;
        FilterStunToggle = false;
        FilterDhcpServerToggle = false;

        // VPN Protocol Filters
        FilterWireGuardToggle = false;
        FilterOpenVpnToggle = false;
        FilterIkeV2Toggle = false;
        FilterIpsecToggle = false;
        FilterL2tpToggle = false;
        FilterPptpToggle = false;

        // Reset logic controls
        FilterUseAndMode = true;
        FilterUseNotMode = false;

        IsFilterActive = false;
        Statistics.ClearFilteredStatistics();

        DebugLogger.Log("[DashboardViewModel] Cleared all filters (NetworkQuickFilters + Dashboard-only)");
    }

    /// <summary>
    /// Async filter implementation with progress reporting and cancellation support.
    /// Uses DashboardFilterService for efficient single-pass smart filtering.
    /// </summary>
    private async Task UpdateFilteredStatisticsAsync()
    {
        // Cancel any in-progress filter operation
        _filterCancellationTokenSource?.Cancel();
        _filterCancellationTokenSource = new CancellationTokenSource();
        var cancellationToken = _filterCancellationTokenSource.Token;

        try
        {
            if (_allPackets == null || _allPackets.Count == 0)
            {
                DebugLogger.Log("[DashboardViewModel] No packets available for filtering");
                return;
            }

            IsFilteringInProgress = true;
            FilterProgress = 0.0;

            var startTime = DateTime.Now;
            DebugLogger.Log($"[DashboardViewModel] Starting async filter on {_allPackets.Count:N0} packets");

            // Build smart filter state from current toggle values
            var smartFilters = BuildSmartFilterState();
            var hasSmartFilters = smartFilters.HasActiveFilters;

            // Check if any filters are active
            var hasCommonFilters = CommonFilters.HasActiveFilters ||
                                   TrafficTypeFilter != "All" ||
                                   !string.IsNullOrWhiteSpace(PortRangeFilter) ||
                                   !string.IsNullOrWhiteSpace(FilterText) ||
                                   FilterStartTime.HasValue ||
                                   FilterEndTime.HasValue ||
                                   FilterProtocol != "All";

            IsFilterActive = hasCommonFilters || hasSmartFilters;

            // Update filter descriptions for badge display
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                ActiveFilterDescriptions.Clear();
                if (hasSmartFilters)
                {
                    var descriptions = _dashboardFilterService.GetActiveFilterDescriptions(smartFilters);
                    foreach (var desc in descriptions)
                    {
                        ActiveFilterDescriptions.Add(desc);
                    }
                }
            });

            if (!IsFilterActive)
            {
                _filteredPackets = null;

                // Update UI to show unfiltered data
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                {
                    // CRITICAL: Set statistics FIRST, before any chart updates
                    _currentStatistics = _unfilteredStatistics;

                    Statistics.ClearFilteredStatistics();

                    // CRITICAL: Update charts with full unfiltered data when filters are cleared
                    if (_unfilteredStatistics != null)
                    {
                        Statistics.UpdateAllStatistics(_unfilteredStatistics, isFiltered: false);
                        Charts.UpdateAllCharts(_unfilteredStatistics);
                        DebugLogger.Log("[DashboardViewModel] Legacy filter cleared - Charts restored to unfiltered data");
                    }

                    // CRITICAL: Refresh extended collections (with ranking) for UI bindings
                    UpdateExtendedCollections();

                    // CRITICAL: Update Port Activity Timeline LAST to ensure _currentStatistics is set
                    UpdatePortActivityTimeline();
                });

                DebugLogger.Log("[DashboardViewModel] No filters active, using unfiltered packets");
                return;
            }

            // Phase 1: Apply common/legacy filters (quick, done on UI thread for small sets, or background for large)
            var preFilteredPackets = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ApplyCommonFilters(_allPackets);
            }, cancellationToken);

            FilterProgress = 0.3;

            // Phase 2: Apply smart filters using the optimized service
            List<PacketInfo> filteredList;
            if (hasSmartFilters)
            {
                var progress = new Progress<double>(p => FilterProgress = 0.3 + (p * 0.5)); // 30-80%
                var anomalyFrameSet = BuildAnomalyFrameSet();
                filteredList = await _dashboardFilterService.ApplySmartFiltersAsync(
                    preFilteredPackets,
                    smartFilters,
                    anomalyFrameSet,
                    FilterUseAndMode,
                    FilterUseNotMode,
                    progress,
                    cancellationToken);
            }
            else
            {
                filteredList = preFilteredPackets;
            }

            FilterProgress = 0.8;
            cancellationToken.ThrowIfCancellationRequested();

            // Phase 3: Calculate statistics on background thread
            var filteredStats = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return _statisticsService.CalculateStatistics(filteredList);
            }, cancellationToken);

            FilterProgress = 0.95;
            cancellationToken.ThrowIfCancellationRequested();

            // Phase 4: Update UI (must be on UI thread)
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                _filteredPackets = filteredList;
                _filteredStatistics = filteredStats;
                _currentStatistics = filteredStats; // Update current statistics to filtered for timeline/other views
                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
                Charts.UpdateAllCharts(filteredStats);

                // Update extended collections (with ranking) for UI bindings
                UpdateExtendedCollections();

                // Update Port Activity Timeline chart with filtered statistics
                UpdatePortActivityTimeline();
            });

            FilterProgress = 1.0;

            var elapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardViewModel] Async filter complete in {elapsed:F2}s: {filteredList.Count:N0}/{_allPackets.Count:N0} packets");
        }
        catch (OperationCanceledException)
        {
            DebugLogger.Log("[DashboardViewModel] Filter operation cancelled");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error in async filtering: {ex.Message}");
        }
        finally
        {
            IsFilteringInProgress = false;
        }
    }

    /// <summary>
    /// Apply common filters (protocol, IP, port, time range) in a single pass.
    /// Returns materialized list for efficient smart filter processing.
    /// </summary>
    private List<PacketInfo> ApplyCommonFilters(IReadOnlyList<PacketInfo> packets)
    {
        // Build a combined predicate for single-pass evaluation
        var predicates = new List<Func<PacketInfo, bool>>();

        // Common filters
        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
        {
            var filter = CommonFilters.ProtocolFilter;
            predicates.Add(p => p.Protocol.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(CommonFilters.SourceIPFilter))
        {
            var filter = CommonFilters.SourceIPFilter;
            predicates.Add(p => p.SourceIP.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(CommonFilters.DestinationIPFilter))
        {
            var filter = CommonFilters.DestinationIPFilter;
            predicates.Add(p => p.DestinationIP.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        // Tab-specific filters
        if (TrafficTypeFilter != "All")
        {
            var filter = TrafficTypeFilter;
            predicates.Add(p => p.Protocol.ToString().Equals(filter, StringComparison.OrdinalIgnoreCase));
        }

        // Port range filter - now supports ranges like "80-443" or comma-separated "80,443,8080"
        if (!string.IsNullOrWhiteSpace(PortRangeFilter))
        {
            var portPredicate = BuildPortRangePredicate(PortRangeFilter);
            if (portPredicate != null)
                predicates.Add(portPredicate);
        }

        // Legacy filters
        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            var filter = FilterText;
            predicates.Add(p =>
                p.SourceIP.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.DestinationIP.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                (p.Info?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        if (FilterStartTime.HasValue)
        {
            var startTime = FilterStartTime.Value;
            predicates.Add(p => p.Timestamp >= startTime);
        }

        if (FilterEndTime.HasValue)
        {
            var endTime = FilterEndTime.Value;
            predicates.Add(p => p.Timestamp <= endTime);
        }

        if (FilterProtocol != "All")
        {
            var filter = FilterProtocol;
            predicates.Add(p => p.Protocol.ToString() == filter);
        }

        // Single-pass evaluation
        if (predicates.Count == 0)
            return packets as List<PacketInfo> ?? packets.ToList();

        var result = new List<PacketInfo>(packets.Count / 2);
        foreach (var packet in packets)
        {
            var passes = true;
            foreach (var pred in predicates)
            {
                if (!pred(packet))
                {
                    passes = false;
                    break;
                }
            }
            if (passes)
                result.Add(packet);
        }

        return result;
    }

    /// <summary>
    /// Build a port filter predicate that supports single port, ranges (80-443), and comma-separated values (80,443,8080).
    /// </summary>
    private static Func<PacketInfo, bool>? BuildPortRangePredicate(string portFilter)
    {
        var ports = new HashSet<ushort>();
        var ranges = new List<(ushort min, ushort max)>();

        foreach (var part in portFilter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains('-', StringComparison.Ordinal))
            {
                var rangeParts = part.Split('-');
                if (rangeParts.Length == 2 &&
                    ushort.TryParse(rangeParts[0].Trim(), out var minPort) &&
                    ushort.TryParse(rangeParts[1].Trim(), out var maxPort))
                {
                    ranges.Add((Math.Min(minPort, maxPort), Math.Max(minPort, maxPort)));
                }
            }
            else if (ushort.TryParse(part, out var singlePort))
            {
                ports.Add(singlePort);
            }
        }

        if (ports.Count == 0 && ranges.Count == 0)
            return null;

        return p =>
        {
            // Check exact port matches
            if (ports.Contains(p.SourcePort) || ports.Contains(p.DestinationPort))
                return true;

            // Check port ranges
            foreach (var (min, max) in ranges)
            {
                if ((p.SourcePort >= min && p.SourcePort <= max) ||
                    (p.DestinationPort >= min && p.DestinationPort <= max))
                    return true;
            }

            return false;
        };
    }

    /// <summary>
    /// Build an immutable AnomalyFrameSet from current ViewModel anomaly caches.
    /// Creates a new instance each time for thread-safety.
    /// </summary>
    private AnomalyFrameSet BuildAnomalyFrameSet()
    {
        return new AnomalyFrameSet
        {
            AllFrames = new HashSet<long>(_anomalyFrameNumbers),
            HighSeverityFrames = new HashSet<long>(_highSeverityFrames),
            TcpAnomalyFrames = new HashSet<long>(_tcpAnomalyFrames),
            NetworkAnomalyFrames = new HashSet<long>(_networkAnomalyFrames)
        };
    }

    /// <summary>
    /// Builds DashboardSmartFilters state from current filter toggle values.
    /// ARCHITECTURE: Shared filters are read via inherited base class wrappers which
    /// delegate to NetworkQuickFilters (single source of truth).
    /// Dashboard-only filters (L7 protocols, TLS, VPN) are read from this class.
    /// </summary>
    private DashboardSmartFilters BuildSmartFilterState()
    {
        return new DashboardSmartFilters
        {
            // ==================== INHERITED FROM SmartFilterableTab ====================
            // These use base class wrappers → NetworkQuickFilters (single source of truth)

            // Network Type Filters
            Rfc1918 = FilterRfc1918Toggle,
            PublicIP = FilterPublicIpToggle,
            Apipa = FilterApipaToggle,
            Ipv4 = FilterIPv4Toggle,
            Ipv6 = FilterIPv6Toggle,
            Multicast = FilterMulticastToggle,
            Broadcast = FilterBroadcastToggle,
            Anycast = FilterAnycastToggle,

            // Security Filters
            Insecure = FilterInsecureToggle,
            Anomalies = FilterAnomaliesToggle,
            Suspicious = FilterSuspiciousToggle,
            TcpIssues = FilterTcpIssuesToggle,
            DnsAnomalies = FilterDnsAnomaliesToggle,
            PortScans = FilterPortScansToggle,

            // Traffic Pattern Filters
            JumboFrames = FilterJumboFramesToggle,
            PrivateToPublic = FilterPrivateToPublicToggle,
            PublicToPrivate = FilterPublicToPrivateToggle,
            LinkLocal = FilterLinkLocalToggle,
            Loopback = FilterLoopbackToggle,

            // TCP Performance
            Retransmissions = FilterRetransmissionsToggle,
            ZeroWindow = FilterZeroWindowToggle,
            KeepAlive = FilterKeepAliveToggle,
            ConnectionRefused = FilterConnectionRefusedToggle,
            WindowFull = FilterWindowFullToggle,

            // Security Audit
            CleartextAuth = FilterCleartextAuthToggle,
            ObsoleteCrypto = FilterObsoleteCryptoToggle,
            DnsTunneling = FilterDnsTunnelingToggle,
            ScanTraffic = FilterScanTrafficToggle,
            NonStandardPorts = FilterNonStandardPortsToggle,
            SmbV1 = FilterSmbV1Toggle,

            // Clean View
            HideBroadcast = FilterHideBroadcastToggle,
            ApplicationDataOnly = FilterApplicationDataOnlyToggle,
            HideTunnelOverhead = FilterHideTunnelOverheadToggle,

            // Protocol Errors
            HttpErrors = FilterHttpErrorsToggle,
            DnsFailures = FilterDnsFailuresToggle,
            IcmpUnreachable = FilterIcmpUnreachableToggle,

            // ==================== DASHBOARD-ONLY FILTERS ====================
            // These use [ObservableProperty] declared in this class

            // L7 Protocol Filters
            TlsV10 = FilterTlsV10Toggle,
            TlsV11 = FilterTlsV11Toggle,
            TlsV12 = FilterTlsV12Toggle,
            TlsV13 = FilterTlsV13Toggle,
            Http = FilterHttpToggle,
            Https = FilterHttpsToggle,
            Dns = FilterDnsToggle,
            Snmp = FilterSnmpToggle,
            Ssh = FilterSshToggle,
            Ftp = FilterFtpToggle,
            Smtp = FilterSmtpToggle,
            Stun = FilterStunToggle,
            Dhcp = FilterDhcpServerToggle,

            // VPN Protocol Filters
            WireGuard = FilterWireGuardToggle,
            OpenVPN = FilterOpenVpnToggle,
            IkeV2 = FilterIkeV2Toggle,
            Ipsec = FilterIpsecToggle,
            L2tp = FilterL2tpToggle,
            Pptp = FilterPptpToggle
        };
    }

    // ==================== FILTER SERVICE INTEGRATION ====================

    private void OnFilterServiceChanged(object? sender, EventArgs e)
    {
        if (_filterService == null) return;

        try
        {
            if (_filterService.IsFilterActive && _allPackets != null)
            {
                var filteredPackets = _filterService.GetFilteredPackets(_allPackets).ToList();
                _filteredPackets = filteredPackets;

                var filteredStats = _statisticsService.CalculateStatistics(filteredPackets);
                _filteredStatistics = filteredStats;

                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
                Charts.UpdateAllCharts(filteredStats);
            }
            else
            {
                // Reset to unfiltered
                _filteredPackets = null;
                if (_unfilteredStatistics != null)
                {
                    Statistics.UpdateAllStatistics(_unfilteredStatistics, isFiltered: false);
                    Charts.UpdateAllCharts(_unfilteredStatistics);
                }
                Statistics.ClearFilteredStatistics();
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error handling filter change: {ex.Message}");
        }
    }

    // ==================== GEOGRAPHIC DATA ====================

    private void UpdateGeographicData(NetworkStatistics statistics, IReadOnlyList<PacketInfo> packets)
    {
        try
        {
            if (statistics.CountryStatistics != null && statistics.CountryStatistics.Any())
            {
                var countryData = new Dictionary<string, double>();

                foreach (var kvp in statistics.CountryStatistics)
                {
                    var percentage = statistics.TotalPackets > 0
                        ? (double)kvp.Value.TotalPackets / statistics.TotalPackets * 100
                        : 0;
                    countryData[kvp.Key] = percentage;
                }

                CountryMapData = countryData;
                ItemsCount = countryData.Count;

                UniqueCountries = statistics.CountryStatistics.Count;
                TopCountry = statistics.CountryStatistics
                    .OrderByDescending(c => c.Value.TotalPackets)
                    .FirstOrDefault().Key ?? "N/A";
                HasInternationalTraffic = statistics.CountryStatistics.Count > 1;

                DebugLogger.Log($"[DashboardViewModel] Updated geographic data: {countryData.Count} countries");
            }
            else
            {
                CountryMapData = new Dictionary<string, double>();
                ItemsCount = 0;
                UniqueCountries = 0;
                TopCountry = "N/A";
                HasInternationalTraffic = false;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error updating geographic data: {ex.Message}");
        }
    }

    // ==================== TCP HEALTH ====================

    private void UpdateTCPHealth(NetworkStatistics statistics)
    {
        try
        {
            var tcpAnomalies = statistics.Threats?
                .Where(t => t.Type.Contains("TCP", StringComparison.OrdinalIgnoreCase))
                .ToList() ?? new List<ThreatInfo>();

            TcpAnomalyCount = tcpAnomalies.Count;

            if (TcpAnomalyCount == 0)
            {
                TcpHealthStatus = "Healthy";
                TcpHealthColor = "#10B981"; // Green
            }
            else if (TcpAnomalyCount < 10)
            {
                TcpHealthStatus = "Minor Issues";
                TcpHealthColor = "#FCD34D"; // Yellow
            }
            else if (TcpAnomalyCount < 50)
            {
                TcpHealthStatus = "Degraded";
                TcpHealthColor = "#F59E0B"; // Orange
            }
            else
            {
                TcpHealthStatus = "Critical";
                TcpHealthColor = "#DC2626"; // Red
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error updating TCP health: {ex.Message}");
        }
    }

    // ==================== HELPER METHODS ====================

    private List<PacketInfo> SamplePackets(IReadOnlyList<PacketInfo> packets, int sampleSize)
    {
        if (packets.Count <= sampleSize)
            return packets as List<PacketInfo> ?? packets.ToList();

        // Stratified sampling to maintain temporal distribution
        var step = packets.Count / sampleSize;
        return packets.Where((p, i) => i % step == 0).Take(sampleSize).ToList();
    }

    // ==================== FILTER PRESET COMMANDS ====================

    /// <summary>
    /// Load all available presets (built-in + user-defined)
    /// </summary>
    private async Task LoadPresetsAsync()
    {
        if (_filterPresetService == null)
        {
            DebugLogger.Log("[DashboardViewModel] FilterPresetService not available");
            return;
        }

        try
        {
            IsLoadingPresets = true;
            var presets = await _filterPresetService.GetAllPresetsAsync();

            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                AvailablePresets.Clear();
                foreach (var preset in presets)
                {
                    AvailablePresets.Add(preset);
                }
            });

            DebugLogger.Log($"[DashboardViewModel] Loaded {presets.Count} filter presets");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error loading presets: {ex.Message}");
        }
        finally
        {
            IsLoadingPresets = false;
        }
    }

    /// <summary>
    /// Apply the selected preset to current filter state
    /// </summary>
    [RelayCommand]
    private async Task ApplyPresetAsync()
    {
        if (SelectedPreset == null || _filterPresetService == null)
        {
            return;
        }

        try
        {
            DebugLogger.Log($"[DashboardViewModel] Applying preset: {SelectedPreset.Name}");

            // Apply preset to this ViewModel
            _filterPresetService.ApplyPreset(SelectedPreset, this);

            // Trigger filter update
            await ApplyFiltersAsync();

            ExportStatusMessage = $"Applied preset: {SelectedPreset.Name}";
            ExportStatusColor = "#3B82F6"; // Blue
            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error applying preset: {ex.Message}");
            ExportStatusMessage = $"Error applying preset: {ex.Message}";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
        }
    }

    /// <summary>
    /// Save current filter state as a new preset
    /// </summary>
    [RelayCommand]
    private async Task SaveCurrentAsPresetAsync(string? presetName)
    {
        if (_filterPresetService == null)
        {
            ExportStatusMessage = "Preset service not available";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
            return;
        }

        if (string.IsNullOrWhiteSpace(presetName))
        {
            ExportStatusMessage = "Preset name is required";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
            return;
        }

        try
        {
            // Create preset from current ViewModel state
            var preset = _filterPresetService.CreateFromViewModel(
                presetName,
                $"Custom preset created on {DateTime.Now:yyyy-MM-dd HH:mm}",
                this);

            // Save preset
            var success = await _filterPresetService.SavePresetAsync(preset);

            if (success)
            {
                // Reload presets to show new one
                await LoadPresetsAsync();

                ExportStatusMessage = $"Saved preset: {presetName}";
                ExportStatusColor = "#10B981"; // Green
                DebugLogger.Log($"[DashboardViewModel] Saved new preset: {presetName}");
            }
            else
            {
                ExportStatusMessage = $"Cannot save preset: {presetName} (conflicts with built-in)";
                ExportStatusColor = "#DC2626"; // Red
                DebugLogger.Log($"[DashboardViewModel] Failed to save preset: {presetName}");
            }

            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error saving preset: {ex.Message}");
            ExportStatusMessage = $"Error saving preset: {ex.Message}";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
        }
    }

    /// <summary>
    /// Delete a user-defined preset
    /// </summary>
    [RelayCommand]
    private async Task DeletePresetAsync(FilterPreset? preset)
    {
        if (preset == null || _filterPresetService == null)
        {
            return;
        }

        if (preset.IsBuiltIn)
        {
            ExportStatusMessage = "Cannot delete built-in presets";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
            return;
        }

        try
        {
            var success = await _filterPresetService.DeletePresetAsync(preset.Name);

            if (success)
            {
                // Reload presets to remove deleted one
                await LoadPresetsAsync();

                // Clear selection if deleted preset was selected
                if (SelectedPreset?.Name == preset.Name)
                {
                    SelectedPreset = null;
                }

                ExportStatusMessage = $"Deleted preset: {preset.Name}";
                ExportStatusColor = "#10B981"; // Green
                DebugLogger.Log($"[DashboardViewModel] Deleted preset: {preset.Name}");
            }
            else
            {
                ExportStatusMessage = $"Failed to delete preset: {preset.Name}";
                ExportStatusColor = "#DC2626"; // Red
            }

            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error deleting preset: {ex.Message}");
            ExportStatusMessage = $"Error deleting preset: {ex.Message}";
            ExportStatusColor = "#DC2626"; // Red
            _ = AutoClearExportStatusAsync();
        }
    }

    // ==================== DISPOSAL ====================

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_isDisposed) return;

        if (disposing)
        {
            try
            {
                // Cancel any in-progress filter operation
                _filterCancellationTokenSource?.Cancel();
                _filterCancellationTokenSource?.Dispose();
                _filterCancellationTokenSource = null;

                // Unsubscribe from CommonFilters property changes (fixes memory leak)
                if (_commonFiltersHandler != null)
                {
                    CommonFilters.PropertyChanged -= _commonFiltersHandler;
                    _commonFiltersHandler = null;
                }

                // Unsubscribe from component property changes
                Statistics.PropertyChanged -= OnStatisticsPropertyChanged;
                Charts.PropertyChanged -= OnChartsPropertyChanged;

                if (_filterService != null)
                {
                    _filterService.FilterChanged -= OnFilterServiceChanged;
                }

                // Unregister from FilterCopyService
                _filterCopyService?.UnregisterTab(TabName);

                // Clear data
                _currentStatistics = null;
                _unfilteredStatistics = null;
                _filteredStatistics = null;
                _allPackets = null;
                _filteredPackets = null;

                DebugLogger.Log("[DashboardViewModel] Disposed successfully");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error during disposal: {ex.Message}");
            }
        }

        _isDisposed = true;
    }

    // ==================== PROPERTY CHANGE FORWARDING ====================

    /// <summary>
    /// Forwards property changes from Statistics component to DashboardViewModel.
    /// This ensures backward compatibility - when Statistics.TotalPackets changes,
    /// UI bindings to DashboardViewModel.TotalPackets get notified.
    /// Also handles property name mapping for compatibility layer aliases.
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Statistics property change handling requires forwarding and mapping multiple property names for backward compatibility with legacy UI bindings")]
    private void OnStatisticsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (string.IsNullOrEmpty(e.PropertyName))
            return;

        // Forward the property change
        OnPropertyChanged(e.PropertyName);

        // Also notify compatibility layer aliases for certain properties
        switch (e.PropertyName)
        {
            case nameof(Statistics.DifferentPorts):
                OnPropertyChanged(nameof(UniqueDestinationPorts)); // Compatibility alias
                OnPropertyChanged(nameof(FilteredDifferentPorts)); // Filtered version
                OnPropertyChanged(nameof(FilteredDifferentPortsPercentage)); // Dependent property
                break;
            case nameof(Statistics.ThreatCount):
                OnPropertyChanged(nameof(TotalAnomalies)); // Compatibility alias
                OnPropertyChanged(nameof(FilteredSecurityThreats)); // Filtered version
                OnPropertyChanged(nameof(FilteredAnomalies)); // Filtered version
                OnPropertyChanged(nameof(FilteredThreatsPercentage)); // Dependent property
                OnPropertyChanged(nameof(FilteredAnomaliesPercentage)); // Dependent property
                break;
            case nameof(Statistics.ActiveConversations):
                OnPropertyChanged(nameof(FilteredConversationCount)); // Filtered version
                OnPropertyChanged(nameof(FilteredConversationsPercentage)); // Dependent property
                break;
            case nameof(Statistics.UniqueIPs):
                OnPropertyChanged(nameof(FilteredUniqueIPs)); // Filtered version
                OnPropertyChanged(nameof(FilteredIPsPercentage)); // Dependent property
                break;
            case nameof(Statistics.TotalPackets):
                OnPropertyChanged(nameof(FilteredTotalPackets)); // Filtered version
                OnPropertyChanged(nameof(FilteredPacketsPercentage)); // Dependent property
                break;
            case nameof(Statistics.TotalBytesFormatted):
                OnPropertyChanged(nameof(FilteredTotalBytesFormatted)); // Filtered version
                OnPropertyChanged(nameof(FilteredTrafficPercentage)); // Dependent property
                break;
            case nameof(Statistics.UniqueProtocols):
                OnPropertyChanged(nameof(FilteredProtocolCount)); // Filtered version
                OnPropertyChanged(nameof(FilteredProtocolsPercentage)); // Dependent property
                break;
            case nameof(Statistics.FilteredTotalPackets):
            case nameof(Statistics.FilteredUniqueIPs):
            case nameof(Statistics.FilteredDifferentPorts):
            case nameof(Statistics.FilteredConversationCount):
            case nameof(Statistics.FilteredSecurityThreats):
            case nameof(Statistics.FilteredAnomalies):
            case nameof(Statistics.FilteredProtocolCount):
                // When filtered values change, notify all percentage properties
                OnPropertyChanged(nameof(FilteredPacketsPercentage));
                OnPropertyChanged(nameof(FilteredTrafficPercentage));
                OnPropertyChanged(nameof(FilteredIPsPercentage));
                OnPropertyChanged(nameof(FilteredDifferentPortsPercentage));
                OnPropertyChanged(nameof(FilteredConversationsPercentage));
                OnPropertyChanged(nameof(FilteredThreatsPercentage));
                OnPropertyChanged(nameof(FilteredAnomaliesPercentage));
                OnPropertyChanged(nameof(FilteredProtocolsPercentage));
                break;
            // Notify for collection changes to ensure tables update
            case nameof(Statistics.TopSources):
            case nameof(Statistics.TopSourcesByBytes):
            case nameof(Statistics.TopSourcesDisplay):
            case nameof(Statistics.TopSourcesByBytesDisplay):
            case nameof(Statistics.TopDestinations):
            case nameof(Statistics.TopDestinationsByBytes):
            case nameof(Statistics.TopDestinationsDisplay):
            case nameof(Statistics.TopDestinationsByBytesDisplay):
            case nameof(Statistics.TopPorts):
            case nameof(Statistics.TopPortsByPacketsDisplay):
            case nameof(Statistics.TopPortsByBytesDisplay):
            case nameof(Statistics.TopConversations):
            case nameof(Statistics.TopConversationsByBytes):
            case nameof(Statistics.TopThreats):
                // Already forwarded by default
                break;
        }
    }

    /// <summary>
    /// Forwards property changes from Charts component to DashboardViewModel.
    /// This ensures backward compatibility for chart-related bindings.
    /// </summary>
    private void OnChartsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward all Charts property changes to the parent ViewModel
        OnPropertyChanged(e.PropertyName);
    }

    // ==================== COMPATIBILITY LAYER ====================
    // Provides backward-compatible properties that delegate to component ViewModels.
    // Merged from DashboardViewModel.Compatibility.cs for cleaner project structure.

    // Statistics properties (delegate to Statistics component)
    public bool IsLoadingStats => Statistics.IsLoadingStats;
    public bool IsLoadingFilteredStats => Statistics.ShowFilteredStats;
    public bool ShowFilteredStats => Statistics.ShowFilteredStats;

    // Basic statistics
    public long TotalPackets => Statistics.TotalPackets;
    public string TotalBytesFormatted => Statistics.TotalBytesFormatted;
    public int UniqueIPs => Statistics.UniqueIPs;
    public int UniqueDestinationPorts => Statistics.DifferentPorts;
    public int ActiveConversations => Statistics.ActiveConversations;
    public int ThreatCount => Statistics.ThreatCount;
    public int TotalAnomalies => Statistics.ThreatCount;

    // Filtered statistics
    public long FilteredTotalPackets => Statistics.FilteredTotalPackets;
    public double FilteredPacketsPercentage => Statistics.TotalPackets > 0 ? (Statistics.FilteredTotalPackets * 100.0 / Statistics.TotalPackets) : 0;
    public string FilteredTotalBytesFormatted => Statistics.FilteredTotalBytesFormatted;
    public double FilteredTrafficPercentage => (_unfilteredStatistics != null && _filteredStatistics != null && _unfilteredStatistics.TotalBytes > 0)
        ? (_filteredStatistics.TotalBytes * 100.0 / _unfilteredStatistics.TotalBytes) : 0;
    public int FilteredUniqueIPs => Statistics.FilteredUniqueIPs;
    public double FilteredIPsPercentage => Statistics.UniqueIPs > 0 ? (Statistics.FilteredUniqueIPs * 100.0 / Statistics.UniqueIPs) : 0;
    public int FilteredDifferentPorts => Statistics.FilteredDifferentPorts;
    public double FilteredDifferentPortsPercentage => Statistics.DifferentPorts > 0 ? (Statistics.FilteredDifferentPorts * 100.0 / Statistics.DifferentPorts) : 0;
    public int FilteredConversationCount => Statistics.FilteredConversationCount;
    public double FilteredConversationsPercentage => Statistics.ActiveConversations > 0 ? (Statistics.FilteredConversationCount * 100.0 / Statistics.ActiveConversations) : 0;
    public int FilteredSecurityThreats => Statistics.FilteredSecurityThreats;
    public double FilteredThreatsPercentage => Statistics.ThreatCount > 0 ? (Statistics.FilteredSecurityThreats * 100.0 / Statistics.ThreatCount) : 0;
    public int FilteredAnomalies => Statistics.FilteredAnomalies;
    public double FilteredAnomaliesPercentage => Statistics.ThreatCount > 0 ? (Statistics.FilteredAnomalies * 100.0 / Statistics.ThreatCount) : 0;
    public int FilteredProtocolCount => Statistics.FilteredProtocolCount;
    public double FilteredProtocolsPercentage => Statistics.UniqueProtocols > 0 ? (Statistics.FilteredProtocolCount * 100.0 / Statistics.UniqueProtocols) : 0;

    // Endpoint collections
    public ObservableCollection<EndpointViewModel> TopSources => Statistics.TopSources;
    public ObservableCollection<EndpointViewModel> TopSourcesByBytes => Statistics.TopSourcesByBytes;
    public ObservableCollection<EndpointViewModel> TopSourcesDisplay => Statistics.TopSourcesDisplay;
    public ObservableCollection<EndpointViewModel> TopSourcesByBytesDisplay => Statistics.TopSourcesByBytesDisplay;
    public ObservableCollection<EndpointViewModel> TopDestinations => Statistics.TopDestinations;
    public ObservableCollection<EndpointViewModel> TopDestinationsByBytes => Statistics.TopDestinationsByBytes;
    public ObservableCollection<EndpointViewModel> TopDestinationsDisplay => Statistics.TopDestinationsDisplay;
    public ObservableCollection<EndpointViewModel> TopDestinationsByBytesDisplay => Statistics.TopDestinationsByBytesDisplay;

    // Port collections
    public ObservableCollection<TopPortViewModel> TopPorts => Statistics.TopPorts;
    public ObservableCollection<TopPortViewModel> TopPortsByPacketsDisplay => Statistics.TopPortsByPacketsDisplay;
    public ObservableCollection<TopPortViewModel> TopPortsByBytesDisplay => Statistics.TopPortsByBytesDisplay;

    // Conversation collections
    public ObservableCollection<ConversationViewModel> TopConversations => Statistics.TopConversations;
    public ObservableCollection<ConversationViewModel> TopConversationsByBytes => Statistics.TopConversationsByBytes;

    // Charts properties (delegate to Charts component)
    public ObservableCollection<ISeries> TimelineSeries => Charts.TimelineSeries;
    public Axis[] XAxes => Charts.XAxes;
    public Axis[] YAxes => Charts.YAxes;
    public ObservableCollection<ISeries> ThroughputSeries => Charts.ThroughputSeries;
    public ObservableCollection<ISeries> ProtocolSeries => Charts.ProtocolSeries;
    public ObservableCollection<ISeries> PortSeries => Charts.PortSeries;
    public ObservableCollection<ISeries> PortByBytesSeries => Charts.PortByBytesSeries;
    public ObservableCollection<ISeries> PortByPacketsSeries => Charts.PortByPacketsSeries;

    /// <summary>
    /// Updates throughput chart (delegates to Charts component)
    /// </summary>
    public void UpdateThroughputChart(NetworkStatistics statistics)
    {
        Charts.UpdateThroughputChart(statistics);
    }

    /// <summary>
    /// Updates throughput chart without parameters (for backward compatibility)
    /// </summary>
    public void UpdateThroughputChart()
    {
        if (_currentStatistics != null)
        {
            Charts.UpdateThroughputChart(_currentStatistics);
        }
    }

    /// <summary>
    /// Updates statistics (delegates to UpdateStatisticsAsync)
    /// </summary>
    public void UpdateStatistics(NetworkStatistics statistics)
    {
        _nextStatisticsOverride = statistics;
    }

    /// <summary>
    /// Updates statistics with packets (delegates to UpdateStatisticsAsync)
    /// </summary>
    public async Task UpdateStatistics(NetworkStatistics statistics, IReadOnlyList<PacketInfo> packets)
    {
        _nextStatisticsOverride = statistics;
        await UpdateStatisticsAsync(packets);
    }

    /// <summary>
    /// Resets all statistics
    /// </summary>
    public void ResetStatistics()
    {
        _currentStatistics = null;
        _unfilteredStatistics = null;
        _filteredStatistics = null;
        _allPackets = null;
        _filteredPackets = null;

        Statistics.TopSources.Clear();
        Statistics.TopDestinations.Clear();
        Statistics.TopPorts.Clear();
        Statistics.TopConversations.Clear();
        Charts.TimelineSeries.Clear();
        Charts.ThroughputSeries.Clear();
        Charts.ProtocolSeries.Clear();
    }

    // ==================== ITabPopulationTarget IMPLEMENTATION ====================

    /// <inheritdoc />
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[DashboardViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");
        SetStatisticsOverride(result.Statistics);
        await UpdateStatisticsAsync(result.AllPackets);
    }
}
