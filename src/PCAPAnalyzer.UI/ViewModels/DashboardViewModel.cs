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
using PCAPAnalyzer.UI.Utilities;

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

    public DashboardChartsViewModel Charts { get; }
    public DashboardStatisticsViewModel Statistics { get; }
    public DashboardPopupViewModel Popups { get; }
    public AnomalySummaryViewModel AnomalySummary { get; }
    public DrillDownPopupViewModel DrillDown { get; }

    /// <summary>
    /// Stats bar using unified Total/Filtered pattern (like Packet Analysis tab).
    /// </summary>
    public StatsBarControlViewModel NetworkStatsBar { get; } = new()
    {
        SectionTitle = "NETWORK STATISTICS",
        AccentColor = ThemeColorHelper.GetColorHex("StatPackets", "#58A6FF"),
        ColumnCount = 5
    };

    // ==================== SERVICES ====================

    private readonly IDispatcherService _dispatcher;
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
    private HashSet<long> _anomalyFrameNumbers = [];
    private List<NetworkAnomaly> _currentAnomalies = [];  // Full anomaly list for time-based filtering
    private HashSet<long> _highSeverityFrames = [];  // Critical + High severity
    private HashSet<long> _tcpAnomalyFrames = [];
    private HashSet<long> _networkAnomalyFrames = [];

    // Filter cancellation and progress tracking
    private CancellationTokenSource? _filterCancellationTokenSource;
    private PropertyChangedEventHandler? _commonFiltersHandler;

    // Current chip-based PacketFilter from SmartFilterableTab
    // This is the authoritative filter built from INCLUDE/EXCLUDE chips
    private PacketFilter? _currentChipBasedFilter;

    // ==================== FILTERABLE TAB IMPLEMENTATION ====================

    public new CommonFilterViewModel CommonFilters { get; } = new CommonFilterViewModel();
    [ObservableProperty] private string _trafficTypeFilter = "All";
    [ObservableProperty] private string _portRangeFilter = "";
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

    private readonly Lock _updateLock = new();
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

    // Network/Traffic/Security filters inherited from SmartFilterableTab → NetworkQuickFilters
    // DO NOT redeclare with [ObservableProperty] - breaks single source of truth

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

    // Additional filters inherited from SmartFilterableTab

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

    [ObservableProperty] private Dictionary<string, double> _countryMapData = [];
    [ObservableProperty] private ObservableCollection<string> _excludedCountries = [];
    [ObservableProperty] private int _itemsCount = 0;

    [ObservableProperty] private int _uniqueCountries;
    [ObservableProperty] private string _topCountry = "N/A";
    [ObservableProperty] private bool _hasInternationalTraffic;

    // ==================== TCP HEALTH ====================

    [ObservableProperty] private int _tcpAnomalyCount;
    [ObservableProperty] private string _tcpHealthStatus = "Unknown";
    [ObservableProperty] private string _tcpHealthColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");

    // ==================== FILTERING STATE ====================

    [ObservableProperty] private bool _isFilteringInProgress = false;
    [ObservableProperty] private double _filterProgress = 0.0;

    // ==================== CSV EXPORT ====================

    [ObservableProperty] private bool _isExporting = false;
    [ObservableProperty] private string? _exportStatusMessage;
    [ObservableProperty] private string _exportStatusColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"); // Default success green
    private System.Threading.CancellationTokenSource? _exportStatusCts;

    // ==================== FILTER PRESETS ====================

    [ObservableProperty] private ObservableCollection<FilterPreset> _availablePresets = [];
    [ObservableProperty] private FilterPreset? _selectedPreset;
    [ObservableProperty] private bool _isLoadingPresets = false;

    // ==================== ACTIVE FILTER DESCRIPTIONS ====================

    [ObservableProperty] private ObservableCollection<string> _activeFilterDescriptions = [];

    // ==================== CONSTRUCTORS ====================

    public DashboardViewModel()
        : this(
            App.Services?.GetService<IDispatcherService>() ?? new AvaloniaDispatcherService(),
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
        IDispatcherService dispatcherService,
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
        ArgumentNullException.ThrowIfNull(dispatcherService);
        _dispatcher = dispatcherService;
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
        Charts = new();
        Statistics = new();
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
        if (_filterService is not null)
        {
            _filterService.FilterChanged += OnFilterServiceChanged;
        }

        // Subscribe to CommonFilters property changes (stored handler for proper cleanup)
        _commonFiltersHandler = (s, e) => _ = ApplyFiltersAsync();
        CommonFilters.PropertyChanged += _commonFiltersHandler;

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        // Subscribe to GlobalFilterState changes for UnifiedFilterPanel integration
        // NOTE: Using OnFiltersApplied (not OnFilterChanged) to avoid auto-apply on chip removal
        if (_globalFilterState is not null)
        {
            _globalFilterState.OnFiltersApplied += OnGlobalFilterChanged;
            DebugLogger.Log("[DashboardViewModel] Subscribed to GlobalFilterState.OnFiltersApplied");
        }

        // Load filter presets
        _ = LoadPresetsAsync();

        DebugLogger.Log("[DashboardViewModel] Initialized with composition pattern and async filter support");
    }

    // ==================== PUBLIC UPDATE METHODS ====================

    public async Task UpdateStatisticsAsync(IReadOnlyList<PacketInfo> packets)
    {
        var methodStart = DateTime.Now;
        DebugLogger.Log($"[{methodStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] ========== METHOD START ==========");

        if (packets is null || packets.Count == 0)
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
            var isUsingFilteredOverride = false;

            if (_nextStatisticsOverride is not null)
            {
                var overrideStart = DateTime.Now;
                statistics = _nextStatisticsOverride;
                _nextStatisticsOverride = null;
                isUsingFilteredOverride = true;  // Mark that we're using filtered stats
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
            // Only update _unfilteredStatistics when NOT using filtered override
            // This preserves the original total for "Total: X / Filtered: Y (Z%)" display
            if (!isUsingFilteredOverride)
            {
                _unfilteredStatistics = statistics;
                DebugLogger.Log($"[DashboardViewModel] Stored unfiltered statistics: {statistics.TotalPackets:N0} packets");
            }
            else
            {
                // Store filtered statistics for display
                _filteredStatistics = statistics;
                DebugLogger.Log($"[DashboardViewModel] Stored filtered statistics: {statistics.TotalPackets:N0} packets (unfiltered preserved: {_unfilteredStatistics?.TotalPackets:N0})");
            }

            var componentsStart = DateTime.Now;
            DebugLogger.Log($"[{componentsStart:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] About to update all components with statistics");

            // Update all component ViewModels
            await UpdateAllComponents(statistics, packets);

            var componentsElapsed = (DateTime.Now - componentsStart).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [DashboardViewModel.UpdateStatisticsAsync] Components updated in {componentsElapsed:F3}s");

            // Update NetworkStatsBar with unified Total/Filtered pattern
            UpdateNetworkStatsBar();

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

    private async Task UpdateAllComponents(NetworkStatistics? statistics, IReadOnlyList<PacketInfo>? packets)
    {
        var updateStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] UpdateAllComponents starting - statistics null: {statistics is null}, packets: {packets?.Count ?? 0}");

        if (statistics is null || packets is null)
        {
            DebugLogger.Log($"[DashboardViewModel] Cannot update components - statistics or packets is null");
            return;
        }

        // Update Charts component
        var chartsStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating Charts component...");
        await _dispatcher.InvokeAsync(() =>
        {
            Charts.UpdateAllCharts(statistics);
        });
        var chartsElapsed = (DateTime.Now - chartsStartTime).TotalSeconds;
        DebugLogger.Log($"[DashboardViewModel] Charts component updated in {chartsElapsed:F2}s");

        // Update Statistics component
        var statsStartTime = DateTime.Now;
        DebugLogger.Log($"[DashboardViewModel] Updating Statistics component...");
        await _dispatcher.InvokeAsync(() =>
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

    public void SetStatisticsOverride(NetworkStatistics statistics)
    {
        _nextStatisticsOverride = statistics;
    }

    public void UpdateAnomalySummary(IReadOnlyList<NetworkAnomaly>? anomalies)
    {
        DebugLogger.Log($"[DashboardViewModel] Updating anomaly summary: {anomalies?.Count ?? 0} anomalies");
        AnomalySummary.UpdateFromAnomalies(anomalies);

        // Store full anomaly list for time-based filtering in chart popups
        _currentAnomalies = anomalies?.ToList() ?? [];

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
    /// Handles GlobalFilterState changes - re-applies global filters from UnifiedFilterPanel to Dashboard.
    /// This is triggered when user clicks Apply/Clear in the UnifiedFilterPanel.
    /// </summary>
    private void OnGlobalFilterChanged()
    {
        DebugLogger.Log("[DashboardViewModel] GlobalFilterState.OnFiltersApplied fired - applying global filters");
        ApplyGlobalFilters();
    }

    public new void ApplyFilters()
    {
        _ = ApplyFiltersAsync();
    }

    public async Task ApplyFiltersAsync()
    {
        await UpdateFilteredStatisticsAsync();
    }

    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Store the chip-based filter for use in filtering
        _currentChipBasedFilter = filter;

        // Apply filter to _displayedPackets and update Dashboard visualizations
        _ = ApplyChipBasedFilterAsync();
        DebugLogger.Log($"[{TabName}] Smart filters applied from chips (IsEmpty={filter?.IsEmpty ?? true})");
    }

    private async Task ApplyChipBasedFilterAsync()
    {
        _filterCancellationTokenSource?.Cancel();
        _filterCancellationTokenSource = new();
        var cancellationToken = _filterCancellationTokenSource.Token;

        try
        {
            if (_allPackets is null || _allPackets.Count == 0)
            {
                DebugLogger.Log("[DashboardViewModel] No packets available for chip-based filtering");
                return;
            }

            IsFilteringInProgress = true;
            FilterProgress = 0.0;

            var startTime = DateTime.Now;
            var filter = _currentChipBasedFilter;

            // Check if filter is empty or null
            IsFilterActive = filter is not null && !filter.IsEmpty;

            if (!IsFilterActive)
            {
                _filteredPackets = null;
                await _dispatcher.InvokeAsync(() =>
                {
                    // CRITICAL: Set statistics FIRST, before any chart updates
                    _currentStatistics = _unfilteredStatistics;

                    Statistics.ClearFilteredStatistics();
                    // CRITICAL: Update charts with full unfiltered data when filters are cleared
                    if (_unfilteredStatistics is not null)
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
            if (_globalFilterState is not null && _globalFilterState.HasAnomalyFilters && _anomalyFrameIndexService is not null)
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
            await _dispatcher.InvokeAsync(() =>
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
    private async Task ApplyFilterAsync() => await ApplyFiltersAsync();

    [RelayCommand]
    public void FilterByConnection(object? parameter)
    {
        if (parameter is ConversationViewModel connection)
        {
            FilterSourceIP = connection.SourceAddress;
            FilterDestinationIP = connection.DestinationAddress;
            FilterPortRange = $"{connection.SourcePort},{connection.DestinationPort}";
            FilterProtocolType = connection.Protocol;
            ExportStatusMessage = $"🔍 Filtered by: {connection.SourceDisplay} ↔ {connection.DestinationDisplay}";
            ExportStatusColor = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
            _ = AutoClearExportStatusAsync();
        }
    }

    [RelayCommand]
    private void ClearFilter()
    {
        CommonFilters.Clear();
        TrafficTypeFilter = "All";
        PortRangeFilter = "";
        FilterText = "";
        FilterStartTime = null;
        FilterEndTime = null;
        FilterProtocol = "All";
        FilterSeverity = "All";
        NetworkQuickFilters.ClearAll();
        FilterTlsV10Toggle = FilterTlsV11Toggle = FilterTlsV12Toggle = FilterTlsV13Toggle = false;
        FilterHttpToggle = FilterHttpsToggle = FilterDnsToggle = FilterSnmpToggle = false;
        FilterSshToggle = FilterFtpToggle = FilterSmtpToggle = FilterStunToggle = FilterDhcpServerToggle = false;
        FilterWireGuardToggle = FilterOpenVpnToggle = FilterIkeV2Toggle = false;
        FilterIpsecToggle = FilterL2tpToggle = FilterPptpToggle = false;
        FilterUseAndMode = true;
        FilterUseNotMode = false;
        IsFilterActive = false;
        Statistics.ClearFilteredStatistics();
        DebugLogger.Log("[DashboardViewModel] Cleared all filters");
    }

    // NOTE: UpdateFilteredStatisticsAsync, ApplyCommonFilters, BuildPortRangePredicate,
    // BuildAnomalyFrameSet, BuildSmartFilterState moved to DashboardViewModel.Filtering.cs

    // ==================== FILTER SERVICE INTEGRATION ====================

    private void OnFilterServiceChanged(object? sender, EventArgs e)
    {
        if (_filterService is null) return;

        try
        {
            if (_filterService.IsFilterActive && _allPackets is not null)
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
                if (_unfilteredStatistics is not null)
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
            if (statistics.CountryStatistics is not null && statistics.CountryStatistics.Any())
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
                TcpHealthColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"); // Green
            }
            else if (TcpAnomalyCount < 10)
            {
                TcpHealthStatus = "Minor Issues";
                TcpHealthColor = ThemeColorHelper.GetColorHex("ColorYellow", "#FCD34D"); // Yellow
            }
            else if (TcpAnomalyCount < 50)
            {
                TcpHealthStatus = "Degraded";
                TcpHealthColor = ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"); // Orange
            }
            else
            {
                TcpHealthStatus = "Critical";
                TcpHealthColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626"); // Red
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
                if (_commonFiltersHandler is not null)
                {
                    CommonFilters.PropertyChanged -= _commonFiltersHandler;
                    _commonFiltersHandler = null;
                }

                // Unsubscribe from component property changes
                Statistics.PropertyChanged -= OnStatisticsPropertyChanged;
                Charts.PropertyChanged -= OnChartsPropertyChanged;

                if (_filterService is not null)
                {
                    _filterService.FilterChanged -= OnFilterServiceChanged;
                }

                // Unsubscribe from GlobalFilterState to prevent memory leaks
                if (_globalFilterState is not null)
                {
                    _globalFilterState.OnFiltersApplied -= OnGlobalFilterChanged;
                    DebugLogger.Log("[DashboardViewModel] Unsubscribed from GlobalFilterState.OnFiltersApplied");
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

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Property forwarding for backward compatibility")]
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

    private void OnChartsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward all Charts property changes to the parent ViewModel
        OnPropertyChanged(e.PropertyName);
    }

    public async Task UpdateStatistics(NetworkStatistics statistics, IReadOnlyList<PacketInfo> packets)
    {
        _nextStatisticsOverride = statistics;
        await UpdateStatisticsAsync(packets);
    }

    // ==================== ITabPopulationTarget IMPLEMENTATION ====================

    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[DashboardViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");

        // CRITICAL: Store unfiltered statistics BEFORE using override
        // This is initial population, so these ARE the unfiltered totals.
        // SetStatisticsOverride + UpdateStatisticsAsync will set isUsingFilteredOverride=true,
        // which preserves _unfilteredStatistics (doesn't overwrite it).
        _unfilteredStatistics = result.Statistics;
        DebugLogger.Log($"[DashboardViewModel] Initial load - stored unfiltered statistics: {result.Statistics.TotalPackets:N0} packets, {result.Statistics.TotalBytes:N0} bytes");

        SetStatisticsOverride(result.Statistics);
        await UpdateStatisticsAsync(result.AllPackets);
    }
}
