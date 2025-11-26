using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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
    private readonly ICsvExportService? _csvExportService;
    private readonly IFileDialogService? _fileDialogService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly Action<string>? _navigateToTab;

    // Anomaly frame number caches for efficient filtering
    private HashSet<long> _anomalyFrameNumbers = new();
    private HashSet<long> _highSeverityFrames = new();  // Critical + High severity
    private HashSet<long> _tcpAnomalyFrames = new();
    private HashSet<long> _networkAnomalyFrames = new();

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
    private List<PacketInfo>? _currentPackets;
    private List<PacketInfo>? _unfilteredPackets;
    private NetworkStatistics? _nextStatisticsOverride;

    public NetworkStatistics? CurrentStatistics => _currentStatistics;

    /// <summary>
    /// Exposes current packets for DrillDown popup time-slice analysis.
    /// </summary>
    public IEnumerable<PacketInfo> CurrentPackets => _currentPackets ?? Enumerable.Empty<PacketInfo>();

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

    // ==================== NETWORK TYPE FILTERS ====================

    [ObservableProperty] private bool _filterRfc1918Toggle = false;
    [ObservableProperty] private bool _filterPublicIpToggle = false;
    [ObservableProperty] private bool _filterApipaToggle = false;
    [ObservableProperty] private bool _filterIPv4Toggle = false;
    [ObservableProperty] private bool _filterIPv6Toggle = false;

    // ==================== TRAFFIC TYPE FILTERS ====================

    [ObservableProperty] private bool _filterMulticastToggle = false;
    [ObservableProperty] private bool _filterBroadcastToggle = false;
    [ObservableProperty] private bool _filterAnycastToggle = false;

    // ==================== SECURITY FILTERS ====================

    [ObservableProperty] private bool _filterInsecureToggle = false;
    [ObservableProperty] private bool _filterAnomaliesToggle = false;

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

    [ObservableProperty] private bool _filterJumboFramesToggle = false;
    [ObservableProperty] private bool _filterPrivateToPublicToggle = false;
    [ObservableProperty] private bool _filterPublicToPrivateToggle = false;
    [ObservableProperty] private bool _filterLinkLocalToggle = false;
    [ObservableProperty] private bool _filterLoopbackToggle = false;
    [ObservableProperty] private bool _filterSuspiciousToggle = false;
    [ObservableProperty] private bool _filterTcpIssuesToggle = false;
    [ObservableProperty] private bool _filterDnsAnomaliesToggle = false;
    [ObservableProperty] private bool _filterPortScansToggle = false;

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

    // ==================== CSV EXPORT ====================

    [ObservableProperty] private bool _isExporting = false;
    [ObservableProperty] private string? _exportStatusMessage;
    [ObservableProperty] private string _exportStatusColor = "#10B981"; // Default success green
    private System.Threading.CancellationTokenSource? _exportStatusCts;

    // ==================== CONSTRUCTORS ====================

    public DashboardViewModel()
        : this(
            App.Services?.GetRequiredService<IStatisticsService>() ?? throw new InvalidOperationException("IStatisticsService not registered"),
            App.Services?.GetService<IUnifiedAnomalyDetectionService>() ?? new UnifiedAnomalyDetectionService(),
            new TabFilterService("Dashboard", new FilterServiceCore()),
            App.Services?.GetService<ICsvExportService>(),
            App.Services?.GetService<IFileDialogService>(),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService())
    {
    }

    public DashboardViewModel(
        IStatisticsService statisticsService,
        IUnifiedAnomalyDetectionService anomalyService,
        ITabFilterService? filterService,
        ICsvExportService? csvExportService = null,
        IFileDialogService? fileDialogService = null,
        ISmartFilterBuilder? filterBuilder = null,
        Action<string>? navigateToTab = null)
        : base(filterBuilder ?? new SmartFilterBuilderService())
    {
        _statisticsService = statisticsService;
        _anomalyService = anomalyService;
        _filterService = filterService;
        _csvExportService = csvExportService;
        _fileDialogService = fileDialogService;
        _filterCopyService = App.Services?.GetService<FilterCopyService>();
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

        // Subscribe to CommonFilters property changes
        CommonFilters.PropertyChanged += (s, e) => ApplyFilters();

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        DebugLogger.Log("[DashboardViewModel] Initialized with composition pattern and filter support");
    }

    // ==================== PUBLIC UPDATE METHODS ====================

    /// <summary>
    /// Main entry point for updating dashboard with new packet data.
    /// Coordinates updates across all component ViewModels.
    /// </summary>
    public async Task UpdateStatisticsAsync(List<PacketInfo> packets)
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

            // Store packet data
            _currentPackets = packets;
            _unfilteredPackets = packets;

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
    private async Task UpdateAllComponents(NetworkStatistics? statistics, List<PacketInfo>? packets)
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
    /// IFilterableTab implementation - applies common and tab-specific filters
    /// </summary>
    public new void ApplyFilters()
    {
        UpdateFilteredStatistics();
    }

    /// <summary>
    /// Applies the sophisticated PacketFilter to Dashboard's displayed packets
    /// </summary>
    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Apply filter to _displayedPackets and update Dashboard visualizations
        // Dashboard filters packets and recalculates statistics
        UpdateFilteredStatistics();
        DebugLogger.Log($"[{TabName}] Smart filters applied to dashboard data");
    }

    [RelayCommand]
    private void ApplyFilter()
    {
        ApplyFilters();
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

        // Clear all smart filter toggles
        FilterRfc1918Toggle = false;
        FilterPublicIpToggle = false;
        FilterApipaToggle = false;
        FilterIPv4Toggle = false;
        FilterIPv6Toggle = false;
        FilterMulticastToggle = false;
        FilterBroadcastToggle = false;
        FilterAnycastToggle = false;
        FilterInsecureToggle = false;
        FilterAnomaliesToggle = false;
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
        FilterWireGuardToggle = false;
        FilterOpenVpnToggle = false;
        FilterIkeV2Toggle = false;
        FilterIpsecToggle = false;
        FilterL2tpToggle = false;
        FilterPptpToggle = false;
        FilterJumboFramesToggle = false;
        FilterPrivateToPublicToggle = false;
        FilterPublicToPrivateToggle = false;
        FilterLinkLocalToggle = false;
        FilterLoopbackToggle = false;
        FilterSuspiciousToggle = false;
        FilterTcpIssuesToggle = false;
        FilterDnsAnomaliesToggle = false;
        FilterPortScansToggle = false;

        // Reset logic controls
        FilterUseAndMode = true;
        FilterUseNotMode = false;

        IsFilterActive = false;
        Statistics.ClearFilteredStatistics();

        DebugLogger.Log("[DashboardViewModel] Cleared all filters including smart filters");
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Comprehensive filter logic with 30+ smart filters requires sequential evaluation")]
    [SuppressMessage("Maintainability", "CA1505:Avoid unmaintainable code",
        Justification = "Filter evaluation is straightforward despite high cyclomatic complexity")]
    private void UpdateFilteredStatistics()
    {
        try
        {
            if (_unfilteredPackets == null || !_unfilteredPackets.Any())
            {
                DebugLogger.Log("[DashboardViewModel] No packets available for filtering");
                return;
            }

            // Apply filters
            var filteredPackets = _unfilteredPackets.AsEnumerable();

            // Apply common filters
            if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            {
                filteredPackets = filteredPackets.Where(p => p.Protocol.ToString().Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(CommonFilters.SourceIPFilter))
            {
                filteredPackets = filteredPackets.Where(p => p.SourceIP.Contains(CommonFilters.SourceIPFilter, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(CommonFilters.DestinationIPFilter))
            {
                filteredPackets = filteredPackets.Where(p => p.DestinationIP.Contains(CommonFilters.DestinationIPFilter, StringComparison.OrdinalIgnoreCase));
            }

            // Apply tab-specific filters
            if (TrafficTypeFilter != "All")
            {
                filteredPackets = filteredPackets.Where(p => p.Protocol.ToString().Equals(TrafficTypeFilter, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(PortRangeFilter))
            {
                if (ushort.TryParse(PortRangeFilter, out var port))
                {
                    filteredPackets = filteredPackets.Where(p => p.SourcePort == port || p.DestinationPort == port);
                }
            }

            // Apply legacy filters
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                filteredPackets = filteredPackets.Where(p =>
                    p.SourceIP.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    p.DestinationIP.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    (p.Info?.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ?? false));
            }

            if (FilterStartTime.HasValue)
            {
                filteredPackets = filteredPackets.Where(p => p.Timestamp >= FilterStartTime.Value);
            }

            if (FilterEndTime.HasValue)
            {
                filteredPackets = filteredPackets.Where(p => p.Timestamp <= FilterEndTime.Value);
            }

            if (FilterProtocol != "All")
            {
                filteredPackets = filteredPackets.Where(p => p.Protocol.ToString() == FilterProtocol);
            }

            // ==================== SMART FILTER LOGIC (AND/OR/NOT) ====================

            var smartFilters = new List<Func<PacketInfo, bool>>();
            var filterDescriptions = new List<string>();

            // Network Type Filters
            if (FilterRfc1918Toggle)
            {
                smartFilters.Add(p => IsRFC1918(p.SourceIP) || IsRFC1918(p.DestinationIP));
                filterDescriptions.Add("RFC1918");
            }
            if (FilterPublicIpToggle)
            {
                smartFilters.Add(p => !IsPrivateIP(p.SourceIP) || !IsPrivateIP(p.DestinationIP));
                filterDescriptions.Add("Public IP");
            }
            if (FilterApipaToggle)
            {
                smartFilters.Add(p => IsAPIPA(p.SourceIP) || IsAPIPA(p.DestinationIP));
                filterDescriptions.Add("APIPA");
            }
            if (FilterIPv4Toggle)
            {
                smartFilters.Add(p => IsIPv4(p.SourceIP) || IsIPv4(p.DestinationIP));
                filterDescriptions.Add("IPv4");
            }
            if (FilterIPv6Toggle)
            {
                smartFilters.Add(p => IsIPv6(p.SourceIP) || IsIPv6(p.DestinationIP));
                filterDescriptions.Add("IPv6");
            }

            // Traffic Type Filters
            if (FilterMulticastToggle)
            {
                smartFilters.Add(p => IsMulticast(p.SourceIP) || IsMulticast(p.DestinationIP));
                filterDescriptions.Add("Multicast");
            }
            if (FilterBroadcastToggle)
            {
                smartFilters.Add(p => IsBroadcast(p.DestinationIP));
                filterDescriptions.Add("Broadcast");
            }
            if (FilterAnycastToggle)
            {
                smartFilters.Add(p => IsAnycast(p.SourceIP) || IsAnycast(p.DestinationIP));
                filterDescriptions.Add("Anycast");
            }

            // Security Filters
            if (FilterInsecureToggle)
            {
                smartFilters.Add(p => IsInsecureProtocol(p));
                filterDescriptions.Add("Insecure");
            }
            if (FilterAnomaliesToggle)
            {
                // Use actual detected anomalies from UnifiedAnomalyDetectionService
                smartFilters.Add(p => _anomalyFrameNumbers.Contains((long)p.FrameNumber));
                filterDescriptions.Add("Anomalies");
            }

            // L7 Protocol Filters
            if (FilterTlsV10Toggle)
            {
                smartFilters.Add(p => p.L7Protocol == "TLS v1.0");
                filterDescriptions.Add("TLS 1.0");
            }
            if (FilterTlsV11Toggle)
            {
                smartFilters.Add(p => p.L7Protocol == "TLS v1.1");
                filterDescriptions.Add("TLS 1.1");
            }
            if (FilterTlsV12Toggle)
            {
                smartFilters.Add(p => p.L7Protocol == "TLS v1.2");
                filterDescriptions.Add("TLS 1.2");
            }
            if (FilterTlsV13Toggle)
            {
                smartFilters.Add(p => p.L7Protocol == "TLS v1.3");
                filterDescriptions.Add("TLS 1.3");
            }
            if (FilterHttpToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "HTTP");
                filterDescriptions.Add("HTTP");
            }
            if (FilterHttpsToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "HTTPS" || p.DestinationPort == 443);
                filterDescriptions.Add("HTTPS");
            }
            if (FilterDnsToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "DNS" || p.DestinationPort == 53);
                filterDescriptions.Add("DNS");
            }
            if (FilterSnmpToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "SNMP" || p.DestinationPort == 161 || p.DestinationPort == 162);
                filterDescriptions.Add("SNMP");
            }
            if (FilterSshToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "SSH" || p.DestinationPort == 22);
                filterDescriptions.Add("SSH");
            }
            if (FilterFtpToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "FTP" || p.DestinationPort == 21);
                filterDescriptions.Add("FTP");
            }
            if (FilterSmtpToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "SMTP" || p.DestinationPort == 25);
                filterDescriptions.Add("SMTP");
            }
            if (FilterStunToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "STUN" || p.DestinationPort == 3478);
                filterDescriptions.Add("STUN");
            }
            if (FilterDhcpServerToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "DHCP" || p.DestinationPort == 67 || p.DestinationPort == 68);
                filterDescriptions.Add("DHCP");
            }

            // VPN Protocol Filters
            if (FilterWireGuardToggle)
            {
                smartFilters.Add(p => p.DestinationPort == 51820);
                filterDescriptions.Add("WireGuard");
            }
            if (FilterOpenVpnToggle)
            {
                smartFilters.Add(p => p.DestinationPort == 1194);
                filterDescriptions.Add("OpenVPN");
            }
            if (FilterIkeV2Toggle)
            {
                smartFilters.Add(p => p.DestinationPort == 500 || p.DestinationPort == 4500);
                filterDescriptions.Add("IKEv2");
            }
            if (FilterIpsecToggle)
            {
                smartFilters.Add(p => p.L7Protocol == "IPSec");
                filterDescriptions.Add("IPSec");
            }
            if (FilterL2tpToggle)
            {
                smartFilters.Add(p => p.DestinationPort == 1701);
                filterDescriptions.Add("L2TP");
            }
            if (FilterPptpToggle)
            {
                smartFilters.Add(p => p.DestinationPort == 1723);
                filterDescriptions.Add("PPTP");
            }

            // Additional Filters
            if (FilterJumboFramesToggle)
            {
                smartFilters.Add(p => p.Length > 1500);
                filterDescriptions.Add("Jumbo Frames");
            }
            if (FilterPrivateToPublicToggle)
            {
                smartFilters.Add(p => IsPrivateIP(p.SourceIP) && !IsPrivateIP(p.DestinationIP));
                filterDescriptions.Add("Private→Public");
            }
            if (FilterPublicToPrivateToggle)
            {
                smartFilters.Add(p => !IsPrivateIP(p.SourceIP) && IsPrivateIP(p.DestinationIP));
                filterDescriptions.Add("Public→Private");
            }
            if (FilterLinkLocalToggle)
            {
                smartFilters.Add(p => p.SourceIP.StartsWith("169.254.") || p.DestinationIP.StartsWith("169.254.") ||
                                      p.SourceIP.StartsWith("fe80:") || p.DestinationIP.StartsWith("fe80:"));
                filterDescriptions.Add("Link-Local");
            }
            if (FilterLoopbackToggle)
            {
                smartFilters.Add(p => p.SourceIP.StartsWith("127.") || p.DestinationIP.StartsWith("127.") ||
                                      p.SourceIP == "::1" || p.DestinationIP == "::1");
                filterDescriptions.Add("Loopback");
            }
            if (FilterSuspiciousToggle)
            {
                // Use high-severity anomalies (Critical + High) for suspicious traffic
                smartFilters.Add(p => _highSeverityFrames.Contains((long)p.FrameNumber));
                filterDescriptions.Add("Suspicious");
            }
            if (FilterTcpIssuesToggle)
            {
                // Use TCP-category anomalies (retransmits, RST floods, duplicate ACKs, etc.)
                smartFilters.Add(p => _tcpAnomalyFrames.Contains((long)p.FrameNumber));
                filterDescriptions.Add("TCP Issues");
            }
            if (FilterDnsAnomaliesToggle)
            {
                // FUTURE: Integrate DNS anomaly detection (tunneling, exfiltration)
                smartFilters.Add(p => (p.L7Protocol == "DNS" || p.DestinationPort == 53) && p.Length > 512);
                filterDescriptions.Add("DNS Anomalies");
            }
            if (FilterPortScansToggle)
            {
                // FUTURE: Integrate port scan detection from NetworkAnomalyDetector
                smartFilters.Add(p => p.Protocol == Protocol.TCP && p.Length < 100);
                filterDescriptions.Add("Port Scans");
            }

            // Apply smart filters with AND/OR/NOT logic
            if (smartFilters.Any())
            {
                if (FilterUseAndMode)
                {
                    // AND: all filters must match
                    filteredPackets = filteredPackets.Where(p => smartFilters.All(f => f(p)));
                }
                else
                {
                    // OR: any filter can match
                    filteredPackets = filteredPackets.Where(p => smartFilters.Any(f => f(p)));
                }

                // Apply NOT mode (invert results)
                if (FilterUseNotMode)
                {
                    var matchingPackets = filteredPackets.ToHashSet();
                    filteredPackets = _unfilteredPackets.Where(p => !matchingPackets.Contains(p));
                }
            }

            var filteredList = filteredPackets.ToList();
            _currentPackets = filteredList;

            // Check if any filters are active
            IsFilterActive = CommonFilters.HasActiveFilters ||
                           TrafficTypeFilter != "All" ||
                           !string.IsNullOrWhiteSpace(PortRangeFilter) ||
                           !string.IsNullOrWhiteSpace(FilterText) ||
                           FilterStartTime.HasValue ||
                           FilterEndTime.HasValue ||
                           FilterProtocol != "All" ||
                           smartFilters.Any();

            if (IsFilterActive)
            {
                // Calculate filtered statistics
                var filteredStats = _statisticsService.CalculateStatistics(filteredList);
                _filteredStatistics = filteredStats;

                // Update Statistics component with filtered data
                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
            }
            else
            {
                Statistics.ClearFilteredStatistics();
            }

            DebugLogger.Log($"[DashboardViewModel] Applied filters: {filteredList.Count:N0} packets");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error updating filtered statistics: {ex.Message}");
        }
    }

    // ==================== FILTER SERVICE INTEGRATION ====================

    private void OnFilterServiceChanged(object? sender, EventArgs e)
    {
        if (_filterService == null) return;

        try
        {
            if (_filterService.IsFilterActive && _unfilteredPackets != null)
            {
                var filteredPackets = _filterService.GetFilteredPackets(_unfilteredPackets).ToList();
                _currentPackets = filteredPackets;

                var filteredStats = _statisticsService.CalculateStatistics(filteredPackets);
                _filteredStatistics = filteredStats;

                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
                Charts.UpdateAllCharts(filteredStats);
            }
            else
            {
                // Reset to unfiltered
                _currentPackets = _unfilteredPackets;
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

    private void UpdateGeographicData(NetworkStatistics statistics, List<PacketInfo> packets)
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

    private List<PacketInfo> SamplePackets(List<PacketInfo> packets, int sampleSize)
    {
        if (packets.Count <= sampleSize)
            return packets;

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
                _currentPackets = null;
                _unfilteredPackets = null;

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
    public async Task UpdateStatistics(NetworkStatistics statistics, List<PacketInfo> packets)
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
        _currentPackets = null;
        _unfilteredPackets = null;

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
