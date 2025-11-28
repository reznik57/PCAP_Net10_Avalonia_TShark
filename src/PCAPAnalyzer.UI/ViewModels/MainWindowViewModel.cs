using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Caching;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.GeoIP;
using PCAPAnalyzer.Core.Services.Statistics;
using PCAPAnalyzer.TShark;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Refactored Main Window ViewModel using composition pattern.
/// Orchestrates 5 specialized component ViewModels for better maintainability.
/// Original: 2,440 lines → Refactored: ~600 lines (75% reduction)
///
/// ✅ C2 REFACTOR: Now inherits from SmartFilterableTab for sophisticated filtering
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Main orchestrator ViewModel coordinates multiple services, tabs, and components by design")]
public partial class MainWindowViewModel : SmartFilterableTab, IDisposable, IAsyncDisposable
{
    // ==================== COMPONENT VIEWMODELS ====================

    public MainWindowFileViewModel FileManager { get; }
    public MainWindowAnalysisViewModel Analysis { get; }
    public MainWindowUIStateViewModel UIState { get; }
    public MainWindowPacketViewModel PacketManager { get; }
    public MainWindowChartsViewModel Charts { get; }

    // ==================== CHILD VIEWMODELS ====================

    [ObservableProperty] private FileAnalysisViewModel? _fileAnalysisViewModel;
    [ObservableProperty] private FileManagerViewModel? _fileManagerViewModel;
    [ObservableProperty] private Components.FileSelectionControlViewModel? _fileSelectionControl;
    [ObservableProperty] private DashboardViewModel _dashboardViewModel;
    [ObservableProperty] private ThreatsViewModel _threatsViewModel;
    [ObservableProperty] private VoiceQoSViewModel _voiceQoSViewModel;
    [ObservableProperty] private CountryTrafficViewModel _countryTrafficViewModel;
    [ObservableProperty] private ReportViewModel _reportViewModel;
    [ObservableProperty] private CompareViewModel? _compareViewModel;
    [ObservableProperty] private EnhancedMapViewModel _enhancedMapViewModel;
    [ObservableProperty] private FlowSummaryViewModel _flowSummaryViewModel = new();
    [ObservableProperty] private TopTalkersViewModel? _topTalkersViewModel;
    [ObservableProperty] private AnomalyViewModel? _anomalyViewModel;

    // ==================== STATS BAR VIEWMODELS ====================

    /// <summary>
    /// Statistics bar for Packet Analysis tab (harmonized design with FilterPanelControl)
    /// </summary>
    public StatsBarControlViewModel PacketAnalysisStats { get; } = new();

    // ==================== SERVICES ====================

    private readonly ITSharkService _tsharkService;

    // Tab-specific filter services (isolated per tab)
    private readonly ITabFilterService _packetAnalysisFilterService;
    private readonly ITabFilterService _dashboardFilterService;
    private readonly ITabFilterService _threatsFilterService;
    private readonly ITabFilterService _voiceQoSFilterService;
    private readonly ITabFilterService _countryTrafficFilterService;
    private readonly IInsecurePortDetector _insecurePortDetector;
    private readonly IStatisticsService _statisticsService;
    private readonly IUnifiedAnomalyDetectionService _anomalyService;
    private readonly IGeoIPService _geoIpService;
    private readonly SuricataService _suricataService;
    private readonly YaraService _yaraService;
    private readonly AnalysisOrchestrator? _orchestrator; // ✅ PRELOAD ARCHITECTURE: Central coordinator
    private readonly IAnalysisCoordinator? _analysisCoordinator; // ✅ PHASE 3: New coordinator for tab population
    private readonly IPacketStatisticsCalculator _packetStatsCalculator; // ✅ PHASE 5: Extracted statistics calculations
    private readonly ISessionAnalysisCache _sessionCache; // ✅ DI: Session analysis cache
    // REMOVED: _filterBuilder field - now inherited from SmartFilterableTab base class
    private readonly SemaphoreSlim _dashboardUpdateGate = new(1, 1);
    private readonly DispatcherTimer _updateTimer;

    // REMOVED: Eager preload mechanism (_preloadComplete, _preloadGate) - eliminated dual-analysis paths

    // ==================== FILTER VIEWMODELS ====================

    public FilterViewModel FilterViewModel { get; }
    public EnhancedFilterViewModel EnhancedFilterViewModel { get; }

    /// <summary>
    /// Statistics component for FilterPanelControl binding (delegates to EnhancedFilterViewModel.Statistics).
    /// Required for Apply button IsEnabled binding: {Binding Statistics.CanApplyFilters}
    /// </summary>
    public FilterStatisticsViewModel Statistics => EnhancedFilterViewModel.Statistics;

    // ==================== PROPERTIES ====================

    public bool ShowNoFileWarning => string.IsNullOrEmpty(FileManager.CurrentFile) && !Analysis.IsAnalyzing;
    public List<int> PageSizeOptions { get; } = new() { 25, 50, 100, 200, 500, 1000 };

    // Tab selection tracking (reserved for future database cache optimization)
    [ObservableProperty] private int _selectedTabIndex = 0;

    // ==================== TAB BADGE PROGRESS INDICATORS ====================
    // Track preparation status for each tab with visual badges
    // Badges: ⏸️ Pending | ⏳ In Progress | ✅ Complete

    // ✅ FIX: Remove badge icons - tab text already has icons (no double icons)
    // Badges remain empty to avoid redundancy with tab header text
    [ObservableProperty] private string _fileManagerBadge = "";
    [ObservableProperty] private string _packetAnalysisBadge = "";
    [ObservableProperty] private string _dashboardBadge = "";
    [ObservableProperty] private string _threatsBadge = "";
    [ObservableProperty] private string _anomaliesBadge = "";
    [ObservableProperty] private string _voiceQoSBadge = "";
    [ObservableProperty] private string _countryTrafficBadge = "";

    // ==================== SMART FILTERABLE TAB IMPLEMENTATION ====================

    /// <summary>
    /// Tab name for IFilterableTab interface and filter copying UI
    /// </summary>
    public override string TabName => "Packet Analysis";

    /// <summary>
    /// Applies the built PacketFilter to the Packet Analysis tab's data.
    /// Called by base class after building combined filter from UI inputs.
    /// </summary>
    /// <param name="filter">The combined PacketFilter built from INCLUDE/EXCLUDE groups and chips</param>
    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Apply filter through PacketManager
        PacketManager.ApplyFilter(filter);

        // Update pagination with filtered count
        var filteredCount = PacketManager.GetFilteredPackets().Count;
        UIState.UpdatePaginationInfo(filteredCount);
        UIState.GoToPage(1);

        DebugLogger.Log($"[{TabName}] Filters applied - {filteredCount:N0} packets match");
    }

    // ==================== FILTER PROPERTIES ====================
    // ✅ C2 REFACTOR: All filter properties now inherited from SmartFilterableTab base class
    // REMOVED: 32 filter-related properties (350+ lines) - now in base class
    // - SourceIPFilter, DestinationIPFilter, PortRangeFilter, ProtocolFilter
    // - NotSourceIPFilter, NotDestinationIPFilter, NotPortRangeFilter, NotProtocolFilter
    // - IncludeFilterUseAndMode, IncludeFilterUseOrMode, ExcludeFilterUseAndMode, ExcludeFilterUseOrMode
    // - IncludeFilterGroups, IncludeIndividualChips, ExcludeFilterGroups, ExcludeIndividualChips
    // - HasFiltersApplied, _nextFilterChipId

    // Filtered Stats Properties for % comparison display (use PacketManager.IsFilterActive for filter state)
    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _filteredPackets;
    [ObservableProperty] private double _filteredPacketsPercentage;
    [ObservableProperty] private string _filteredTrafficVolume = "0 B";
    [ObservableProperty] private double _filteredTrafficPercentage;

    // ==================== COMMANDS ====================

    private IAsyncRelayCommand? _startAnalysisCommand;
    public IAsyncRelayCommand StartAnalysisCommand => _startAnalysisCommand ??= new AsyncRelayCommand(
        StartAnalysisAsync,
        () => {
            var canExecute = FileManager.CanStartAnalysis(Analysis.IsAnalyzing);
            DebugLogger.Log($"[StartAnalysisCommand] CanExecute: {canExecute} (CanAnalyze: {FileManager.CanAnalyze}, IsAnalyzing: {Analysis.IsAnalyzing}, File: {FileManager.CurrentFile})");
            return canExecute;
        }
    );

    public MainWindowViewModel()
        : this(
            App.Services?.GetService<ITSharkService>() ?? new TSharkService(NullLogger<TSharkService>.Instance),
            App.Services?.GetService<IInsecurePortDetector>() ?? new InsecurePortDetector(),
            App.Services?.GetService<IStatisticsService>(),
            App.Services?.GetService<IUnifiedAnomalyDetectionService>(),
            App.Services?.GetService<IGeoIPService>() ?? new UnifiedGeoIPService(),
            App.Services?.GetService<PacketDetailsViewModel>(),
            App.Services?.GetService<AnalysisOrchestrator>(),
            App.Services?.GetService<IReportGeneratorService>(),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
            App.Services?.GetService<IAnalysisCoordinator>(), // ✅ PHASE 3: Coordinator for tab population
            sessionCache: App.Services?.GetService<ISessionAnalysisCache>() ?? new SessionAnalysisCacheService()) // ✅ DI: Session cache
    {
        // ✅ C2 REFACTOR: Base constructor called with filterBuilder
        // ✅ DI REFACTOR: Now uses App.Services with fallbacks for testability
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Constructor must initialize all required services and dependencies for main application ViewModel")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Main ViewModel constructor requires sequential initialization of many interdependent services")]
    public MainWindowViewModel(
        ITSharkService tsharkService,
        IInsecurePortDetector insecurePortDetector,
        IStatisticsService? statisticsService,
        IUnifiedAnomalyDetectionService? anomalyService,
        IGeoIPService? geoIpService,
        PacketDetailsViewModel? packetDetailsViewModel = null,
        AnalysisOrchestrator? orchestrator = null,
        IReportGeneratorService? reportService = null,
        ISmartFilterBuilder? filterBuilder = null,
        IAnalysisCoordinator? analysisCoordinator = null,
        IPacketStatisticsCalculator? packetStatsCalculator = null, // ✅ PHASE 5: Statistics calculator
        ISessionAnalysisCache? sessionCache = null) // ✅ DI: Session cache
        : base(filterBuilder ?? App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService()) // ✅ C2 REFACTOR: Call base constructor with filterBuilder via DI
    {
        _tsharkService = tsharkService ?? throw new ArgumentNullException(nameof(tsharkService));
        _insecurePortDetector = insecurePortDetector ?? new InsecurePortDetector();
        _geoIpService = geoIpService ?? throw new ArgumentNullException(nameof(geoIpService), "GeoIPService must be provided via DI");
        _statisticsService = statisticsService ?? throw new ArgumentNullException(nameof(statisticsService), "StatisticsService must be provided via DI");
        _anomalyService = anomalyService ?? new UnifiedAnomalyDetectionService();
        _packetStatsCalculator = packetStatsCalculator ?? App.Services?.GetService<IPacketStatisticsCalculator>() ?? new PacketStatisticsCalculator();
        _orchestrator = orchestrator; // ✅ PRELOAD ARCHITECTURE: Optional for backwards compatibility
        _analysisCoordinator = analysisCoordinator; // ✅ PHASE 3: Store coordinator for tab population
        _sessionCache = sessionCache ?? App.Services?.GetService<ISessionAnalysisCache>() ?? new SessionAnalysisCacheService(); // ✅ DI: Session cache with fallback

        // ✅ DIAGNOSTIC: Log orchestrator injection status
        DebugLogger.Log($"[MainWindowViewModel] Orchestrator injected: {_orchestrator != null}");
        DebugLogger.Log($"[MainWindowViewModel] AnalysisCoordinator injected: {_analysisCoordinator != null}");
        if (_orchestrator == null)
        {
            DebugLogger.Critical("[MainWindowViewModel] ⚠️ WARNING: AnalysisOrchestrator is NULL - Analyze button will be disabled!");
            DebugLogger.Log("[MainWindowViewModel] ⚠️ Check ServiceConfiguration.cs - ensure AnalysisOrchestrator is registered");
        }

        // Initialize tab-specific filter services (isolated per tab)
        // Each tab gets its own FilterServiceCore instance for isolated filter state
        _packetAnalysisFilterService = new TabFilterService("Packet Analysis", new FilterServiceCore());
        _dashboardFilterService = new TabFilterService("Dashboard", new FilterServiceCore());
        _threatsFilterService = new TabFilterService("Security Threats", new FilterServiceCore());
        _voiceQoSFilterService = new TabFilterService("Voice/QoS", new FilterServiceCore());
        _countryTrafficFilterService = new TabFilterService("Country Traffic", new FilterServiceCore());
        DebugLogger.Log("[MainWindowViewModel] Tab-specific filter services initialized");

        // Initialize component ViewModels
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] Creating component ViewModels...");
        FileManager = new MainWindowFileViewModel();
        Analysis = new MainWindowAnalysisViewModel(_tsharkService);
        UIState = new MainWindowUIStateViewModel();
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] UIState created (monitoring initialized)");

        // ✅ DI INJECTION: Get PacketDetailsViewModel from DI container (or create fallback)
        // Services ProtocolParser, HexFormatter, StreamAnalyzer, and HexDataService are properly injected
        var packetDetails = packetDetailsViewModel ?? App.Services?.GetService<PacketDetailsViewModel>();
        if (packetDetails == null)
        {
            // Fallback: Manual instantiation if DI not available
            var protocolParser = new ProtocolParser();
            var hexFormatter = new HexFormatter();
            var streamAnalyzer = new StreamAnalyzer();
            var hexDataService = new PCAPAnalyzer.Core.Services.HexDataService(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<PCAPAnalyzer.Core.Services.HexDataService>.Instance);
            var deepDiveService = new ProtocolDeepDiveService();
            packetDetails = new PacketDetailsViewModel(protocolParser, hexFormatter, streamAnalyzer, hexDataService, deepDiveService);
            DebugLogger.Log("[MainWindowViewModel] ⚠️ PacketDetailsViewModel created manually (DI not available)");
        }
        else
        {
            DebugLogger.Log("[MainWindowViewModel] ✅ PacketDetailsViewModel injected from DI");
        }
        PacketManager = new MainWindowPacketViewModel(_packetAnalysisFilterService, packetDetails);

        Charts = new MainWindowChartsViewModel();

        // Subscribe to component events
        FileManager.FileLoaded += OnFileLoaded;
        FileManager.FileClear += OnFileCleared;
        FileManager.PropertyChanged += OnFileManagerPropertyChanged;

        Analysis.AnalysisCompleted += OnAnalysisCompleted;
        Analysis.AnalysisStopped += OnAnalysisStopped;
        Analysis.AnalysisFailed += OnAnalysisFailed;
        Analysis.PacketBatchProcessed += OnPacketBatchProcessed;
        Analysis.StatusChanged += OnAnalysisStatusChanged;
        Analysis.PropertyChanged += OnAnalysisPropertyChanged;

        UIState.PageChanged += OnPageChanged;
        UIState.GoToPacketRequested += OnGoToPacketRequested;
        UIState.SearchStreamRequested += OnSearchStreamRequested;
        UIState.PropertyChanged += OnUIStatePropertyChanged;
        PacketManager.FilteredPacketsChanged += OnFilteredPacketsChanged;
        PacketManager.PropertyChanged += OnPacketManagerPropertyChanged;
        PacketManager.SearchByStreamRequested += OnSearchByStreamFromDetails;
        PacketManager.NavigateToPacketRequested += OnNavigateToPacketFromDetails;
        Charts.PropertyChanged += OnChartsPropertyChanged;

        // Initialize filter view models
        FilterViewModel = new FilterViewModel(PacketManager.ApplyFilter);
        EnhancedFilterViewModel = new EnhancedFilterViewModel(_packetAnalysisFilterService, PacketManager.ApplyFilter);

        // Subscribe to Packet Analysis tab filter service events (only this tab triggers UI updates)
        _packetAnalysisFilterService.FilterChanged += OnFilterServiceChanged;

        // Initialize PacketAnalysisStats
        InitializePacketAnalysisStats();

        // Initialize FileAnalysisViewModel from DI if available
        var fileAnalysisVM = App.Services?.GetService<FileAnalysisViewModel>();
        if (fileAnalysisVM != null)
        {
            FileAnalysisViewModel = fileAnalysisVM;
            FileAnalysisViewModel.NavigateToTab = (tabIndex) => SelectedTabIndex = tabIndex;
            FileAnalysisViewModel.OnAnalysisCompleted += OnFileAnalysisCompleted;

            // ✅ PHASE 2: Wire FileAnalysisViewModel to forward progress to global overlay
            FileAnalysisViewModel.SetAnalysisViewModel(Analysis);
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] FileAnalysisViewModel created from DI + wired to global overlay");

            // Initialize FileSelectionControl with FileAnalysisViewModel
            var fileSelectionVM = App.Services?.GetService<Components.FileSelectionControlViewModel>();
            if (fileSelectionVM == null && FileAnalysisViewModel != null)
            {
                // Fallback: Create manually if not in DI
                fileSelectionVM = new Components.FileSelectionControlViewModel(FileAnalysisViewModel);
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] FileSelectionControlViewModel created manually");
            }
            FileSelectionControl = fileSelectionVM;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] FileSelectionControl initialized");

            // Initialize FileManagerViewModel with FileAnalysisViewModel (null-checked for CS8604)
            FileManagerViewModel = new FileManagerViewModel(FileAnalysisViewModel ?? throw new InvalidOperationException("FileAnalysisViewModel is required"));
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] FileManagerViewModel created");
        }
        else
        {
            DebugLogger.Critical("[WARNING] FileAnalysisViewModel not available in DI container");
        }

        // Initialize dashboard view model with navigation callback
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] Creating DashboardViewModel...");
        try
        {
            DashboardViewModel = new DashboardViewModel(
                _statisticsService,
                _anomalyService,
                _dashboardFilterService,
                csvExportService: null,
                fileDialogService: null,
                filterBuilder: null,
                navigateToTab: HandleDashboardNavigation);
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[ERROR] Failed to initialize DashboardViewModel: {ex.Message}");
            DashboardViewModel = new DashboardViewModel(
                _statisticsService,
                _anomalyService,
                _dashboardFilterService,
                csvExportService: null,
                fileDialogService: null,
                filterBuilder: null,
                navigateToTab: HandleDashboardNavigation);
        }
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] DashboardViewModel created");

        // Initialize services
        var suricataScript = System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "run-suricata.sh");
        var suricataRules = System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "rules", "emerging.rules");
        _suricataService = new SuricataService(suricataScript, suricataRules);

        var yaraScript = System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "run-yara.sh");
        var yaraRules = System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "rules");
        _yaraService = new YaraService(yaraScript, yaraRules);

        // Initialize child view models - FIX: Use DI to get cache service injection
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] Creating tab ViewModels...");
        var cacheService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
        DebugLogger.Log($"[MainWindowViewModel] Cache service resolved from DI: {cacheService != null}");

        ThreatsViewModel = new ThreatsViewModel(_insecurePortDetector, _anomalyService, _threatsFilterService, cacheService);
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] ThreatsViewModel created");

        // Wire up DrillDown navigation to Packet Analysis
        ThreatsViewModel.NavigateToPacketAnalysis = OnNavigateToPacketAnalysisFromThreat;
        VoiceQoSViewModel = new VoiceQoSViewModel();
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] VoiceQoSViewModel created");
        CountryTrafficViewModel = new CountryTrafficViewModel(_geoIpService, _countryTrafficFilterService);
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] CountryTrafficViewModel created");
        EnhancedMapViewModel = new EnhancedMapViewModel(_geoIpService, _statisticsService);
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] EnhancedMapViewModel created");

        // Initialize CompareViewModel from DI
        var packetComparer = App.Services?.GetService<IPacketComparer>();
        var compareFileDialogService = App.Services?.GetService<IFileDialogService>();
        if (packetComparer != null)
        {
            CompareViewModel = new CompareViewModel(packetComparer, compareFileDialogService);
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] CompareViewModel created");
        }
        else
        {
            DebugLogger.Critical("[WARNING] IPacketComparer not available - Compare tab will not function");
        }

        // Initialize TopTalkersViewModel from DI if available
        var topTalkersVM = App.Services?.GetService<TopTalkersViewModel>();
        if (topTalkersVM != null)
        {
            TopTalkersViewModel = topTalkersVM;
        }
        else
        {
            DebugLogger.Critical("[WARNING] TopTalkersViewModel not available in DI container");
            // Create instance directly if DI not available
            var csvService = App.Services?.GetService<ICsvExportService>();
            var fileDialogService = App.Services?.GetService<IFileDialogService>();
            if (csvService != null && fileDialogService != null)
            {
                TopTalkersViewModel = new TopTalkersViewModel(csvService, fileDialogService);
            }
        }

        // Initialize AnomalyViewModel from DI if available
        var anomalyVM = App.Services?.GetService<AnomalyViewModel>();
        if (anomalyVM != null)
        {
            AnomalyViewModel = anomalyVM;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [INIT] AnomalyViewModel created");
        }
        else
        {
            DebugLogger.Critical("[WARNING] AnomalyViewModel not available in DI container");
            AnomalyViewModel = new AnomalyViewModel();
        }

        // Initialize ReportViewModel with DI if available, otherwise create with service locator
        if (reportService != null)
        {
            ReportViewModel = new ReportViewModel(reportService);
        }
        else
        {
            // Fallback to service locator pattern for backward compatibility
            var reportGen = App.Services?.GetService<Core.Services.IReportGeneratorService>();
            if (reportGen != null)
            {
                ReportViewModel = new ReportViewModel(reportGen);
            }
            else
            {
                DebugLogger.Critical("[WARNING] ReportGeneratorService not available in DI container");
                // Will be null - UI should handle gracefully
                ReportViewModel = null!;
            }
        }

        // Commands are auto-generated by [RelayCommand] attributes

        // Initialize update timer
        _updateTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _updateTimer.Tick += UpdateUI;

        // ✅ PHASE 3: Register tabs with coordinator for centralized population
        RegisterTabsWithCoordinator();

        UIState.UpdateStatus("Please select a PCAP file to analyze", "#4ADE80");
    }

    /// <summary>
    /// ✅ PHASE 3: Registers all tab ViewModels with the AnalysisCoordinator.
    /// Enables future migration to coordinator-based population (Strangler Fig pattern).
    /// </summary>
    private void RegisterTabsWithCoordinator()
    {
        if (_analysisCoordinator == null)
        {
            DebugLogger.Log("[MainWindowViewModel] Coordinator not available - skipping tab registration");
            return;
        }

        var tabs = new List<ITabPopulationTarget>();

        if (DashboardViewModel is ITabPopulationTarget dashboard)
            tabs.Add(dashboard);
        if (ThreatsViewModel is ITabPopulationTarget threats)
            tabs.Add(threats);
        if (VoiceQoSViewModel is ITabPopulationTarget voiceQos)
            tabs.Add(voiceQos);
        if (CountryTrafficViewModel is ITabPopulationTarget countryTraffic)
            tabs.Add(countryTraffic);

        _analysisCoordinator.RegisterTabs(tabs.ToArray());
        DebugLogger.Log($"[MainWindowViewModel] ✅ Registered {tabs.Count} tabs with coordinator: {string.Join(", ", tabs.Select(t => t.TabName))}");
    }

    // ==================== FILE OPERATIONS ====================

    private void OnFileLoaded(object? sender, string filePath)
    {
        var (fileName, fileSize, expectedDataSize) = FileManager.GetFileInfo();
        UIState.UpdateStatus(
            $"File loaded: {fileName} (File: {NumberFormatter.FormatBytes(fileSize)})",
            "#4ADE80"
        );
        Analysis.ProgressMessage = $"Ready to analyze • Expected data: ~{NumberFormatter.FormatBytes(expectedDataSize)}";
        OnPropertyChanged(nameof(ShowNoFileWarning));
        OnPropertyChanged(nameof(CanAnalyze));
        OnPropertyChanged(nameof(HasFile));

        // Set PCAP path for PacketDetailsViewModel hex dump functionality
        PacketManager?.PacketDetails?.SetPcapPath(filePath);
        DebugLogger.Log($"[MainWindowVM] SetPcapPath called with '{filePath}'");

        // Set File A for Compare tab (current loaded file)
        CompareViewModel?.SetFileA(filePath);

        // Notify StartAnalysisCommand that CanExecute may have changed
        if (_startAnalysisCommand is AsyncRelayCommand cmd)
        {
            cmd.NotifyCanExecuteChanged();
        }
    }

    private void OnFileCleared(object? sender, EventArgs e)
    {
        // ✅ PRELOAD ARCHITECTURE: Clear session cache and reclaim memory
        _sessionCache.Clear();
        DebugLogger.Log("[OnFileCleared] Session cache cleared - memory reclaimed");

        UIState.UpdateStatus("No file selected", "#4ADE80");
        Analysis.ProgressMessage = "Select or drop a PCAP file to analyze";
        UIState.HasResults = false;
        OnPropertyChanged(nameof(ShowNoFileWarning));
        OnPropertyChanged(nameof(CanAnalyze));
        OnPropertyChanged(nameof(HasFile));

        // Notify StartAnalysisCommand that CanExecute may have changed
        if (_startAnalysisCommand is AsyncRelayCommand cmd)
        {
            cmd.NotifyCanExecuteChanged();
        }
    }

    // ==================== ANALYSIS OPERATIONS ====================

    private async Task StartAnalysisAsync()
    {
        if (string.IsNullOrEmpty(FileManager.CurrentFile))
        {
            UIState.UpdateStatus("No file selected", "#FF5252");
            return;
        }

        // SINGLE PATH: Orchestrator ONLY (throws if null)
        if (_orchestrator == null)
            throw new InvalidOperationException("AnalysisOrchestrator required - ensure ServiceConfiguration registers it");

        try
        {
            DebugLogger.Log("[MainWindowViewModel] Starting orchestrator-only analysis (legacy path removed)");

            // Reset state
            await PacketManager.ClearPacketsAsync();
            UIState.ResetState();
            Charts.ResetCharts();
            Analysis.ResetAnalysis();

            if (DashboardViewModel != null)
            {
                DashboardViewModel.ResetStatistics();
            }

            // Clear session cache
            _sessionCache.Clear();

            // Run orchestrator analysis (ONLY path)
            await RunPreloadAnalysisAsync(FileManager.CurrentFile);
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[MainWindowViewModel] Analysis error: {ex.Message}");
            UIState.UpdateStatus($"Error: {ex.Message}", "#FF5252");

            // ✅ FIX: Ensure IsAnalyzing is reset on error so Analyze button re-enables
            Analysis.IsAnalyzing = false;
            UIState.SetAnalysisStatus(false);

            throw;
        }
    }

    /// <summary>
    /// ✅ PRELOAD ARCHITECTURE: Run complete analysis using AnalysisOrchestrator.
    /// Loads ALL packets, analyzes ALL tabs in parallel, caches results for instant tab switching.
    /// Expected: 60-70s for 5GB (vs 178s legacy), <100ms tab switching (vs 5-10s).
    /// </summary>
    private async Task RunPreloadAnalysisAsync(string pcapPath)
    {
        try
        {
            // Clear old session cache
            _sessionCache.Clear();
            DebugLogger.Log("[RunPreloadAnalysis] Session cache cleared");

            // ✅ FIX: Set IsAnalyzing to true to show progress panel
            Analysis.IsAnalyzing = true;

            // Disable tabs during analysis
            UIState.CanAccessAnalysisTabs = false;
            UIState.SetAnalysisStatus(true);

            // ✅ NEW: Initialize FileAnalysisViewModel progress reporter for accurate 0-100% updates
            FileAnalysisViewModel?.InitializeProgressReporter();

            // Progress tracking
            var progress = new Progress<AnalysisProgress>(p =>
            {
                Analysis.AnalysisProgress = p.Percent;
                Analysis.ProgressMessage = $"{p.Phase}: {p.Detail}";
                Analysis.UpdateRealtimeMetrics(p); // Update real-time metrics for UI display

                // ✅ NEW: Also forward progress to FileAnalysisViewModel for real-time stage updates
                FileAnalysisViewModel?.ProgressReporter?.Report(p);

                // ✅ FIX: Synchronize FileAnalysisViewModel stages with orchestrator progress
                // This ensures FileManagerViewModel shows correct stage names instead of "Idle"
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [ORCHESTRATOR → MainWindowVM] Phase: {p.Phase}, Percent: {p.Percent:F1}%, ETA: {p.RemainingTime.TotalSeconds:F1}s");
                FileAnalysisViewModel?.SyncStageFromOrchestrator(p.Phase, p.Percent, p.Detail);

                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [ORCHESTRATOR] {p.Phase} {p.Percent}% - {p.Detail}");
            });

            var startTime = DateTime.Now;
            DebugLogger.Log($"[{startTime:HH:mm:ss.fff}] [ORCHESTRATOR] ========== PRELOAD ANALYSIS STARTED ==========");

            // Run complete analysis
            var result = await _orchestrator!.AnalyzeFileAsync(pcapPath, progress, Analysis.CurrentCancellationToken);

            var elapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [ORCHESTRATOR] ========== ANALYSIS COMPLETE ({elapsed:F2}s) ==========");
            DebugLogger.Log($"[ORCHESTRATOR] Total Packets: {result.TotalPackets:N0}");
            DebugLogger.Log($"[ORCHESTRATOR] Memory Usage: {result.EstimatedMemoryGB:F2}GB");
            DebugLogger.Log($"[ORCHESTRATOR] Cache Status: {(_sessionCache.Get() != null ? "CACHED" : "NOT CACHED")}");

            // Set total packets for UI display
            TotalPackets = result.TotalPackets;

            // ✅ FIX: Capture orchestrator completion % for dynamic tab progress handoff
            var orchestratorCompletionPercent = Analysis.AnalysisProgress;
            Analysis.SetOrchestratorCompletionPercent(orchestratorCompletionPercent);
            DebugLogger.Log($"[RunPreloadAnalysis] ✅ Orchestrator phase complete at {orchestratorCompletionPercent:F1}%");
            DebugLogger.Log($"[RunPreloadAnalysis] ✅ Tab population will continue from {orchestratorCompletionPercent:F1}% → 100%");

            // Populate all ViewModels from cached result
            await PopulateViewModelsFromCacheAsync(result);

            // ✅ NEW: Update FileAnalysisViewModel quick stats from result (fixes "all zeros" bug)
            DebugLogger.Log($"[MainWindowViewModel] 🔗 About to call FileAnalysisViewModel.UpdateQuickStatsFromResult");
            DebugLogger.Log($"[MainWindowViewModel]   📊 Result data - TotalPackets: {result.TotalPackets:N0}, TotalBytes: {result.TotalBytes:N0}, Threats: {result.Threats.Count}, UniqueIPs: {result.Statistics?.AllUniqueIPs.Count ?? 0}");
            FileAnalysisViewModel?.UpdateQuickStatsFromResult(result);
            DebugLogger.Log($"[MainWindowViewModel] 🔗 UpdateQuickStatsFromResult call completed");

            // ✅ FIX: Set IsAnalyzing to false to hide progress panel
            Analysis.IsAnalyzing = false;

            // Enable tabs (all data preloaded)
            UIState.CanAccessAnalysisTabs = true;
            UIState.SetAnalysisStatus(false);
            UIState.UpdateStatus($"Analysis complete: {result.TotalPackets:N0} packets ({elapsed:F1}s)", "#4CAF50");

            DebugLogger.Log("[ORCHESTRATOR] All tabs populated - instant switching enabled");
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[ERROR] Preload analysis failed: {ex.Message}");
            UIState.UpdateStatus($"Analysis error: {ex.Message}", "#FF5252");

            // ✅ FIX: Ensure IsAnalyzing is reset on error
            Analysis.IsAnalyzing = false;
            UIState.SetAnalysisStatus(false);
            throw;
        }
    }

    /// <summary>
    /// ✅ COORDINATOR REFACTOR: Populate all ViewModels via AnalysisCoordinator.
    /// Uses centralized parallel tab population for better performance and testability.
    /// Expected: <1s to populate ALL tabs (vs 10s+ redundant analysis).
    /// </summary>
    private async Task PopulateViewModelsFromCacheAsync(AnalysisResult result)
    {
        var startTime = DateTime.Now;
        DebugLogger.Log("[PopulateViewModels] Populating all tabs via coordinator...");

        // Update UI state
        UIState.HasResults = true;
        EnhancedFilterViewModel.IsAnalyzing = false;
        EnhancedFilterViewModel.CanApplyFilters = true;

        // ✅ PACKET LIST: Populate packet list for Packet Analysis tab
        if (PacketManager != null)
        {
            await PacketManager.PopulateFullPacketListAsync(result.Statistics);
            PacketManager.ApplyFilter(new PacketFilter());
            var filteredCount = PacketManager.GetFilteredPackets().Count;
            UIState.UpdatePaginationInfo(filteredCount);
            UIState.GoToPage(1);
            UpdatePacketAnalysisStats();
        }

        // ✅ CHARTS: Update charts with statistics from TShark service
        var packetStats = _tsharkService.GetStatistics();
        Charts.UpdateCharts(packetStats);
        if (PacketManager != null)
        {
            var filteredPackets = PacketManager.GetFilteredPackets();
            Charts.UpdatePacketsOverTimeChart(filteredPackets);
        }

        // ✅ COORDINATOR: Parallel tab population (Dashboard, Threats, VoiceQoS, CountryTraffic)
        if (_analysisCoordinator != null)
        {
            await _analysisCoordinator.PopulateTabsAsync(result);
        }
        else
        {
            // Fallback: Legacy manual population if coordinator not available
            DebugLogger.Log("[PopulateViewModels] ⚠️ Coordinator not available - using legacy population");
            await PopulateTabsLegacyAsync(result);
        }

        // FileAnalysisViewModel - Quick stats already updated by UpdateQuickStatsFromResult in RunPreloadAnalysisAsync

        var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
        DebugLogger.Log($"[PopulateViewModels] ✓✓ ALL TABS POPULATED in {elapsed:F0}ms (via coordinator)");
    }

    /// <summary>
    /// Legacy fallback for tab population when coordinator is not available.
    /// Kept for backwards compatibility during migration period.
    /// </summary>
    private async Task PopulateTabsLegacyAsync(AnalysisResult result)
    {
        // Dashboard
        if (DashboardViewModel != null)
        {
            DashboardViewModel.SetStatisticsOverride(result.Statistics);
            await DashboardViewModel.UpdateStatisticsAsync(result.AllPackets);
        }

        // Threats
        if (ThreatsViewModel != null)
        {
            await ThreatsViewModel.SetFromCacheAsync(result.Threats, result.AllPackets);
        }

        // VoiceQoS
        if (VoiceQoSViewModel != null && result.VoiceQoSData != null)
        {
            await VoiceQoSViewModel.SetFromCacheAsync(result.VoiceQoSData, result.VoiceQoSTimeSeries, result.AllPackets);
        }

        // Country Traffic
        if (CountryTrafficViewModel != null)
        {
            await CountryTrafficViewModel.UpdateStatistics(result.Statistics);
        }
    }


    /// <summary>
    /// Event handler for FileAnalysisViewModel analysis completion.
    /// Propagates results to all tabs and calculates quick stats.
    /// </summary>
    private void OnFileAnalysisCompleted(AnalysisCompletedEventArgs args)
    {
        DebugLogger.Log($"[MainWindowViewModel] 🎯 OnFileAnalysisCompleted EVENT HANDLER CALLED - Success: {args.IsSuccessful}, Packets: {args.Packets?.Count ?? 0}");

        if (!args.IsSuccessful)
        {
            DebugLogger.Critical($"[MainWindowViewModel] ❌ Analysis failed: {args.ErrorMessage}");
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                UIState.UpdateStatus($"Analysis failed: {args.ErrorMessage}", "#F85149");
                UIState.CanAccessAnalysisTabs = false; // Keep tabs disabled on failure
            });
            return;
        }

        DebugLogger.Log($"[MainWindowViewModel] ✅ Analysis successful - Propagating results to all tabs...");

        Dispatcher.UIThread.InvokeAsync(async () =>
        {
            // Update FileManager with file path
            if (!string.IsNullOrEmpty(args.FilePath))
            {
                FileManager.CurrentFile = args.FilePath;
            }

            // CRITICAL FIX: Initialize packet store BEFORE inserting packets
            // Without this, ActivePacketStore is NullPacketStore and inserts are no-ops
            await PacketManager.InitializePacketStoreAsync(CancellationToken.None);

            // CRITICAL FIX: Set PCAP path for PacketDetailsViewModel hex dump functionality
            // OnFileLoaded may not fire for preloaded/cached data, so set it here too
            if (!string.IsNullOrEmpty(args.FilePath))
            {
                DebugLogger.Log($"[MainWindowVM] Setting PCAP path: '{args.FilePath}'");
                PacketManager?.PacketDetails?.SetPcapPath(args.FilePath);
                PacketManager?.PacketDetails?.SetPacketStore(PacketManager.ActivePacketStore);
            }

            // Insert packets into initialized PacketStore BEFORE populating tabs
            if (args.Packets != null && args.Packets.Count > 0 && PacketManager != null)
            {
                var insertStart = DateTime.Now;
                await PacketManager.ActivePacketStore.InsertPacketsAsync(args.Packets, CancellationToken.None);
                DebugLogger.Log($"[OnFileAnalysisCompleted] ✓ Inserted {args.Packets.Count:N0} packets into store in {(DateTime.Now - insertStart).TotalSeconds:F2}s");
            }

            // ✅ PERFORMANCE FIX: Use cached AnalysisResult for fast parallel tab population (~1s vs ~27s)
            var cachedResult = _sessionCache.Get();
            if (cachedResult != null)
            {
                var tabPopStart = DateTime.Now;
                DebugLogger.Log("[OnFileAnalysisCompleted] ⚡ Using cached AnalysisResult for fast tab population");

                // Report tab loading progress
                FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Populating tabs from cache...");

                await PopulateViewModelsFromCacheAsync(cachedResult);

                // Complete analysis stage
                FileAnalysisViewModel?.ReportTabLoadingProgress(100, "Tabs populated");
                FileAnalysisViewModel?.CompleteAnalysis();

                var tabPopElapsed = (DateTime.Now - tabPopStart).TotalSeconds;
                DebugLogger.Log($"[OnFileAnalysisCompleted] ⚡ Fast tab population completed in {tabPopElapsed:F2}s");
            }
            else
            {
                // Fallback to legacy path if cache miss (shouldn't happen normally)
                DebugLogger.Log("[OnFileAnalysisCompleted] ⚠️ Cache miss - using legacy OnAnalysisCompleted (slow path)");
                OnAnalysisCompleted(this, args.Statistics);
            }

            // Calculate quick stats (deferred for performance)
            if (FileAnalysisViewModel != null && args.Packets != null)
            {
                await CalculateFileAnalysisQuickStats(args.Statistics, args.Packets);
            }

            // CRITICAL FIX: Enable tabs after loading completes
            DebugLogger.Log($"[MainWindowViewModel] 🔓 Enabling tabs access (CanAccessAnalysisTabs = true)");
            UIState.CanAccessAnalysisTabs = true;
            UIState.HasResults = true;
            UIState.UpdateStatus($"Analysis complete: {args.Packets?.Count ?? 0:N0} packets analyzed", "#4ADE80");

            DebugLogger.Log($"[MainWindowViewModel] ✓ Results propagated in {args.TotalDuration.TotalSeconds:F2}s - Tabs enabled");
        });
    }

    /// <summary>
    /// Calculate quick stats for FileAnalysisView (deferred post-analysis for performance).
    /// </summary>
    private async Task CalculateFileAnalysisQuickStats(NetworkStatistics statistics, IReadOnlyList<Core.Models.PacketInfo> packets)
    {
        await Task.Run(() =>
        {
            if (FileAnalysisViewModel == null) return;

            var quickStats = FileAnalysisViewModel.QuickStats;

            // 8-metric quick stats grid
            quickStats.TotalPackets = packets.Count;
            quickStats.TotalTrafficMB = statistics.TotalBytes / 1024.0 / 1024.0;
            quickStats.UniqueIPs = statistics.AllUniqueIPs.Count;
            quickStats.UniquePorts = statistics.UniquePortCount;
            quickStats.Conversations = statistics.TotalConversationCount;
            quickStats.Threats = statistics.DetectedThreats?.Count ?? 0;
            quickStats.Anomalies = 0; // Will be calculated by anomaly service if needed
            quickStats.UniqueProtocols = statistics.ProtocolStats.Count;

            // FIX: Calculate ProcessingRate from elapsed time
            if (FileAnalysisViewModel.ElapsedTime.TotalSeconds > 0)
            {
                quickStats.ProcessingRate = (long)(packets.Count / FileAnalysisViewModel.ElapsedTime.TotalSeconds);
                DebugLogger.Log($"[CalculateFileAnalysisQuickStats] ⚡ ProcessingRate calculated: {quickStats.ProcessingRate:N0} pps ({packets.Count:N0} packets / {FileAnalysisViewModel.ElapsedTime.TotalSeconds:F2}s)");
            }
            else
            {
                quickStats.ProcessingRate = 0;
                DebugLogger.Log($"[CalculateFileAnalysisQuickStats] ⚠️ Cannot calculate ProcessingRate - ElapsedTime is 0");
            }

            DebugLogger.Log($"[CalculateFileAnalysisQuickStats] ✓ Quick stats calculated: {quickStats.TotalPackets:N0} packets, {quickStats.UniqueIPs:N0} IPs, {quickStats.ProcessingRate:N0} pps");
        });
    }

    private void OnAnalysisCompleted(object? sender, NetworkStatistics statistics)
    {
        _updateTimer.Stop();

        Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var tabLoadStart = DateTime.Now;
            DebugLogger.Log($"[{tabLoadStart:HH:mm:ss.fff}] [TAB-ANALYSIS] ========== TAB LOADING PHASE STARTED ==========");

            UIState.UpdateStatus($"Analysis completed. Processing results...", "#4ADE80");
            UIState.HasResults = true;
            UIState.CanAccessAnalysisTabs = false; // Keep locked until all tabs load
            EnhancedFilterViewModel.IsAnalyzing = false;
            EnhancedFilterViewModel.CanApplyFilters = true;

            try
            {
                // TAB ORDER: Packet Analysis → Dashboard → Security Threats → Voice/QoS → Country Traffic
                // ✅ REFACTOR: Report tab loading progress to FileAnalysisViewModel (Stage 6: 97-100%)

                // Phase 1: Packet Analysis List (first tab) - 0-15% of tab loading
                FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Loading Packet Analysis tab...");
                var phase1Start = DateTime.Now;
                DebugLogger.Log($"[{phase1Start:HH:mm:ss.fff}] [TAB-ANALYSIS] Phase 1/6: Packet Analysis - Starting...");
                Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 0, "Populating packet list...");
                await PacketManager.PopulateFullPacketListAsync(statistics);
                Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 75, "Applying filters...");
                PacketManager.ApplyFilter(new PacketFilter());
                var filteredCount = PacketManager.GetFilteredPackets().Count;
                UIState.UpdatePaginationInfo(filteredCount);
                UIState.GoToPage(1);
                var phase1Elapsed = (DateTime.Now - phase1Start).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [TAB-ANALYSIS] Phase 1/6: Packet Analysis - Completed in {phase1Elapsed:F2}s ({filteredCount:N0} packets)");
                Analysis.CompleteTabStage(Analysis.GetPacketAnalysisStageKey(),
                    $"Packet list ready ({filteredCount:N0} packets)");
                FileAnalysisViewModel?.ReportTabLoadingProgress(15, $"Packet Analysis loaded ({filteredCount:N0} packets)");

                // Update PacketAnalysisStats bar with final values
                UpdatePacketAnalysisStats();

                // Update Packets Over Time chart with filtered packets
                var filteredPacketsForChart = PacketManager.GetFilteredPackets();
                Charts.UpdatePacketsOverTimeChart(filteredPacketsForChart);

                // ═══════════════════════════════════════════════════════════════════════════════
                // PARALLEL TAB LOADING - Phases 2-5 run concurrently for ~65% time reduction
                // Dependencies: CountryTraffic needs Dashboard's enriched stats, so they run sequentially
                // Independent: Threats, Anomaly, VoiceQoS can run in parallel with Dashboard chain
                // ═══════════════════════════════════════════════════════════════════════════════

                FileAnalysisViewModel?.ReportTabLoadingProgress(15, "Loading tabs in parallel...");
                var parallelStart = DateTime.Now;
                var packets = PacketManager.GetFilteredPackets().ToList();
                DebugLogger.Log($"[{parallelStart:HH:mm:ss.fff}] [TAB-ANALYSIS] ═══ PARALLEL PHASE START ═══ ({packets.Count:N0} packets)");

                // Update charts with current statistics (quick, do first)
                var stats = _tsharkService.GetStatistics();
                Charts.UpdateCharts(stats);

                // ─── Task A: Dashboard → CountryTraffic (sequential chain) ───
                var dashboardCountryTask = Task.Run(async () =>
                {
                    var taskStart = DateTime.Now;
                    DebugLogger.Log($"[{taskStart:HH:mm:ss.fff}] [PARALLEL] Task A: Dashboard+Country - Starting...");

                    // Dashboard first
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        await UpdateDashboardAsync(forceUpdate: true);
                    });
                    var dashboardElapsed = (DateTime.Now - taskStart).TotalSeconds;
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task A: Dashboard completed in {dashboardElapsed:F2}s");

                    // Country Traffic after Dashboard (needs enriched stats)
                    if (CountryTrafficViewModel != null)
                    {
                        await Dispatcher.UIThread.InvokeAsync(async () =>
                        {
                            CountryTrafficViewModel.SetPackets(packets);
                            var enrichedStats = DashboardViewModel?.CurrentStatistics ?? statistics;
                            await CountryTrafficViewModel.UpdateStatistics(enrichedStats);
                        });
                    }
                    var totalElapsed = (DateTime.Now - taskStart).TotalSeconds;
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task A: Dashboard+Country completed in {totalElapsed:F2}s");
                    return totalElapsed;
                });

                // ─── Task B: Security Threats ───
                var threatsTask = Task.Run(async () =>
                {
                    var taskStart = DateTime.Now;
                    DebugLogger.Log($"[{taskStart:HH:mm:ss.fff}] [PARALLEL] Task B: Threats - Starting ({packets.Count:N0} packets)...");

                    if (ThreatsViewModel != null)
                    {
                        await ThreatsViewModel.UpdateThreatsAsync(packets);
                    }

                    var elapsed = (DateTime.Now - taskStart).TotalSeconds;
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task B: Threats completed in {elapsed:F2}s");
                    return elapsed;
                });

                // ─── Task C: Anomaly Detection ───
                var anomalyTask = Task.Run(async () =>
                {
                    var taskStart = DateTime.Now;
                    DebugLogger.Log($"[{taskStart:HH:mm:ss.fff}] [PARALLEL] Task C: Anomaly - Starting ({packets.Count:N0} packets)...");

                    var detectedAnomalies = await _anomalyService.DetectAllAnomaliesAsync(packets);
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task C: Anomaly detected {detectedAnomalies.Count} anomalies");

                    // Update ViewModels on UI thread
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        AnomalyViewModel?.UpdateAnomalies(detectedAnomalies);
                        DashboardViewModel?.UpdateAnomalySummary(detectedAnomalies);
                    });

                    var elapsed = (DateTime.Now - taskStart).TotalSeconds;
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task C: Anomaly completed in {elapsed:F2}s");
                    return elapsed;
                });

                // ─── Task D: VoiceQoS Analysis ───
                var voiceQoSTask = Task.Run(async () =>
                {
                    var taskStart = DateTime.Now;
                    DebugLogger.Log($"[{taskStart:HH:mm:ss.fff}] [PARALLEL] Task D: VoiceQoS - Starting ({packets.Count:N0} packets)...");

                    if (VoiceQoSViewModel != null)
                    {
                        await VoiceQoSViewModel.AnalyzePacketsAsync(packets);
                    }

                    var elapsed = (DateTime.Now - taskStart).TotalSeconds;
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [PARALLEL] Task D: VoiceQoS completed in {elapsed:F2}s");
                    return elapsed;
                });

                // ═══ Wait for all parallel tasks ═══
                FileAnalysisViewModel?.ReportTabLoadingProgress(50, "Analyzing Dashboard, Threats, VoiceQoS, Country...");
                var results = await Task.WhenAll(dashboardCountryTask, threatsTask, anomalyTask, voiceQoSTask);

                var parallelElapsed = (DateTime.Now - parallelStart).TotalSeconds;
                var sequentialWouldBe = results.Sum();
                var savedTime = sequentialWouldBe - parallelElapsed;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [TAB-ANALYSIS] ═══ PARALLEL PHASE COMPLETE ═══");
                DebugLogger.Log($"[TAB-ANALYSIS] Parallel time: {parallelElapsed:F2}s | Sequential would be: {sequentialWouldBe:F2}s | Saved: {savedTime:F2}s ({(savedTime/sequentialWouldBe*100):F0}%)");

                // Complete stage tracking for UI
                Analysis.CompleteTabStage(Analysis.GetDashboardStageKey(), $"Dashboard ready");
                Analysis.CompleteTabStage(Analysis.GetThreatsStageKey(), $"Threats detected");
                Analysis.CompleteTabStage(Analysis.GetVoiceQoSStageKey(), $"VoIP analysis complete");
                Analysis.CompleteTabStage(Analysis.GetCountryTrafficStageKey(), $"Geographic analysis complete");
                FileAnalysisViewModel?.ReportTabLoadingProgress(95, "All tabs loaded");

                // Phase 6: Finalization - AFTER all other stages (95-100% of tab loading)
                FileAnalysisViewModel?.ReportTabLoadingProgress(95, "Finalizing analysis...");
                var phase6Start = DateTime.Now;
                DebugLogger.Log($"[{phase6Start:HH:mm:ss.fff}] [TAB-ANALYSIS] Phase 6/6: Finalization - Starting...");
                Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 0, "Finalizing analysis...");

                // Run external tools (Suricata, YARA) in background with proper error handling
                try
                {
                    Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 50, "Running background tools...");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await RunExternalToolsAsync(statistics);
                        }
                        catch (Exception toolEx)
                        {
                            DebugLogger.Log($"[MainWindowViewModel] External tools failed (non-critical): {toolEx.Message}");
                            DebugLogger.Log($"[MainWindowViewModel] Stack trace: {toolEx.StackTrace}");
                            // External tools are optional - don't crash if they fail
                        }
                    });
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[MainWindowViewModel] Failed to start external tools (non-critical): {ex.Message}");
                    // External tools are optional - continue with analysis completion
                }

                var phase6Elapsed = (DateTime.Now - phase6Start).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [TAB-ANALYSIS] Phase 6/6: Finalization - Completed in {phase6Elapsed:F2}s");

                var totalTabLoadElapsed = (DateTime.Now - tabLoadStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [TAB-ANALYSIS] ========== ALL TABS LOADED in {totalTabLoadElapsed:F2}s ==========");

                // Complete finalization - this will reach 100% through ReportTabProgress
                Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 100, "Finalizing complete");
                Analysis.CompleteTabStage(Analysis.GetFinalizingStageKey(), $"Analysis complete ({phase6Elapsed:F1}s)");

                // ✅ REFACTOR: Complete entire analysis (Stage 6 done, progress -> 100%, IsAnalyzing -> false)
                FileAnalysisViewModel?.CompleteAnalysis();

                // Now allow tab access
                UIState.CanAccessAnalysisTabs = FileManager.HasFile;
                UIState.UpdateStatus(
                    $"Analysis complete. {Analysis.PacketCount:N0} packets analyzed.", "#4ADE80");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MainWindowViewModel] Tab loading error: {ex.Message}");
                // ✅ REFACTOR: Complete analysis even if tab loading failed
                FileAnalysisViewModel?.CompleteAnalysis();
                // Allow tab access even if some loading failed
                UIState.CanAccessAnalysisTabs = FileManager.HasFile;
                UIState.UpdateStatus($"Analysis complete with some errors: {ex.Message}", "#FFA500");
            }
        });
    }

    private void OnAnalysisStopped(object? sender, EventArgs e)
    {
        _updateTimer.Stop();
        UIState.UpdateStatus($"Analysis stopped. Processed {Analysis.PacketCount:N0} packets", "#FF5252");
        UIState.CanAccessAnalysisTabs = FileManager.HasFile;
        EnhancedFilterViewModel.IsAnalyzing = false;
        EnhancedFilterViewModel.CanApplyFilters = true;

        // Update dashboard with final data
        _ = UpdateDashboardAsync();
    }

    private void OnAnalysisFailed(object? sender, Exception ex)
    {
        _updateTimer.Stop();
        UIState.UpdateStatus($"Error: {ex.Message}", "#FF5252");
        UIState.CanAccessAnalysisTabs = FileManager.HasFile;
        EnhancedFilterViewModel.IsAnalyzing = false;
        EnhancedFilterViewModel.CanApplyFilters = true;
    }

    private void OnPacketBatchProcessed(object? sender, (long packets, long bytes, NetworkStatistics? stats) data)
    {
        // Real-time updates during analysis (optional - already handled by Analysis component)
    }

    private void OnAnalysisStatusChanged(object? sender, string status)
    {
        UIState.UpdateStatus(status, UIState.StatusColor);
    }

    // ==================== DASHBOARD OPERATIONS ====================

    [RelayCommand]
    private async Task UpdateDashboardAsync()
    {
        await UpdateDashboardAsync(forceUpdate: false);
    }

    private async Task UpdateDashboardAsync(bool forceUpdate = false)
    {
        var methodStart = DateTime.Now;
        DebugLogger.Log($"[{methodStart:HH:mm:ss.fff}] [UpdateDashboardAsync] ========== METHOD START ==========");

        if (!Analysis.IsAnalysisComplete && !forceUpdate)
        {
            DebugLogger.Log("[DEBUG] Skipping dashboard update - analysis not complete");
            return;
        }

        // PERFORMANCE FIX: Skip if dashboard already loaded (unless force update requested)
        if (DashboardViewModel != null &&
            DashboardViewModel.CurrentStatistics != null &&
            DashboardViewModel.CurrentStatistics.TotalPackets > 0 &&
            !forceUpdate)
        {
            DebugLogger.Log("[UpdateDashboardAsync] Dashboard data already loaded, skipping redundant update (set forceUpdate=true to override)");
            return;
        }

        if (!await _dashboardUpdateGate.WaitAsync(TimeSpan.FromSeconds(10)))
        {
            DebugLogger.Critical("[WARNING] Dashboard update gate timeout - possible contention");
            return;
        }

        try
        {
            // NOTE: Progress reporting removed - now handled by OnAnalysisCompleted()
            // This prevents Dashboard stage from appearing to restart during analysis

            // STEP 1: Load preliminary statistics
            var step1Start = DateTime.Now;
            DebugLogger.Log($"[{step1Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 1: Building preliminary statistics...");
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 10, "Building preliminary statistics...");
            var preliminaryStats = Analysis.FinalStatistics ?? Analysis.StatisticsAggregator.BuildStatistics();
            var step1Elapsed = (DateTime.Now - step1Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 1 Complete in {step1Elapsed:F3}s");

            // STEP 2: Reference existing packets (MEMORY FIX - don't reload from store!)
            var step2Start = DateTime.Now;
            DebugLogger.Log($"[{step2Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Referencing existing packet collection...");
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 30, "Loading packet data...");
            // CRITICAL MEMORY OPTIMIZATION: Reuse existing packets instead of loading duplicate copy
            // Old approach loaded 5.8M packets AGAIN from store (causing 13GB memory spike)
            // New approach references existing in-memory collection (saves 6-7GB)
            List<PacketInfo> allPackets;
            if (PacketManager.CachedDashboardPackets != null && PacketManager.CachedDashboardPackets.Count > 0)
            {
                allPackets = PacketManager.CachedDashboardPackets;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Using cached {allPackets.Count:N0} packets (MEMORY OPTIMIZED - no reload)");
            }
            else
            {
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Cache empty, loading packets from store...");
                allPackets = await PacketManager.LoadAllPacketsForDashboardAsync(preliminaryStats, CancellationToken.None).ConfigureAwait(false);
            }
            var step2Elapsed = (DateTime.Now - step2Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2 Complete in {step2Elapsed:F3}s - {allPackets.Count:N0} packets ready");

            // STEP 3: GeoIP initialization (defensive - ensures providers ready even if DI init failed/timed out)
            var step3Start = DateTime.Now;
            DebugLogger.Log($"[{step3Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 3: Ensuring GeoIP service initialized...");
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 50, "Initializing GeoIP service...");
            await _geoIpService.InitializeAsync().ConfigureAwait(false);
            var step3Elapsed = (DateTime.Now - step3Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 3 Complete in {step3Elapsed:F3}s");

            // STEP 4: Use pre-calculated statistics (PERFORMANCE FIX - skip redundant re-analysis!)
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 60, "Calculating network statistics...");
            var (statistics, step4Elapsed) = await ComputeOrReuseStatisticsAsync(preliminaryStats, allPackets).ConfigureAwait(false);

            // MEMORY OPTIMIZATION: Force garbage collection after large operations
            PerformGarbageCollection();

            // STEP 5: Update DashboardViewModel
            var step5Start = DateTime.Now;
            DebugLogger.Log($"[{step5Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 5: Updating DashboardViewModel UI components...");
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 75, "Updating dashboard visualizations...");
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                if (DashboardViewModel == null)
                {
                    DashboardViewModel = new DashboardViewModel(_statisticsService, _anomalyService, _dashboardFilterService);
                }

                await DashboardViewModel.UpdateStatistics(statistics, allPackets);
            });
            var step5Elapsed = (DateTime.Now - step5Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 5 Complete in {step5Elapsed:F3}s");

            // STEP 6: Update supplementary views
            var step6Start = DateTime.Now;
            DebugLogger.Log($"[{step6Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 6: Updating supplementary views (Country, Map, Threats, VoiceQoS)...");
            Analysis.ReportTabProgress(Analysis.GetDashboardStageKey(), 90, "Updating charts and maps...");
            var enrichedStatistics = DashboardViewModel?.CurrentStatistics ?? statistics;
            var packetsForViews = (_packetAnalysisFilterService?.IsFilterActive == true)
                ? _packetAnalysisFilterService.GetFilteredPackets(allPackets).ToList()
                : allPackets.ToList();

            await UpdateSupplementaryViewsAsync(statistics, packetsForViews);
            var step6Elapsed = (DateTime.Now - step6Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 6 Complete in {step6Elapsed:F3}s");

            var totalElapsed = (DateTime.Now - methodStart).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] ========== METHOD COMPLETE in {totalElapsed:F3}s ==========");
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] BREAKDOWN: Step1={step1Elapsed:F3}s, Step2={step2Elapsed:F3}s, Step3={step3Elapsed:F3}s, Step4={step4Elapsed:F3}s, Step5={step5Elapsed:F3}s, Step6={step6Elapsed:F3}s");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] ERROR: {ex.Message}");
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] Stack trace: {ex.StackTrace}");
        }
        finally
        {
            _dashboardUpdateGate.Release();
        }
    }

    private async Task UpdateSupplementaryViewsAsync(NetworkStatistics statistics, IReadOnlyList<PacketInfo> sample)
    {
        try
        {
            // Only update geographic views here (Country, Map)
            // ThreatsViewModel and VoiceQoSViewModel have dedicated phases

            if (CountryTrafficViewModel != null)
            {
                await Dispatcher.UIThread.InvokeAsync(() => CountryTrafficViewModel.SetPackets(sample));
                await CountryTrafficViewModel.UpdateStatistics(statistics);
            }

            if (EnhancedMapViewModel != null)
            {
                await Dispatcher.UIThread.InvokeAsync(() => EnhancedMapViewModel.SetPackets(sample));
                await EnhancedMapViewModel.UpdateStatistics(statistics);
            }

            if (ReportViewModel != null && ThreatsViewModel != null)
            {
                await ReportViewModel.UpdateData(statistics, ThreatsViewModel.GetCurrentThreats());
            }

            if (FlowSummaryViewModel != null && statistics.TopConversations != null)
            {
                // Snapshot collection first, then transform
                var conversations = statistics.TopConversations.ToList();
                var flows = conversations
                    .Select(c => new FlowRecord
                    {
                        SourceIP = c.SourceAddress,
                        DestinationIP = c.DestinationAddress,
                        SourcePort = (ushort)c.SourcePort,
                        DestinationPort = (ushort)c.DestinationPort,
                        Protocol = c.Protocol,
                        PacketCount = c.PacketCount,
                        ByteCount = c.ByteCount,
                        FirstSeen = c.StartTime,
                        LastSeen = c.EndTime
                    }).ToList();
                await Dispatcher.UIThread.InvokeAsync(() => FlowSummaryViewModel.LoadFlows(flows));
            }

            if (TopTalkersViewModel != null)
            {
                // Convert to List as TopTalkersViewModel expects List<PacketInfo>
                await Dispatcher.UIThread.InvokeAsync(async () => await TopTalkersViewModel.UpdateData(statistics, sample.ToList()));
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Supplementary view update failed: {ex.Message}");
        }
    }

    private async Task RunExternalToolsAsync(NetworkStatistics statistics)
    {
        try
        {
            var currentFile = FileManager.CurrentFile;
            if (string.IsNullOrWhiteSpace(currentFile))
                return;

            if (_suricataService.IsAvailable)
            {
                var outputDir = System.IO.Path.Combine(Environment.CurrentDirectory, "analysis", "suricata", System.IO.Path.GetFileNameWithoutExtension(currentFile) + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                var alerts = await _suricataService.RunAsync(currentFile, outputDir, CancellationToken.None);
                DebugLogger.Log($"[Suricata] Parsed {alerts.Count} alerts");
                if (alerts.Count > 0 && ThreatsViewModel != null)
                {
                    await Dispatcher.UIThread.InvokeAsync(() => ThreatsViewModel.SetSuricataAlerts(alerts));
                }
            }

            if (_yaraService.IsAvailable)
            {
                var yaraOutput = System.IO.Path.Combine(Environment.CurrentDirectory, "analysis", "yara", System.IO.Path.GetFileNameWithoutExtension(currentFile) + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
                var matches = await _yaraService.RunAsync(currentFile, yaraOutput, CancellationToken.None);
                DebugLogger.Log($"[YARA] Matches: {matches.Count}");
                if (matches.Count > 0 && ThreatsViewModel != null)
                {
                    await Dispatcher.UIThread.InvokeAsync(() => ThreatsViewModel.SetYaraMatches(matches));
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PostAnalysis] Error: {ex.Message}");
        }
    }

    // ==================== STATS BAR OPERATIONS ====================

    /// <summary>
    /// Initialize PacketAnalysisStats with default configuration
    /// </summary>
    private void InitializePacketAnalysisStats()
    {
        PacketAnalysisStats.SectionTitle = "PACKET ANALYSIS OVERVIEW";
        PacketAnalysisStats.AccentColor = "#3B82F6"; // Blue accent matching Packet Analysis theme
        PacketAnalysisStats.ColumnCount = 5; // 5 metrics: Packets, Traffic, IPs, Ports, Conversations

        // Initialize with zeros
        UpdatePacketAnalysisStats();
    }

    /// <summary>
    /// Update PacketAnalysisStats with current values.
    /// Called after analysis completion and filter changes.
    /// Uses German number formatting (1.106.728) and Style B display (Total: X / Filtered: Y).
    /// </summary>
    private void UpdatePacketAnalysisStats()
    {
        PacketAnalysisStats.ClearStats();

        var data = GatherStatsData();
        var germanCulture = new System.Globalization.CultureInfo("de-DE");

        // Stat 1: Packets (Total + Filtered with percentage)
        if (data.FilterActive)
        {
            var totalPackets = $"Total: {data.TotalPackets.ToString("N0", germanCulture)}";
            var filtered = $"Filtered: {data.FilteredCount.ToString("N0", germanCulture)} ({data.FilteredPct:F1}%)";
            PacketAnalysisStats.AddStat("PACKETS", totalPackets, "📦", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            PacketAnalysisStats.AddStat("PACKETS", data.TotalPackets.ToString("N0", germanCulture), "📦", "#58A6FF");
        }

        // Stat 2: Traffic (Total + Filtered with percentage)
        if (data.FilterActive)
        {
            var totalTraffic = $"Total: {FormatBytesGerman(data.TotalBytes)}";
            var filtered = $"Filtered: {FormatBytesGerman(data.FilteredBytes)} ({data.TrafficPct:F1}%)";
            PacketAnalysisStats.AddStat("TRAFFIC", totalTraffic, "💾", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            PacketAnalysisStats.AddStat("TRAFFIC", FormatBytesGerman(data.TotalBytes), "💾", "#58A6FF");
        }

        // Stat 3: Unique IPs (Total + Filtered with percentage)
        if (data.FilterActive)
        {
            var totalIPs = $"Total: {data.TotalUniqueIPs.ToString("N0", germanCulture)}";
            var ipPct = data.TotalUniqueIPs > 0 ? (data.FilteredUniqueIPs * 100.0 / data.TotalUniqueIPs) : 0.0;
            var filtered = $"Filtered: {data.FilteredUniqueIPs.ToString("N0", germanCulture)} ({ipPct:F1}%)";
            PacketAnalysisStats.AddStat("UNIQUE IPs", totalIPs, "🌐", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            PacketAnalysisStats.AddStat("UNIQUE IPs", data.TotalUniqueIPs.ToString("N0", germanCulture), "🌐", "#58A6FF");
        }

        // Stat 4: Destination Ports (Total + Filtered with percentage)
        if (data.FilterActive)
        {
            var totalPorts = $"Total: {data.TotalDestPorts.ToString("N0", germanCulture)}";
            var portPct = data.TotalDestPorts > 0 ? (data.FilteredDestPorts * 100.0 / data.TotalDestPorts) : 0.0;
            var filtered = $"Filtered: {data.FilteredDestPorts.ToString("N0", germanCulture)} ({portPct:F1}%)";
            PacketAnalysisStats.AddStat("DEST PORTS", totalPorts, "🔌", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            PacketAnalysisStats.AddStat("DEST PORTS", data.TotalDestPorts.ToString("N0", germanCulture), "🔌", "#58A6FF");
        }

        // Stat 5: Streams (Total + Filtered with percentage) - All protocols (TCP + UDP + other)
        if (data.FilterActive)
        {
            var totalConvs = $"Total: {data.TotalConversations.ToString("N0", germanCulture)}";
            var convPct = data.TotalConversations > 0 ? (data.FilteredConversations * 100.0 / data.TotalConversations) : 0.0;
            var filtered = $"Filtered: {data.FilteredConversations.ToString("N0", germanCulture)} ({convPct:F1}%)";
            PacketAnalysisStats.AddStat("STREAMS", totalConvs, "💬", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            PacketAnalysisStats.AddStat("STREAMS", data.TotalConversations.ToString("N0", germanCulture), "💬", "#58A6FF");
        }
    }

    /// <summary>
    /// Gather all stats data from multiple sources with defensive fallbacks.
    /// Calculates: Packets, Traffic, Unique IPs, Destination Ports, TCP Conversations (total + filtered).
    /// </summary>
    private (long TotalPackets, long FilteredCount, long TotalBytes, long FilteredBytes,
             bool FilterActive, double FilteredPct, double TrafficPct,
             int TotalUniqueIPs, int FilteredUniqueIPs,
             int TotalDestPorts, int FilteredDestPorts,
             int TotalConversations, int FilteredConversations) GatherStatsData()
    {
        // ✅ FIX: Calculate totals from CachedDashboardPackets (same source as other metrics)
        // This ensures consistent data across all stats
        long totalPackets = 0;
        long totalBytes = 0;

        if (PacketManager?.CachedDashboardPackets != null)
        {
            var allPackets = PacketManager.CachedDashboardPackets;
            totalPackets = allPackets.Count;
            totalBytes = allPackets.Sum(p => (long)p.Length);
        }

        var filteredCount = PacketManager?.FilteredPacketCount ?? 0;
        var filteredBytes = PacketManager?.FilteredBytes ?? 0;
        var filterActive = PacketManager?.IsFilterActive ?? false;

        var filteredPct = totalPackets > 0 ? (filteredCount * 100.0 / totalPackets) : 0.0;
        var trafficPct = totalBytes > 0 ? (filteredBytes * 100.0 / totalBytes) : 0.0;

        // Calculate Unique IPs (total + filtered)
        var (totalIPs, filteredIPs) = CalculateUniqueIPs();

        // Calculate Destination Ports (total + filtered)
        var (totalPorts, filteredPorts) = CalculateDestinationPorts();

        // Calculate TCP Conversations (total + filtered)
        var (totalConvs, filteredConvs) = CalculateTCPConversations();

        return (totalPackets, filteredCount, totalBytes, filteredBytes, filterActive,
                filteredPct, trafficPct, totalIPs, filteredIPs, totalPorts, filteredPorts,
                totalConvs, filteredConvs);
    }

    /// <summary>
    /// Calculate unique IP addresses (source + destination combined) for total and filtered packets.
    /// Delegates to IPacketStatisticsCalculator for actual computation.
    /// </summary>
    private (int Total, int Filtered) CalculateUniqueIPs()
    {
        if (PacketManager?.CachedDashboardPackets == null || PacketManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalIPs = _packetStatsCalculator.CalculateUniqueIPs(PacketManager.CachedDashboardPackets);

        if (!PacketManager.IsFilterActive)
            return (totalIPs, 0);

        var filteredPackets = PacketManager.GetFilteredPackets().ToList();
        var filteredIPs = _packetStatsCalculator.CalculateUniqueIPs(filteredPackets);
        return (totalIPs, filteredIPs);
    }

    /// <summary>
    /// Calculate unique destination ports for total and filtered packets.
    /// Delegates to IPacketStatisticsCalculator for actual computation.
    /// </summary>
    private (int Total, int Filtered) CalculateDestinationPorts()
    {
        if (PacketManager?.CachedDashboardPackets == null || PacketManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalPorts = _packetStatsCalculator.CalculateUniqueDestinationPorts(PacketManager.CachedDashboardPackets);

        if (!PacketManager.IsFilterActive)
            return (totalPorts, 0);

        var filteredPackets = PacketManager.GetFilteredPackets().ToList();
        var filteredPorts = _packetStatsCalculator.CalculateUniqueDestinationPorts(filteredPackets);
        return (totalPorts, filteredPorts);
    }

    /// <summary>
    /// Calculate TCP conversations (unique 4-tuple: SrcIP + DstIP + SrcPort + DstPort) for total and filtered packets.
    /// Delegates to IPacketStatisticsCalculator for actual computation.
    /// </summary>
    private (int Total, int Filtered) CalculateTCPConversations()
    {
        if (PacketManager?.CachedDashboardPackets == null || PacketManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalConversations = _packetStatsCalculator.CalculateTCPConversations(PacketManager.CachedDashboardPackets);

        if (!PacketManager.IsFilterActive)
            return (totalConversations, 0);

        var filteredPackets = PacketManager.GetFilteredPackets().ToList();
        var filteredConversations = _packetStatsCalculator.CalculateTCPConversations(filteredPackets);
        return (totalConversations, filteredConversations);
    }

    /// <summary>
    /// Format bytes with German number formatting (e.g., "287,35 MB").
    /// </summary>
    private string FormatBytesGerman(long bytes)
    {
        if (bytes == 0) return "0 B";

        var germanCulture = new System.Globalization.CultureInfo("de-DE");
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double size = bytes;

        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }

        return $"{size.ToString("F2", germanCulture)} {sizes[order]}";
    }


    // ==================== FILTER OPERATIONS ====================

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        PacketManager.ApplyFilter(e.Filter);
    }

    private void OnFilteredPacketsChanged(object? sender, int filteredCount)
    {
        UIState.UpdatePaginationInfo(filteredCount);
        UIState.GoToPage(1);

        // Update filtered stats for display
        var totalCount = Analysis.FinalStatistics?.TotalPackets ?? Analysis.PacketCount;
        FilteredPackets = PacketManager.FilteredPacketCount;
        FilteredPacketsPercentage = totalCount > 0 ? (FilteredPackets * 100.0 / totalCount) : 0;

        FilteredTrafficVolume = PacketManager.FilteredBytesFormatted;
        // Calculate traffic percentage from Analysis stats
        var totalBytes = Analysis.FinalStatistics?.TotalBytes ?? 0;
        FilteredTrafficPercentage = totalBytes > 0 ? (PacketManager.FilteredBytes * 100.0 / totalBytes) : 0;
        EnhancedFilterViewModel.UpdateStatistics(totalCount, filteredCount);

        // Update PacketAnalysisStats bar
        UpdatePacketAnalysisStats();

        // Update Packets Over Time chart with filtered packets
        var filteredPackets = PacketManager.GetFilteredPackets();
        Charts.UpdatePacketsOverTimeChart(filteredPackets);
    }

    // ==================== PAGINATION OPERATIONS ====================

    private void OnPageChanged(object? sender, int pageNumber)
    {
        PacketManager.UpdatePageDisplay(pageNumber, UIState.PageSize);
    }

    /// <summary>
    /// Handles "Go to Packet" request - finds the packet by frame number and navigates to its page.
    /// </summary>
    private void OnGoToPacketRequested(object? sender, uint frameNumber)
    {
        var filteredPackets = PacketManager.GetFilteredPackets();
        var packetIndex = -1;

        // Find packet index in filtered list
        for (int i = 0; i < filteredPackets.Count; i++)
        {
            if (filteredPackets[i].FrameNumber == frameNumber)
            {
                packetIndex = i;
                break;
            }
        }

        if (packetIndex < 0)
        {
            UIState.UpdateStatus($"Packet #{frameNumber:N0} not found in current view", "#FF5252");
            return;
        }

        // Calculate page number (1-based)
        var pageNumber = (packetIndex / UIState.PageSize) + 1;
        UIState.GoToPage(pageNumber);

        // Select the packet and load its details
        var packet = filteredPackets[packetIndex];
        _ = PacketManager.SelectPacketAsync(packet);

        UIState.UpdateStatus($"Navigated to packet #{frameNumber:N0} (page {pageNumber})", "#4ADE80");
    }

    /// <summary>
    /// Handles "Stream Filter" request - filters packets to show only those matching the stream pattern.
    /// </summary>
    private void OnSearchStreamRequested(object? sender, string searchPattern)
    {
        if (string.IsNullOrWhiteSpace(searchPattern))
        {
            // Clear stream filter - reset to no filter
            PacketManager.ClearStreamFilter();
            UIState.StreamSearchStatus = "";
            UIState.UpdateStatus("Stream filter cleared", "#4ADE80");
            return;
        }

        // Apply stream filter
        var matchCount = PacketManager.ApplyStreamFilter(searchPattern);

        if (matchCount == 0)
        {
            UIState.StreamSearchStatus = "No matches";
            UIState.UpdateStatus($"No packets found matching '{searchPattern}'", "#FF5252");
        }
        else
        {
            UIState.StreamSearchStatus = $"{matchCount:N0} packets";
            UIState.UpdateStatus($"Filtered to {matchCount:N0} packets matching '{searchPattern}'", "#4ADE80");

            // Go to first page since we've filtered
            UIState.GoToPage(1);
            PacketManager.UpdatePageDisplay(1, UIState.PageSize);
        }
    }

    /// <summary>
    /// Handles search by stream request from Packet Details panel.
    /// Populates the stream search box and executes the search.
    /// </summary>
    private void OnSearchByStreamFromDetails(object? sender, string searchPattern)
    {
        UIState.SearchStreamText = searchPattern;
        OnSearchStreamRequested(this, searchPattern);
    }

    /// <summary>
    /// Handles navigation to packet request from Packet Details panel (Previous/Next in Stream buttons).
    /// Delegates to existing OnGoToPacketRequested logic.
    /// </summary>
    private void OnNavigateToPacketFromDetails(object? sender, uint frameNumber)
    {
        OnGoToPacketRequested(this, frameNumber);
    }

    // ==================== ANALYSIS COMMANDS ====================
    // Note: Commands are exposed via Compatibility layer to avoid duplication

    // ==================== UI COMMANDS ====================

    [RelayCommand]
    private void ShowFilterDialog()
    {
        UIState.UpdateStatus("Configure filters to narrow down packet display", UIState.StatusColor);
    }

    [RelayCommand]
    private void Export()
    {
        UIState.UpdateStatus("Export feature coming soon", UIState.StatusColor);
    }

    [RelayCommand]
    private async Task ClearResults()
    {
        Analysis.ResetAnalysis();
        await PacketManager.ClearPacketsAsync();
        UIState.ResetState();
        Charts.ResetCharts();

        _tsharkService.ResetService();

        FilterViewModel.ClearFilterCommand.Execute(null);
        EnhancedFilterViewModel.ClearFilterCommand.Execute(null);

        UIState.UpdateStatus(
            string.IsNullOrEmpty(FileManager.CurrentFile)
                ? "Select or drop a PCAP file to analyze"
                : "Capture loaded. Use 'Analyze' to re-run if needed.",
            "#4A9FFF"
        );

        if (FileManager.HasFile && System.IO.File.Exists(FileManager.CurrentFile))
        {
            FileManager.CanAnalyze = true;
        }
    }

    // ==================== UI UPDATE TIMER ====================

    private void UpdateUI(object? sender, EventArgs e)
    {
        if (!Analysis.IsAnalyzing && !Analysis.IsAnalysisComplete) return;

        var stats = _tsharkService.GetStatistics();

        if (!Analysis.IsAnalyzing && Analysis.PacketCount > 0)
        {
            Charts.UpdateCharts(stats);
        }
    }

    // ==================== DASHBOARD NAVIGATION HANDLER ====================

    /// <summary>
    /// Handles navigation requests from Dashboard DrillDown popup.
    /// Parses tab name and optional filter from format "TabName?filter=value".
    /// </summary>
    private void HandleDashboardNavigation(string navigationTarget)
    {
        DebugLogger.Log($"[MainWindowViewModel] HandleDashboardNavigation: {navigationTarget}");

        // Parse tab name and filter from "TabName?filter=value" format
        var parts = navigationTarget.Split('?', 2);
        var tabName = parts[0];
        var filter = parts.Length > 1 ? parts[1] : null;

        // Map tab name to tab index
        var tabIndex = tabName switch
        {
            "PacketAnalysis" => 1,
            "Dashboard" => 2,
            "Threats" => 3,
            "VoiceQoS" => 4,
            "CountryTraffic" => 5,
            "Map" => 6,
            "Report" => 7,
            "Anomalies" => 8,
            _ => -1
        };

        if (tabIndex >= 0)
        {
            DebugLogger.Log($"[MainWindowViewModel] Navigating to tab {tabName} (index {tabIndex}), filter: {filter ?? "none"}");
            SelectedTabIndex = tabIndex;

            // Apply filter if provided (for PacketAnalysis tab)
            if (!string.IsNullOrEmpty(filter) && tabIndex == 1)
            {
                // Parse filter like "ip=192.168.1.1" or "port=443" or "connection=..."
                var filterParts = filter.Split('=', 2);
                if (filterParts.Length == 2)
                {
                    var filterType = filterParts[0];
                    var filterValue = filterParts[1];
                    DebugLogger.Log($"[MainWindowViewModel] Applying filter: {filterType}={filterValue}");

                    // Apply appropriate filter based on type
                    switch (filterType.ToLowerInvariant())
                    {
                        case "ip":
                            _packetAnalysisFilterService.ApplyIPFilter(filterValue);
                            break;
                        case "port":
                            if (int.TryParse(filterValue, out var port))
                                _packetAnalysisFilterService.ApplyPortFilter(port);
                            break;
                        case "conversation":
                        case "connection":
                            // Connection/Conversation filter: "srcIP:srcPort-dstIP:dstPort"
                            var convParts = filterValue.Split('-');
                            if (convParts.Length == 2)
                            {
                                var srcParts = convParts[0].Split(':');
                                var dstParts = convParts[1].Split(':');
                                if (srcParts.Length == 2 && dstParts.Length == 2 &&
                                    int.TryParse(srcParts[1], out var srcPort) &&
                                    int.TryParse(dstParts[1], out var dstPort))
                                {
                                    var srcIP = srcParts[0];
                                    var dstIP = dstParts[0];
                                    _packetAnalysisFilterService.ApplyCustomFilter(
                                        p => (p.SourceIP == srcIP && p.SourcePort == srcPort && p.DestinationIP == dstIP && p.DestinationPort == dstPort) ||
                                             (p.SourceIP == dstIP && p.SourcePort == dstPort && p.DestinationIP == srcIP && p.DestinationPort == srcPort),
                                        $"Connection: {srcIP}:{srcPort} ↔ {dstIP}:{dstPort}");
                                }
                            }
                            break;
                        default:
                            DebugLogger.Log($"[MainWindowViewModel] Unknown filter type: {filterType}");
                            break;
                    }
                }
            }
        }
        else
        {
            DebugLogger.Critical($"[MainWindowViewModel] Unknown tab name: {tabName}");
        }
    }

    /// <summary>
    /// Handler for DrillDown navigation from Security Threats to Packet Analysis.
    /// Filters Packet Analysis to show only packets matching the threat's frame numbers.
    /// </summary>
    private void OnNavigateToPacketAnalysisFromThreat(List<uint> frameNumbers, string context)
    {
        try
        {
            if (frameNumbers == null || frameNumbers.Count == 0)
            {
                DebugLogger.Log("[MainWindowViewModel] No frame numbers to filter - showing all packets");
                SelectedTabIndex = 1; // Navigate to Packet Analysis anyway
                return;
            }

            // Create a HashSet for O(1) lookup
            var frameSet = new HashSet<uint>(frameNumbers);

            // Apply custom filter for frame numbers
            _packetAnalysisFilterService.ApplyCustomFilter(
                p => frameSet.Contains(p.FrameNumber),
                $"Threat Evidence: {context} ({frameNumbers.Count} packets)");

            // Navigate to Packet Analysis tab (index 1)
            SelectedTabIndex = 1;

            // Update status
            UIState.UpdateStatus($"Showing {frameNumbers.Count} packets for: {context}", "#4ADE80");
            DebugLogger.Log($"[MainWindowViewModel] Navigated to Packet Analysis with {frameNumbers.Count} threat-related frames");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Error navigating to Packet Analysis: {ex.Message}");
            UIState.UpdateStatus("Navigation error", "#EF4444");
        }
    }

    // ==================== PROPERTY CHANGE FORWARDING ====================

    private void OnFileManagerPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward FileManager property changes to MainWindowViewModel
        OnPropertyChanged(e.PropertyName);

        // ✅ FIX: Notify StartAnalysisCommand to re-evaluate CanExecute when CanAnalyze changes
        if (e.PropertyName == nameof(FileManager.CanAnalyze) ||
            e.PropertyName == nameof(FileManager.CurrentFile) ||
            e.PropertyName == nameof(FileManager.HasFile))
        {
            _startAnalysisCommand?.NotifyCanExecuteChanged();
            DebugLogger.Log($"[MainWindowViewModel] Command CanExecute refreshed due to FileManager.{e.PropertyName} change");
        }
    }

    private void OnAnalysisPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward Analysis property changes to MainWindowViewModel
        OnPropertyChanged(e.PropertyName);

        // ✅ FIX: Notify commands to re-evaluate CanExecute when IsAnalyzing changes
        if (e.PropertyName == nameof(Analysis.IsAnalyzing))
        {
            _startAnalysisCommand?.NotifyCanExecuteChanged();
            DebugLogger.Log($"[MainWindowViewModel] Command CanExecute refreshed due to Analysis.IsAnalyzing = {Analysis.IsAnalyzing}");
        }
    }

    private void OnUIStatePropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward UIState property changes to MainWindowViewModel
        OnPropertyChanged(e.PropertyName);
    }

    private void OnPacketManagerPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward PacketManager property changes to MainWindowViewModel
        OnPropertyChanged(e.PropertyName);
    }

    private void OnChartsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward Charts property changes to MainWindowViewModel
        OnPropertyChanged(e.PropertyName);
    }

    // ==================== FILTER COMMANDS ====================

    /// <summary>
    /// Copies current filters from Packet Analysis tab to Dashboard tab
    /// </summary>
    protected override void CopyFiltersToDashboard()
    {
        if (DashboardViewModel != null)
        {
            _dashboardFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Dashboard", "#4ADE80");
            DebugLogger.Log("[MainWindowViewModel] Copied filters: Packet Analysis → Dashboard");
        }
    }

    /// <summary>
    /// Copies current filters from Packet Analysis tab to Security Threats tab
    /// </summary>
    protected override void CopyFiltersToThreats()
    {
        if (ThreatsViewModel != null)
        {
            _threatsFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Security Threats", "#4ADE80");
            DebugLogger.Log("[MainWindowViewModel] Copied filters: Packet Analysis → Security Threats");
        }
    }

    /// <summary>
    /// Copies current filters from Packet Analysis tab to Voice/QoS tab
    /// </summary>
    protected override void CopyFiltersToVoiceQoS()
    {
        if (VoiceQoSViewModel != null)
        {
            _voiceQoSFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Voice/QoS", "#4ADE80");
            DebugLogger.Log("[MainWindowViewModel] Copied filters: Packet Analysis → Voice/QoS");
        }
    }

    /// <summary>
    /// Copies current filters from Packet Analysis tab to Country Traffic tab
    /// </summary>
    protected override void CopyFiltersToCountryTraffic()
    {
        if (CountryTrafficViewModel != null)
        {
            _countryTrafficFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Country Traffic", "#4ADE80");
            DebugLogger.Log("[MainWindowViewModel] Copied filters: Packet Analysis → Country Traffic");
        }
    }

    // ==================== DISPOSAL ====================

    /// <summary>
    /// Async disposal - gracefully disposes child ViewModels and services.
    /// Preferred disposal method.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            DebugLogger.Log("[MainWindowViewModel] Disposing asynchronously...");

            _updateTimer?.Stop();

            // Dispose services with async support
            if (_tsharkService is IAsyncDisposable asyncTShark)
                await asyncTShark.DisposeAsync().ConfigureAwait(false);
            else
                _tsharkService?.Dispose();

            Analysis?.Dispose();

            // Properly await PacketManager disposal
            if (PacketManager != null)
                await PacketManager.DisposeAsync().ConfigureAwait(false);

            // Dispose child ViewModels
            if (DashboardViewModel is IDisposable disposableDashboard)
                disposableDashboard.Dispose();

            DebugLogger.Log("[MainWindowViewModel] Disposed asynchronously successfully");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Error during async disposal: {ex.Message}");
        }
    }

    /// <summary>
    /// Synchronous disposal - aggressive cleanup without waiting.
    /// Use DisposeAsync() when possible.
    /// </summary>
    public void Dispose()
    {
        try
        {
            DebugLogger.Log("[MainWindowViewModel] Disposing synchronously...");

            _updateTimer?.Stop();
            _tsharkService?.Dispose();
            Analysis?.Dispose();

            // Don't block on async disposal in sync Dispose
            // PacketManager cleanup will happen via finalizer if needed

            if (DashboardViewModel is IDisposable disposableDashboard)
                disposableDashboard.Dispose();

            DebugLogger.Log("[MainWindowViewModel] Disposed synchronously (aggressive cleanup)");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Error during synchronous disposal: {ex.Message}");
        }
    }

    /// <summary>
    /// Computes or reuses network statistics based on availability of preliminary data.
    /// PERFORMANCE OPTIMIZATION: Avoids redundant re-analysis of millions of packets.
    /// </summary>
    private async Task<(NetworkStatistics statistics, double elapsedSeconds)> ComputeOrReuseStatisticsAsync(
        NetworkStatistics? preliminaryStats,
        List<PacketInfo> allPackets)
    {
        var step4Start = DateTime.Now;

        // ✅ P0 FIX: GeoIP cache hit detection - check if CountryStatistics has data
        // If preliminaryStats has country data, GeoIP analysis already completed (save 20s)
        var hasCompleteStats = preliminaryStats != null &&
                               preliminaryStats.TotalPackets > 0 &&
                               preliminaryStats.CountryStatistics?.Count > 0;

        NetworkStatistics statistics;

        if (hasCompleteStats && allPackets.Count > 0)
        {
            DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Using pre-calculated statistics (OPTIMIZED - skipping 97s re-analysis)");
            statistics = preliminaryStats!;

            // Only enrich with GeoIP if countries are missing
            if (statistics.CountryStatistics?.Count == 0)
            {
                DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Enriching with GeoIP data...");
                var enrichStart = DateTime.Now;
                statistics = await Task.Run(() => _statisticsService.CalculateStatistics(allPackets)).ConfigureAwait(false);
                var enrichElapsed = (DateTime.Now - enrichStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: GeoIP enrichment complete in {enrichElapsed:F3}s");
            }

            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Complete in {elapsed:F3}s (reused pre-calculated data)");
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Results - Threats: {statistics.DetectedThreats?.Count ?? 0}, Services: {statistics.ServiceStats?.Count ?? 0}, Ports: {statistics.UniquePortCount}, Countries: {statistics.CountryStatistics?.Count ?? 0}");
            return (statistics, elapsed);
        }
        else if (allPackets.Count > 0)
        {
            // Fallback: Full recalculation if preliminary stats incomplete
            DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Preliminary stats incomplete, running full analysis...");
            DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Calling _statisticsService.CalculateStatistics({allPackets.Count:N0} packets)...");

            statistics = await Task.Run(() => _statisticsService.CalculateStatistics(allPackets)).ConfigureAwait(false);

            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Complete in {elapsed:F3}s");
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Results - Threats: {statistics.DetectedThreats?.Count ?? 0}, Services: {statistics.ServiceStats?.Count ?? 0}, Ports: {statistics.UniquePortCount}, Countries: {statistics.CountryStatistics?.Count ?? 0}");
            return (statistics, elapsed);
        }
        else
        {
            statistics = preliminaryStats ?? new NetworkStatistics();
            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Skipped - no packets to analyze ({elapsed:F3}s)");
            return (statistics, elapsed);
        }
    }

    /// <summary>
    /// Performs aggressive garbage collection to free memory after large operations.
    /// MEMORY OPTIMIZATION: Reclaims memory from duplicate packet collections.
    /// </summary>
    private static void PerformGarbageCollection()
    {
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] Running garbage collection to free memory...");
        var gcStart = DateTime.Now;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var gcElapsed = (DateTime.Now - gcStart).TotalMilliseconds;
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] Garbage collection completed in {gcElapsed:F0}ms");
    }


    // ==================== COMPATIBILITY LAYER ====================
    // Provides backward-compatible properties and methods that delegate to component ViewModels.
    // Merged from MainWindowViewModel.Compatibility.cs for cleaner project structure.

    // ==================== FILE MANAGEMENT PROPERTIES ====================

    public string? CurrentFile => FileManager.CurrentFile;
    public bool HasFile => FileManager.HasFile;
    public bool CanAnalyze => FileManager.CanAnalyze;

    // ==================== ANALYSIS PROPERTIES ====================

    public bool IsAnalyzing => Analysis.IsAnalyzing;
    public long PacketCount => Analysis.PacketCount;
    public long TotalPacketsInFile => Analysis.TotalPacketsInFile;
    public double ProcessingRate => Analysis.ProcessingRate;
    public long TotalBytes => Analysis.TotalBytes;
    public double BytesPerSecond => Analysis.BytesPerSecond;
    public double AnalysisProgress => Analysis.AnalysisProgress;
    public bool IsProgressIndeterminate => Analysis.IsProgressIndeterminate;
    public string ProgressMessage => Analysis.ProgressMessage;
    public double ProgressPercentage => Analysis.ProgressPercentage;
    public string TotalBytesFormatted => Analysis.TotalBytesFormatted;
    public int ThreatsDetected => Analysis.ThreatsDetected;
    public bool IsPaused => Analysis.IsPaused;
    public string PauseResumeText => Analysis.PauseResumeText;
    public string PauseResumeIcon => Analysis.PauseResumeIcon;
    public string ElapsedTime => Analysis.ElapsedTime;
    public double FinalizingProgressPercent => Analysis.FinalizingProgressPercent;
    public bool IsFinalizingStats => Analysis.IsFinalizingStats;
    public ObservableCollection<AnalysisProgressStage> AnalysisStages => Analysis.AnalysisStages;

    // ==================== UI STATE PROPERTIES ====================

    public string Status => UIState.Status;
    public string StatusColor => UIState.StatusColor;
    public bool HasResults => UIState.HasResults;
    public bool CanAccessAnalysisTabs => UIState.CanAccessAnalysisTabs;
    public string LastScreenshotInfo => UIState.LastScreenshotInfo;
    public int CurrentPage => UIState.CurrentPage;
    public int TotalPages => UIState.TotalPages;
    public int PageSize => UIState.PageSize;
    public string PageSizeText => UIState.PageSizeText;
    public string PageInfo => UIState.PageInfo;
    public bool CanGoToPreviousPage => UIState.CanGoToPreviousPage;
    public bool CanGoToNextPage => UIState.CanGoToNextPage;
    public bool CanGoToFirstPage => UIState.CanGoToFirstPage;
    public bool CanGoToLastPage => UIState.CanGoToLastPage;
    public string MemoryUsage => UIState.MemoryUsage;
    public string CpuUsage => UIState.CpuUsage;
    public string MemoryPressureLevel => UIState.MemoryPressureLevel;
    public string PerformanceStatus => UIState.PerformanceStatus;

    // ==================== PACKET PROPERTIES ====================

    public ObservableCollection<PacketInfo> Packets => PacketManager.Packets;
    public bool HasPackets => PacketManager.HasPackets;
    public long FilteredPacketCount => PacketManager.FilteredPacketCount;
    public long FilteredBytes => PacketManager.FilteredBytes;
    public string FilteredBytesFormatted => PacketManager.FilteredBytesFormatted;
    public int FilteredThreatsCount => PacketManager.FilteredThreatsCount;
    public int TotalFilteredPackets => PacketManager.TotalFilteredPackets;
    public string FilterStatus => PacketManager.FilterStatus;
    public bool IsFilterActive => PacketManager.IsFilterActive;
    public string AppliedFiltersText => PacketManager.AppliedFiltersText;
    public string CapturedStatsTitle => PacketManager.CapturedStatsTitle;
    public double FilteredStatsProgressPercent { get; private set; }
    public bool IsFilteredStatsLoading { get; private set; }

    // ==================== CHART PROPERTIES ====================

    public ObservableCollection<ISeries> ProtocolSeries => Charts.ProtocolSeries;
    public ObservableCollection<ISeries> TrafficSeries => Charts.TrafficSeries;

    // ==================== BACKWARD-COMPATIBLE COMMANDS ====================

    // File commands
    public IAsyncRelayCommand OpenFileCommand => FileManager.OpenFileCommand;

    // Analysis commands - StartAnalysisCommand is defined in MainWindowViewModel.cs as a field
    public IRelayCommand StopCommand => Analysis.StopCommand;
    public IRelayCommand PauseResumeCommand => Analysis.PauseResumeCommand;

    // UI commands
    public IAsyncRelayCommand TakeScreenshotCommand => UIState.TakeScreenshotCommand;
    public IAsyncRelayCommand<object?> TakeFullScreenshotCommand => UIState.TakeFullScreenshotCommand;
    public IRelayCommand GoToFirstPageCommand => UIState.GoToFirstPageCommand;
    public IRelayCommand GoToPreviousPageCommand => UIState.GoToPreviousPageCommand;
    public IRelayCommand GoToNextPageCommand => UIState.GoToNextPageCommand;
    public IRelayCommand GoToLastPageCommand => UIState.GoToLastPageCommand;

    // ==================== BACKWARD-COMPATIBLE METHODS ====================

    /// <summary>
    /// Loads a capture file (delegates to FileManager)
    /// </summary>
    public Task LoadCaptureAsync(string? filePath)
    {
        return FileManager.LoadCaptureAsync(filePath);
    }

    /// <summary>
    /// Navigates to a specific page (delegates to UIState)
    /// </summary>
    public void GoToPage(int pageNumber)
    {
        UIState.GoToPage(pageNumber);
    }
}
