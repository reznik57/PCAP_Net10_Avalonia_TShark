using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading; // Required for DispatcherTimer only
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
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Main orchestrator coordinates services, tabs, components")]
public partial class MainWindowViewModel : SmartFilterableTab, IDisposable, IAsyncDisposable
{
    // ==================== COMPONENT VIEWMODELS ====================

    public MainWindowFileViewModel FileManager { get; }
    public MainWindowAnalysisViewModel Analysis { get; }
    public MainWindowUIStateViewModel UIState { get; }
    public MainWindowPacketViewModel PacketManager { get; }
    public MainWindowChartsViewModel Charts { get; }
    private readonly MainWindowDashboardViewModel _dashboardComponent;
    private readonly MainWindowStatsViewModel _statsComponent;
    private readonly MainWindowNavigationViewModel _navigationComponent;

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
    [ObservableProperty] private GeographicMapViewModel _geographicMapViewModel;
    [ObservableProperty] private FlowSummaryViewModel _flowSummaryViewModel = new();
    [ObservableProperty] private TopTalkersViewModel? _topTalkersViewModel;
    [ObservableProperty] private AnomalyViewModel? _anomalyViewModel;
    [ObservableProperty] private AnomaliesViewModel? _anomaliesViewModel;
    [ObservableProperty] private HostInventoryViewModel? _hostInventoryViewModel;

    // ==================== STATS BAR VIEWMODELS ====================

    public StatsBarControlViewModel PacketAnalysisStats { get; } = new();

    // ==================== SERVICES ====================

    private readonly IDispatcherService _dispatcher;
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
    private readonly AnalysisOrchestrator? _orchestrator;
    private readonly IAnalysisCoordinator? _analysisCoordinator;
    private readonly IPacketStatisticsCalculator _packetStatsCalculator;
    private readonly ISessionAnalysisCache _sessionCache;
    private readonly DispatcherTimer _updateTimer;
    private readonly GlobalFilterState? _globalFilterState;

    // REMOVED: Eager preload mechanism (_preloadComplete, _preloadGate) - eliminated dual-analysis paths

    // ==================== FILTER VIEWMODELS ====================

    public FilterViewModel FilterViewModel { get; }
    public PacketFilterViewModel PacketFilterViewModel { get; }
    public FilterStatisticsViewModel Statistics => PacketFilterViewModel.Statistics;

    // ==================== PROPERTIES ====================

    public bool ShowNoFileWarning => string.IsNullOrEmpty(FileManager.CurrentFile) && !Analysis.IsAnalyzing;
    public List<int> PageSizeOptions { get; } = [30, 50, 100, 200, 500, 1000];

    // Tab selection tracking (reserved for future database cache optimization)
    [ObservableProperty] private int _selectedTabIndex = 0;

    // ==================== TAB BADGE PROGRESS INDICATORS ====================
    [ObservableProperty] private string _fileManagerBadge = "";
    [ObservableProperty] private string _packetAnalysisBadge = "";
    [ObservableProperty] private string _dashboardBadge = "";
    [ObservableProperty] private string _threatsBadge = "";
    [ObservableProperty] private string _anomaliesBadge = "";
    [ObservableProperty] private string _voiceQoSBadge = "";
    [ObservableProperty] private string _countryTrafficBadge = "";

    public override string TabName => "Packet Analysis";

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

    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _filteredPackets;
    [ObservableProperty] private double _filteredPacketsPercentage;
    [ObservableProperty] private string _filteredTrafficVolume = "0 B";
    [ObservableProperty] private double _filteredTrafficPercentage;

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
            App.Services?.GetService<IDispatcherService>() ?? new AvaloniaDispatcherService(),
            App.Services?.GetService<ITSharkService>() ?? new TSharkService(NullLogger<TSharkService>.Instance),
            App.Services?.GetService<IInsecurePortDetector>() ?? new InsecurePortDetector(),
            App.Services?.GetService<IStatisticsService>(),
            App.Services?.GetService<IUnifiedAnomalyDetectionService>(),
            App.Services?.GetService<IGeoIPService>() ?? new UnifiedGeoIPService(),
            App.Services?.GetService<PacketDetailsViewModel>(),
            App.Services?.GetService<AnalysisOrchestrator>(),
            App.Services?.GetService<IReportGeneratorService>(),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
            App.Services?.GetService<IAnalysisCoordinator>(),
            sessionCache: App.Services?.GetService<ISessionAnalysisCache>() ?? new SessionAnalysisCacheService())
    {
    }
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Constructor must initialize all required services and dependencies for main application ViewModel")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Main ViewModel constructor requires sequential initialization of many interdependent services")]
    public MainWindowViewModel(
        IDispatcherService dispatcherService,
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
        IPacketStatisticsCalculator? packetStatsCalculator = null,
        ISessionAnalysisCache? sessionCache = null)
        : base(filterBuilder ?? App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService())
    {
        ArgumentNullException.ThrowIfNull(dispatcherService);
        ArgumentNullException.ThrowIfNull(tsharkService);
        ArgumentNullException.ThrowIfNull(geoIpService);
        ArgumentNullException.ThrowIfNull(statisticsService);
        _dispatcher = dispatcherService;
        _tsharkService = tsharkService;
        _insecurePortDetector = insecurePortDetector ?? new InsecurePortDetector();
        _geoIpService = geoIpService;
        _statisticsService = statisticsService;
        _anomalyService = anomalyService ?? new UnifiedAnomalyDetectionService();
        _packetStatsCalculator = packetStatsCalculator ?? App.Services?.GetService<IPacketStatisticsCalculator>() ?? new PacketStatisticsCalculator();
        _orchestrator = orchestrator;
        _analysisCoordinator = analysisCoordinator;
        _sessionCache = sessionCache ?? App.Services?.GetService<ISessionAnalysisCache>() ?? new SessionAnalysisCacheService();

        if (_orchestrator is null)
            DebugLogger.Critical("[MainWindowViewModel] AnalysisOrchestrator is NULL - Analyze button will be disabled!");

        // Initialize tab-specific filter services (isolated per tab)
        // Each tab gets its own FilterServiceCore instance for isolated filter state
        _packetAnalysisFilterService = new TabFilterService("Packet Analysis", new FilterServiceCore());
        _dashboardFilterService = new TabFilterService("Dashboard", new FilterServiceCore());
        _threatsFilterService = new TabFilterService("Security Threats", new FilterServiceCore());
        _voiceQoSFilterService = new TabFilterService("Voice/QoS", new FilterServiceCore());
        _countryTrafficFilterService = new TabFilterService("Country Traffic", new FilterServiceCore());

        FileManager = new();
        Analysis = new MainWindowAnalysisViewModel(_dispatcher, _tsharkService);
        UIState = new();
        var packetDetails = packetDetailsViewModel ?? App.Services?.GetService<PacketDetailsViewModel>();
        if (packetDetails is null)
        {

            var protocolParser = new ProtocolParser();
            var streamAnalyzer = new StreamAnalyzer();
            var deepDiveService = new ProtocolDeepDiveService();
            packetDetails = new PacketDetailsViewModel(protocolParser, streamAnalyzer, deepDiveService);
        }
        PacketManager = new MainWindowPacketViewModel(_packetAnalysisFilterService, packetDetails);

        Charts = new();

        // Initialize extracted components
        _dashboardComponent = new MainWindowDashboardViewModel(_statisticsService, _geoIpService);
        _statsComponent = new MainWindowStatsViewModel(_packetStatsCalculator);
        _navigationComponent = new MainWindowNavigationViewModel(_packetAnalysisFilterService);

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
        UIState.PageSizeChanged += OnPageSizeChanged;
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
        PacketFilterViewModel = new PacketFilterViewModel(_packetAnalysisFilterService, PacketManager.ApplyFilter);

        // Subscribe to Packet Analysis tab filter service events (only this tab triggers UI updates)
        _packetAnalysisFilterService.FilterChanged += OnFilterServiceChanged;

        // Initialize PacketAnalysisStats
        InitializePacketAnalysisStats();

        var fileAnalysisVM = App.Services?.GetService<FileAnalysisViewModel>();
        if (fileAnalysisVM is not null)
        {
            FileAnalysisViewModel = fileAnalysisVM;
            FileAnalysisViewModel.NavigateToTab = (tabIndex) => SelectedTabIndex = tabIndex;
            FileAnalysisViewModel.OnAnalysisCompleted += OnFileAnalysisCompleted;
            FileAnalysisViewModel.SetAnalysisViewModel(Analysis);
            var fileSelectionVM = App.Services?.GetService<Components.FileSelectionControlViewModel>();
            if (fileSelectionVM is null && FileAnalysisViewModel is not null)
                fileSelectionVM = new Components.FileSelectionControlViewModel(FileAnalysisViewModel);
            FileSelectionControl = fileSelectionVM;
            FileManagerViewModel = new FileManagerViewModel(FileAnalysisViewModel ?? throw new InvalidOperationException("FileAnalysisViewModel is required"));
        }

        _globalFilterState = App.Services?.GetService<Models.GlobalFilterState>();
        var anomalyFrameIndexService = App.Services?.GetService<IAnomalyFrameIndexService>();
        DashboardViewModel = new DashboardViewModel(
            _dispatcher, _statisticsService, _anomalyService,
            filterService: _dashboardFilterService,
            dashboardFilterService: null, csvExportService: null, fileDialogService: null,
            filterBuilder: null, filterPresetService: null,
            globalFilterState: _globalFilterState,
            anomalyFrameIndexService: anomalyFrameIndexService,
            navigateToTab: HandleDashboardNavigation);

        // Subscribe to GlobalFilterState for explicit Apply button clicks only
        // NOTE: Using OnFiltersApplied (not OnFilterChanged) to avoid auto-apply on chip removal
        if (_globalFilterState is not null)
        {
            _globalFilterState.OnFiltersApplied += OnGlobalFilterStateChanged;
            DebugLogger.Log("[MainWindowViewModel] Subscribed to GlobalFilterState.OnFiltersApplied");
        }

        _suricataService = new SuricataService(
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "run-suricata.sh"),
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "rules", "emerging.rules"));
        _yaraService = new YaraService(
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "run-yara.sh"),
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "rules"));

        var cacheService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
        var credentialService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Credentials.ICredentialDetectionService>();
        ThreatsViewModel = new ThreatsViewModel(_dispatcher, _insecurePortDetector, _anomalyService, credentialService, _threatsFilterService, cacheService);
        ThreatsViewModel.NavigateToPacketAnalysis = OnNavigateToPacketAnalysisFromThreat;
        VoiceQoSViewModel = new VoiceQoSViewModel(_dispatcher);
        CountryTrafficViewModel = new CountryTrafficViewModel(_dispatcher, _geoIpService, _countryTrafficFilterService);
        GeographicMapViewModel = new GeographicMapViewModel(_geoIpService, _statisticsService);

        var packetComparer = App.Services?.GetService<IPacketComparer>();
        var compareFileDialogService = App.Services?.GetService<IFileDialogService>();
        if (packetComparer is not null)
            CompareViewModel = new CompareViewModel(packetComparer, compareFileDialogService);

        var topTalkersVM = App.Services?.GetService<TopTalkersViewModel>();
        if (topTalkersVM is not null)
            TopTalkersViewModel = topTalkersVM;
        else
        {
            var csvService = App.Services?.GetService<ICsvExportService>();
            var fileDialogService = App.Services?.GetService<IFileDialogService>();
            if (csvService is not null && fileDialogService is not null)
                TopTalkersViewModel = new TopTalkersViewModel(csvService, fileDialogService);
        }

        var anomalyVM = App.Services?.GetService<AnomalyViewModel>();
        AnomalyViewModel = anomalyVM ?? new AnomalyViewModel();

        var anomaliesVM = App.Services?.GetService<AnomaliesViewModel>();
        AnomaliesViewModel = anomaliesVM;

        var hostInventoryVM = App.Services?.GetService<HostInventoryViewModel>();
        HostInventoryViewModel = hostInventoryVM ?? new HostInventoryViewModel();

        if (reportService is not null)
            ReportViewModel = new ReportViewModel(reportService);
        else
        {
            var reportGen = App.Services?.GetService<Core.Services.IReportGeneratorService>();
            ReportViewModel = reportGen is not null ? new ReportViewModel(reportGen) : null!;
        }

        _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _updateTimer.Tick += UpdateUI;
        RegisterTabsWithCoordinator();
        UIState.UpdateStatus("Please select a PCAP file to analyze", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
    }

    private void RegisterTabsWithCoordinator()
    {
        if (_analysisCoordinator is null)
        {
            DebugLogger.Log("[MainWindowViewModel] Coordinator not available - skipping tab registration");
            return;
        }

        var tabs = new List<ITabPopulationTarget>();

        if (DashboardViewModel is ITabPopulationTarget dashboard)
            tabs.Add(dashboard);
        if (ThreatsViewModel is ITabPopulationTarget threats)
            tabs.Add(threats);
        if (AnomaliesViewModel is ITabPopulationTarget anomalies)
            tabs.Add(anomalies);
        if (VoiceQoSViewModel is ITabPopulationTarget voiceQos)
            tabs.Add(voiceQos);
        if (CountryTrafficViewModel is ITabPopulationTarget countryTraffic)
            tabs.Add(countryTraffic);
        if (HostInventoryViewModel is ITabPopulationTarget hostInventory)
            tabs.Add(hostInventory);

        _analysisCoordinator.RegisterTabs(tabs.ToArray());
    }

    private void OnFileLoaded(object? sender, string filePath)
    {
        var (fileName, fileSize, expectedDataSize) = FileManager.GetFileInfo();
        UIState.UpdateStatus(
            $"File loaded: {fileName} (File: {Core.Utilities.NumberFormatter.FormatBytes(fileSize)})",
            ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80")
        );
        Analysis.ProgressMessage = $"Ready to analyze • Expected data: ~{Core.Utilities.NumberFormatter.FormatBytes(expectedDataSize)}";
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
        _sessionCache.Clear();

        UIState.UpdateStatus("No file selected", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
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

    private async Task StartAnalysisAsync()
    {
        if (string.IsNullOrEmpty(FileManager.CurrentFile))
        {
            UIState.UpdateStatus("No file selected", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
            return;
        }

        if (_orchestrator is null)
            throw new InvalidOperationException("AnalysisOrchestrator required - ensure ServiceConfiguration registers it");

        try
        {
            // Reset state
            await PacketManager.ClearPacketsAsync();
            UIState.ResetState();
            Charts.ResetCharts();
            Analysis.ResetAnalysis();

            if (DashboardViewModel is not null)
            {
                DashboardViewModel.ResetStatistics();
            }

            if (AnomaliesViewModel is not null)
            {
                AnomaliesViewModel.Clear();
            }

            _sessionCache.Clear();
            await RunPreloadAnalysisAsync(FileManager.CurrentFile);
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[MainWindowViewModel] Analysis error: {ex.Message}");
            UIState.UpdateStatus($"Error: {ex.Message}", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
            Analysis.IsAnalyzing = false;
            UIState.SetAnalysisStatus(false);
            throw;
        }
    }

    private async Task RunPreloadAnalysisAsync(string pcapPath)
    {
        try
        {
            _sessionCache.Clear();
            Analysis.IsAnalyzing = true;
            UIState.CanAccessAnalysisTabs = false;
            UIState.SetAnalysisStatus(true);
            FileAnalysisViewModel?.InitializeProgressReporter();

            var progress = new Progress<AnalysisProgress>(p =>
            {
                Analysis.AnalysisProgress = p.Percent;
                Analysis.ProgressMessage = $"{p.Phase}: {p.Detail}";
                Analysis.UpdateRealtimeMetrics(p);
                FileAnalysisViewModel?.ProgressReporter?.Report(p);
                FileAnalysisViewModel?.SyncStageFromOrchestrator(p.Phase, p.Percent, p.Detail);
            });

            var startTime = DateTime.Now;
            var result = await _orchestrator!.AnalyzeFileAsync(pcapPath, progress, Analysis.CurrentCancellationToken);
            var elapsed = (DateTime.Now - startTime).TotalSeconds;

            TotalPackets = result.TotalPackets;
            Analysis.SetOrchestratorCompletionPercent(Analysis.AnalysisProgress);
            await PopulateViewModelsFromCacheAsync(result);
            FileAnalysisViewModel?.UpdateQuickStatsFromResult(result);
            Analysis.IsAnalyzing = false;
            UIState.CanAccessAnalysisTabs = true;
            UIState.SetAnalysisStatus(false);
            UIState.UpdateStatus($"Analysis complete: {result.TotalPackets:N0} packets ({elapsed:F1}s)", ThemeColorHelper.GetColorHex("ColorSuccess", "#4CAF50"));
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[ERROR] Preload analysis failed: {ex.Message}");
            UIState.UpdateStatus($"Analysis error: {ex.Message}", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
            Analysis.IsAnalyzing = false;
            UIState.SetAnalysisStatus(false);
            throw;
        }
    }

    private async Task PopulateViewModelsFromCacheAsync(AnalysisResult result)
    {
        UIState.HasResults = true;
        PacketFilterViewModel.IsAnalyzing = false;
        PacketFilterViewModel.CanApplyFilters = true;

        if (PacketManager is not null)
        {
            await PacketManager.PopulateFullPacketListAsync(result.Statistics);
            PacketManager.ApplyFilter(new PacketFilter());
            var filteredCount = PacketManager.GetFilteredPackets().Count;
            UIState.UpdatePaginationInfo(filteredCount);
            UIState.GoToPage(1);
            UpdatePacketAnalysisStats();
        }

        var packetStats = _tsharkService.GetStatistics();
        Charts.UpdateCharts(packetStats);
        if (PacketManager is not null)
        {
            var filteredPackets = PacketManager.GetFilteredPackets();
            Charts.UpdatePacketsOverTimeChart(filteredPackets);
        }

        if (_analysisCoordinator is not null)
            await _analysisCoordinator.PopulateTabsAsync(result);
        else
            await PopulateTabsLegacyAsync(result);
    }

    private async Task PopulateTabsLegacyAsync(AnalysisResult result)
    {
        // Dashboard
        if (DashboardViewModel is not null)
        {
            DashboardViewModel.SetStatisticsOverride(result.Statistics);
            await DashboardViewModel.UpdateStatisticsAsync(result.AllPackets);
        }

        // Threats
        if (ThreatsViewModel is not null)
        {
            await ThreatsViewModel.SetFromCacheAsync(result.Threats, result.AllPackets);
        }

        // VoiceQoS
        if (VoiceQoSViewModel is not null && result.VoiceQoSData is not null)
        {
            await VoiceQoSViewModel.SetFromCacheAsync(result.VoiceQoSData, result.VoiceQoSTimeSeries, result.AllPackets);
        }

        // Country Traffic
        if (CountryTrafficViewModel is not null)
        {
            await CountryTrafficViewModel.UpdateStatistics(result.Statistics);
        }
    }

    // NOTE: OnFileAnalysisCompleted, CalculateFileAnalysisQuickStats, OnAnalysisCompleted,
    // ProcessAnalysisCompletionAsync, FinalizeAnalysisAsync, RunExternalToolsAsync
    // moved to MainWindowViewModel.AnalysisCompletion.cs

    private void OnAnalysisStopped(object? sender, EventArgs e)
    {
        _updateTimer.Stop();
        UIState.UpdateStatus($"Analysis stopped. Processed {Analysis.PacketCount:N0} packets", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
        UIState.CanAccessAnalysisTabs = FileManager.HasFile;
        PacketFilterViewModel.IsAnalyzing = false;
        PacketFilterViewModel.CanApplyFilters = true;

        // Update dashboard with final data
        _ = UpdateDashboardAsync();
    }

    private void OnAnalysisFailed(object? sender, Exception ex)
    {
        _updateTimer.Stop();
        UIState.UpdateStatus($"Error: {ex.Message}", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
        UIState.CanAccessAnalysisTabs = FileManager.HasFile;
        PacketFilterViewModel.IsAnalyzing = false;
        PacketFilterViewModel.CanApplyFilters = true;
    }

    private void OnPacketBatchProcessed(object? sender, (long packets, long bytes, NetworkStatistics? stats) data)
    {
        // Real-time updates during analysis (optional - already handled by Analysis component)
    }

    private void OnAnalysisStatusChanged(object? sender, string status)
    {
        UIState.UpdateStatus(status, UIState.StatusColor);
    }

    [RelayCommand]
    private async Task UpdateDashboardAsync()
    {
        await UpdateDashboardAsync(forceUpdate: false);
    }

    private async Task UpdateDashboardAsync(bool forceUpdate = false)
    {
        await _dashboardComponent.UpdateDashboardAsync(
            DashboardViewModel, Analysis, PacketManager,
            _packetAnalysisFilterService, _dashboardFilterService, forceUpdate);

        // Update supplementary views after dashboard update
        var enrichedStats = DashboardViewModel?.CurrentStatistics ?? Analysis.FinalStatistics;
        if (enrichedStats is not null)
        {
            var packets = (_packetAnalysisFilterService?.IsFilterActive == true)
                ? _packetAnalysisFilterService.GetFilteredPackets(PacketManager.CachedDashboardPackets ?? new List<PacketInfo>()).ToList()
                : PacketManager.CachedDashboardPackets ?? new List<PacketInfo>();

            await UpdateSupplementaryViewsAsync(enrichedStats, packets);
        }
    }

    private async Task UpdateSupplementaryViewsAsync(NetworkStatistics statistics, IReadOnlyList<PacketInfo> sample)
    {
        try
        {
            // Only update geographic views here (Country, Map)
            // ThreatsViewModel and VoiceQoSViewModel have dedicated phases

            if (CountryTrafficViewModel is not null)
            {
                await _dispatcher.InvokeAsync(() => CountryTrafficViewModel.SetPackets(sample));
                await CountryTrafficViewModel.UpdateStatistics(statistics);
            }

            if (GeographicMapViewModel is not null)
            {
                await _dispatcher.InvokeAsync(() => GeographicMapViewModel.SetPackets(sample));
                await GeographicMapViewModel.UpdateStatistics(statistics);
            }

            if (ReportViewModel is not null && ThreatsViewModel is not null)
            {
                await ReportViewModel.UpdateData(statistics, ThreatsViewModel.GetCurrentThreats());
            }

            if (FlowSummaryViewModel is not null && statistics.TopConversations is not null)
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
                await _dispatcher.InvokeAsync(() => FlowSummaryViewModel.LoadFlows(flows));
            }

            if (TopTalkersViewModel is not null)
            {
                // Convert to List as TopTalkersViewModel expects List<PacketInfo>
                await _dispatcher.InvokeAsync(async () => await TopTalkersViewModel.UpdateData(statistics, sample.ToList()));
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Supplementary view update failed: {ex.Message}");
        }
    }

    private void InitializePacketAnalysisStats()
    {
        _statsComponent.InitializePacketAnalysisStats(PacketAnalysisStats);
    }

    private void UpdatePacketAnalysisStats()
    {
        _statsComponent.UpdatePacketAnalysisStats(PacketAnalysisStats, PacketManager);
    }

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        PacketManager.ApplyFilter(e.Filter);
    }

    /// <summary>
    /// Handles GlobalFilterState changes - propagates filters to Packet Analysis tab.
    /// Dashboard handles its own via ApplyGlobalFilters() called from View code-behind.
    /// </summary>
    private void OnGlobalFilterStateChanged()
    {
        // Fire-and-forget with discard to avoid async void
        _ = HandleGlobalFilterStateChangedAsync();
    }

    /// <summary>
    /// Async implementation of global filter state change handling.
    /// Separated from event handler to ensure proper Task-based async pattern.
    /// </summary>
    private async Task HandleGlobalFilterStateChangedAsync()
    {
        if (_globalFilterState is null) return;

        DebugLogger.Log("[MainWindowViewModel] GlobalFilterState changed - applying to Packet Analysis tab");

        // Show progress bar during filtering
        _globalFilterState.IsFilteringInProgress = true;
        _globalFilterState.FilterProgress = 0.0;

        try
        {
            // Build PacketFilter from GlobalFilterState using the same logic as DashboardViewModel
            var filter = BuildPacketFilterFromGlobalState();
            _globalFilterState.FilterProgress = 0.3;

            // Apply to Packet Analysis tab
            PacketManager.ApplyFilter(filter);
            _globalFilterState.FilterProgress = 0.7;

            // Ensure minimum visibility of progress bar for UX feedback
            await Task.Delay(300);
            _globalFilterState.FilterProgress = 1.0;

            DebugLogger.Log($"[MainWindowViewModel] Applied global filters to PacketManager (IsEmpty={filter.IsEmpty})");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Error in HandleGlobalFilterStateChangedAsync: {ex.Message}");
        }
        finally
        {
            // Give UI a moment to show 100% before hiding
            try { await Task.Delay(100); } catch { /* ignore */ }
            _globalFilterState.IsFilteringInProgress = false;
        }
    }

    /// <summary>
    /// Builds a PacketFilter from GlobalFilterState groups.
    /// Simplified version of DashboardViewModel.ApplyGlobalFilters logic.
    /// </summary>
    private PacketFilter BuildPacketFilterFromGlobalState()
    {
        if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
            return new PacketFilter(); // Empty filter - show all

        var includeFilters = new List<PacketFilter>();
        var excludeFilters = new List<PacketFilter>();

        // Process Include groups
        foreach (var group in _globalFilterState.IncludeGroups)
        {
            var groupFilter = BuildFilterFromGroup(group);
            if (groupFilter is not null)
                includeFilters.Add(groupFilter);
        }

        // Process Exclude groups
        foreach (var group in _globalFilterState.ExcludeGroups)
        {
            var groupFilter = BuildFilterFromGroup(group);
            if (groupFilter is not null)
                excludeFilters.Add(groupFilter);
        }

        // Combine include filters with OR
        PacketFilter? includeFilter = includeFilters.Count switch
        {
            0 => null,
            1 => includeFilters[0],
            _ => new PacketFilter
            {
                CombinedFilters = includeFilters,
                CombineMode = FilterCombineMode.Or,
                Description = string.Join(" OR ", includeFilters.Select(f => f.Description))
            }
        };

        // Combine exclude filters with OR, then invert
        PacketFilter? excludeFilter = null;
        if (excludeFilters.Count > 0)
        {
            var combinedExclude = excludeFilters.Count == 1 ? excludeFilters[0] : new PacketFilter
            {
                CombinedFilters = excludeFilters,
                CombineMode = FilterCombineMode.Or,
                Description = string.Join(" OR ", excludeFilters.Select(f => f.Description))
            };
            // Invert: packets must NOT match exclude criteria
            excludeFilter = new PacketFilter
            {
                CustomPredicate = p => !combinedExclude.MatchesPacket(p),
                Description = $"NOT({combinedExclude.Description})"
            };
        }

        // Combine: INCLUDE AND NOT(EXCLUDE)
        var finalFilters = new List<PacketFilter>();
        if (includeFilter is not null) finalFilters.Add(includeFilter);
        if (excludeFilter is not null) finalFilters.Add(excludeFilter);

        if (finalFilters.Count == 0)
            return new PacketFilter();
        if (finalFilters.Count == 1)
            return finalFilters[0];

        return new PacketFilter
        {
            CombinedFilters = finalFilters,
            CombineMode = FilterCombineMode.And,
            Description = string.Join(" AND ", finalFilters.Select(f => f.Description))
        };
    }

    /// <summary>
    /// Builds a PacketFilter from a FilterGroup (all criteria AND'd together).
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Filter builder with multiple criteria types")]
    private PacketFilter? BuildFilterFromGroup(FilterGroup group)
    {
        var groupFilters = new List<PacketFilter>();

        AddIpFilters(groupFilters, group);
        AddPortFilter(groupFilters, group);
        AddProtocolFilter(groupFilters, group);
        AddDirectionFilter(groupFilters, group);
        AddQuickFilters(groupFilters, group);

        return CombineGroupFilters(groupFilters, group.DisplayLabel);
    }

    private static void AddIpFilters(List<PacketFilter> filters, FilterGroup group)
    {
        if (!string.IsNullOrWhiteSpace(group.SourceIP))
        {
            var srcIp = group.SourceIP;
            filters.Add(new PacketFilter
            {
                CustomPredicate = p => Core.Services.NetworkHelper.MatchesIpPattern(p.SourceIP, srcIp),
                Description = $"Src IP: {srcIp}"
            });
        }

        if (!string.IsNullOrWhiteSpace(group.DestinationIP))
        {
            var destIp = group.DestinationIP;
            filters.Add(new PacketFilter
            {
                CustomPredicate = p => Core.Services.NetworkHelper.MatchesIpPattern(p.DestinationIP, destIp),
                Description = $"Dest IP: {destIp}"
            });
        }
    }

    private static void AddPortFilter(List<PacketFilter> filters, FilterGroup group)
    {
        if (!string.IsNullOrWhiteSpace(group.PortRange) && TryParsePortOrRange(group.PortRange, out var portPredicate))
        {
            filters.Add(new PacketFilter
            {
                CustomPredicate = portPredicate,
                Description = $"Port: {group.PortRange}"
            });
        }
    }

    private static void AddProtocolFilter(List<PacketFilter> filters, FilterGroup group)
    {
        if (string.IsNullOrWhiteSpace(group.Protocol)) return;

        var protocols = group.Protocol.Split(',', StringSplitOptions.RemoveEmptyEntries);
        var protocolFilters = protocols.Select(proto =>
        {
            var p = proto.Trim();
            return new PacketFilter
            {
                CustomPredicate = pkt => pkt.Protocol.ToString().Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                         (pkt.L7Protocol?.Equals(p, StringComparison.OrdinalIgnoreCase) ?? false),
                Description = $"Protocol: {p}"
            };
        }).ToList();

        if (protocolFilters.Count == 1)
            filters.Add(protocolFilters[0]);
        else if (protocolFilters.Count > 1)
            filters.Add(new PacketFilter
            {
                CombinedFilters = protocolFilters,
                CombineMode = FilterCombineMode.Or,
                Description = $"Protocol: ({string.Join("|", protocols)})"
            });
    }

    private static void AddDirectionFilter(List<PacketFilter> filters, FilterGroup group)
    {
        if (group.Directions?.Count == 0) return;
        if (group.Directions is null) return;

        var directions = group.Directions;
        filters.Add(new PacketFilter
        {
            CustomPredicate = p => MatchesDirection(p, directions),
            Description = $"Direction: {string.Join("|", directions)}"
        });
    }

    private static bool MatchesDirection(PacketInfo p, List<string> directions)
    {
        var srcPrivate = NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP);
        var dstPrivate = NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP);

        foreach (var dir in directions)
        {
            var match = dir.ToUpperInvariant() switch
            {
                "INBOUND" => !srcPrivate && dstPrivate,
                "OUTBOUND" => srcPrivate && !dstPrivate,
                "INTERNAL" => srcPrivate && dstPrivate,
                _ => false
            };
            if (match) return true;
        }
        return false;
    }

    private static void AddQuickFilters(List<PacketFilter> filters, FilterGroup group)
    {
        if (group.QuickFilters?.Count == 0) return;
        if (group.QuickFilters is null) return;

        // Build individual QuickFilter predicates
        var quickFilterList = new List<PacketFilter>();
        foreach (var qf in group.QuickFilters)
        {
            var pred = BuildQuickFilterPredicate(qf);
            if (pred is not null)
            {
                quickFilterList.Add(new PacketFilter
                {
                    CustomPredicate = pred,
                    Description = qf
                });
            }
        }

        if (quickFilterList.Count == 0) return;

        // ✅ FIX: Combine QuickFilters with OR logic (any can match)
        // User selecting [SYN] + [RST] expects: "show SYN OR RST packets"
        // Previously: each added separately → AND'd → 0 packets!
        if (quickFilterList.Count == 1)
        {
            filters.Add(quickFilterList[0]);
        }
        else
        {
            filters.Add(new PacketFilter
            {
                CombinedFilters = quickFilterList,
                CombineMode = FilterCombineMode.Or,
                Description = $"QuickFilter: ({string.Join("|", quickFilterList.Select(f => f.Description))})"
            });
        }
    }

    private static PacketFilter? CombineGroupFilters(List<PacketFilter> groupFilters, string? displayLabel)
    {
        if (groupFilters.Count == 0)
            return null;

        if (groupFilters.Count == 1)
        {
            groupFilters[0].Description = displayLabel ?? groupFilters[0].Description;
            return groupFilters[0];
        }

        return new PacketFilter
        {
            CombinedFilters = groupFilters,
            CombineMode = FilterCombineMode.And,
            Description = displayLabel ?? string.Join(" AND ", groupFilters.Select(f => f.Description))
        };
    }

    private static bool TryParsePortOrRange(string portString, out Func<PacketInfo, bool> predicate)
    {
        predicate = null!;
        if (string.IsNullOrWhiteSpace(portString))
            return false;

        if (int.TryParse(portString, out var singlePort))
        {
            predicate = p => p.SourcePort == singlePort || p.DestinationPort == singlePort;
            return true;
        }

        if (portString.Contains('-', StringComparison.Ordinal))
        {
            var parts = portString.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out var start) && int.TryParse(parts[1], out var end))
            {
                predicate = p => (p.SourcePort >= start && p.SourcePort <= end) ||
                                (p.DestinationPort >= start && p.DestinationPort <= end);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Builds predicate for QuickFilter strings.
    /// Delegates to SmartFilterBuilderService.GetQuickFilterPredicate for consistency.
    /// This ensures all quick filters work identically across all tabs.
    /// </summary>
    private static Func<PacketInfo, bool>? BuildQuickFilterPredicate(string quickFilter)
    {
        // Delegate to the shared service - SINGLE SOURCE OF TRUTH
        // Try exact case first (e.g., "SYN"), then uppercase (e.g., "INSECURE")
        return Services.SmartFilterBuilderService.GetQuickFilterPredicate(quickFilter)
            ?? Services.SmartFilterBuilderService.GetQuickFilterPredicate(quickFilter.ToUpperInvariant());
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
        PacketFilterViewModel.UpdateStatistics(totalCount, filteredCount);

        // Update PacketAnalysisStats bar
        UpdatePacketAnalysisStats();

        // Update Packets Over Time chart with filtered packets
        var filteredPackets = PacketManager.GetFilteredPackets();
        Charts.UpdatePacketsOverTimeChart(filteredPackets);
    }

    private void OnPageChanged(object? sender, int pageNumber)
    {
        PacketManager.UpdatePageDisplay(pageNumber, UIState.PageSize);
    }

    private void OnPageSizeChanged(object? sender, int newPageSize)
    {
        // Recalculate pagination with new page size
        var filteredPackets = PacketManager.GetFilteredPackets();
        UIState.UpdatePaginationInfo(filteredPackets.Count);
        PacketManager.UpdatePageDisplay(1, newPageSize);
    }

    private void OnGoToPacketRequested(object? sender, uint frameNumber)
    {
        var filteredPackets = PacketManager.GetFilteredPackets();
        var (pageNumber, packetIndex) = _navigationComponent.FindPacketPage(frameNumber, filteredPackets, UIState.PageSize);

        if (packetIndex < 0)
        {
            UIState.UpdateStatus($"Packet #{frameNumber:N0} not found in current view", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
            return;
        }

        UIState.GoToPage(pageNumber);
        var packet = filteredPackets[packetIndex];
        _ = PacketManager.SelectPacketAsync(packet);
        UIState.UpdateStatus($"Navigated to packet #{frameNumber:N0} (page {pageNumber})", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
    }

    private void OnSearchStreamRequested(object? sender, string searchPattern)
    {
        var matchCount = _navigationComponent.ApplyStreamFilter(searchPattern, PacketManager);

        if (string.IsNullOrWhiteSpace(searchPattern))
        {
            UIState.StreamSearchStatus = "";
            UIState.UpdateStatus("Stream filter cleared", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        }
        else if (matchCount == 0)
        {
            UIState.StreamSearchStatus = "No matches";
            UIState.UpdateStatus($"No packets found matching '{searchPattern}'", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
        }
        else
        {
            UIState.StreamSearchStatus = $"{matchCount:N0} packets";
            UIState.UpdateStatus($"Filtered to {matchCount:N0} packets matching '{searchPattern}'", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
            UIState.GoToPage(1);
            PacketManager.UpdatePageDisplay(1, UIState.PageSize);
        }
    }

    private void OnSearchByStreamFromDetails(object? sender, string searchPattern)
    {
        UIState.SearchStreamText = searchPattern;
        OnSearchStreamRequested(this, searchPattern);
    }

    private void OnNavigateToPacketFromDetails(object? sender, uint frameNumber)
    {
        OnGoToPacketRequested(this, frameNumber);
    }

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
        PacketFilterViewModel.ClearFilterCommand.Execute(null);

        UIState.UpdateStatus(
            string.IsNullOrEmpty(FileManager.CurrentFile)
                ? "Select or drop a PCAP file to analyze"
                : "Capture loaded. Use 'Analyze' to re-run if needed.",
            ThemeColorHelper.GetColorHex("AccentBlue", "#4A9FFF")
        );

        if (FileManager.HasFile && System.IO.File.Exists(FileManager.CurrentFile))
        {
            FileManager.CanAnalyze = true;
        }
    }

    private void UpdateUI(object? sender, EventArgs e)
    {
        if (!Analysis.IsAnalyzing && !Analysis.IsAnalysisComplete) return;

        var stats = _tsharkService.GetStatistics();

        if (!Analysis.IsAnalyzing && Analysis.PacketCount > 0)
        {
            Charts.UpdateCharts(stats);
        }
    }

    private void HandleDashboardNavigation(string navigationTarget)
    {
        var tabIndex = _navigationComponent.HandleDashboardNavigation(navigationTarget);
        if (tabIndex.HasValue)
        {
            SelectedTabIndex = tabIndex.Value;
        }
    }

    private void OnNavigateToPacketAnalysisFromThreat(List<uint> frameNumbers, string context)
    {
        _navigationComponent.NavigateToPacketAnalysisFromThreat(frameNumbers, context);
        SelectedTabIndex = 1; // Navigate to Packet Analysis tab
        UIState.UpdateStatus($"Showing {frameNumbers.Count} packets for: {context}", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
    }

    private void OnFileManagerPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        OnPropertyChanged(e.PropertyName);
        if (e.PropertyName == nameof(FileManager.CanAnalyze) ||
            e.PropertyName == nameof(FileManager.CurrentFile) ||
            e.PropertyName == nameof(FileManager.HasFile))
            _startAnalysisCommand?.NotifyCanExecuteChanged();
    }

    private void OnAnalysisPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        OnPropertyChanged(e.PropertyName);
        if (e.PropertyName == nameof(Analysis.IsAnalyzing))
            _startAnalysisCommand?.NotifyCanExecuteChanged();
    }

    private void OnUIStatePropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        OnPropertyChanged(e.PropertyName);
    }

    private void OnPacketManagerPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        OnPropertyChanged(e.PropertyName);
    }

    private void OnChartsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        OnPropertyChanged(e.PropertyName);
    }

    protected override void CopyFiltersToDashboard()
    {
        if (DashboardViewModel is not null)
        {
            _dashboardFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Dashboard", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        }
    }

    protected override void CopyFiltersToThreats()
    {
        if (ThreatsViewModel is not null)
        {
            _threatsFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Security Threats", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        }
    }

    protected override void CopyFiltersToVoiceQoS()
    {
        if (VoiceQoSViewModel is not null)
        {
            _voiceQoSFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Voice/QoS", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        }
    }

    protected override void CopyFiltersToCountryTraffic()
    {
        if (CountryTrafficViewModel is not null)
        {
            _countryTrafficFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Country Traffic", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        }
    }

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
            if (PacketManager is not null)
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

    public void Dispose()
    {
        try
        {
            DebugLogger.Log("[MainWindowViewModel] Disposing synchronously...");

            _updateTimer?.Stop();
            _tsharkService?.Dispose();
            Analysis?.Dispose();
            _dashboardComponent?.Dispose();

            // Dispose PacketManager (which owns PacketDetailsViewModel with stream cache)
            PacketManager?.DisposeAsync().AsTask().GetAwaiter().GetResult();

            if (DashboardViewModel is IDisposable disposableDashboard)
                disposableDashboard.Dispose();

            DebugLogger.Log("[MainWindowViewModel] Disposed synchronously (aggressive cleanup)");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Error during synchronous disposal: {ex.Message}");
        }
    }

    public string? CurrentFile => FileManager.CurrentFile;
    public bool HasFile => FileManager.HasFile;
    public bool CanAnalyze => FileManager.CanAnalyze;
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
    public ObservableCollection<ISeries> ProtocolSeries => Charts.ProtocolSeries;
    public ObservableCollection<ISeries> TrafficSeries => Charts.TrafficSeries;
    public IAsyncRelayCommand OpenFileCommand => FileManager.OpenFileCommand;
    public IRelayCommand StopCommand => Analysis.StopCommand;
    public IRelayCommand PauseResumeCommand => Analysis.PauseResumeCommand;
    public IAsyncRelayCommand TakeScreenshotCommand => UIState.TakeScreenshotCommand;
    public IAsyncRelayCommand<object?> TakeFullScreenshotCommand => UIState.TakeFullScreenshotCommand;
    public IRelayCommand GoToFirstPageCommand => UIState.GoToFirstPageCommand;
    public IRelayCommand GoToPreviousPageCommand => UIState.GoToPreviousPageCommand;
    public IRelayCommand GoToNextPageCommand => UIState.GoToNextPageCommand;
    public IRelayCommand GoToLastPageCommand => UIState.GoToLastPageCommand;
    public Task LoadCaptureAsync(string? filePath) => FileManager.LoadCaptureAsync(filePath);
    public void GoToPage(int pageNumber) => UIState.GoToPage(pageNumber);
}
