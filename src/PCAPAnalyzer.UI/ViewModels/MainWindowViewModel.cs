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
    [ObservableProperty] private EnhancedMapViewModel _enhancedMapViewModel;
    [ObservableProperty] private FlowSummaryViewModel _flowSummaryViewModel = new();
    [ObservableProperty] private TopTalkersViewModel? _topTalkersViewModel;
    [ObservableProperty] private AnomalyViewModel? _anomalyViewModel;
    [ObservableProperty] private AnomaliesViewModel? _anomaliesViewModel;
    [ObservableProperty] private HostInventoryViewModel? _hostInventoryViewModel;

    // ==================== STATS BAR VIEWMODELS ====================

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
    private readonly AnalysisOrchestrator? _orchestrator;
    private readonly IAnalysisCoordinator? _analysisCoordinator;
    private readonly IPacketStatisticsCalculator _packetStatsCalculator;
    private readonly ISessionAnalysisCache _sessionCache;
    private readonly DispatcherTimer _updateTimer;

    // REMOVED: Eager preload mechanism (_preloadComplete, _preloadGate) - eliminated dual-analysis paths

    // ==================== FILTER VIEWMODELS ====================

    public FilterViewModel FilterViewModel { get; }
    public EnhancedFilterViewModel EnhancedFilterViewModel { get; }
    public FilterStatisticsViewModel Statistics => EnhancedFilterViewModel.Statistics;

    // ==================== PROPERTIES ====================

    public bool ShowNoFileWarning => string.IsNullOrEmpty(FileManager.CurrentFile) && !Analysis.IsAnalyzing;
    public List<int> PageSizeOptions { get; } = new() { 25, 50, 100, 200, 500, 1000 };

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
        _tsharkService = tsharkService ?? throw new ArgumentNullException(nameof(tsharkService));
        _insecurePortDetector = insecurePortDetector ?? new InsecurePortDetector();
        _geoIpService = geoIpService ?? throw new ArgumentNullException(nameof(geoIpService), "GeoIPService must be provided via DI");
        _statisticsService = statisticsService ?? throw new ArgumentNullException(nameof(statisticsService), "StatisticsService must be provided via DI");
        _anomalyService = anomalyService ?? new UnifiedAnomalyDetectionService();
        _packetStatsCalculator = packetStatsCalculator ?? App.Services?.GetService<IPacketStatisticsCalculator>() ?? new PacketStatisticsCalculator();
        _orchestrator = orchestrator;
        _analysisCoordinator = analysisCoordinator;
        _sessionCache = sessionCache ?? App.Services?.GetService<ISessionAnalysisCache>() ?? new SessionAnalysisCacheService();

        if (_orchestrator == null)
            DebugLogger.Critical("[MainWindowViewModel] AnalysisOrchestrator is NULL - Analyze button will be disabled!");

        // Initialize tab-specific filter services (isolated per tab)
        // Each tab gets its own FilterServiceCore instance for isolated filter state
        _packetAnalysisFilterService = new TabFilterService("Packet Analysis", new FilterServiceCore());
        _dashboardFilterService = new TabFilterService("Dashboard", new FilterServiceCore());
        _threatsFilterService = new TabFilterService("Security Threats", new FilterServiceCore());
        _voiceQoSFilterService = new TabFilterService("Voice/QoS", new FilterServiceCore());
        _countryTrafficFilterService = new TabFilterService("Country Traffic", new FilterServiceCore());

        FileManager = new MainWindowFileViewModel();
        Analysis = new MainWindowAnalysisViewModel(_tsharkService);
        UIState = new MainWindowUIStateViewModel();
        var packetDetails = packetDetailsViewModel ?? App.Services?.GetService<PacketDetailsViewModel>();
        if (packetDetails == null)
        {

            var protocolParser = new ProtocolParser();
            var hexFormatter = new HexFormatter();
            var streamAnalyzer = new StreamAnalyzer();
            var hexDataService = new PCAPAnalyzer.Core.Services.HexDataService(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<PCAPAnalyzer.Core.Services.HexDataService>.Instance);
            var deepDiveService = new ProtocolDeepDiveService();
            packetDetails = new PacketDetailsViewModel(protocolParser, hexFormatter, streamAnalyzer, hexDataService, deepDiveService);
        }
        PacketManager = new MainWindowPacketViewModel(_packetAnalysisFilterService, packetDetails);

        Charts = new MainWindowChartsViewModel();

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

        var fileAnalysisVM = App.Services?.GetService<FileAnalysisViewModel>();
        if (fileAnalysisVM != null)
        {
            FileAnalysisViewModel = fileAnalysisVM;
            FileAnalysisViewModel.NavigateToTab = (tabIndex) => SelectedTabIndex = tabIndex;
            FileAnalysisViewModel.OnAnalysisCompleted += OnFileAnalysisCompleted;
            FileAnalysisViewModel.SetAnalysisViewModel(Analysis);
            var fileSelectionVM = App.Services?.GetService<Components.FileSelectionControlViewModel>();
            if (fileSelectionVM == null && FileAnalysisViewModel != null)
                fileSelectionVM = new Components.FileSelectionControlViewModel(FileAnalysisViewModel);
            FileSelectionControl = fileSelectionVM;
            FileManagerViewModel = new FileManagerViewModel(FileAnalysisViewModel ?? throw new InvalidOperationException("FileAnalysisViewModel is required"));
        }

        var globalFilterState = App.Services?.GetService<Models.GlobalFilterState>();
        var anomalyFrameIndexService = App.Services?.GetService<IAnomalyFrameIndexService>();
        DashboardViewModel = new DashboardViewModel(
            _statisticsService, _anomalyService,
            filterService: _dashboardFilterService,
            dashboardFilterService: null, csvExportService: null, fileDialogService: null,
            filterBuilder: null, filterPresetService: null,
            globalFilterState: globalFilterState,
            anomalyFrameIndexService: anomalyFrameIndexService,
            navigateToTab: HandleDashboardNavigation);

        _suricataService = new SuricataService(
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "run-suricata.sh"),
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "suricata", "rules", "emerging.rules"));
        _yaraService = new YaraService(
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "run-yara.sh"),
            System.IO.Path.Combine(Environment.CurrentDirectory, "tools", "yara", "rules"));

        var cacheService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
        var credentialService = App.Services?.GetService<PCAPAnalyzer.Core.Services.Credentials.ICredentialDetectionService>();
        ThreatsViewModel = new ThreatsViewModel(_insecurePortDetector, _anomalyService, credentialService, _threatsFilterService, cacheService);
        ThreatsViewModel.NavigateToPacketAnalysis = OnNavigateToPacketAnalysisFromThreat;
        VoiceQoSViewModel = new VoiceQoSViewModel();
        CountryTrafficViewModel = new CountryTrafficViewModel(_geoIpService, _countryTrafficFilterService);
        EnhancedMapViewModel = new EnhancedMapViewModel(_geoIpService, _statisticsService);

        var packetComparer = App.Services?.GetService<IPacketComparer>();
        var compareFileDialogService = App.Services?.GetService<IFileDialogService>();
        if (packetComparer != null)
            CompareViewModel = new CompareViewModel(packetComparer, compareFileDialogService);

        var topTalkersVM = App.Services?.GetService<TopTalkersViewModel>();
        if (topTalkersVM != null)
            TopTalkersViewModel = topTalkersVM;
        else
        {
            var csvService = App.Services?.GetService<ICsvExportService>();
            var fileDialogService = App.Services?.GetService<IFileDialogService>();
            if (csvService != null && fileDialogService != null)
                TopTalkersViewModel = new TopTalkersViewModel(csvService, fileDialogService);
        }

        var anomalyVM = App.Services?.GetService<AnomalyViewModel>();
        AnomalyViewModel = anomalyVM ?? new AnomalyViewModel();

        var anomaliesVM = App.Services?.GetService<AnomaliesViewModel>();
        AnomaliesViewModel = anomaliesVM;

        var hostInventoryVM = App.Services?.GetService<HostInventoryViewModel>();
        HostInventoryViewModel = hostInventoryVM ?? new HostInventoryViewModel();

        if (reportService != null)
            ReportViewModel = new ReportViewModel(reportService);
        else
        {
            var reportGen = App.Services?.GetService<Core.Services.IReportGeneratorService>();
            ReportViewModel = reportGen != null ? new ReportViewModel(reportGen) : null!;
        }

        _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _updateTimer.Tick += UpdateUI;
        RegisterTabsWithCoordinator();
        UIState.UpdateStatus("Please select a PCAP file to analyze", "#4ADE80");
    }

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
        _sessionCache.Clear();

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

    private async Task StartAnalysisAsync()
    {
        if (string.IsNullOrEmpty(FileManager.CurrentFile))
        {
            UIState.UpdateStatus("No file selected", "#FF5252");
            return;
        }

        if (_orchestrator == null)
            throw new InvalidOperationException("AnalysisOrchestrator required - ensure ServiceConfiguration registers it");

        try
        {
            // Reset state
            await PacketManager.ClearPacketsAsync();
            UIState.ResetState();
            Charts.ResetCharts();
            Analysis.ResetAnalysis();

            if (DashboardViewModel != null)
            {
                DashboardViewModel.ResetStatistics();
            }

            if (AnomaliesViewModel != null)
            {
                AnomaliesViewModel.Clear();
            }

            _sessionCache.Clear();
            await RunPreloadAnalysisAsync(FileManager.CurrentFile);
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[MainWindowViewModel] Analysis error: {ex.Message}");
            UIState.UpdateStatus($"Error: {ex.Message}", "#FF5252");
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
            UIState.UpdateStatus($"Analysis complete: {result.TotalPackets:N0} packets ({elapsed:F1}s)", "#4CAF50");
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[ERROR] Preload analysis failed: {ex.Message}");
            UIState.UpdateStatus($"Analysis error: {ex.Message}", "#FF5252");
            Analysis.IsAnalyzing = false;
            UIState.SetAnalysisStatus(false);
            throw;
        }
    }

    private async Task PopulateViewModelsFromCacheAsync(AnalysisResult result)
    {
        UIState.HasResults = true;
        EnhancedFilterViewModel.IsAnalyzing = false;
        EnhancedFilterViewModel.CanApplyFilters = true;

        if (PacketManager != null)
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
        if (PacketManager != null)
        {
            var filteredPackets = PacketManager.GetFilteredPackets();
            Charts.UpdatePacketsOverTimeChart(filteredPackets);
        }

        if (_analysisCoordinator != null)
            await _analysisCoordinator.PopulateTabsAsync(result);
        else
            await PopulateTabsLegacyAsync(result);
    }

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

    private void OnFileAnalysisCompleted(AnalysisCompletedEventArgs args)
    {
        if (!args.IsSuccessful)
        {
            DebugLogger.Critical($"[MainWindowViewModel] Analysis failed: {args.ErrorMessage}");
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                UIState.UpdateStatus($"Analysis failed: {args.ErrorMessage}", "#F85149");
                UIState.CanAccessAnalysisTabs = false;
            });
            return;
        }

        Dispatcher.UIThread.InvokeAsync(async () =>
        {
            if (!string.IsNullOrEmpty(args.FilePath))
                FileManager.CurrentFile = args.FilePath;

            await PacketManager.InitializePacketStoreAsync(CancellationToken.None);

            if (!string.IsNullOrEmpty(args.FilePath))
            {
                PacketManager?.PacketDetails?.SetPcapPath(args.FilePath);
                PacketManager?.PacketDetails?.SetPacketStore(PacketManager.ActivePacketStore);
            }

            if (args.Packets != null && args.Packets.Count > 0 && PacketManager != null)
                await PacketManager.ActivePacketStore.InsertPacketsAsync(args.Packets, CancellationToken.None);

            var cachedResult = _sessionCache.Get();
            if (cachedResult != null)
            {
                FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Populating tabs from cache...");
                await PopulateViewModelsFromCacheAsync(cachedResult);
                FileAnalysisViewModel?.ReportTabLoadingProgress(100, "Tabs populated");
                FileAnalysisViewModel?.CompleteAnalysis();
            }
            else
                OnAnalysisCompleted(this, args.Statistics);

            if (FileAnalysisViewModel != null && args.Packets != null)
                await CalculateFileAnalysisQuickStats(args.Statistics, args.Packets);

            UIState.CanAccessAnalysisTabs = true;
            UIState.HasResults = true;
            UIState.UpdateStatus($"Analysis complete: {args.Packets?.Count ?? 0:N0} packets analyzed", "#4ADE80");
        });
    }

    private async Task CalculateFileAnalysisQuickStats(NetworkStatistics statistics, IReadOnlyList<Core.Models.PacketInfo> packets)
    {
        await Task.Run(() =>
        {
            if (FileAnalysisViewModel == null) return;
            var quickStats = FileAnalysisViewModel.QuickStats;
            quickStats.TotalPackets = packets.Count;
            quickStats.TotalTrafficMB = statistics.TotalBytes / 1024.0 / 1024.0;
            quickStats.UniqueIPs = statistics.AllUniqueIPs.Count;
            quickStats.UniquePorts = statistics.UniquePortCount;
            quickStats.Conversations = statistics.TotalConversationCount;
            quickStats.Threats = statistics.DetectedThreats?.Count ?? 0;
            quickStats.Anomalies = 0;
            quickStats.UniqueProtocols = statistics.ProtocolStats.Count;
            quickStats.ProcessingRate = FileAnalysisViewModel.ElapsedTime.TotalSeconds > 0
                ? (long)(packets.Count / FileAnalysisViewModel.ElapsedTime.TotalSeconds)
                : 0;
        });
    }

    private void OnAnalysisCompleted(object? sender, NetworkStatistics statistics)
    {
        _updateTimer.Stop();
        Dispatcher.UIThread.InvokeAsync(async () =>
        {
            UIState.UpdateStatus($"Analysis completed. Processing results...", "#4ADE80");
            UIState.HasResults = true;
            UIState.CanAccessAnalysisTabs = false;
            EnhancedFilterViewModel.IsAnalyzing = false;
            EnhancedFilterViewModel.CanApplyFilters = true;

            try
            {
                FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Loading Packet Analysis tab...");
                Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 0, "Populating packet list...");
                await PacketManager.PopulateFullPacketListAsync(statistics);
                Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 75, "Applying filters...");
                PacketManager.ApplyFilter(new PacketFilter());
                var filteredCount = PacketManager.GetFilteredPackets().Count;
                UIState.UpdatePaginationInfo(filteredCount);
                UIState.GoToPage(1);
                Analysis.CompleteTabStage(Analysis.GetPacketAnalysisStageKey(),
                    $"Packet list ready ({filteredCount:N0} packets)");
                FileAnalysisViewModel?.ReportTabLoadingProgress(15, $"Packet Analysis loaded ({filteredCount:N0} packets)");
                UpdatePacketAnalysisStats();
                var filteredPacketsForChart = PacketManager.GetFilteredPackets();
                Charts.UpdatePacketsOverTimeChart(filteredPacketsForChart);

                FileAnalysisViewModel?.ReportTabLoadingProgress(15, "Loading tabs in parallel...");
                var packets = PacketManager.GetFilteredPackets().ToList();
                var stats = _tsharkService.GetStatistics();
                Charts.UpdateCharts(stats);

                var dashboardCountryTask = Task.Run(async () =>
                {
                    await Dispatcher.UIThread.InvokeAsync(async () => await UpdateDashboardAsync(forceUpdate: true));
                    if (CountryTrafficViewModel != null)
                    {
                        await Dispatcher.UIThread.InvokeAsync(async () =>
                        {
                            CountryTrafficViewModel.SetPackets(packets);
                            var enrichedStats = DashboardViewModel?.CurrentStatistics ?? statistics;
                            await CountryTrafficViewModel.UpdateStatistics(enrichedStats);
                        });
                    }
                    return 0;
                });

                var threatsTask = Task.Run(async () =>
                {
                    if (ThreatsViewModel != null)
                        await ThreatsViewModel.UpdateThreatsAsync(packets);
                    return 0;
                });

                var anomalyTask = Task.Run(async () =>
                {
                    var detectedAnomalies = await _anomalyService.DetectAllAnomaliesAsync(packets);
                    await Dispatcher.UIThread.InvokeAsync(async () =>
                    {
                        AnomalyViewModel?.UpdateAnomalies(detectedAnomalies);
                        if (AnomaliesViewModel != null)
                            await AnomaliesViewModel.LoadFromAnalysisResultAsync(detectedAnomalies);
                        DashboardViewModel?.UpdateAnomalySummary(detectedAnomalies);
                    });
                    return 0;
                });

                var voiceQoSTask = Task.Run(async () =>
                {
                    if (VoiceQoSViewModel != null)
                        await VoiceQoSViewModel.AnalyzePacketsAsync(packets);
                    return 0;
                });

                FileAnalysisViewModel?.ReportTabLoadingProgress(50, "Analyzing Dashboard, Threats, VoiceQoS, Country...");
                await Task.WhenAll(dashboardCountryTask, threatsTask, anomalyTask, voiceQoSTask);

                Analysis.CompleteTabStage(Analysis.GetDashboardStageKey(), $"Dashboard ready");
                Analysis.CompleteTabStage(Analysis.GetThreatsStageKey(), $"Threats detected");
                Analysis.CompleteTabStage(Analysis.GetVoiceQoSStageKey(), $"VoIP analysis complete");
                Analysis.CompleteTabStage(Analysis.GetCountryTrafficStageKey(), $"Geographic analysis complete");
                FileAnalysisViewModel?.ReportTabLoadingProgress(95, "All tabs loaded");

                Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 0, "Finalizing analysis...");
                try
                {
                    Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 50, "Running background tools...");
                    _ = Task.Run(async () =>
                    {
                        try { await RunExternalToolsAsync(statistics); }
                        catch (Exception toolEx)
                        {
                            DebugLogger.Log($"[MainWindowViewModel] External tools failed: {toolEx.Message}");
                        }
                    });
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[MainWindowViewModel] Failed to start external tools: {ex.Message}");
                }

                Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 100, "Finalizing complete");
                Analysis.CompleteTabStage(Analysis.GetFinalizingStageKey(), "Analysis complete");
                FileAnalysisViewModel?.CompleteAnalysis();
                UIState.CanAccessAnalysisTabs = FileManager.HasFile;
                UIState.UpdateStatus($"Analysis complete. {Analysis.PacketCount:N0} packets analyzed.", "#4ADE80");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MainWindowViewModel] Tab loading error: {ex.Message}");
                FileAnalysisViewModel?.CompleteAnalysis();
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
        if (enrichedStats != null)
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

    private void OnPageChanged(object? sender, int pageNumber)
    {
        PacketManager.UpdatePageDisplay(pageNumber, UIState.PageSize);
    }

    private void OnGoToPacketRequested(object? sender, uint frameNumber)
    {
        var filteredPackets = PacketManager.GetFilteredPackets();
        var (pageNumber, packetIndex) = _navigationComponent.FindPacketPage(frameNumber, filteredPackets, UIState.PageSize);

        if (packetIndex < 0)
        {
            UIState.UpdateStatus($"Packet #{frameNumber:N0} not found in current view", "#FF5252");
            return;
        }

        UIState.GoToPage(pageNumber);
        var packet = filteredPackets[packetIndex];
        _ = PacketManager.SelectPacketAsync(packet);
        UIState.UpdateStatus($"Navigated to packet #{frameNumber:N0} (page {pageNumber})", "#4ADE80");
    }

    private void OnSearchStreamRequested(object? sender, string searchPattern)
    {
        var matchCount = _navigationComponent.ApplyStreamFilter(searchPattern, PacketManager);

        if (string.IsNullOrWhiteSpace(searchPattern))
        {
            UIState.StreamSearchStatus = "";
            UIState.UpdateStatus("Stream filter cleared", "#4ADE80");
        }
        else if (matchCount == 0)
        {
            UIState.StreamSearchStatus = "No matches";
            UIState.UpdateStatus($"No packets found matching '{searchPattern}'", "#FF5252");
        }
        else
        {
            UIState.StreamSearchStatus = $"{matchCount:N0} packets";
            UIState.UpdateStatus($"Filtered to {matchCount:N0} packets matching '{searchPattern}'", "#4ADE80");
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
        UIState.UpdateStatus($"Showing {frameNumbers.Count} packets for: {context}", "#4ADE80");
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
        if (DashboardViewModel != null)
        {
            _dashboardFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Dashboard", "#4ADE80");
        }
    }

    protected override void CopyFiltersToThreats()
    {
        if (ThreatsViewModel != null)
        {
            _threatsFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Security Threats", "#4ADE80");
        }
    }

    protected override void CopyFiltersToVoiceQoS()
    {
        if (VoiceQoSViewModel != null)
        {
            _voiceQoSFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Voice/QoS", "#4ADE80");
        }
    }

    protected override void CopyFiltersToCountryTraffic()
    {
        if (CountryTrafficViewModel != null)
        {
            _countryTrafficFilterService.CopyFilterFrom(_packetAnalysisFilterService);
            UIState.UpdateStatus("Filters copied to Country Traffic", "#4ADE80");
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

    public void Dispose()
    {
        try
        {
            DebugLogger.Log("[MainWindowViewModel] Disposing synchronously...");

            _updateTimer?.Stop();
            _tsharkService?.Dispose();
            Analysis?.Dispose();
            _dashboardComponent?.Dispose();

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
