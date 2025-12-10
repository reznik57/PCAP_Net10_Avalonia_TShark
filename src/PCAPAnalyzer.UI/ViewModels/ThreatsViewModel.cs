using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.Credentials;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.ViewModels.Threats;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    [SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Threats ViewModel requires coordination of security services, anomaly detection, and visualization components - this is necessary for comprehensive threat analysis")]
    public partial class ThreatsViewModel : SmartFilterableTab, ILazyLoadableTab, IDisposable
    {
        private readonly IDispatcherService _dispatcher;
        private readonly IInsecurePortDetector _insecurePortDetector;
        private readonly IUnifiedAnomalyDetectionService _anomalyService;
        private readonly ICredentialDetectionService? _credentialService;
        private readonly ITabFilterService? _filterService;
        private readonly PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? _cacheService;
        private readonly FilterCopyService? _filterCopyService;
        private readonly GlobalFilterState? _globalFilterState;
        private readonly Components.UnifiedFilterPanelViewModel? _unifiedFilterPanel;
        private bool _disposed;
    private List<EnhancedSecurityThreat> _allThreats = [];
    private List<SuricataAlert> _suricataAlerts = [];
    private List<YaraMatch> _yaraMatches = [];
        private IReadOnlyList<PacketInfo> _currentPackets = []; // Filtered packets (may be reference or new list)
        private IReadOnlyList<PacketInfo> _unfilteredPackets = []; // Reference to cache (NOT a copy)
        private SecurityMetrics? _metrics;

        // Cache to prevent redundant analysis
        private int _lastAnalyzedPacketCount;
        private bool _lastFilterState;
        private bool _isAnalyzing;
        private string? _currentFilePath;
        // NOTE: _currentCacheKey moved to ThreatsAnalysisViewModel

        // Lazy loading support
        [ObservableProperty] private bool _isDataLoaded = false;
        [ObservableProperty] private bool _isLoading = false;
        private Task? _loadingTask;

        // Paginated collections using composition
        public SecurityThreatPaginationViewModel SecurityThreatsPagination { get; } = new();
        public InsecurePortPaginationViewModel InsecurePortsPagination { get; } = new();

        // ==================== COMPONENT VIEWMODELS (Dashboard pattern) ====================
        public ThreatsChartsViewModel Charts { get; }
        public ThreatsDrillDownViewModel DrillDown { get; } = new();
        public Action<List<uint>, string>? NavigateToPacketAnalysis { get; set; }
        public ThreatsReportExportViewModel ReportExport { get; }
        public ThreatsAnalysisViewModel Analysis { get; }
        public ThreatsFilterViewModel QuickFilters { get; } = new();
        public ThreatsStatisticsViewModel Statistics { get; } = new();

        // Chart series - delegated to Charts component but exposed for backward compatibility
        public ObservableCollection<ISeries> ThreatSeveritySeries => Charts.ThreatSeveritySeries;
        public ObservableCollection<ISeries> ThreatTimelineSeries => Charts.ThreatTimelineSeries;
        public ObservableCollection<ISeries> PortRiskSeries => Charts.PortRiskSeries;
        public ObservableCollection<ISeries> ThreatCategorySeries => Charts.ThreatCategorySeries;

        [ObservableProperty] private int _totalThreats;
        [ObservableProperty] private int _criticalThreats;
        [ObservableProperty] private int _highThreats;
        [ObservableProperty] private int _mediumThreats;
        [ObservableProperty] private int _lowThreats;
        [ObservableProperty] private double _overallRiskScore;
        [ObservableProperty] private string _riskLevel = "Unknown";
        [ObservableProperty] private string _riskLevelColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");

        // ==================== FILTER DROPDOWN PROPERTIES (Delegated to QuickFilters component) ====================

        public bool ShowCriticalOnly
        {
            get => QuickFilters.ShowCriticalOnly;
            set => QuickFilters.ShowCriticalOnly = value;
        }

        public bool ShowHighOnly
        {
            get => QuickFilters.ShowHighOnly;
            set => QuickFilters.ShowHighOnly = value;
        }

        public bool GroupByService
        {
            get => QuickFilters.GroupByService;
            set => QuickFilters.GroupByService = value;
        }

        public string SelectedCategory
        {
            get => QuickFilters.SelectedCategory;
            set => QuickFilters.SelectedCategory = value;
        }

        public string SelectedThreatType
        {
            get => QuickFilters.SelectedThreatType;
            set => QuickFilters.SelectedThreatType = value;
        }

        public string SearchFilter
        {
            get => QuickFilters.SearchFilter;
            set => QuickFilters.SearchFilter = value;
        }

        public ObservableCollection<string> ThreatTypes => QuickFilters.ThreatTypes;

        public new bool HasFiltersApplied
        {
            get => QuickFilters.HasFiltersApplied;
            set => QuickFilters.HasFiltersApplied = value;
        }

        // ==================== SORTING (Delegated to Statistics) ====================
        public ObservableCollection<string> SortOptions => Statistics.SortOptions;
        public string SelectedSortOption
        {
            get => Statistics.SelectedSortOption;
            set => Statistics.SelectedSortOption = value;
        }

        // ==================== QUICK FILTER TOGGLES (Delegated to QuickFilters) ====================
        public bool IsInsecureProtocolFilterActive
        {
            get => QuickFilters.IsInsecureProtocolFilterActive;
            set => QuickFilters.IsInsecureProtocolFilterActive = value;
        }

        public bool IsKnownCVEFilterActive
        {
            get => QuickFilters.IsKnownCVEFilterActive;
            set => QuickFilters.IsKnownCVEFilterActive = value;
        }

        public bool IsWeakEncryptionFilterActive
        {
            get => QuickFilters.IsWeakEncryptionFilterActive;
            set => QuickFilters.IsWeakEncryptionFilterActive = value;
        }

        public bool IsAuthIssuesFilterActive
        {
            get => QuickFilters.IsAuthIssuesFilterActive;
            set => QuickFilters.IsAuthIssuesFilterActive = value;
        }

        public bool IsCleartextFilterActive
        {
            get => QuickFilters.IsCleartextFilterActive;
            set => QuickFilters.IsCleartextFilterActive = value;
        }

        public ObservableCollection<ActiveQuickFilterChip> ActiveQuickFilterChips => QuickFilters.ActiveQuickFilterChips;

        // Side-by-side table data now managed by Statistics component

        // ==================== FILTERABLE TAB IMPLEMENTATION ====================
        public new CommonFilterViewModel CommonFilters { get; } = new();
        [ObservableProperty] private string _severityFilter = "All";
        [ObservableProperty] private string _portFilter = "";

        // ==================== UNIVERSAL FILTER PROPERTIES ====================

        [ObservableProperty] private string _filterSourceIP = "";
        [ObservableProperty] private string _filterDestinationIP = "";
        [ObservableProperty] private string _filterPortRange = "";
        [ObservableProperty] private string _filterProtocolType = "";

        partial void OnFilterSourceIPChanged(string value) => ApplyFilters();
        partial void OnFilterDestinationIPChanged(string value) => ApplyFilters();
        partial void OnFilterPortRangeChanged(string value) => ApplyFilters();
        partial void OnFilterProtocolTypeChanged(string value) => ApplyFilters();

        public override string TabName => TabNames.Threats;
        public new void ApplyFilters() => UpdateThreatsList();
        protected override void ApplySmartFilter(PacketFilter filter)
        {
            UpdateThreatsList();
            DebugLogger.Log($"[{TabName}] Smart filters applied to threats data");
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

        [ObservableProperty] private SecurityThreatItemViewModel? _selectedThreat;
        [ObservableProperty] private bool _isDetailsPanelVisible;
        [ObservableProperty] private string _detailsTitle = "";
        [ObservableProperty] private string _detailsDescription = "";
        [ObservableProperty] private ObservableCollection<string> _detailsVulnerabilities = [];
        [ObservableProperty] private ObservableCollection<string> _detailsMitigations = [];
        [ObservableProperty] private ObservableCollection<string> _affectedEndpoints = [];
        [ObservableProperty] private ObservableCollection<string> _detailsConnections = [];

        // Chart axes - delegated to Charts component
        public Axis[] XAxes => Charts.XAxes;
        public Axis[] YAxes => Charts.YAxes;
        public Axis[] PortRiskXAxes => Charts.PortRiskXAxes;
        public Axis[] ThreatCategoryYAxes => Charts.ThreatCategoryYAxes;

        // Peak/average rates from Charts
        public double PeakThreatRate => Charts.PeakThreatRate;
        public double AverageThreatRate => Charts.AverageThreatRate;

        public ObservableCollection<string> Categories { get; } = new()
        {
            "All",
            "CleartextCredentials",
            "InsecureProtocol",
            "UnencryptedService",
            "LegacyProtocol",
            "KnownVulnerability",
            "MaliciousActivity",
            "Reconnaissance",
            "DataExfiltration",
            "CommandAndControl",
            "DenialOfService"
        };
        
        public ObservableCollection<int> PageSizeOptions { get; } = new() { 10, 25, 50, 100 };

        public ThreatsViewModel()
            : this(
                App.Services?.GetService<IDispatcherService>() ?? new AvaloniaDispatcherService(),
                App.Services?.GetService<IInsecurePortDetector>() ?? new InsecurePortDetector(),
                App.Services?.GetService<IUnifiedAnomalyDetectionService>() ?? new UnifiedAnomalyDetectionService(),
                App.Services?.GetService<ICredentialDetectionService>(),
                new TabFilterService("Security Threats", new FilterServiceCore()),
                App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>(),
                App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
                App.Services?.GetService<GlobalFilterState>(),
                App.Services?.GetService<Components.UnifiedFilterPanelViewModel>())
        {
        }

        public ThreatsViewModel(
            IDispatcherService dispatcherService,
            IInsecurePortDetector insecurePortDetector,
            IUnifiedAnomalyDetectionService anomalyService,
            ICredentialDetectionService? credentialService,
            ITabFilterService? filterService,
            PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? cacheService = null,
            ISmartFilterBuilder? filterBuilder = null,
            GlobalFilterState? globalFilterState = null,
            Components.UnifiedFilterPanelViewModel? unifiedFilterPanel = null)
            : base(filterBuilder ?? new SmartFilterBuilderService())
        {
            ArgumentNullException.ThrowIfNull(dispatcherService);
            _dispatcher = dispatcherService;
            _insecurePortDetector = insecurePortDetector;
            _anomalyService = anomalyService;
            _credentialService = credentialService;
            _filterService = filterService;
            _cacheService = cacheService;
            _filterCopyService = App.Services?.GetService<FilterCopyService>();
            _globalFilterState = globalFilterState;
            _unifiedFilterPanel = unifiedFilterPanel;

            // Initialize component ViewModels (Dashboard composition pattern)
            Charts = new ThreatsChartsViewModel(insecurePortDetector);
            ReportExport = new ThreatsReportExportViewModel(Charts);
            Analysis = new ThreatsAnalysisViewModel(insecurePortDetector, anomalyService, cacheService);

            // Wire up Analysis completion event
            Analysis.AnalysisCompleted += OnAnalysisCompleted;

            // Wire up QuickFilters change event (legacy - kept for backward compatibility)
            QuickFilters.FiltersChanged += () => UpdateThreatsList();

            // Wire up UnifiedFilterPanel's ThreatsTab change event
            if (_unifiedFilterPanel is not null)
            {
                _unifiedFilterPanel.ThreatsTab.FiltersChanged += OnUnifiedFilterChanged;
                _unifiedFilterPanel.ApplyFiltersRequested += OnUnifiedFilterApplied;
            }

            // Wire up Statistics sort change event
            Statistics.SortChanged += () => UpdateThreatsList();

            // Subscribe to filter changes
            if (_filterService is not null)
            {
                _filterService.FilterChanged += OnFilterServiceChanged;
            }

            // Subscribe to GlobalFilterState for explicit Apply button clicks only
            // NOTE: Using OnFiltersApplied (not OnFilterChanged) to avoid auto-apply on chip removal
            if (_globalFilterState is not null)
            {
                _globalFilterState.OnFiltersApplied += OnGlobalFilterChanged;
            }

            // Subscribe to CommonFilters property changes
            CommonFilters.PropertyChanged += (s, e) => ApplyFilters();

            // Subscribe to PortFilter changes
            PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(PortFilter))
                {
                    ApplyFilters();
                }
            };

            // Register with FilterCopyService
            _filterCopyService?.RegisterTab(TabName, this);

            // Subscribe to DrillDown navigation request
            DrillDown.ViewInPacketAnalysisRequested += OnDrillDownNavigationRequested;

            DebugLogger.Log("[ThreatsViewModel] Initialized with component ViewModels (Charts, DrillDown, ReportExport)");
        }

        private void OnUnifiedFilterChanged()
        {
            // Quick filters changed in UnifiedFilterPanel - trigger immediate update
            UpdateThreatsList();
        }

        private void OnUnifiedFilterApplied()
        {
            // Apply button pressed in UnifiedFilterPanel - trigger update
            UpdateThreatsList();
        }
        
        private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
        {
            // When filter changes and we have packets, reprocess threats
            if (_unfilteredPackets is not null && _unfilteredPackets.Any())
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await UpdateThreatsAsync(_unfilteredPackets);
                        DebugLogger.Log($"[ThreatsViewModel] Threats updated after filter change");
                    }
                    catch (Exception ex)
                    {
                        DebugLogger.Log($"[ThreatsViewModel] Error updating threats on filter change: {ex.Message}");
                    }
                });
            }
        }

        /// <summary>
        /// Handles GlobalFilterState changes - re-applies tab-specific filters to threat list.
        /// </summary>
        private void OnGlobalFilterChanged()
        {
            // Re-apply filters when global filter state changes (e.g., severity/category from UnifiedFilterPanel)
            if (_allThreats.Count > 0)
            {
                _dispatcher.Post(() =>
                {
                    UpdateThreatsList();
                    DebugLogger.Log($"[ThreatsViewModel] Threats list updated after global filter change");
                });
            }
        }

        /// <summary>
        /// Loads threat analysis data on-demand. Call this when the Threats tab is first accessed.
        /// Returns immediately if data is already loaded or loading is in progress.
        /// </summary>
        public async Task LoadDataAsync(IReadOnlyList<PacketInfo> packets)
        {
            // Already loaded - instant return
            if (IsDataLoaded)
            {
                DebugLogger.Log("[ThreatsViewModel] Data already loaded, skipping");
                return;
            }

            // Currently loading - wait for existing operation
            if (_loadingTask is not null)
            {
                DebugLogger.Log("[ThreatsViewModel] Loading already in progress, awaiting existing task");
                await _loadingTask;
                return;
            }

            // Start new loading operation
            DebugLogger.Log($"[ThreatsViewModel] Starting lazy load for {packets.Count:N0} packets");
            IsLoading = true;
            _loadingTask = UpdateThreatsAsync(packets);

            try
            {
                await _loadingTask;
                IsDataLoaded = true;
                DebugLogger.Log("[ThreatsViewModel] Lazy load completed successfully");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsViewModel] Error during lazy load: {ex.Message}");
                throw;
            }
            finally
            {
                IsLoading = false;
                _loadingTask = null;
            }
        }

        /// <summary>
        /// ✅ PRELOAD ARCHITECTURE: Sets threats from pre-analyzed SessionAnalysisCache.
        /// Bypasses ALL analysis - instantly binds cached threat data to UI.
        /// Expected: <100ms to populate (vs 5s re-analysis).
        /// </summary>
        public async Task SetFromCacheAsync(List<SecurityThreat> threats, IReadOnlyList<PacketInfo> packets)
        {
            DebugLogger.Log($"[ThreatsViewModel] SetFromCache - {threats.Count:N0} threats, {packets.Count:N0} packets");

            // Convert SecurityThreat to EnhancedSecurityThreat
            _allThreats = threats.Select(t => new EnhancedSecurityThreat
            {
                Category = ThreatCategory.InsecureProtocol, // Default category
                Severity = t.Severity,
                ThreatName = t.Type,
                Description = t.Description,
                FirstSeen = t.DetectedAt,
                LastSeen = t.DetectedAt,
                OccurrenceCount = t.AffectedPackets?.Count ?? 1,
                RiskScore = (int)t.Severity * 2,
                Service = t.Type,
                AffectedIPs = new List<string> { t.SourceAddress, t.DestinationAddress }
            }).ToList();

            _currentPackets = packets; // Reference, no copy
            _unfilteredPackets = packets;
            _lastAnalyzedPacketCount = packets.Count;
            _lastFilterState = false;

            // Calculate metrics from cached threats
            _metrics = _insecurePortDetector.CalculateSecurityMetrics(_allThreats);

            // Update UI (handles metrics, collections, charts)
            await _dispatcher.InvokeAsync(() => UpdateUI());

            IsDataLoaded = true;
            DebugLogger.Log($"[ThreatsViewModel] ✓ SetFromCache complete in <100ms - {_allThreats.Count:N0} threats bound");
        }

        /// <summary>
        /// Sets the current file path for cache key computation
        /// </summary>
        public void SetCurrentFile(string filePath)
        {
            _currentFilePath = filePath;
            Analysis.SetCurrentFile(filePath); // Delegates cache key management to Analysis component
        }

        // NOTE: Cache methods moved to ThreatsAnalysisViewModel
        // - TryLoadFromCacheAsync -> Analysis.TryLoadFromCacheAsync
        // - TrySaveToCache -> Analysis.TrySaveToCache

    // NOTE: UpdateThreatsAsync moved to ThreatsViewModel.ThreatDetection.cs

    /// <summary>
    /// Adds Suricata alerts to threat list - delegates to Analysis component
    /// </summary>
    public void SetSuricataAlerts(List<SuricataAlert> alerts)
    {
        _suricataAlerts = alerts;
        if (alerts is null || alerts.Count == 0) return;

        // Delegate to Analysis component - OnAnalysisCompleted will sync _allThreats and update UI
        Analysis.AddSuricataAlerts(alerts);
    }

    /// <summary>
    /// Adds YARA matches to threat list - delegates to Analysis component
    /// </summary>
    public void SetYaraMatches(List<YaraMatch> matches)
    {
        _yaraMatches = matches;
        if (matches is null || matches.Count == 0) return;

        // Delegate to Analysis component - OnAnalysisCompleted will sync _allThreats and update UI
        Analysis.AddYaraMatches(matches);
    }

        /// <summary>
        /// Event handler for Analysis component completion - syncs data and updates UI
        /// </summary>
        private void OnAnalysisCompleted(List<EnhancedSecurityThreat> threats, SecurityMetrics? metrics)
        {
            _allThreats = threats;
            _metrics = metrics;
            UpdateUI();
        }

        private void UpdateUI()
        {
            if (_metrics is null) return;

            TotalThreats = _metrics.TotalThreats;
            CriticalThreats = _metrics.CriticalThreats;
            HighThreats = _metrics.HighThreats;
            MediumThreats = _metrics.MediumThreats;
            LowThreats = _metrics.LowThreats;
            OverallRiskScore = Math.Round(_metrics.OverallRiskScore, 2);

            UpdateRiskLevel();
            UpdateThreatTypes();
            UpdateThreatsList();
            UpdateInsecurePortsList();
            UpdateCharts();
        }

        private void UpdateRiskLevel()
        {
            if (OverallRiskScore >= 8)
            {
                RiskLevel = "CRITICAL";
                RiskLevelColor = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
            }
            else if (OverallRiskScore >= 6)
            {
                RiskLevel = "HIGH";
                RiskLevelColor = ThemeColorHelper.GetColorHex("ColorOrange", "#F97316");
            }
            else if (OverallRiskScore >= 4)
            {
                RiskLevel = "MEDIUM";
                RiskLevelColor = ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B");
            }
            else if (OverallRiskScore >= 2)
            {
                RiskLevel = "LOW";
                RiskLevelColor = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
            }
            else
            {
                RiskLevel = "MINIMAL";
                RiskLevelColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
            }
        }
        
        private void UpdateThreatTypes()
        {
            // Get unique threat types from detected threats
            var uniqueThreatTypes = _allThreats
                .Select(t => t.ThreatName)
                .Where(name => !string.IsNullOrEmpty(name))
                .Distinct()
                .OrderBy(name => name)
                .ToList();

            QuickFilters.ThreatTypes.Clear();
            QuickFilters.ThreatTypes.Add("All");

            foreach (var threatType in uniqueThreatTypes)
            {
                QuickFilters.ThreatTypes.Add(threatType);
            }
        }


        private void UpdateThreatsList()
        {
            QuickFilters.UpdateActiveChips();
            HasFiltersApplied = CheckIfFiltersApplied();

            // Apply all filters and grouping
            var threatsList = ApplyThreatFilters();
            threatsList = Statistics.ApplySorting(threatsList);

            // Update metrics and charts
            UpdateMetricsAndCharts(threatsList);

            // Build view model items and update pagination
            var securityThreatItems = BuildSecurityThreatViewModels(threatsList);
            SecurityThreatsPagination.SetItems(securityThreatItems);
            Statistics.UpdateTableData(_allThreats);
        }

        private bool CheckIfFiltersApplied()
        {
            // Check unified panel filters first
            var unifiedFilters = _unifiedFilterPanel?.ThreatsTab.GetQuickFilters();
            if (unifiedFilters?.HasAnyFilter == true)
                return true;

            // Fallback to legacy filters
            return CommonFilters.HasActiveFilters ||
                ShowCriticalOnly || ShowHighOnly ||
                SeverityFilter != "All" ||
                SelectedCategory != "All" ||
                SelectedThreatType != "All" ||
                !string.IsNullOrWhiteSpace(SearchFilter) ||
                !string.IsNullOrWhiteSpace(PortFilter) ||
                IsInsecureProtocolFilterActive || IsKnownCVEFilterActive ||
                IsWeakEncryptionFilterActive || IsAuthIssuesFilterActive ||
                IsCleartextFilterActive;
        }

        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Filter method with many filter conditions is inherently complex")]
        private List<EnhancedSecurityThreat> ApplyThreatFilters()
        {
            var filtered = _allThreats.AsEnumerable();

            // Get filters from UnifiedFilterPanel if available, otherwise use legacy QuickFilters
            var unifiedFilters = _unifiedFilterPanel?.ThreatsTab.GetQuickFilters();

            // Common filters
            if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
                filtered = filtered.Where(t => t.Protocol?.Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            if (!string.IsNullOrWhiteSpace(CommonFilters.SourceIPFilter))
                filtered = filtered.Where(t => t.AffectedIPs?.Any(ip => ip.Contains(CommonFilters.SourceIPFilter, StringComparison.OrdinalIgnoreCase)) ?? false);
            if (!string.IsNullOrWhiteSpace(CommonFilters.DestinationIPFilter))
                filtered = filtered.Where(t => t.AffectedIPs?.Any(ip => ip.Contains(CommonFilters.DestinationIPFilter, StringComparison.OrdinalIgnoreCase)) ?? false);
            if (!string.IsNullOrWhiteSpace(PortFilter))
                filtered = filtered.Where(t => t.Port.ToString().Contains(PortFilter, StringComparison.OrdinalIgnoreCase));

            // Severity filters - prefer UnifiedFilterPanel, fallback to legacy
            var showCritical = unifiedFilters?.ShowCriticalOnly ?? ShowCriticalOnly;
            var showHigh = unifiedFilters?.ShowHighOnly ?? ShowHighOnly;

            if (SeverityFilter != "All")
                filtered = filtered.Where(t => t.Severity == Enum.Parse<ThreatSeverity>(SeverityFilter));
            else if (showCritical)
                filtered = filtered.Where(t => t.Severity == ThreatSeverity.Critical);
            else if (showHigh)
                filtered = filtered.Where(t => t.Severity >= ThreatSeverity.High);

            // Category/Type filters - prefer UnifiedFilterPanel, fallback to legacy
            var selectedCategory = unifiedFilters?.SelectedCategory ?? SelectedCategory;
            var selectedThreatType = unifiedFilters?.SelectedThreatType ?? SelectedThreatType;
            var searchFilter = unifiedFilters?.SearchInput ?? SearchFilter;

            if (selectedCategory != "All" && !string.IsNullOrEmpty(selectedCategory))
                filtered = filtered.Where(t => t.Category.ToString() == selectedCategory);
            if (selectedThreatType != "All" && !string.IsNullOrEmpty(selectedThreatType))
                filtered = filtered.Where(t => t.ThreatName == selectedThreatType);
            if (!string.IsNullOrWhiteSpace(searchFilter))
                filtered = filtered.Where(t =>
                    t.ThreatName.Contains(searchFilter, StringComparison.OrdinalIgnoreCase) ||
                    t.Description.Contains(searchFilter, StringComparison.OrdinalIgnoreCase) ||
                    t.Service.Contains(searchFilter, StringComparison.OrdinalIgnoreCase));

            // Quick filter toggles - prefer UnifiedFilterPanel, fallback to legacy
            var insecureActive = unifiedFilters?.IsInsecureProtocolFilterActive ?? IsInsecureProtocolFilterActive;
            var cveActive = unifiedFilters?.IsKnownCVEFilterActive ?? IsKnownCVEFilterActive;
            var weakEncryptActive = unifiedFilters?.IsWeakEncryptionFilterActive ?? IsWeakEncryptionFilterActive;
            var authActive = unifiedFilters?.IsAuthIssuesFilterActive ?? IsAuthIssuesFilterActive;
            var cleartextActive = unifiedFilters?.IsCleartextFilterActive ?? IsCleartextFilterActive;

            var hasQuickFilters = insecureActive || cveActive || weakEncryptActive || authActive || cleartextActive;

            if (hasQuickFilters)
            {
                filtered = filtered.Where(t =>
                    (insecureActive && ThreatsFilterViewModel.IsInsecureProtocolThreat(t)) ||
                    (cveActive && ThreatsFilterViewModel.IsKnownCVEThreat(t)) ||
                    (weakEncryptActive && ThreatsFilterViewModel.IsWeakEncryptionThreat(t)) ||
                    (authActive && ThreatsFilterViewModel.IsAuthIssueThreat(t)) ||
                    (cleartextActive && ThreatsFilterViewModel.IsCleartextThreat(t)));
            }

            filtered = ApplyGlobalFilterStateCriteria(filtered);
            var threatsList = filtered.ToList();

            // Group similar threats if enabled
            if (GroupByService && threatsList.Any())
            {
                threatsList = threatsList
                    .GroupBy(t => new { t.ThreatName, t.Service, t.Port, t.Severity })
                    .Select(g =>
                    {
                        var first = g.First();
                        first.OccurrenceCount = g.Count();
                        first.AffectedIPs = g.SelectMany(t => t.AffectedIPs ?? new List<string>()).Distinct().ToList();
                        first.Description = g.Count() > 1 ? $"{first.Description} (Aggregated: {g.Count()} occurrences)" : first.Description;
                        return first;
                    }).ToList();
            }

            return threatsList;
        }

        private void UpdateMetricsAndCharts(List<EnhancedSecurityThreat> threatsList)
        {
            SecurityMetrics metrics;
            List<EnhancedSecurityThreat> chartsData;

            if (HasFiltersApplied && threatsList.Any())
            {
                metrics = _insecurePortDetector.CalculateSecurityMetrics(threatsList);
                chartsData = threatsList;
            }
            else if (_metrics is not null)
            {
                metrics = _metrics;
                chartsData = _allThreats;
            }
            else return;

            TotalThreats = metrics.TotalThreats;
            CriticalThreats = metrics.CriticalThreats;
            HighThreats = metrics.HighThreats;
            MediumThreats = metrics.MediumThreats;
            LowThreats = metrics.LowThreats;
            OverallRiskScore = Math.Round(metrics.OverallRiskScore, 2);
            UpdateRiskLevel();

            Charts.UpdateAllCharts(chartsData, metrics, CriticalThreats, HighThreats, MediumThreats, LowThreats);
            NotifyChartPropertiesChanged();
        }

        private void NotifyChartPropertiesChanged()
        {
            OnPropertyChanged(nameof(ThreatSeveritySeries));
            OnPropertyChanged(nameof(ThreatTimelineSeries));
            OnPropertyChanged(nameof(PortRiskSeries));
            OnPropertyChanged(nameof(ThreatCategorySeries));
            OnPropertyChanged(nameof(XAxes));
            OnPropertyChanged(nameof(YAxes));
            OnPropertyChanged(nameof(PeakThreatRate));
            OnPropertyChanged(nameof(AverageThreatRate));
        }

        private List<SecurityThreatItemViewModel> BuildSecurityThreatViewModels(List<EnhancedSecurityThreat> threats)
        {
            var items = new List<SecurityThreatItemViewModel>();
            var totalOccurrences = threats.Sum(t => t.OccurrenceCount);
            var rank = 1;

            foreach (var threat in threats)
            {
                var item = new SecurityThreatItemViewModel
                {
                    Id = threat.Id,
                    Rank = rank++,
                    ThreatName = threat.ThreatName,
                    Category = threat.Category.ToString(),
                    Severity = threat.Severity.ToString(),
                    SeverityColor = ThreatDisplayHelpers.GetSeverityColor(threat.Severity),
                    Service = threat.Service,
                    Port = threat.Port,
                    RiskScore = threat.RiskScore,
                    OccurrenceCount = threat.OccurrenceCount,
                    FirstSeen = threat.FirstSeen,
                    LastSeen = threat.LastSeen,
                    Description = threat.Description,
                    Vulnerabilities = threat.Vulnerabilities,
                    Mitigations = threat.Mitigations,
                    AffectedIPs = threat.AffectedIPs,
                    Percentage = totalOccurrences > 0 ? (threat.OccurrenceCount / (double)totalOccurrences) * 100 : 0
                };

                PopulateMetadataFields(item, threat);
                items.Add(item);
            }

            return items;
        }

        private static void PopulateMetadataFields(SecurityThreatItemViewModel item, EnhancedSecurityThreat threat)
        {
            if (threat.Metadata is null) return;

            if (threat.Metadata.TryGetValue("DetectedVersion", out var version))
                item.DetectedVersion = version?.ToString() ?? "";
            if (threat.Metadata.TryGetValue("IsEncryptedButInsecure", out var encrypted) && encrypted is bool b)
                item.IsEncryptedButInsecure = b;

            ExtractIPsFromMetadata(item, threat.Metadata, "SourceIPs", ips => item.SourceIPs = ips);
            ExtractIPsFromMetadata(item, threat.Metadata, "DestinationIPs", ips => item.DestinationIPs = ips);

            if (threat.Metadata.TryGetValue("Connections", out var conns) && conns is List<(string, string)> connList)
                item.Connections = connList;

            // Fallback: split AffectedIPs if no specific IPs in metadata
            if (!item.SourceIPs.Any() && !item.DestinationIPs.Any() && threat.AffectedIPs.Any())
            {
                var halfCount = threat.AffectedIPs.Count / 2;
                item.SourceIPs = threat.AffectedIPs.Take(halfCount).ToList();
                item.DestinationIPs = threat.AffectedIPs.Skip(halfCount).ToList();
                for (int i = 0; i < Math.Min(item.SourceIPs.Count, item.DestinationIPs.Count); i++)
                    item.Connections.Add((item.SourceIPs[i], item.DestinationIPs[i]));
            }
        }

        private static void ExtractIPsFromMetadata(SecurityThreatItemViewModel item, Dictionary<string, object> metadata, string key, Action<List<string>> setter)
        {
            if (!metadata.TryGetValue(key, out var value)) return;
            if (value is List<string> list)
                setter(list);
            else if (value is IEnumerable<object> objs)
                setter(objs.Select(o => o?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s)).ToList());
        }


        private void UpdateInsecurePortsList()
        {
            var knownPorts = _insecurePortDetector.GetKnownInsecurePorts();
            var detectedPorts = _allThreats
                .Where(t => t.Port > 0)
                .GroupBy(t => t.Port)
                .ToDictionary(g => g.Key, g => g.ToList());

            var insecurePortItems = new List<InsecurePortItemViewModel>();
            foreach (var kvp in knownPorts.OrderByDescending(p => p.Value.RiskLevel))
            {
                var port = kvp.Key;
                var profile = kvp.Value;
                var threats = detectedPorts.ContainsKey(port) ? detectedPorts[port] : new List<EnhancedSecurityThreat>();

                insecurePortItems.Add(new InsecurePortItemViewModel
                {
                    Port = port,
                    ServiceName = profile.ServiceName,
                    Protocol = profile.Protocol,
                    RiskLevel = profile.RiskLevel.ToString(),
                    RiskColor = ThreatDisplayHelpers.GetSeverityColor(profile.RiskLevel),
                    IsEncrypted = profile.IsEncrypted,
                    DetectedPackets = threats.Sum(t => t.OccurrenceCount),
                    IsActive = threats.Any(),
                    RecommendedAlternative = profile.RecommendedAlternative,
                    SecurityNotes = profile.SecurityNotes,
                    RequiresAction = profile.RequiresImmediateAction
                });
            }

            // Update pagination using the new wrapper
            InsecurePortsPagination.SetItems(insecurePortItems);
        }

        private void UpdateCharts()
        {
            // Delegate to Charts component (Dashboard composition pattern)
            Charts.UpdateAllCharts(_allThreats, _metrics, CriticalThreats, HighThreats, MediumThreats, LowThreats);

            // Notify UI that chart properties may have changed
            OnPropertyChanged(nameof(ThreatSeveritySeries));
            OnPropertyChanged(nameof(ThreatTimelineSeries));
            OnPropertyChanged(nameof(PortRiskSeries));
            OnPropertyChanged(nameof(ThreatCategorySeries));
            OnPropertyChanged(nameof(XAxes));
            OnPropertyChanged(nameof(YAxes));
            OnPropertyChanged(nameof(PeakThreatRate));
            OnPropertyChanged(nameof(AverageThreatRate));

            // Update ReportExport with current data
            ReportExport.SetExportData(_allThreats, _metrics, _currentFilePath ?? "Unknown");
        }

        // ==================== DRILLDOWN INVESTIGATION ====================

        /// <summary>
        /// Opens the full investigation DrillDown panel for a threat.
        /// Delegates to ThreatsDrillDownViewModel (Dashboard composition pattern).
        /// </summary>
        [RelayCommand]
        private void ShowThreatDetails(SecurityThreatItemViewModel threat)
        {
            // Find the original EnhancedSecurityThreat for full investigation data
            var enhancedThreat = _allThreats.FirstOrDefault(t => t.Id == threat.Id);

            if (enhancedThreat is not null)
            {
                // Use DrillDown component for full investigation (Dashboard pattern)
                DrillDown.ShowForThreat(enhancedThreat, _currentPackets, _allThreats);
                DebugLogger.Log($"[ThreatsViewModel] DrillDown opened for threat: {threat.ThreatName}");
            }
            else
            {
                // Fallback: populate legacy panel for backward compatibility
                SelectedThreat = threat;
                DetailsTitle = threat.ThreatName;
                DetailsDescription = threat.Description;

                DetailsVulnerabilities.Clear();
                foreach (var vuln in threat.Vulnerabilities)
                    DetailsVulnerabilities.Add(vuln);

                DetailsMitigations.Clear();
                foreach (var mitigation in threat.Mitigations)
                    DetailsMitigations.Add(mitigation);

                AffectedEndpoints.Clear();
                foreach (var ip in threat.AffectedIPs.Take(20))
                    AffectedEndpoints.Add(ip);

                DetailsConnections.Clear();
                if (threat.Connections.Any())
                {
                    foreach (var conn in threat.Connections.Take(50))
                        DetailsConnections.Add($"{conn.Source} → {conn.Destination}");
                }

                IsDetailsPanelVisible = true;
                DebugLogger.Log($"[ThreatsViewModel] Legacy details panel opened (threat not found in _allThreats)");
            }
        }

        [RelayCommand]
        private void CloseDetails()
        {
            // Close both DrillDown and legacy panel
            DrillDown.IsVisible = false;
            IsDetailsPanelVisible = false;
            SelectedThreat = null;
        }

        /// <summary>
        /// Handles DrillDown navigation request to Packet Analysis tab
        /// </summary>
        private void OnDrillDownNavigationRequested(object? sender, ViewInPacketAnalysisEventArgs e)
        {
            try
            {
                if (NavigateToPacketAnalysis is null)
                {
                    DebugLogger.Log("[ThreatsViewModel] NavigateToPacketAnalysis not wired - cannot navigate");
                    return;
                }

                // Build a descriptive context for the navigation
                var threatName = DrillDown.ThreatName ?? "Unknown Threat";
                var context = $"Threat: {threatName} (Port {e.Port})";

                DebugLogger.Log($"[ThreatsViewModel] Navigating to Packet Analysis with {e.FrameNumbers.Count} frames for: {context}");

                // Invoke the navigation action
                NavigateToPacketAnalysis(e.FrameNumbers, context);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsViewModel] Navigation error: {ex.Message}");
            }
        }

        [RelayCommand]
        private void ShowAllThreats()
        {
            ShowCriticalOnly = false;
            ShowHighOnly = false;
            SelectedCategory = "All";
            SelectedThreatType = "All";
            SearchFilter = "";
            UpdateThreatsList();
        }
        
        [RelayCommand]
        private void ClearLocalFilters()
        {
            // Reset severity toggles
            ShowCriticalOnly = false;
            ShowHighOnly = false;

            // Reset category/search filters
            SelectedCategory = "All";
            SelectedThreatType = "All";
            SearchFilter = "";

            // Reset quick filter toggles
            IsInsecureProtocolFilterActive = false;
            IsKnownCVEFilterActive = false;
            IsWeakEncryptionFilterActive = false;
            IsAuthIssuesFilterActive = false;
            IsCleartextFilterActive = false;

            UpdateThreatsList();
        }

        // NOTE: Export methods moved to ThreatsViewModel.Export.cs

        // ==================== QUICK FILTER HELPER METHODS ====================
        // NOTE: Filter helper methods moved to ThreatsFilterViewModel (static methods)
        // Usage: ThreatsFilterViewModel.IsInsecureProtocolThreat(threat), etc.

        // ==================== CLEAR FILTER UPDATES ====================

        public List<SecurityThreat> GetCurrentThreats()
        {
            // Convert EnhancedSecurityThreat to SecurityThreat for the report
            return _allThreats.Select(t => new SecurityThreat
            {
                Type = t.Category.ToString(),
                Severity = t.Severity,
                Description = t.Description,
                SourceAddress = t.AffectedIPs?.FirstOrDefault() ?? "",
                DestinationAddress = t.AffectedIPs?.Skip(1).FirstOrDefault() ?? "",
                DetectedAt = t.FirstSeen
            }).ToList();
        }

        // ==================== ITabPopulationTarget IMPLEMENTATION ====================

        /// <inheritdoc />
        public async Task PopulateFromCacheAsync(AnalysisResult result)
        {
            DebugLogger.Log($"[ThreatsViewModel.PopulateFromCacheAsync] Populating from cache with {result.Threats.Count:N0} threats, {result.AllPackets.Count:N0} packets");
            await SetFromCacheAsync(result.Threats, result.AllPackets);
        }

        // ==================== GLOBAL FILTER STATE FILTERING ====================

        /// <summary>
        /// Maps abstract UI category names to specific ThreatCategory enum values.
        /// Allows user-friendly filter chips while matching technical threat types.
        /// </summary>
        private static readonly Dictionary<string, HashSet<ThreatCategory>> CategoryMapping = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Network"] = [ThreatCategory.InsecureProtocol, ThreatCategory.UnencryptedService,
                           ThreatCategory.LegacyProtocol, ThreatCategory.Reconnaissance, ThreatCategory.DenialOfService],
            ["Application"] = [ThreatCategory.KnownVulnerability, ThreatCategory.MaliciousActivity,
                               ThreatCategory.CommandAndControl],
            ["Crypto"] = [ThreatCategory.CleartextCredentials, ThreatCategory.DefaultCredentials,
                          ThreatCategory.UnencryptedService],
            ["Exfiltration"] = [ThreatCategory.DataExfiltration],
            ["IoT"] = [ThreatCategory.InsecureProtocol, ThreatCategory.DefaultCredentials],  // IoT often uses insecure protocols
            ["VoIP"] = [ThreatCategory.InsecureProtocol, ThreatCategory.UnencryptedService]  // VoIP security issues
        };

        /// <summary>
        /// Checks if a threat's category matches any of the UI category filters.
        /// Uses CategoryMapping to translate abstract UI categories to specific ThreatCategory enums.
        /// </summary>
        private static bool MatchesCategory(ThreatCategory threatCategory, HashSet<string> uiCategories)
        {
            // First check direct match (in case user passes actual enum names)
            if (uiCategories.Contains(threatCategory.ToString()))
                return true;

            // Then check mapped categories
            foreach (var uiCategory in uiCategories)
            {
                if (CategoryMapping.TryGetValue(uiCategory, out var mappedCategories) &&
                    mappedCategories.Contains(threatCategory))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Applies threat-specific criteria from GlobalFilterState (severity, category filters from UnifiedFilterPanel).
        /// Supports both flat IncludeFilters/ExcludeFilters and AND-grouped IncludeGroups/ExcludeGroups.
        /// </summary>
        private IEnumerable<EnhancedSecurityThreat> ApplyGlobalFilterStateCriteria(IEnumerable<EnhancedSecurityThreat> threats)
        {
            if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
                return threats;

            var result = threats;

            // Use helper to collect all criteria
            var (includeSeverities, includeCategories, excludeSeverities, excludeCategories) =
                GlobalFilterStateHelper.CollectThreatCriteria(_globalFilterState);

            // Apply include severity filter (OR within severities)
            if (includeSeverities.Count > 0)
            {
                result = result.Where(t => includeSeverities.Contains(t.Severity.ToString()));
                HasFiltersApplied = true;
            }

            // Apply include category filter (OR within categories) - uses mapping for UI categories
            if (includeCategories.Count > 0)
            {
                result = result.Where(t => MatchesCategory(t.Category, includeCategories));
                HasFiltersApplied = true;
            }

            // Apply exclude severity filter
            if (excludeSeverities.Count > 0)
            {
                result = result.Where(t => !excludeSeverities.Contains(t.Severity.ToString()));
                HasFiltersApplied = true;
            }

            // Apply exclude category filter - uses mapping for UI categories
            if (excludeCategories.Count > 0)
            {
                result = result.Where(t => !MatchesCategory(t.Category, excludeCategories));
                HasFiltersApplied = true;
            }

            return result;
        }

        // ==================== IDisposable IMPLEMENTATION ====================

        /// <summary>
        /// Disposes managed resources including event subscriptions.
        /// Prevents memory leaks from GlobalFilterState event handlers.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            // Unsubscribe from GlobalFilterState to prevent memory leaks
            if (_globalFilterState is not null)
            {
                _globalFilterState.OnFiltersApplied -= OnGlobalFilterChanged;
            }

            // Unsubscribe from filter service events
            if (_filterService is not null)
            {
                _filterService.FilterChanged -= OnFilterServiceChanged;
            }

            // Unregister from filter copy service
            _filterCopyService?.UnregisterTab(TabName);

            // Unsubscribe from Analysis completion
            if (Analysis is not null)
            {
                Analysis.AnalysisCompleted -= OnAnalysisCompleted;
            }

            // Unsubscribe from DrillDown navigation
            if (DrillDown is not null)
            {
                DrillDown.ViewInPacketAnalysisRequested -= OnDrillDownNavigationRequested;
            }

            DebugLogger.Log("[ThreatsViewModel] Disposed - cleaned up event handlers");
        }
    }
}
