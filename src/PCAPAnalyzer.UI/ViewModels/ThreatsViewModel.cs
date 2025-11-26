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
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.ViewModels.Threats;
using PCAPAnalyzer.UI.Constants;

namespace PCAPAnalyzer.UI.ViewModels
{
    [SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "Threats ViewModel requires coordination of security services, anomaly detection, and visualization components - this is necessary for comprehensive threat analysis")]
    public partial class ThreatsViewModel : SmartFilterableTab, ILazyLoadableTab
    {
        private readonly IInsecurePortDetector _insecurePortDetector;
        private readonly IUnifiedAnomalyDetectionService _anomalyService;
        private readonly ITabFilterService? _filterService;
        private readonly PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? _cacheService;
        private readonly FilterCopyService? _filterCopyService;
    private List<EnhancedSecurityThreat> _allThreats = new();
    private List<SuricataAlert> _suricataAlerts = new();
    private List<YaraMatch> _yaraMatches = new();
        private List<PacketInfo> _currentPackets = new();
        private List<PacketInfo> _unfilteredPackets = new();
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
        /// <summary>
        /// Component ViewModel for all chart visualizations
        /// </summary>
        public ThreatsChartsViewModel Charts { get; }

        /// <summary>
        /// Component ViewModel for full investigation DrillDown
        /// </summary>
        public ThreatsDrillDownViewModel DrillDown { get; } = new();

        /// <summary>
        /// Action to navigate to Packet Analysis tab with frame filter.
        /// Set by MainWindowViewModel to enable cross-tab navigation from DrillDown.
        /// </summary>
        public Action<List<uint>, string>? NavigateToPacketAnalysis { get; set; }

        /// <summary>
        /// Component ViewModel for export functionality (CSV, JSON, HTML)
        /// </summary>
        public ThreatsReportExportViewModel ReportExport { get; }

        /// <summary>
        /// Component ViewModel for threat analysis and caching (NEW - composition pattern)
        /// </summary>
        public ThreatsAnalysisViewModel Analysis { get; }

        /// <summary>
        /// Component ViewModel for quick filter toggles (NEW - composition pattern)
        /// </summary>
        public ThreatsFilterViewModel QuickFilters { get; } = new();

        /// <summary>
        /// Component ViewModel for statistics and table data (NEW - composition pattern)
        /// </summary>
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
        [ObservableProperty] private string _riskLevelColor = "#6B7280";

        [ObservableProperty] private bool _showCriticalOnly;
        [ObservableProperty] private bool _showHighOnly;
        [ObservableProperty] private bool _groupByService;
        [ObservableProperty] private string _selectedCategory = "All";
        [ObservableProperty] private string _selectedThreatType = "All";
        [ObservableProperty] private string _searchFilter = "";
        [ObservableProperty] private ObservableCollection<string> _threatTypes = new();
        [ObservableProperty] private bool _hasFiltersApplied = false;

        // ==================== SORTING ====================
        [ObservableProperty] private string _selectedSortOption = "Severity ▼";
        public ObservableCollection<string> SortOptions { get; } = new()
        {
            "Severity ▼", "Severity ▲", "Time ▼", "Time ▲",
            "Occurrences ▼", "Occurrences ▲", "Source IP", "Dest IP"
        };

        partial void OnSelectedSortOptionChanged(string value)
        {
            UpdateThreatsList();
        }

        // ==================== QUICK FILTER TOGGLES (OR logic within) ====================
        [ObservableProperty] private bool _isInsecureProtocolFilterActive;
        [ObservableProperty] private bool _isKnownCVEFilterActive;
        [ObservableProperty] private bool _isWeakEncryptionFilterActive;
        [ObservableProperty] private bool _isAuthIssuesFilterActive;
        [ObservableProperty] private bool _isCleartextFilterActive;

        /// <summary>
        /// Active quick filter chips displayed below the THREAT FILTERS section (purple theme)
        /// </summary>
        public ObservableCollection<ActiveQuickFilterChip> ActiveQuickFilterChips { get; } = new();

        // Side-by-side table data now managed by Statistics component

        // ==================== FILTERABLE TAB IMPLEMENTATION ====================

        /// <summary>
        /// Common filters for protocol, source IP, and destination IP
        /// </summary>
        public new CommonFilterViewModel CommonFilters { get; } = new();

        /// <summary>
        /// Tab-specific filter: Threat severity filter
        /// </summary>
        [ObservableProperty] private string _severityFilter = "All";

        /// <summary>
        /// Tab-specific filter: Port filter (e.g. "80", "443", "8080")
        /// </summary>
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

        /// <summary>
        /// Unique tab identifier for FilterCopyService
        /// </summary>
        public override string TabName => TabNames.Threats;

        /// <summary>
        /// IFilterableTab implementation - applies common and tab-specific filters
        /// </summary>
        public new void ApplyFilters()
        {
            UpdateThreatsList();
        }

        /// <summary>
        /// Applies the sophisticated PacketFilter to Threats tab's threat list
        /// </summary>
        protected override void ApplySmartFilter(PacketFilter filter)
        {
            // Apply filter to _allThreats list and update threat statistics
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
        [ObservableProperty] private ObservableCollection<string> _detailsVulnerabilities = new();
        [ObservableProperty] private ObservableCollection<string> _detailsMitigations = new();
        [ObservableProperty] private ObservableCollection<string> _affectedEndpoints = new();
        [ObservableProperty] private ObservableCollection<string> _detailsConnections = new();

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
                App.Services?.GetService<IInsecurePortDetector>() ?? new InsecurePortDetector(),
                App.Services?.GetService<IUnifiedAnomalyDetectionService>() ?? new UnifiedAnomalyDetectionService(),
                new TabFilterService("Security Threats", new FilterServiceCore()),
                App.Services?.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>(),
                App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService())
        {
        }

        public ThreatsViewModel(
            IInsecurePortDetector insecurePortDetector,
            IUnifiedAnomalyDetectionService anomalyService,
            ITabFilterService? filterService,
            PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? cacheService = null,
            ISmartFilterBuilder? filterBuilder = null)
            : base(filterBuilder ?? new SmartFilterBuilderService())
        {
            _insecurePortDetector = insecurePortDetector;
            _anomalyService = anomalyService;
            _filterService = filterService;
            _cacheService = cacheService;
            _filterCopyService = App.Services?.GetService<FilterCopyService>();

            // Initialize component ViewModels (Dashboard composition pattern)
            Charts = new ThreatsChartsViewModel(insecurePortDetector);
            ReportExport = new ThreatsReportExportViewModel(Charts);
            Analysis = new ThreatsAnalysisViewModel(insecurePortDetector, anomalyService, cacheService);

            // Wire up Analysis completion event
            Analysis.AnalysisCompleted += OnAnalysisCompleted;

            // Wire up QuickFilters change event
            QuickFilters.FiltersChanged += () => UpdateThreatsList();

            // Subscribe to filter changes
            if (_filterService != null)
            {
                _filterService.FilterChanged += OnFilterServiceChanged;
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
        
        private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
        {
            // When filter changes and we have packets, reprocess threats
            if (_unfilteredPackets != null && _unfilteredPackets.Any())
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
            if (_loadingTask != null)
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

            _currentPackets = packets.ToList();
            _unfilteredPackets = _currentPackets;
            _lastAnalyzedPacketCount = packets.Count;
            _lastFilterState = false;

            // Calculate metrics from cached threats
            _metrics = _insecurePortDetector.CalculateSecurityMetrics(_allThreats);

            // Update UI (handles metrics, collections, charts)
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => UpdateUI());

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

        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Complex threat detection requires filtering, caching, parallel batching, anomaly detection, and UI updates - justified for performance optimization")]
        public async Task UpdateThreatsAsync(IReadOnlyList<PacketInfo> packets)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] UpdateThreatsAsync starting with {packets.Count:N0} packets");

            // Prevent concurrent analysis
            if (_isAnalyzing)
            {
                DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] Analysis already in progress, skipping redundant call");
                return;
            }

            var startTime = DateTime.Now;

            // Store unfiltered packets (can do on any thread)
            _unfilteredPackets = packets as List<PacketInfo> ?? packets.ToList();

            // Apply filter if filter service is available and active
            var isFilterActive = _filterService?.IsFilterActive == true;
            _currentPackets = isFilterActive
                ? _filterService!.GetFilteredPackets(_unfilteredPackets).ToList()
                : _unfilteredPackets;

            // OPTIMIZATION: Skip analysis if packets and filter state unchanged
            var currentPacketCount = _currentPackets.Count;
            if (_lastAnalyzedPacketCount == currentPacketCount &&
                _lastFilterState == isFilterActive &&
                _allThreats.Count > 0)
            {
                DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] Skipping analysis - already analyzed {currentPacketCount:N0} packets with filter={isFilterActive}");
                return;
            }

            _isAnalyzing = true;

            // Show initial UI with loading state (dispatch to UI thread)
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                TotalThreats = 0;
                OverallRiskScore = 0;
                RiskLevel = "Analyzing...";
                RiskLevelColor = "#6B7280";
            });

            // TRY CACHE FIRST - delegate to Analysis component
            if (await Analysis.TryLoadFromCacheAsync(currentPacketCount, isFilterActive))
            {
                _isAnalyzing = false;
                return; // OnAnalysisCompleted will update UI
            }

            // PERFORMANCE OPTIMIZATION: Parallel batch processing for large packet sets
            // Old approach: Sequential processing of all packets (219s for 5.8M packets)
            // New approach: Parallel batch processing with 100k packet chunks (expected 44s - 5x faster)
            await Task.Run(async () =>
            {
                DebugLogger.Log($"[ThreatsViewModel] Starting PARALLEL threat detection on background thread...");
                var workingSet = _currentPackets ?? _unfilteredPackets;
                DebugLogger.Log($"[ThreatsViewModel] Analyzing {workingSet.Count:N0} packets for threats...");

                const int BATCH_SIZE = 100_000; // Process 100k packets per batch
                var allThreatsCollection = new System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat>();

                // Optimize for large datasets (>500k packets) with parallel processing
                if (workingSet.Count > 500_000)
                {
                    DebugLogger.Log($"[ThreatsViewModel] Large dataset detected - using parallel batch processing (batch size: {BATCH_SIZE:N0})");

                    // OPTIMIZATION: Pre-filter for version detection ONCE before batching (not per-batch)
                    // Previous: Filtered 12 times inside each batch (1.2M × 12 = 14.4M filter operations)
                    // Optimized: Filter once globally (1.2M filter operations)
                    var monitoredPorts = new HashSet<int> { 21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443 };
                    var versionCheckPackets = workingSet.Where(p => monitoredPorts.Contains(p.DestinationPort) || monitoredPorts.Contains(p.SourcePort)).ToList();
                    DebugLogger.Log($"[ThreatsViewModel] Pre-filtered {versionCheckPackets.Count:N0} packets for version detection (monitored ports only)");

                    // Split packets into batches
                    var batches = new List<List<PacketInfo>>();
                    var versionBatches = new List<List<PacketInfo>>();
                    for (int i = 0; i < workingSet.Count; i += BATCH_SIZE)
                    {
                        var batchSize = Math.Min(BATCH_SIZE, workingSet.Count - i);
                        batches.Add(workingSet.GetRange(i, batchSize));
                    }
                    for (int i = 0; i < versionCheckPackets.Count; i += BATCH_SIZE)
                    {
                        var batchSize = Math.Min(BATCH_SIZE, versionCheckPackets.Count - i);
                        versionBatches.Add(versionCheckPackets.GetRange(i, batchSize));
                    }

                    DebugLogger.Log($"[ThreatsViewModel] Created {batches.Count} full batches + {versionBatches.Count} version check batches for parallel processing");

                    // Process insecure ports batches in parallel
                    var processedBatches = 0;
                    await Parallel.ForEachAsync(batches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                        async (batch, cancellationToken) =>
                        {
                            // OPTIMIZED: Detect insecure ports only (version detection done separately with pre-filtered packets)
                            var batchPortThreats = _insecurePortDetector.DetectInsecurePorts(batch);
                            var batchAnomalies = await _anomalyService.DetectAllAnomaliesAsync(batch);

                            // Add all detected threats to concurrent collection
                            foreach (var threat in batchPortThreats)
                                allThreatsCollection.Add(threat);

                            // Convert anomalies to threats
                            foreach (var anomaly in batchAnomalies.Where(a => a.Severity >= AnomalySeverity.Medium))
                            {
                                allThreatsCollection.Add(new EnhancedSecurityThreat
                                {
                                    Category = MapAnomalyCategory(anomaly.Category),
                                    Severity = MapAnomalySeverity(anomaly.Severity),
                                    ThreatName = anomaly.Type,
                                    Description = anomaly.Description,
                                    FirstSeen = anomaly.DetectedAt,
                                    LastSeen = anomaly.DetectedAt,
                                    OccurrenceCount = 1,
                                    RiskScore = anomaly.Severity == AnomalySeverity.Critical ? 9 :
                                               anomaly.Severity == AnomalySeverity.High ? 7 : 5,
                                    AffectedIPs = new List<string> { anomaly.SourceIP, anomaly.DestinationIP }
                                        .Where(ip => !string.IsNullOrEmpty(ip))
                                        .Distinct()
                                        .ToList()
                                });
                            }

                            var completed = System.Threading.Interlocked.Increment(ref processedBatches);
                            var progress = (completed * 100.0) / batches.Count;
                            // Log only at 25%, 50%, 75%, 100% milestones (reduced verbosity)
                            if ((progress >= 24.5 && progress < 26) ||
                                (progress >= 49.5 && progress < 51) ||
                                (progress >= 74.5 && progress < 76) ||
                                completed == batches.Count)
                            {
                                DebugLogger.Log($"[Threats] {progress:F0}% ({completed}/{batches.Count} batches) - {allThreatsCollection.Count:N0} threats");
                            }

                            await Task.CompletedTask;
                        });

                    // Process version detection batches in parallel (using pre-filtered packets)
                    if (versionCheckPackets.Count > 0)
                    {
                        DebugLogger.Log($"[ThreatsViewModel] Starting parallel version detection on {versionBatches.Count} pre-filtered batches...");
                        await Parallel.ForEachAsync(versionBatches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                            async (batch, cancellationToken) =>
                            {
                                var versionThreats = _insecurePortDetector.DetectInsecureVersions(batch);
                                foreach (var threat in versionThreats)
                                    allThreatsCollection.Add(threat);
                                await Task.CompletedTask;
                            });
                        DebugLogger.Log($"[ThreatsViewModel] Version detection complete");
                    }

                    _allThreats = allThreatsCollection.ToList();
                    DebugLogger.Log($"[ThreatsViewModel] Parallel processing complete - {_allThreats.Count:N0} total threats detected");
                }
                else
                {
                    // Sequential processing for smaller datasets (already fast enough)
                    DebugLogger.Log($"[ThreatsViewModel] Small dataset - using sequential processing");

                    DebugLogger.Log($"[ThreatsViewModel] Detecting insecure ports...");
                    _allThreats = _insecurePortDetector.DetectInsecurePorts(workingSet);
                    DebugLogger.Log($"[ThreatsViewModel] Found {_allThreats.Count} insecure port threats");

                    DebugLogger.Log($"[ThreatsViewModel] Detecting insecure versions...");
                    var versionThreats = _insecurePortDetector.DetectInsecureVersions(workingSet);
                    _allThreats.AddRange(versionThreats);
                    DebugLogger.Log($"[ThreatsViewModel] Total threats after version check: {_allThreats.Count}");

                    DebugLogger.Log($"[ThreatsViewModel] Detecting anomalies...");
                    var anomalies = await _anomalyService.DetectAllAnomaliesAsync(workingSet);
                    DebugLogger.Log($"[ThreatsViewModel] Found {anomalies.Count} anomalies");

                    foreach (var anomaly in anomalies.Where(a => a.Severity >= AnomalySeverity.Medium))
                    {
                        _allThreats.Add(new EnhancedSecurityThreat
                        {
                            Category = MapAnomalyCategory(anomaly.Category),
                            Severity = MapAnomalySeverity(anomaly.Severity),
                            ThreatName = anomaly.Type,
                            Description = anomaly.Description,
                            FirstSeen = anomaly.DetectedAt,
                            LastSeen = anomaly.DetectedAt,
                            OccurrenceCount = 1,
                            RiskScore = anomaly.Severity == AnomalySeverity.Critical ? 9 :
                                       anomaly.Severity == AnomalySeverity.High ? 7 : 5,
                            AffectedIPs = new List<string> { anomaly.SourceIP, anomaly.DestinationIP }
                                .Where(ip => !string.IsNullOrEmpty(ip))
                                .Distinct()
                                .ToList()
                        });
                    }
                }

                // Ensure all threats have valid risk scores
                foreach (var threat in _allThreats.Where(t => t.RiskScore == 0))
                {
                    threat.RiskScore = threat.Severity switch
                    {
                        ThreatSeverity.Critical => 9.0,
                        ThreatSeverity.High => 7.0,
                        ThreatSeverity.Medium => 5.0,
                        ThreatSeverity.Low => 3.0,
                        _ => 1.0
                    };
                }

                _metrics = _insecurePortDetector.CalculateSecurityMetrics(_allThreats);

                var analysisElapsed = (DateTime.Now - startTime).TotalSeconds;
                DebugLogger.Log($"[ThreatsViewModel] Threat analysis complete in {analysisElapsed:F2}s - {_allThreats.Count:N0} total threats");
            });

            // Update UI on UI thread (only after all heavy work is done)
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => UpdateUI());

            // SAVE TO CACHE - delegate to Analysis component
            Analysis.TrySaveToCache();

            // Update cache tracking
            _lastAnalyzedPacketCount = currentPacketCount;
            _lastFilterState = isFilterActive;
            _isAnalyzing = false;

            var totalElapsed = (DateTime.Now - startTime).TotalSeconds;
            var endTimestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{endTimestamp}] [ThreatsViewModel] UpdateThreatsAsync complete in {totalElapsed:F2}s");
        }

    /// <summary>
    /// Adds Suricata alerts to threat list - delegates to Analysis component
    /// </summary>
    public void SetSuricataAlerts(List<SuricataAlert> alerts)
    {
        _suricataAlerts = alerts;
        if (alerts == null || alerts.Count == 0) return;

        // Delegate to Analysis component - OnAnalysisCompleted will sync _allThreats and update UI
        Analysis.AddSuricataAlerts(alerts);
    }

    /// <summary>
    /// Adds YARA matches to threat list - delegates to Analysis component
    /// </summary>
    public void SetYaraMatches(List<YaraMatch> matches)
    {
        _yaraMatches = matches;
        if (matches == null || matches.Count == 0) return;

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
            if (_metrics == null) return;

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
                RiskLevelColor = "#EF4444";
            }
            else if (OverallRiskScore >= 6)
            {
                RiskLevel = "HIGH";
                RiskLevelColor = "#F97316";
            }
            else if (OverallRiskScore >= 4)
            {
                RiskLevel = "MEDIUM";
                RiskLevelColor = "#F59E0B";
            }
            else if (OverallRiskScore >= 2)
            {
                RiskLevel = "LOW";
                RiskLevelColor = "#3B82F6";
            }
            else
            {
                RiskLevel = "MINIMAL";
                RiskLevelColor = "#10B981";
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
            
            ThreatTypes.Clear();
            ThreatTypes.Add("All");
            
            foreach (var threatType in uniqueThreatTypes)
            {
                ThreatTypes.Add(threatType);
            }
        }

        /// <summary>
        /// Updates the active quick filter chips collection based on which quick filters are enabled.
        /// Creates visual chips with emoji, label, and remove command.
        /// </summary>
        private void UpdateActiveQuickFilterChips()
        {
            ActiveQuickFilterChips.Clear();

            if (IsInsecureProtocolFilterActive)
            {
                ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
                {
                    Emoji = "🔓",
                    DisplayLabel = "Insecure Protocol",
                    RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                    {
                        IsInsecureProtocolFilterActive = false;
                        ApplyFilters();
                    })
                });
            }

            if (IsKnownCVEFilterActive)
            {
                ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
                {
                    Emoji = "🛡️",
                    DisplayLabel = "Known CVEs",
                    RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                    {
                        IsKnownCVEFilterActive = false;
                        ApplyFilters();
                    })
                });
            }

            if (IsWeakEncryptionFilterActive)
            {
                ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
                {
                    Emoji = "🔐",
                    DisplayLabel = "Weak Encryption",
                    RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                    {
                        IsWeakEncryptionFilterActive = false;
                        ApplyFilters();
                    })
                });
            }

            if (IsAuthIssuesFilterActive)
            {
                ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
                {
                    Emoji = "🔑",
                    DisplayLabel = "Auth Issues",
                    RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                    {
                        IsAuthIssuesFilterActive = false;
                        ApplyFilters();
                    })
                });
            }

            if (IsCleartextFilterActive)
            {
                ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
                {
                    Emoji = "📝",
                    DisplayLabel = "Cleartext",
                    RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                    {
                        IsCleartextFilterActive = false;
                        ApplyFilters();
                    })
                });
            }

            // Notify UI that chip count changed for IsVisible binding
            OnPropertyChanged(nameof(ActiveQuickFilterChips));
        }

        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Threat list update requires processing multiple threat categories, severity levels, filtering criteria, grouping logic, and aggregation operations")]
        private void UpdateThreatsList()
        {
            // Update active filter chips display
            UpdateActiveQuickFilterChips();
            // Check if any filters are applied (includes quick filter toggles)
            HasFiltersApplied = CommonFilters.HasActiveFilters ||
                               ShowCriticalOnly || ShowHighOnly ||
                               SeverityFilter != "All" ||
                               SelectedCategory != "All" ||
                               SelectedThreatType != "All" ||
                               !string.IsNullOrWhiteSpace(SearchFilter) ||
                               !string.IsNullOrWhiteSpace(PortFilter) ||
                               IsInsecureProtocolFilterActive || IsKnownCVEFilterActive ||
                               IsWeakEncryptionFilterActive || IsAuthIssuesFilterActive ||
                               IsCleartextFilterActive;

            var filteredThreats = _allThreats.AsEnumerable();

            // Apply common filters first
            if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            {
                filteredThreats = filteredThreats.Where(t =>
                    t.Protocol?.Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            }

            if (!string.IsNullOrWhiteSpace(CommonFilters.SourceIPFilter))
            {
                filteredThreats = filteredThreats.Where(t =>
                    t.AffectedIPs?.Any(ip => ip.Contains(CommonFilters.SourceIPFilter, StringComparison.OrdinalIgnoreCase)) ?? false);
            }

            if (!string.IsNullOrWhiteSpace(CommonFilters.DestinationIPFilter))
            {
                filteredThreats = filteredThreats.Where(t =>
                    t.AffectedIPs?.Any(ip => ip.Contains(CommonFilters.DestinationIPFilter, StringComparison.OrdinalIgnoreCase)) ?? false);
            }

            // Port filter
            if (!string.IsNullOrWhiteSpace(PortFilter))
            {
                filteredThreats = filteredThreats.Where(t =>
                    t.Port.ToString().Contains(PortFilter, StringComparison.OrdinalIgnoreCase));
            }

            // Apply tab-specific filters
            if (SeverityFilter != "All")
            {
                var severityEnum = Enum.Parse<ThreatSeverity>(SeverityFilter);
                filteredThreats = filteredThreats.Where(t => t.Severity == severityEnum);
            }
            else if (ShowCriticalOnly)
            {
                filteredThreats = filteredThreats.Where(t => t.Severity == ThreatSeverity.Critical);
            }
            else if (ShowHighOnly)
            {
                filteredThreats = filteredThreats.Where(t => t.Severity >= ThreatSeverity.High);
            }

            if (SelectedCategory != "All")
                filteredThreats = filteredThreats.Where(t => t.Category.ToString() == SelectedCategory);

            if (SelectedThreatType != "All")
                filteredThreats = filteredThreats.Where(t => t.ThreatName == SelectedThreatType);

            if (!string.IsNullOrWhiteSpace(SearchFilter))
                filteredThreats = filteredThreats.Where(t =>
                    t.ThreatName.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ||
                    t.Description.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ||
                    t.Service.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase));

            // Quick Filter Toggles (OR logic - delegated to QuickFilters component)
            if (QuickFilters.HasActiveQuickFilters)
            {
                filteredThreats = filteredThreats.Where(t =>
                    (IsInsecureProtocolFilterActive && ThreatsFilterViewModel.IsInsecureProtocolThreat(t)) ||
                    (IsKnownCVEFilterActive && ThreatsFilterViewModel.IsKnownCVEThreat(t)) ||
                    (IsWeakEncryptionFilterActive && ThreatsFilterViewModel.IsWeakEncryptionThreat(t)) ||
                    (IsAuthIssuesFilterActive && ThreatsFilterViewModel.IsAuthIssueThreat(t)) ||
                    (IsCleartextFilterActive && ThreatsFilterViewModel.IsCleartextThreat(t)));
            }

            // Aggregate similar threats if grouping is enabled
            var threatsList = filteredThreats.ToList();

            if (GroupByService && threatsList.Any())
            {
                // Group similar threats together
                var groupedThreats = threatsList
                    .GroupBy(t => new { t.ThreatName, t.Service, t.Port, t.Severity })
                    .Select(g =>
                    {
                        var first = g.First();
                        first.OccurrenceCount = g.Count();
                        first.AffectedIPs = g.SelectMany(t => t.AffectedIPs ?? new List<string>()).Distinct().ToList();
                        first.Description = g.Count() > 1
                            ? $"{first.Description} (Aggregated: {g.Count()} occurrences)"
                            : first.Description;
                        return first;
                    })
                    .ToList();
                threatsList = groupedThreats;
            }

            // ==================== APPLY SORTING ====================
            threatsList = ApplySorting(threatsList);

            // ==================== RECALCULATE METRICS FROM FILTERED THREATS ====================
            // Issue Fix: Stats and charts should reflect filtered threats, not all threats
            if (HasFiltersApplied && threatsList.Any())
            {
                // Recalculate SecurityMetrics from filtered threat list
                var filteredMetrics = _insecurePortDetector.CalculateSecurityMetrics(threatsList);

                // Update stats with filtered values
                TotalThreats = filteredMetrics.TotalThreats;
                CriticalThreats = filteredMetrics.CriticalThreats;
                HighThreats = filteredMetrics.HighThreats;
                MediumThreats = filteredMetrics.MediumThreats;
                LowThreats = filteredMetrics.LowThreats;
                OverallRiskScore = Math.Round(filteredMetrics.OverallRiskScore, 2);
                UpdateRiskLevel(); // Update risk level badge based on filtered score

                // Update charts with filtered threat data
                Charts.UpdateAllCharts(threatsList, filteredMetrics, CriticalThreats, HighThreats, MediumThreats, LowThreats);
                OnPropertyChanged(nameof(ThreatSeveritySeries));
                OnPropertyChanged(nameof(ThreatTimelineSeries));
                OnPropertyChanged(nameof(PortRiskSeries));
                OnPropertyChanged(nameof(ThreatCategorySeries));
                OnPropertyChanged(nameof(XAxes));
                OnPropertyChanged(nameof(YAxes));
                OnPropertyChanged(nameof(PeakThreatRate));
                OnPropertyChanged(nameof(AverageThreatRate));
            }
            else if (!HasFiltersApplied && _metrics != null)
            {
                // No filters active - use original unfiltered metrics
                TotalThreats = _metrics.TotalThreats;
                CriticalThreats = _metrics.CriticalThreats;
                HighThreats = _metrics.HighThreats;
                MediumThreats = _metrics.MediumThreats;
                LowThreats = _metrics.LowThreats;
                OverallRiskScore = Math.Round(_metrics.OverallRiskScore, 2);
                UpdateRiskLevel();

                // Update charts with all threats
                Charts.UpdateAllCharts(_allThreats, _metrics, CriticalThreats, HighThreats, MediumThreats, LowThreats);
                OnPropertyChanged(nameof(ThreatSeveritySeries));
                OnPropertyChanged(nameof(ThreatTimelineSeries));
                OnPropertyChanged(nameof(PortRiskSeries));
                OnPropertyChanged(nameof(ThreatCategorySeries));
                OnPropertyChanged(nameof(XAxes));
                OnPropertyChanged(nameof(YAxes));
                OnPropertyChanged(nameof(PeakThreatRate));
                OnPropertyChanged(nameof(AverageThreatRate));
            }
            
            var securityThreatItems = new List<SecurityThreatItemViewModel>();
            // Calculate total occurrences for proper percentage calculation
            var totalOccurrences = threatsList.Sum(t => t.OccurrenceCount);
            var rank = 1;
            foreach (var threat in threatsList)
            {
                var item = new SecurityThreatItemViewModel
                {
                    Id = threat.Id,
                    Rank = rank++,
                    ThreatName = threat.ThreatName,
                    Category = threat.Category.ToString(),
                    Severity = threat.Severity.ToString(),
                    SeverityColor = GetSeverityColor(threat.Severity),
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
                    // Fixed: Percentage based on occurrence count relative to total occurrences
                    Percentage = totalOccurrences > 0 ? (threat.OccurrenceCount / (double)totalOccurrences) * 100 : 0
                };

                // Add version information if available
                if (threat.Metadata != null)
                {
                    if (threat.Metadata.ContainsKey("DetectedVersion"))
                        item.DetectedVersion = threat.Metadata["DetectedVersion"]?.ToString() ?? "";
                    if (threat.Metadata.ContainsKey("IsEncryptedButInsecure"))
                        item.IsEncryptedButInsecure = (bool)threat.Metadata["IsEncryptedButInsecure"];

                    // Extract source and destination IPs from metadata
                    if (threat.Metadata.ContainsKey("SourceIPs"))
                    {
                        if (threat.Metadata["SourceIPs"] is List<string> srcList)
                            item.SourceIPs = srcList;
                        else if (threat.Metadata["SourceIPs"] is IEnumerable<object> srcObjs)
                            item.SourceIPs = srcObjs.Select(o => o?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s)).ToList();
                    }

                    if (threat.Metadata.ContainsKey("DestinationIPs"))
                    {
                        if (threat.Metadata["DestinationIPs"] is List<string> dstList)
                            item.DestinationIPs = dstList;
                        else if (threat.Metadata["DestinationIPs"] is IEnumerable<object> dstObjs)
                            item.DestinationIPs = dstObjs.Select(o => o?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s)).ToList();
                    }

                    // Extract connections if available
                    if (threat.Metadata.ContainsKey("Connections"))
                    {
                        if (threat.Metadata["Connections"] is List<(string, string)> connList)
                            item.Connections = connList;
                    }
                }

                // If no specific IPs in metadata, try to extract from AffectedIPs
                if (!item.SourceIPs.Any() && !item.DestinationIPs.Any() && threat.AffectedIPs.Any())
                {
                    // For backward compatibility, split AffectedIPs between source and destination
                    var halfCount = threat.AffectedIPs.Count / 2;
                    item.SourceIPs = threat.AffectedIPs.Take(halfCount).ToList();
                    item.DestinationIPs = threat.AffectedIPs.Skip(halfCount).ToList();

                    // Create connections from the IPs
                    for (int i = 0; i < Math.Min(item.SourceIPs.Count, item.DestinationIPs.Count); i++)
                    {
                        item.Connections.Add((item.SourceIPs[i], item.DestinationIPs[i]));
                    }
                }

                securityThreatItems.Add(item);
            }

            // Update pagination using the new wrapper
            SecurityThreatsPagination.SetItems(securityThreatItems);

            // Update side-by-side table data (delegated to Statistics component)
            Statistics.UpdateTableData(_allThreats);
        }

        /// <summary>
        /// Applies the selected sort option to the threat list
        /// </summary>
        private List<EnhancedSecurityThreat> ApplySorting(List<EnhancedSecurityThreat> threats)
        {
            if (!threats.Any()) return threats;

            return SelectedSortOption switch
            {
                "Severity ▼" => threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList(),
                "Severity ▲" => threats.OrderBy(t => t.Severity).ThenBy(t => t.RiskScore).ToList(),
                "Time ▼" => threats.OrderByDescending(t => t.LastSeen).ToList(),
                "Time ▲" => threats.OrderBy(t => t.FirstSeen).ToList(),
                "Occurrences ▼" => threats.OrderByDescending(t => t.OccurrenceCount).ToList(),
                "Occurrences ▲" => threats.OrderBy(t => t.OccurrenceCount).ToList(),
                "Source IP" => threats.OrderBy(t => t.AffectedIPs.FirstOrDefault() ?? "").ToList(),
                "Dest IP" => threats.OrderBy(t => t.AffectedIPs.Skip(1).FirstOrDefault() ?? "").ToList(),
                _ => threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList()
            };
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
                    RiskColor = GetSeverityColor(profile.RiskLevel),
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

            if (enhancedThreat != null)
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
                if (NavigateToPacketAnalysis == null)
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

        // ==================== EXPORT (Delegated to ReportExport component) ====================

        /// <summary>
        /// Exports Top Affected Ports (by Count) to CSV file.
        /// </summary>
        [RelayCommand]
        private async Task ExportPortsByCount()
        {
            await ExportTableToCsvAsync("threats_ports_by_count.csv",
                new[] { "Rank", "Port", "Protocol", "Service", "Percentage", "ThreatCount" },
                Statistics.TopAffectedPortsByCount.Select(p => new[] { p.Rank.ToString(), p.Port.ToString(), p.Protocol, p.ServiceName, $"{p.Percentage:F1}%", p.ThreatCount.ToString() }));
        }

        /// <summary>
        /// Exports Top Affected Ports (by Severity) to CSV file.
        /// </summary>
        [RelayCommand]
        private async Task ExportPortsBySeverity()
        {
            await ExportTableToCsvAsync("threats_ports_by_severity.csv",
                new[] { "Rank", "Port", "Protocol", "Service", "Percentage", "SeverityScore" },
                Statistics.TopAffectedPortsBySeverity.Select(p => new[] { p.Rank.ToString(), p.Port.ToString(), p.Protocol, p.ServiceName, $"{p.Percentage:F1}%", $"{p.SeverityScore:F1}" }));
        }

        /// <summary>
        /// Exports Top Source IPs to CSV file.
        /// </summary>
        [RelayCommand]
        private async Task ExportSourceIPs()
        {
            await ExportTableToCsvAsync("threats_source_ips.csv",
                new[] { "Rank", "Address", "Country", "Percentage", "ThreatCount" },
                Statistics.TopSourceIPs.Select(ip => new[] { ip.Rank.ToString(), ip.Address, ip.Country, $"{ip.Percentage:F1}%", ip.ThreatCount.ToString() }));
        }

        /// <summary>
        /// Exports Top Destination IPs to CSV file.
        /// </summary>
        [RelayCommand]
        private async Task ExportDestinationIPs()
        {
            await ExportTableToCsvAsync("threats_dest_ips.csv",
                new[] { "Rank", "Address", "Country", "Percentage", "ThreatCount" },
                Statistics.TopDestinationIPs.Select(ip => new[] { ip.Rank.ToString(), ip.Address, ip.Country, $"{ip.Percentage:F1}%", ip.ThreatCount.ToString() }));
        }

        /// <summary>
        /// Generic CSV export helper for table data.
        /// </summary>
        private async Task ExportTableToCsvAsync(string filename, string[] headers, IEnumerable<string[]> rows)
        {
            try
            {
                var saveFileDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
                {
                    Title = "Export Table to CSV",
                    SuggestedFileName = filename,
                    FileTypeChoices = new[]
                    {
                        new Avalonia.Platform.Storage.FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } }
                    }
                };

                var topLevel = Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow
                    : null;

                if (topLevel == null)
                {
                    DebugLogger.Log("[ThreatsViewModel] Export failed - no main window found");
                    return;
                }

                var storageProvider = topLevel.StorageProvider;
                var file = await storageProvider.SaveFilePickerAsync(saveFileDialog);

                if (file == null) return;

                await using var stream = await file.OpenWriteAsync();
                await using var writer = new System.IO.StreamWriter(stream);

                // Write header
                await writer.WriteLineAsync(string.Join(",", headers));

                // Write rows
                foreach (var row in rows)
                {
                    var escapedRow = row.Select(v => v?.Contains(',', StringComparison.Ordinal) == true ? $"\"{v}\"" : v);
                    await writer.WriteLineAsync(string.Join(",", escapedRow));
                }

                DebugLogger.Log($"[ThreatsViewModel] Exported {filename} successfully");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsViewModel] Export error: {ex.Message}");
            }
        }

        /// <summary>
        /// Opens export dialog - delegates to ThreatsReportExportViewModel.
        /// Supports CSV, JSON, and full HTML Investigation Dossier.
        /// </summary>
        [RelayCommand]
        private async Task ExportThreats()
        {
            // Delegate to ReportExport component (Dashboard composition pattern)
            // Use the generated command from [RelayCommand] attribute
            if (ReportExport.ExportAllCommand.CanExecute(null))
            {
                await ReportExport.ExportAllCommand.ExecuteAsync(null);
            }
            DebugLogger.Log("[ThreatsViewModel] Export completed via ReportExport component");
        }

        private string GetSeverityColor(ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Critical => "#EF4444",
                ThreatSeverity.High => "#F97316",
                ThreatSeverity.Medium => "#F59E0B",
                ThreatSeverity.Low => "#3B82F6",
                ThreatSeverity.Info => "#6B7280",
                _ => "#6B7280"
            };
        }

        private ThreatSeverity MapAnomalySeverity(AnomalySeverity anomalySeverity)
        {
            return anomalySeverity switch
            {
                AnomalySeverity.Critical => ThreatSeverity.Critical,
                AnomalySeverity.High => ThreatSeverity.High,
                AnomalySeverity.Medium => ThreatSeverity.Medium,
                AnomalySeverity.Low => ThreatSeverity.Low,
                _ => ThreatSeverity.Info
            };
        }

        private ThreatCategory MapAnomalyCategory(AnomalyCategory anomalyCategory)
        {
            return anomalyCategory switch
            {
                AnomalyCategory.Network => ThreatCategory.MaliciousActivity,
                AnomalyCategory.TCP => ThreatCategory.MaliciousActivity,
                AnomalyCategory.Application => ThreatCategory.MaliciousActivity,
                AnomalyCategory.Security => ThreatCategory.KnownVulnerability,
                AnomalyCategory.Malformed => ThreatCategory.MaliciousActivity,
                _ => ThreatCategory.MaliciousActivity
            };
        }

        partial void OnShowCriticalOnlyChanged(bool value)
        {
            // Mutual exclusion: Critical and High+ are mutually exclusive
            if (value) ShowHighOnly = false;
            // Note: Requires Apply button - no auto-update
        }

        partial void OnShowHighOnlyChanged(bool value)
        {
            // Mutual exclusion: High+ and Critical are mutually exclusive
            if (value) ShowCriticalOnly = false;
            // Note: Requires Apply button - no auto-update
        }

        partial void OnSelectedCategoryChanged(string value)
        {
            // Note: Requires Apply button - no auto-update
        }
        
        partial void OnSelectedThreatTypeChanged(string value)
        {
            // Note: Requires Apply button - no auto-update
        }

        partial void OnSearchFilterChanged(string value)
        {
            // Note: Requires Apply button - no auto-update
        }

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
    }

    public class SecurityThreatItemViewModel : ObservableObject
    {
        public string Id { get; set; } = "";
        public int Rank { get; set; }
        public string ThreatName { get; set; } = "";
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "";
        public string SeverityColor { get; set; } = "#6B7280";
        public string Service { get; set; } = "";
        public int Port { get; set; }
        public double RiskScore { get; set; }
        public int OccurrenceCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public string Description { get; set; } = "";
        public List<string> Vulnerabilities { get; set; } = new();
        public List<string> Mitigations { get; set; } = new();
        public List<string> AffectedIPs { get; set; } = new();
        public string DetectedVersion { get; set; } = "";
        public bool IsEncryptedButInsecure { get; set; }
        public List<string> SourceIPs { get; set; } = new();
        public List<string> DestinationIPs { get; set; } = new();
        /// <summary>
        /// Percentage of total threats this item represents (for percentage bar display).
        /// </summary>
        public double Percentage { get; set; }
        public List<(string Source, string Destination)> Connections { get; set; } = new();
    }

    public class InsecurePortItemViewModel : ObservableObject
    {
        public int Port { get; set; }
        public string ServiceName { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string RiskLevel { get; set; } = "";
        public string RiskColor { get; set; } = "#6B7280";
        public bool IsEncrypted { get; set; }
        public int DetectedPackets { get; set; }
        public bool IsActive { get; set; }
        public string RecommendedAlternative { get; set; } = "";
        public string SecurityNotes { get; set; } = "";
        public bool RequiresAction { get; set; }
        public string StatusIcon => IsActive ? "⚠️" : "✓";
        public string StatusText => IsActive ? "DETECTED" : "Not Detected";
        public string EncryptionIcon => IsEncrypted ? "🔒" : "🔓";
        public string EncryptionText => IsEncrypted ? "Encrypted" : "UNENCRYPTED";
    }

    /// <summary>
    /// Represents an active quick filter chip displayed in the purple-themed active filters section.
    /// Includes emoji, label, and remove command for interactive filter management.
    /// </summary>
    public class ActiveQuickFilterChip : ObservableObject
    {
        /// <summary>
        /// Emoji icon displayed on the chip (e.g., 🔓, 🛡️, 🔐)
        /// </summary>
        public string Emoji { get; set; } = "";

        /// <summary>
        /// Display label for the filter (e.g., "Insecure Protocol", "Known CVEs")
        /// </summary>
        public string DisplayLabel { get; set; } = "";

        /// <summary>
        /// Command to remove this filter chip (clears the corresponding toggle and reapplies filters)
        /// </summary>
        public IRelayCommand? RemoveCommand { get; set; }
    }
}
