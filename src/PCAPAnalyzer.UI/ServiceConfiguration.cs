using System;
using System.IO;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PCAPAnalyzer.Core.Caching;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Configuration.Options;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.Caching;
using PCAPAnalyzer.Core.Services.Capture;
using PCAPAnalyzer.Core.Services.GeoIP;
using PCAPAnalyzer.Core.Services.Reporting;
using PCAPAnalyzer.Core.Services.Statistics;
using PCAPAnalyzer.TShark;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.ViewModels.Capture;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI
{
    /// <summary>
    /// Configures dependency injection for the application.
    /// Centralizes service registration for better maintainability.
    /// </summary>
    public static class ServiceConfiguration
    {
        /// <summary>
        /// Configure and build the service provider
        /// </summary>
        public static IServiceProvider ConfigureServices()
        {
            var services = new ServiceCollection();

            // Build configuration from JSON files
            var configuration = BuildConfiguration();
            services.AddSingleton<IConfiguration>(configuration);

            // Register Configuration Options (IOptions<T> pattern)
            RegisterConfigurationOptions(services, configuration);

            // Register Core Services
            RegisterCoreServices(services);

            // Register Reporting Services
            RegisterReportingServices(services);

            // Register UI Services
            RegisterUIServices(services);

            // Register ViewModels
            RegisterViewModels(services);

            return services.BuildServiceProvider();
        }

        /// <summary>
        /// Build configuration from JSON files in config/ directory.
        /// </summary>
        private static IConfiguration BuildConfiguration()
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config");

            var builder = new ConfigurationBuilder()
                .SetBasePath(configPath);

            // Add each config file if it exists (optional - won't fail if missing)
            AddJsonFileIfExists(builder, configPath, "ports.json");
            AddJsonFileIfExists(builder, configPath, "countries.json");
            AddJsonFileIfExists(builder, configPath, "timeouts.json");
            AddJsonFileIfExists(builder, configPath, "protocols.json");

            return builder.Build();
        }

        private static void AddJsonFileIfExists(IConfigurationBuilder builder, string configPath, string fileName)
        {
            var filePath = Path.Combine(configPath, fileName);
            if (File.Exists(filePath))
            {
                builder.AddJsonFile(fileName, optional: true, reloadOnChange: false);
                DebugLogger.Log($"[ServiceConfiguration] ✅ Loaded config: {fileName}");
            }
            else
            {
                DebugLogger.Log($"[ServiceConfiguration] ⚠️  Config not found (using defaults): {fileName}");
            }
        }

        /// <summary>
        /// Register configuration options using IOptions<T> pattern.
        /// Binds JSON config files to strongly-typed Options classes.
        /// </summary>
        private static void RegisterConfigurationOptions(IServiceCollection services, IConfiguration configuration)
        {
            // Port Configuration (config/ports.json)
            services.Configure<PortConfiguration>(configuration);

            // Country Configuration (config/countries.json)
            services.Configure<CountryConfiguration>(configuration);

            // Timeout Configuration (config/timeouts.json)
            services.Configure<TimeoutConfiguration>(configuration);

            // Protocol Configuration (config/protocols.json)
            services.Configure<ProtocolConfiguration>(configuration);

            DebugLogger.Log("[ServiceConfiguration] ✅ Configuration options registered");
        }

        /// <summary>
        /// Extension method to register all PCAP Analyzer services
        /// </summary>
        public static IServiceCollection AddPcapAnalyzerServices(this IServiceCollection services)
        {
            RegisterCoreServices(services);
            RegisterReportingServices(services);
            RegisterUIServices(services);
            RegisterViewModels(services);
            return services;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling", Justification = "DI registration method must reference all service types")]
        private static void RegisterCoreServices(IServiceCollection services)
        {
            // Logging (provide NullLogger for services expecting ILogger<T>)
            services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(NullLogger<>));

            // Port Database Service (Singleton - static port definitions)
            services.AddSingleton<IPortDatabase, PortDatabaseService>();

            // Protocol Security Evaluator Service (Singleton - stateless security evaluation)
            services.AddSingleton<IProtocolSecurityEvaluator, ProtocolSecurityEvaluatorService>();

            // Session Analysis Cache Service (Singleton - shared in-memory cache)
            services.AddSingleton<ISessionAnalysisCache, SessionAnalysisCacheService>();

            // Network Filter Helper Service (Singleton - stateless IP classification)
            services.AddSingleton<INetworkFilterHelper, NetworkFilterHelperService>();

            // Memory Cache (Singleton - shared across services)
            services.AddSingleton<IMemoryCache>(provider =>
            {
                var cacheConfig = StatisticsCacheConfiguration.Default;
                return new MemoryCache(cacheConfig.ToMemoryCacheOptions());
            });

            // Statistics Cache Configuration (Singleton)
            services.AddSingleton(provider =>
            {
                // Determine configuration based on environment or settings
                var isLargeFileMode = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LARGE_FILE_MODE") == "1";
                var isLowMemoryMode = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LOW_MEMORY") == "1";

                if (isLowMemoryMode)
                    return StatisticsCacheConfiguration.LowMemory;
                else if (isLargeFileMode)
                    return StatisticsCacheConfiguration.LargeFile;
                else
                    return StatisticsCacheConfiguration.Default;
            });

            // GeoIP Service (Singleton - expensive to initialize)
            // ⚡ OPTIMIZATION: Eager initialization to avoid delay on first lookup
            // Initializes synchronously during DI setup (app startup) instead of on first analysis
            // Timeout: 10s (accounts for multi-path MMDB file search on slow drives/network shares)
            services.AddSingleton<IGeoIPService>(provider =>
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var service = new UnifiedGeoIPService();

                // Synchronous initialization - blocks DI setup but ensures ready before analysis
                var initTask = service.InitializeAsync();
                if (initTask.Wait(TimeSpan.FromSeconds(10)))
                {
                    DebugLogger.Log($"[ServiceConfiguration] ✅ GeoIP initialized in {sw.Elapsed.TotalSeconds:F2}s");
                }
                else
                {
                    DebugLogger.Log("[ServiceConfiguration] ⚠️  GeoIP initialization timeout (10s) - service will retry on first use");
                }

                return service;
            });

            // Statistics Helper Services (Singleton - stateless calculations via DI)
            services.AddSingleton<IStatisticsCalculator, StatisticsCalculator>();
            services.AddSingleton<IPacketStatisticsCalculator, PacketStatisticsCalculator>();
            services.AddSingleton<ITimeSeriesGenerator, TimeSeriesGeneratorService>();
            services.AddSingleton<IGeoIPEnricher>(provider =>
            {
                var geoIPService = provider.GetRequiredService<IGeoIPService>();
                return new GeoIPEnricher(geoIPService);
            });
            services.AddSingleton<IThreatDetector>(provider =>
            {
                var timeSeriesGen = provider.GetRequiredService<ITimeSeriesGenerator>();
                var protocolOptions = provider.GetRequiredService<IOptions<ProtocolConfiguration>>();
                return new ThreatDetector(timeSeriesGen, protocolOptions);
            });

            // Statistics Service (Base implementation - Singleton)
            services.AddSingleton(provider =>
            {
                var geo = provider.GetRequiredService<IGeoIPService>();
                var statsCalc = provider.GetRequiredService<IStatisticsCalculator>();
                var geoEnrich = provider.GetRequiredService<IGeoIPEnricher>();
                var threatDet = provider.GetRequiredService<IThreatDetector>();
                var timeSeries = provider.GetRequiredService<ITimeSeriesGenerator>();
                var detector = provider.GetRequiredService<IInsecurePortDetector>();
                var packetSizeAnalyzer = provider.GetRequiredService<IPacketSizeAnalyzer>();
                return new StatisticsService(geo, statsCalc, geoEnrich, threatDet, timeSeries, detector, packetSizeAnalyzer);
            });

            // Cached Statistics Service (Decorator with enterprise-grade caching - Singleton)
            services.AddSingleton<IStatisticsService>(provider =>
            {
                var baseStatistics = provider.GetRequiredService<StatisticsService>();
                var cache = provider.GetRequiredService<IMemoryCache>();
                var config = provider.GetRequiredService<StatisticsCacheConfiguration>();

                return new EnhancedCachedStatisticsService(baseStatistics, cache, config);
            });

            // ✅ ARCHITECTURE: FilterServiceCore composition pattern
            // FilterServiceCore is the core component containing all filter operations.
            // Both GlobalFilterService and TabFilterService delegate to FilterServiceCore instances.
            // - Transient: Each service gets its own isolated FilterServiceCore instance
            // - Eliminates 200+ lines of code duplication between the two services
            services.AddTransient<IFilterServiceCore, FilterServiceCore>();

            // ✅ ARCHITECTURE CHANGE: Tab-Specific Filter Services (Transient - one per tab)
            // Each tab gets its own isolated filter instance - filters don't broadcast globally
            // Old: IGlobalFilterService (Singleton) → FilterChanged event broadcast to ALL tabs
            // New: ITabFilterService (Transient) → Tab-local filtering, no cross-tab pollution
            //
            // Usage: Inject ITabFilterService into each tab ViewModel constructor
            // - PacketAnalysisViewModel: new TabFilterService("Packet Analysis")
            // - DashboardViewModel: new TabFilterService("Dashboard")
            // - ThreatsViewModel: new TabFilterService("Security Threats")
            // - VoiceQoSViewModel: new TabFilterService("Voice/QoS")
            // - CountryTrafficViewModel: new TabFilterService("Country Traffic")
            //
            // Filter Copy: Use ITabFilterService.CopyFilterFrom(sourceTab) for cross-tab filter copying
            services.AddTransient<ITabFilterService>(provider =>
                new TabFilterService("Unknown", provider.GetRequiredService<IFilterServiceCore>()));

            // Insecure Port Detector
            services.AddSingleton<IInsecurePortDetector, InsecurePortDetector>();

            // Packet Size Analyzer (Singleton - stateless analysis)
            services.AddSingleton<IPacketSizeAnalyzer, PacketSizeAnalyzer>();

            // Packet Store (Singleton - holds data)
            services.AddSingleton<IPacketStore>(provider =>
            {
                // Check environment variable for DuckDB usage
                var useDuckDb = Environment.GetEnvironmentVariable("PCAP_ANALYZER_USE_DUCKDB") == "1";

                if (useDuckDb)
                {
                    return new DuckDbPacketStore();
                }
                else
                {
                    return new InMemoryPacketStore();
                }
            });

            // TShark Service (Singleton - process management)
            // ⚡ PERFORMANCE: Use ParallelTSharkService for 3-4× faster packet loading
            // Requires: editcap (part of Wireshark tools) installed on system
            // Falls back to: TSharkService if editcap not available
            // Supports: Windows native, WSL2, Linux native execution modes
            services.AddSingleton<ITSharkService>(provider =>
            {
                // Detect editcap across Windows, WSL2, and Linux
                var editcapInfo = WiresharkToolDetector.DetectEditcap();

                if (editcapInfo.IsAvailable)
                {
                    // Test that editcap actually works
                    if (WiresharkToolDetector.TestTool(editcapInfo, out var version))
                    {
                        DebugLogger.Log($"[ServiceConfiguration] ⚡ editcap detected: {editcapInfo.Description} ({version})");
                        DebugLogger.Log($"[ServiceConfiguration] ⚡ Using ParallelTSharkService ({Environment.ProcessorCount} cores)");

                        var logger = provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ParallelTSharkService>>();
                        return new ParallelTSharkService(logger, editcapInfo);
                    }
                    else
                    {
                        DebugLogger.Log($"[ServiceConfiguration] ⚠️  editcap found but test failed: {editcapInfo.Description}");
                    }
                }
                else
                {
                    DebugLogger.Log($"[ServiceConfiguration] ⚠️  {editcapInfo.Description}");
                }

                // Fallback to sequential TSharkService
                DebugLogger.Log("[ServiceConfiguration] ⚠️  Using sequential TSharkService (slower)");
                var seqLogger = provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<TSharkService>>();
                return new TSharkService(seqLogger);
            });

            // Anomaly Detection (Singleton - maintains registered detectors)
            services.AddSingleton<IUnifiedAnomalyDetectionService, UnifiedAnomalyDetectionService>();

            // ✅ ARCHITECTURE REDESIGN: Analysis Orchestrator (Singleton - central coordinator)
            // Replaces fragmented MainWindowViewModel analysis logic with unified orchestration
            // Implements aggressive preloading: load all packets once, analyze all tabs in parallel
            services.AddSingleton<AnalysisOrchestrator>();

            // ✅ Analysis Coordinator Service (Singleton - orchestrates analysis + tab population)
            // Extracts orchestration logic from MainWindowViewModel for better testability
            services.AddSingleton<IAnalysisCoordinator>(provider =>
            {
                var orchestrator = provider.GetRequiredService<AnalysisOrchestrator>();
                var sessionCache = provider.GetRequiredService<ISessionAnalysisCache>();
                var cacheService = provider.GetService<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>();
                return new AnalysisCoordinatorService(orchestrator, sessionCache, cacheService);
            });

            // Analysis Cache Service (Singleton - persistent SQLite cache for PCAP analysis results)
            // Dramatically reduces load times for previously analyzed files (310s -> 10-15s)
            //
            // CACHE CONTROL:
            // - ENABLED by default (massive performance improvement for tab switches)
            // - To DISABLE: Set environment variable PCAP_ANALYZER_CACHE_ENABLED=0
            // - Cache database: %LocalAppData%/PCAPAnalyzer/analysis_cache.db
            services.AddSingleton<PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService>(provider =>
            {
                var cacheEnabled = Environment.GetEnvironmentVariable("PCAP_ANALYZER_CACHE_ENABLED") != "0";

                if (cacheEnabled)
                {
                    DebugLogger.Log("[ServiceConfiguration] ✅ Cache ENABLED - Using SQLite cache for analysis results");
                    return new PCAPAnalyzer.Core.Services.Cache.AnalysisCacheService();
                }
                else
                {
                    DebugLogger.Log("[ServiceConfiguration] ⚠️  Cache DISABLED - Using NoOp cache (fresh analysis only)");
                    return new PCAPAnalyzer.Core.Services.Cache.NoOpAnalysisCacheService();
                }
            });

            // Report Generator (Transient - stateless orchestrator)
            // Note: Even though it depends on Scoped services, the orchestrator itself is stateless
            // and can be Transient. DI will create new instances of Scoped dependencies per request.
            services.AddTransient<IReportGeneratorService, ReportGeneratorService>();

            // Live Capture Services (Phase 2B)
            services.AddSingleton<INetworkInterfaceManager>(provider =>
            {
                var logger = provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<NetworkInterfaceManager>>();
                return new NetworkInterfaceManager(logger);
            });

            // Live Capture Service - Using Adapter Pattern
            // Bridges LiveCaptureManager (backend) with ILiveCaptureService (UI)
            services.AddSingleton<ILiveCaptureService>(provider =>
            {
                return new LiveCaptureManagerAdapter();
            });
        }

        /// <summary>
        /// Register reporting services - Report generation and export with caching
        /// </summary>
        private static void RegisterReportingServices(IServiceCollection services)
        {
            // Cache Infrastructure (Singleton - shared across services)
            services.AddSingleton(provider =>
            {
                // Determine configuration based on environment
                var isLargeFileMode = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LARGE_FILE_MODE") == "1";
                var isLowMemoryMode = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LOW_MEMORY") == "1";
                var cacheDisabled = Environment.GetEnvironmentVariable("PCAP_ANALYZER_CACHE_DISABLED") == "1";

                if (cacheDisabled)
                    return CacheConfiguration.Disabled;
                else if (isLowMemoryMode)
                    return CacheConfiguration.LowMemory;
                else if (isLargeFileMode)
                    return CacheConfiguration.LargeFile;
                else
                    return CacheConfiguration.Default;
            });

            services.AddSingleton<ICacheService, MemoryCacheService>();
            services.AddSingleton<CacheKeyGenerator>();

            // Security Findings Generator
            // Register inner service (concrete implementation)
            services.AddTransient<SecurityFindingsGenerator>();
            // Register cached wrapper as interface implementation
            services.AddTransient<ISecurityFindingsGenerator, CachedSecurityFindingsGenerator>();

            // Remediation Planner
            // Register inner service (concrete implementation)
            services.AddTransient<RemediationPlanner>();
            // Register cached wrapper as interface implementation
            services.AddTransient<IRemediationPlanner, CachedRemediationPlanner>();

            // HTML Report Generator (Transient - stateless report generation)
            services.AddTransient<IHtmlReportGenerator, HtmlReportGenerator>();

            // JSON Report Generator (Transient - stateless report generation)
            services.AddTransient<IJsonReportGenerator, JsonReportGenerator>();

            // PDF Report Generator (Transient - stateless report generation)
            services.AddTransient<IPdfReportGenerator, PdfReportGenerator>();
        }

        private static void RegisterUIServices(IServiceCollection services)
        {
            // Screenshot Service (Transient)
            services.AddTransient<IScreenshotService, ScreenshotService>();

            // File Dialog Service (Transient)
            services.AddTransient<IFileDialogService, FileDialogService>();

            // CSV Export Service (Transient - stateless export operations)
            services.AddTransient<ICsvExportService, CsvExportService>();

            // Protocol Color Service (Singleton - shared color definitions)
            services.AddSingleton<IProtocolColorService, ProtocolColorService>();

            // Recent Files Service (Singleton - shared state)
            services.AddSingleton<RecentFilesService>();

            // Filter Copy Service (Singleton - manages tab-specific filter registration and copying)
            services.AddSingleton<FilterCopyService>();

            // Global Filter State (Singleton - centralized filter state for unified filter panel)
            services.AddSingleton<GlobalFilterState>();

            // Smart Filter Builder Service (Singleton - stateless filter building logic)
            // Provides sophisticated packet filtering with INCLUDE/EXCLUDE groups, AND/OR logic,
            // port range patterns, and protocol matching - shared across all analysis tabs
            services.AddSingleton<ISmartFilterBuilder, SmartFilterBuilderService>();

            // Dashboard Filter Service (Singleton - stateless filter logic for Dashboard tab)
            // Extracted from DashboardViewModel.UpdateFilteredStatistics() for testability
            services.AddSingleton<IDashboardFilterService, DashboardFilterService>();

            // Filter Preset Service (Singleton - manages saved Dashboard filter presets)
            // Stores user presets in JSON, provides immutable built-in presets
            services.AddSingleton<IFilterPresetService, FilterPresetService>();

            // Packet Details Services (Transient - stateless parsing and formatting)
            services.AddTransient<ProtocolParser>();
            services.AddTransient<HexFormatter>();

            // Stream Analyzer (Singleton - stateless stream analysis with security services)
            // Analyzes TCP/UDP streams for state machine, bandwidth, timing, and protocol detection
            // Now includes security indicators (port risk, GeoIP) for enhanced flow analysis
            services.AddSingleton<StreamAnalyzer>(provider =>
            {
                var portDetector = provider.GetRequiredService<IInsecurePortDetector>();
                var geoService = provider.GetRequiredService<IGeoIPService>();
                return new StreamAnalyzer(portDetector, geoService);
            });

            // Hex Data Service (Singleton - manages TShark JSON extraction for hex dump)
            // Extracts raw packet bytes on-demand using TShark -T json -x
            services.AddSingleton<PCAPAnalyzer.Core.Services.HexDataService>(provider =>
            {
                var logger = provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<PCAPAnalyzer.Core.Services.HexDataService>>();
                return new PCAPAnalyzer.Core.Services.HexDataService(logger);
            });

            // Protocol Deep Dive Service (Singleton - TShark verbose output extraction)
            // Extracts detailed protocol dissection for on-demand protocol analysis tab
            services.AddSingleton<ProtocolDeepDiveService>();
        }

        private static void RegisterViewModels(IServiceCollection services)
        {
            // Main Window ViewModel (Transient - created once per window)
            services.AddTransient<MainWindowViewModel>();

            // Child ViewModels
            // ✅ CRITICAL FIX: FileAnalysisViewModel MUST be Singleton to ensure event subscriptions work
            // Bug: Transient scope created multiple instances → MainWindowViewModel subscribed to Instance A,
            // but FileSelectionControl used Instance B → event fired with 0 subscribers!
            services.AddSingleton<FileAnalysisViewModel>(provider =>
            {
                var tshark = provider.GetRequiredService<ITSharkService>();
                var stats = provider.GetRequiredService<IStatisticsService>();
                var sessionCache = provider.GetRequiredService<ISessionAnalysisCache>();
                var fileDialog = provider.GetRequiredService<IFileDialogService>();
                var orchestrator = provider.GetRequiredService<AnalysisOrchestrator>();
                return new FileAnalysisViewModel(tshark, stats, sessionCache, null, fileDialog, orchestrator);
            });
            services.AddTransient<DashboardViewModel>();
            services.AddTransient<CountryTrafficViewModel>();
            services.AddTransient<ThreatsViewModel>();
            services.AddTransient<EnhancedMapViewModel>();
            services.AddTransient<ReportViewModel>();
            services.AddTransient<TopTalkersViewModel>();
            services.AddTransient<AnomalyViewModel>();
            services.AddTransient<CompareViewModel>();

            // Compare Tab Services
            services.AddSingleton<Core.Interfaces.IPacketLoader, TShark.TSharkPacketLoader>();
            services.AddSingleton<Core.Interfaces.IPacketComparer, Core.Services.PacketComparer>();

            // Live Capture ViewModels (Transient - Phase 2B)
            services.AddTransient<LiveCaptureViewModel>();
            services.AddTransient<CaptureConfigurationViewModel>();
            services.AddTransient<LiveStatisticsViewModel>();
            services.AddTransient<PacketListViewModel>();

            // Component ViewModels
            // ✅ CRITICAL FIX: FileSelectionControlViewModel also Singleton to share same FileAnalysisViewModel instance
            services.AddSingleton<FileSelectionControlViewModel>();

            // Packet Details ViewModels (Transient - one per packet details panel)
            services.AddTransient<PacketDetailsViewModel>(provider =>
            {
                var protocolParser = provider.GetRequiredService<ProtocolParser>();
                var hexFormatter = provider.GetRequiredService<HexFormatter>();
                var streamAnalyzer = provider.GetRequiredService<StreamAnalyzer>();
                var hexDataService = provider.GetRequiredService<PCAPAnalyzer.Core.Services.HexDataService>();
                var deepDiveService = provider.GetRequiredService<ProtocolDeepDiveService>();
                return new PacketDetailsViewModel(protocolParser, hexFormatter, streamAnalyzer, hexDataService, deepDiveService);
            });

            // Filter Panel ViewModels (Transient - one per filter panel instance)
            services.AddTransient<FilterSummaryViewModel>();
            services.AddTransient<UnifiedFilterPanelViewModel>();
            services.AddTransient<GeneralFilterTabViewModel>();

            // Note: Add more ViewModels as they are migrated to DI
        }
    }
}
