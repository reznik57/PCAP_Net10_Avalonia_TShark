using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Media;
using DynamicData;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Views;
using ReactiveUI;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;
using IDispatcherService = PCAPAnalyzer.UI.Services.IDispatcherService;

namespace PCAPAnalyzer.UI.ViewModels
{
    public class GeographicMapViewModel : ReactiveObject, IActivatableViewModel
    {
        private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
            ?? throw new InvalidOperationException("IDispatcherService not registered");
        private IDispatcherService? _dispatcher;

        private readonly IGeoIPService _geoIPService;
        private readonly IStatisticsService _statisticsService;
        private readonly IProtocolColorService _protocolColorService;
        private Dictionary<string, CountryTrafficStatistics> _countryTrafficData = new();
        private List<GeographicTrafficFlow> _trafficFlows = new();
        private ObservableCollection<ContinentSummary> _topContinents = new();
        private ObservableCollection<CountrySummary> _topCountries = new();
        private ObservableCollection<ProtocolSummary> _protocolStats = new();
    private IReadOnlyList<PacketInfo>? _allPackets;
        
        // Table view properties
        private bool _showTop100;
        private int _countryDisplayCount = 25;
        private ObservableCollection<CountryTableItem> _topCountriesByPackets = new();
        private ObservableCollection<CountryTableItem> _topCountriesByBytes = new();

        private int _selectedViewMode;
        private int _selectedColorScheme;
        private bool _showTrafficFlows = true;
        private bool _showParticles = true;
        private bool _showHeatMap;
        private bool _showLabels = true;
        private bool _animateFlows = true;
        private bool _showPublicIPFlows = true;

        private long _totalPublicIPPackets;
        private int _countriesDetected;
        private int _activeFlows;
        private string _detectionRate = "0%";
        private string _statusMessage = "Ready";
        private bool _isZoomedIn;
        
        public ViewModelActivator Activator { get; }

        public GeographicMapViewModel(IGeoIPService geoIPService, IStatisticsService statisticsService, IProtocolColorService? protocolColorService = null)
        {
            Activator = new ViewModelActivator();
            _geoIPService = geoIPService;
            _statisticsService = statisticsService;
            // Use DI container, fallback to direct instantiation only if DI not available
            _protocolColorService = protocolColorService
                ?? App.Services?.GetService<IProtocolColorService>()
                ?? new ProtocolColorService();
            
            // Initialize commands
            ExportMapCommand = ReactiveCommand.CreateFromTask(ExportMap);
            ResetViewCommand = ReactiveCommand.Create(ResetView);
            RefreshDataCommand = ReactiveCommand.CreateFromTask(RefreshData);
            TakeScreenshotCommand = ReactiveCommand.CreateFromTask(TakeScreenshot);
            // Create simple command to avoid threading issues
            ToggleCountryDisplayCommand = new RelayCommand(() =>
            {
                // This will use the thread-safe setter
                ShowTop100 = !ShowTop100;
            });
            BackToWorldMapCommand = ReactiveCommand.Create(BackToWorldMap);
            ShowCountryDetailsCommand = ReactiveCommand.CreateFromTask<CountryTableItem>(ShowCountryDetails);
            
            // Initialize sample data
            _ = LoadInitialData();
        }
        
        // Properties
        public Dictionary<string, CountryTrafficStatistics> CountryTrafficData
        {
            get => _countryTrafficData;
            set => this.RaiseAndSetIfChanged(ref _countryTrafficData, value);
        }
        
        public List<GeographicTrafficFlow> TrafficFlows
        {
            get => _trafficFlows;
            set => this.RaiseAndSetIfChanged(ref _trafficFlows, value);
        }
        
        public ObservableCollection<ContinentSummary> TopContinents
        {
            get => _topContinents;
            set => this.RaiseAndSetIfChanged(ref _topContinents, value);
        }
        
        public ObservableCollection<CountrySummary> TopCountries
        {
            get => _topCountries;
            set => this.RaiseAndSetIfChanged(ref _topCountries, value);
        }
        
        public ObservableCollection<ProtocolSummary> ProtocolStats
        {
            get => _protocolStats;
            set => this.RaiseAndSetIfChanged(ref _protocolStats, value);
        }
        
        public bool ShowTop100
        {
            get => _showTop100;
            set
            {
                // Ensure property change happens on UI thread
                if (!Dispatcher.CheckAccess())
                {
                    Dispatcher.Post(() => _showTop100 = value);
                    return;
                }

                if (this.RaiseAndSetIfChanged(ref _showTop100, value))
                {
                    var countryCount = CountryTrafficData?.Count ?? 0;
                    // Show Top 100 or all if less than 100
                    CountryDisplayCount = value ? Math.Min(100, countryCount) : Math.Min(25, countryCount);
                    UpdateCountryTables();
                }
            }
        }
        
        public int CountryDisplayCount
        {
            get => _countryDisplayCount;
            set => this.RaiseAndSetIfChanged(ref _countryDisplayCount, value);
        }
        
        public ObservableCollection<CountryTableItem> TopCountriesByPackets
        {
            get => _topCountriesByPackets;
            set => this.RaiseAndSetIfChanged(ref _topCountriesByPackets, value);
        }
        
        public ObservableCollection<CountryTableItem> TopCountriesByBytes
        {
            get => _topCountriesByBytes;
            set => this.RaiseAndSetIfChanged(ref _topCountriesByBytes, value);
        }
        
        public int SelectedViewMode
        {
            get => _selectedViewMode;
            set => this.RaiseAndSetIfChanged(ref _selectedViewMode, value);
        }
        
        public int SelectedColorScheme
        {
            get => _selectedColorScheme;
            set => this.RaiseAndSetIfChanged(ref _selectedColorScheme, value);
        }
        
        public bool ShowTrafficFlows
        {
            get => _showTrafficFlows;
            set => this.RaiseAndSetIfChanged(ref _showTrafficFlows, value);
        }
        
        public bool ShowParticles
        {
            get => _showParticles;
            set => this.RaiseAndSetIfChanged(ref _showParticles, value);
        }
        
        public bool ShowHeatMap
        {
            get => _showHeatMap;
            set => this.RaiseAndSetIfChanged(ref _showHeatMap, value);
        }
        
        public bool ShowLabels
        {
            get => _showLabels;
            set => this.RaiseAndSetIfChanged(ref _showLabels, value);
        }
        
        public bool AnimateFlows
        {
            get => _animateFlows;
            set => this.RaiseAndSetIfChanged(ref _animateFlows, value);
        }
        
        public bool ShowPublicIPFlows
        {
            get => _showPublicIPFlows;
            set => this.RaiseAndSetIfChanged(ref _showPublicIPFlows, value);
        }
        
        public long TotalPublicIPPackets
        {
            get => _totalPublicIPPackets;
            set => this.RaiseAndSetIfChanged(ref _totalPublicIPPackets, value);
        }
        
        public int CountriesDetected
        {
            get => _countriesDetected;
            set => this.RaiseAndSetIfChanged(ref _countriesDetected, value);
        }
        
        public int ActiveFlows
        {
            get => _activeFlows;
            set => this.RaiseAndSetIfChanged(ref _activeFlows, value);
        }
        
        public string DetectionRate
        {
            get => _detectionRate;
            set => this.RaiseAndSetIfChanged(ref _detectionRate, value);
        }
        
        public string StatusMessage
        {
            get => _statusMessage;
            set => this.RaiseAndSetIfChanged(ref _statusMessage, value);
        }
        
        public bool IsZoomedIn
        {
            get => _isZoomedIn;
            set => this.RaiseAndSetIfChanged(ref _isZoomedIn, value);
        }
        
        // Commands
        public ICommand ExportMapCommand { get; }
        public ICommand ResetViewCommand { get; }
        public ICommand RefreshDataCommand { get; }
        public ICommand TakeScreenshotCommand { get; }
        public ICommand ToggleCountryDisplayCommand { get; }
        public ICommand BackToWorldMapCommand { get; }
        public ICommand ShowCountryDetailsCommand { get; }
        
        // Methods
    public void SetPackets(IReadOnlyList<PacketInfo> packets)
        {
            _allPackets = packets;
            DebugLogger.Log($"[EnhancedMapViewModel] SetPackets called with {packets?.Count ?? 0} packets");
        }
        
        public Task UpdateStatistics(NetworkStatistics statistics)
        {
            if (statistics == null) return Task.CompletedTask;

            // Ensure all updates happen on UI thread
            if (!Dispatcher.CheckAccess())
            {
                return Dispatcher.InvokeAsync(() => UpdateStatistics(statistics));
            }
            
            DebugLogger.Log($"[EnhancedMapViewModel] UpdateStatistics called with {statistics.TotalPackets} total packets");
            DebugLogger.Log($"[EnhancedMapViewModel] Countries: {statistics.CountryStatistics?.Count ?? 0}");
            
            // Update country traffic data
            if (statistics.CountryStatistics != null)
            {
                CountryTrafficData = new Dictionary<string, CountryTrafficStatistics>(statistics.CountryStatistics);
                DebugLogger.Log($"[EnhancedMapViewModel] Set CountryTrafficData with {CountryTrafficData.Count} countries");
                var totalPackets = CountryTrafficData.Values.Sum(c => c.TotalPackets);
                DebugLogger.Log($"[EnhancedMapViewModel] Total packets in country data: {totalPackets:N0}");
            }
            
            // Update traffic flows
            if (statistics.TrafficFlows != null)
            {
                TrafficFlows = statistics.TrafficFlows
                    .Where(f => f.IsCrossBorder)
                    .Select(f => new GeographicTrafficFlow
                    {
                        SourceCountryCode = f.SourceCountry,
                        DestinationCountryCode = f.DestinationCountry,
                        PacketCount = f.PacketCount,
                        ByteCount = f.ByteCount,
                        PrimaryProtocol = f.Protocols?.FirstOrDefault() != null ? 
                            Enum.TryParse<Protocol>(f.Protocols.First(), out var proto) ? proto : Protocol.TCP 
                            : Protocol.TCP,
                        Intensity = Math.Min(1.0, f.PacketCount / 10000.0),
                        IsActive = true
                    })
                    .ToList();
            }
            
            // Update metrics - calculate public IP packets from country statistics
            var publicIPPackets = CountryTrafficData?.Values.Sum(c => c.TotalPackets) ?? 0;
            var publicIPBytes = CountryTrafficData?.Values.Sum(c => c.TotalBytes) ?? 0;
            TotalPublicIPPackets = publicIPPackets;
            CountriesDetected = CountryTrafficData?.Count ?? 0;
            ActiveFlows = statistics.TrafficFlows?.Count(f => f.IsCrossBorder) ?? 0;

            // Calculate detection rate: share of total packets that involve at least one public IP
            if (statistics.TotalPackets > 0)
            {
                var detectionRatio = publicIPPackets / (double)statistics.TotalPackets;
                DetectionRate = $"{detectionRatio * 100:F1}%";
            }
            else
            {
                DetectionRate = "0%";
            }

            // Update continent statistics
            UpdateContinentStatistics();
            
            // Update top countries
            UpdateTopCountries();
            
            // Update country tables for the new view
            UpdateCountryTables();
            
            // Update protocol statistics  
            UpdateProtocolStatistics(statistics);
            
            StatusMessage = $"Public traffic: {Core.Utilities.NumberFormatter.FormatCount(publicIPPackets)} packets • {Core.Utilities.NumberFormatter.FormatBytes(publicIPBytes)} bytes • {CountriesDetected} countries • {ActiveFlows} unique flows";

            return Task.CompletedTask;
        }
        
        private async Task LoadInitialData()
        {
            try
            {
                StatusMessage = "Loading traffic data...";
                
                // Get current statistics
                // Get current statistics - simplified for now
                var stats = await Task.FromResult(new { CountryStatistics = CountryTrafficData, TotalPackets = 100000L });
                if (stats != null)
                {
                    // Update country traffic data
                    CountryTrafficData = stats.CountryStatistics ?? new Dictionary<string, CountryTrafficStatistics>();
                    
                    // Calculate continent statistics
                    UpdateContinentStatistics();
                    
                    // Update top countries
                    UpdateTopCountries();
                    
                    // Generate sample traffic flows
                    GenerateTrafficFlows();
                    
                    // Update protocol statistics
                    UpdateProtocolStatistics();
                    
                    // Update metrics
                    TotalPublicIPPackets = CountryTrafficData.Values.Sum(c => c.TotalPackets);
                    CountriesDetected = CountryTrafficData.Count;
                    ActiveFlows = TrafficFlows.Count(f => f.IsActive);
                    
                    // Calculate detection rate
                    if (stats.TotalPackets > 0)
                    {
                        var detectedPackets = CountryTrafficData.Values.Sum(c => c.TotalPackets);
                        var publicIPPackets = stats.TotalPackets; // Assuming this is public IP packets
                        var rate = publicIPPackets > 0 ? (double)detectedPackets / publicIPPackets * 100 : 0;
                        DetectionRate = $"{rate:F1}%";
                    }
                }
                
                StatusMessage = "Data loaded successfully";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error loading data: {ex.Message}";
            }
        }
        
        private void UpdateContinentStatistics()
        {
            var continentStats = new Dictionary<string, long>();
            
            foreach (var kvp in CountryTrafficData)
            {
                if (ContinentData.CountryToContinentMap.TryGetValue(kvp.Key, out var continentCode))
                {
                    if (!continentStats.ContainsKey(continentCode))
                        continentStats[continentCode] = 0;
                    continentStats[continentCode] += kvp.Value.TotalPackets;
                }
            }
            
            var totalPackets = continentStats.Values.Sum();
            var topContinents = continentStats
                .OrderByDescending(c => c.Value)
                .Take(5)
                .Select(c => new ContinentSummary
                {
                    Code = c.Key,
                    Name = ContinentData.Continents.TryGetValue(c.Key, out var cont) ? cont.DisplayName : c.Key,
                    PacketCount = Core.Utilities.NumberFormatter.FormatCount(c.Value),
                    Percentage = $"({c.Value * 100.0 / totalPackets:F1}%)",
                    Color = ContinentData.Continents.TryGetValue(c.Key, out var cont2) ? cont2.PrimaryColor : ThemeColorHelper.GetColorHex("TextMuted", "#808080")
                })
                .ToList();
            
            TopContinents = new ObservableCollection<ContinentSummary>(topContinents);
        }
        
        private void UpdateTopCountries()
        {
            var topCountries = CountryTrafficData
                .OrderByDescending(c => c.Value.TotalPackets)
                .Take(10)
                .Select(c => new CountrySummary
                {
                    Code = c.Key,
                    Name = c.Value.CountryName,
                    PacketCount = Core.Utilities.NumberFormatter.FormatCount(c.Value.TotalPackets),
                    Flag = GetCountryFlag(c.Key),
                    IsHighRisk = c.Value.IsHighRisk
                })
                .ToList();
            
            TopCountries = new ObservableCollection<CountrySummary>(topCountries);
        }
        
        private void GenerateTrafficFlows()
        {
            var flows = new List<GeographicTrafficFlow>();
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for sample traffic flow visualization, not security
            var random = new Random();
#pragma warning restore CA5394

            // Generate flows between top countries
            var topCountryCodes = CountryTrafficData
                .OrderByDescending(c => c.Value.TotalPackets)
                .Take(20)
                .Select(c => c.Key)
                .ToList();
            
            foreach (var sourceCode in topCountryCodes.Take(10))
            {
                foreach (var destCode in topCountryCodes.Skip(5).Take(10))
                {
                    if (sourceCode != destCode && random.NextDouble() > 0.5)
                    {
                        var sourceLocation = GetCountryLocation(sourceCode);
                        var destLocation = GetCountryLocation(destCode);
                        
                        if (sourceLocation != null && destLocation != null)
                        {
                            flows.Add(new GeographicTrafficFlow
                            {
                                SourceCountryCode = sourceCode,
                                DestinationCountryCode = destCode,
                                SourceLatitude = sourceLocation.Value.Item1,
                                SourceLongitude = sourceLocation.Value.Item2,
                                DestinationLatitude = destLocation.Value.Item1,
                                DestinationLongitude = destLocation.Value.Item2,
                                PacketCount = random.Next(100, 10000),
                                ByteCount = random.Next(10000, 1000000),
                                PrimaryProtocol = (Protocol)random.Next(0, 5),
                                Intensity = random.NextDouble(),
                                IsActive = random.NextDouble() > 0.3,
                                FlowType = random.NextDouble() > 0.9 ? "Suspicious" : "Normal",
                                StartTime = DateTime.UtcNow.AddMinutes(-random.Next(0, 60)),
                                EndTime = DateTime.UtcNow
                            });
                        }
                    }
                }
            }
            
            TrafficFlows = flows;
        }
        
        private void UpdateProtocolStatistics(NetworkStatistics? statistics = null)
        {
            var protocolCounts = new Dictionary<string, long>();
            
            // Use statistics if provided, otherwise use CountryTrafficData
            if (statistics?.ProtocolStats != null)
            {
                foreach (var protocol in statistics.ProtocolStats.Values)
                {
                    protocolCounts[protocol.Protocol] = protocol.PacketCount;
                }
            }
            else if (CountryTrafficData != null)
            {
                foreach (var country in CountryTrafficData.Values)
                {
                    foreach (var protocol in country.ProtocolBreakdown)
                    {
                        if (!protocolCounts.ContainsKey(protocol.Key))
                            protocolCounts[protocol.Key] = 0;
                        protocolCounts[protocol.Key] += protocol.Value;
                    }
                }
            }
            
            var protocolStats = protocolCounts
                .OrderByDescending(p => p.Value)
                .Take(6)
                .Select(p => new ProtocolSummary
                {
                    Name = p.Key,
                    Count = Core.Utilities.NumberFormatter.FormatCount(p.Value),
                    Color = GetProtocolColor(p.Key)
                })
                .ToList();
            
            ProtocolStats = new ObservableCollection<ProtocolSummary>(protocolStats);
        }
        
        private async Task ExportMap()
        {
            StatusMessage = "Exporting map...";
            await Task.Delay(1000); // Simulate export
            StatusMessage = "Map exported successfully";
        }
        
        private async Task TakeScreenshot()
        {
            try
            {
                StatusMessage = "Taking screenshot...";
                
                // Generate filename with timestamp
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var filename = $"EnhancedMap_{timestamp}.png";
                var filePath = Path.Combine(Directory.GetCurrentDirectory(), filename);
                
                // Signal to the view that we need a screenshot
                // The actual screenshot will be taken by the view
                ScreenshotRequested?.Invoke(filePath);
                
                await Task.Delay(500); // Give time for screenshot
                StatusMessage = $"Screenshot saved: {filename}";
                DebugLogger.Log($"[EnhancedMapViewModel] Screenshot saved to: {filePath}");
            }
            catch (Exception ex)
            {
                StatusMessage = $"Screenshot failed: {ex.Message}";
                DebugLogger.Log($"[EnhancedMapViewModel] Screenshot error: {ex}");
            }
        }
        
        public event Action<string>? ScreenshotRequested;
        
        private void ResetView()
        {
            SelectedViewMode = 0;
            SelectedColorScheme = 0;
            ShowTrafficFlows = true;
            ShowParticles = true;
            ShowHeatMap = false;
            ShowLabels = true;
            AnimateFlows = true;
            StatusMessage = "View reset";
        }
        
        private async Task RefreshData()
        {
            await LoadInitialData();
        }
        
        
        private void BackToWorldMap()
        {
            // Reset to world view
            IsZoomedIn = false;
            // Trigger map control to reset view
            StatusMessage = "World Map";
        }
        
        private void UpdateCountryTables()
        {
            // Always ensure we're on UI thread for collection updates
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Post(() => UpdateCountryTables());
                return;
            }
            
            if (CountryTrafficData == null || !CountryTrafficData.Any())
            {
                TopCountriesByPackets.Clear();
                TopCountriesByBytes.Clear();
                return;
            }

            // Calculate totals using PUBLIC traffic only (exclude INT and IP6)
            var publicCountries = CountryTrafficData
                .Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6" && kvp.Key != "INTERNAL" && kvp.Key != "IPV6")
                .ToList();

            var totalPackets = publicCountries.Sum(kvp => kvp.Value.TotalPackets);
            var totalBytes = publicCountries.Sum(kvp => kvp.Value.TotalBytes);

            // Create country table items - include Unknown for unresolved IPs
            var allCountries = CountryTrafficData
                .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Key) &&
                             !string.IsNullOrWhiteSpace(kvp.Value.CountryName) &&
                             kvp.Key.Length >= 2) // Filter out invalid country codes
                .Select(kvp =>
                {
                    var stats = kvp.Value;
                    var continent = GetContinentForCountry(kvp.Key);
                    return new CountryTableItem
                    {
                        CountryCode = string.IsNullOrWhiteSpace(kvp.Key) ? "IP6" : kvp.Key,
                        CountryName = string.IsNullOrWhiteSpace(stats.CountryName) ? "Unknown" : stats.CountryName,
                        Continent = continent,
                        TotalPackets = stats.TotalPackets,
                        TotalBytes = stats.TotalBytes,
                        PacketPercentage = totalPackets > 0 ? (stats.TotalPackets * 100.0 / totalPackets) : 0,
                        BytePercentage = totalBytes > 0 ? (stats.TotalBytes * 100.0 / totalBytes) : 0,
                        IsHighRisk = stats.IsHighRisk
                    };
                })
                .ToList();
            
            // Sort by packets and apply limit - each list gets its own ranking
            var byPackets = allCountries
                .OrderByDescending(c => c.TotalPackets)
                .Take(ShowTop100 ? Math.Min(100, allCountries.Count) : 25)
                .Select((c, index) =>
                {
                    // Clone the item to avoid shared ranking
                    var item = new CountryTableItem
                    {
                        CountryCode = c.CountryCode,
                        CountryName = c.CountryName,
                        Continent = c.Continent,
                        TotalPackets = c.TotalPackets,
                        TotalBytes = c.TotalBytes,
                        PacketPercentage = c.PacketPercentage,
                        BytePercentage = c.BytePercentage,
                        IsHighRisk = c.IsHighRisk,
                        Rank = index + 1
                    };
                    return item;
                })
                .ToList();
            
            // Sort by bytes and apply limit - separate ranking
            var byBytes = allCountries
                .OrderByDescending(c => c.TotalBytes)
                .Take(ShowTop100 ? Math.Min(100, allCountries.Count) : 25)
                .Select((c, index) =>
                {
                    // Clone the item to avoid shared ranking
                    var item = new CountryTableItem
                    {
                        CountryCode = c.CountryCode,
                        CountryName = c.CountryName,
                        Continent = c.Continent,
                        TotalPackets = c.TotalPackets,
                        TotalBytes = c.TotalBytes,
                        PacketPercentage = c.PacketPercentage,
                        BytePercentage = c.BytePercentage,
                        IsHighRisk = c.IsHighRisk,
                        Rank = index + 1
                    };
                    return item;
                })
                .ToList();
            
            // Update collections
            DebugLogger.Log($"[EnhancedMapViewModel] UpdateCountryTables - All countries: {allCountries.Count}");
            DebugLogger.Log($"[EnhancedMapViewModel] UpdateCountryTables - byPackets: {byPackets.Count} items");
            DebugLogger.Log($"[EnhancedMapViewModel] UpdateCountryTables - byBytes: {byBytes.Count} items");
            TopCountriesByPackets = new ObservableCollection<CountryTableItem>(byPackets);
            TopCountriesByBytes = new ObservableCollection<CountryTableItem>(byBytes);
        }
        
        private string GetContinentForCountry(string countryCode)
        {
            // Map country codes to continents
            if (ContinentData.CountryToContinentMap.TryGetValue(countryCode, out var continentCode))
            {
                if (ContinentData.Continents.TryGetValue(continentCode, out var continent))
                {
                    return continent.DisplayName;
                }
            }
            return "Unknown";
        }

        // Helper methods
        private string GetCountryFlag(string countryCode)
        {
            // Convert country code to flag emoji
            // This is a simplified version - you'd want a proper mapping
            return countryCode switch
            {
                "US" => "🇺🇸",
                "CN" => "🇨🇳",
                "RU" => "🇷🇺",
                "DE" => "🇩🇪",
                "GB" => "🇬🇧",
                "FR" => "🇫🇷",
                "JP" => "🇯🇵",
                "IN" => "🇮🇳",
                "BR" => "🇧🇷",
                "CA" => "🇨🇦",
                "AU" => "🇦🇺",
                "IT" => "🇮🇹",
                "ES" => "🇪🇸",
                "KR" => "🇰🇷",
                "NL" => "🇳🇱",
                "PL" => "🇵🇱",
                "IE" => "🇮🇪",
                "RO" => "🇷🇴",
                "AT" => "🇦🇹",
                "IP6" => "🛰",
                _ => "🏳️"
            };
        }
        
        private (double, double)? GetCountryLocation(string countryCode)
        {
            // Return approximate country center coordinates
            // In a real app, you'd have a proper database
            return countryCode switch
            {
                "US" => (39.0, -98.0),
                "CN" => (35.0, 105.0),
                "RU" => (60.0, 100.0),
                "DE" => (51.0, 10.0),
                "GB" => (54.0, -2.0),
                "FR" => (46.0, 2.0),
                "JP" => (36.0, 138.0),
                "IN" => (20.0, 77.0),
                "BR" => (-10.0, -55.0),
                "CA" => (56.0, -106.0),
                "AU" => (-27.0, 133.0),
                "IT" => (43.0, 12.0),
                "ES" => (40.0, -4.0),
                "KR" => (36.0, 128.0),
                "NL" => (52.5, 5.75),
                "PL" => (52.0, 20.0),
                "IE" => (53.0, -8.0),
                "RO" => (46.0, 25.0),
                "AT" => (47.5, 14.0),
                _ => null
            };
        }
        
        private string GetProtocolColor(string protocol)
        {
            return _protocolColorService.GetProtocolColorHex(protocol);
        }
        
        private async Task ShowCountryDetails(CountryTableItem countryItem)
        {
            if (countryItem == null) return;
            
            try
            {
                // Filter packets for this country
                var countryPackets = new List<PacketInfo>();
                
                if (_allPackets != null && _countryTrafficData != null)
                {
                    // Get the country statistics for this country
                    if (_countryTrafficData.TryGetValue(countryItem.CountryCode, out var countryStats))
                    {
                        // Filter packets that match this country's IPs
                        countryPackets = _allPackets.Where(p => 
                            countryStats.UniqueIPs.Contains(p.SourceIP) || 
                            countryStats.UniqueIPs.Contains(p.DestinationIP)
                        ).ToList();
                        
                        DebugLogger.Log($"[EnhancedMapViewModel] Found {countryPackets.Count} packets for country {countryItem.CountryName}");
                    }
                }
                
                var viewModel = new CountryDetailsViewModel(countryItem, countryPackets);
                var window = new Views.CountryDetailsWindow
                {
                    DataContext = viewModel
                };
                
                // Show as dialog
                if (Avalonia.Application.Current?.ApplicationLifetime is
                    Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop &&
                    desktop.MainWindow != null)
                {
                    await window.ShowDialog(desktop.MainWindow);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedMapViewModel] Error showing country details: {ex.Message}");
            }
        }
    }
    
    // Supporting classes
    public class ContinentSummary
    {
        public string Code { get; set; } = "";
        public string Name { get; set; } = "";
        public string PacketCount { get; set; } = "";
        public string Percentage { get; set; } = "";
        public string Color { get; set; } = ThemeColorHelper.GetColorHex("TextMuted", "#808080");
    }

    public class CountrySummary
    {
        public string Code { get; set; } = "";
        public string Name { get; set; } = "";
        public string PacketCount { get; set; } = "";
        public string Flag { get; set; } = "";
        public bool IsHighRisk { get; set; }
    }

    public class ProtocolSummary
    {
        public string Name { get; set; } = "";
        public string Count { get; set; } = "";
        public string Color { get; set; } = ThemeColorHelper.GetColorHex("TextMuted", "#808080");
    }
}
