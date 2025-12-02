using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Base;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Orchestrator ViewModel for country traffic analysis.
/// Coordinates 6 specialized component ViewModels using composition pattern.
/// Reduced from 1,675 lines to ~350 lines through component-based architecture.
/// </summary>
public partial class CountryTrafficViewModel : SmartFilterableTab, ITabPopulationTarget, IDisposable
{
    private readonly IGeoIPService _geoIPService;
    private readonly ITabFilterService? _filterService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly GlobalFilterState? _globalFilterState;
    private NetworkStatistics? _currentStatistics;
    private IReadOnlyList<PacketInfo>? _allPackets;
    private bool _disposed;

    // Component ViewModels (Composition)
    public CountryDataViewModel DataManager { get; }
    public CountryStatisticsViewModel Statistics { get; }
    public CountryVisualizationViewModel Visualization { get; }
    public CountryFilterViewModel Filter { get; }
    public CountryTableViewModel Tables { get; }
    public CountryUIStateViewModel UIState { get; }

    // Top countries list (for legacy compatibility)
    [ObservableProperty] private System.Collections.ObjectModel.ObservableCollection<CountryItemViewModel> _topCountries = new();

    // ==================== FILTERABLE TAB IMPLEMENTATION ====================

    /// <summary>
    /// Common filters for protocol, source IP, and destination IP
    /// </summary>
    public new CommonFilterViewModel CommonFilters { get; } = new();

    /// <summary>
    /// Tab-specific filter: Country code filter
    /// </summary>
    [ObservableProperty] private string _countryFilter = "";

    /// <summary>
    /// Tab-specific filter: Traffic direction (All/Incoming/Outgoing)
    /// </summary>
    [ObservableProperty] private string _directionFilter = "All";

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
    public override string TabName => TabNames.CountryTraffic;

    /// <summary>
    /// IFilterableTab implementation - applies common and tab-specific filters
    /// </summary>
    public new void ApplyFilters()
    {
        // Reapply filters by triggering a statistics update
        if (_currentStatistics != null)
        {
            _ = UpdateStatistics(_currentStatistics);
        }
    }

    /// <summary>
    /// Applies the sophisticated PacketFilter to Country Traffic tab's country statistics
    /// </summary>
    protected override void ApplySmartFilter(PacketFilter filter)
    {
        // Apply filter to country statistics and update visualizations
        if (_currentStatistics != null)
        {
            _ = UpdateStatistics(_currentStatistics);
        }
        DebugLogger.Log($"[{TabName}] Smart filters applied to country traffic data");
    }

    [RelayCommand]
    private void ApplyFilter()
    {
        ApplyFilters();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        CommonFilters.ProtocolFilter = string.Empty;
        CommonFilters.SourceIPFilter = string.Empty;
        CommonFilters.DestinationIPFilter = string.Empty;
        ApplyFilters();
    }

    // Constructors
    public CountryTrafficViewModel()
        : this(
            App.Services?.GetService<IGeoIPService>() ?? throw new InvalidOperationException("GeoIPService not registered in DI container"),
            new TabFilterService("Country Traffic", new FilterServiceCore()),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
            App.Services?.GetService<GlobalFilterState>())
    {
    }

    public CountryTrafficViewModel(IGeoIPService geoIPService, ITabFilterService? filterService, ISmartFilterBuilder? filterBuilder = null, GlobalFilterState? globalFilterState = null)
        : base(filterBuilder ?? new SmartFilterBuilderService())
    {
        _geoIPService = geoIPService;
        _filterService = filterService;
        _filterCopyService = App.Services?.GetService<FilterCopyService>();
        _globalFilterState = globalFilterState;

        // Initialize component ViewModels
        DataManager = new CountryDataViewModel();
        Statistics = new CountryStatisticsViewModel();
        Visualization = new CountryVisualizationViewModel();
        Filter = new CountryFilterViewModel();
        Tables = new CountryTableViewModel();
        UIState = new CountryUIStateViewModel();

        // Subscribe to component events
        Filter.SortModeChanged += OnFilterSortModeChanged;
        Filter.ExcludedCountriesChanged += OnExcludedCountriesChanged;
        Filter.DisplayCountChanged += OnDisplayCountChanged;
        UIState.ContinentChanged += OnContinentChanged;

        // GeoIP service is initialized via DI (ServiceConfiguration.cs) - no duplicate init needed

        // Subscribe to filter service changes
        if (_filterService != null)
        {
            _filterService.FilterChanged += OnFilterServiceChanged;
        }

        // Subscribe to GlobalFilterState changes for tab-specific filtering (country, region)
        if (_globalFilterState != null)
        {
            _globalFilterState.OnFilterChanged += OnGlobalFilterChanged;
        }

        // Subscribe to CommonFilters property changes
        CommonFilters.PropertyChanged += (s, e) => ApplyFilters();

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        DebugLogger.Log("[CountryTrafficViewModel] Initialized with component-based architecture and filter support");
    }

    /// <summary>
    /// Sets the packet collection for analysis
    /// </summary>
    public void SetPackets(IReadOnlyList<PacketInfo> packets)
    {
        _allPackets = packets;
        DataManager.SetPackets(packets);
        DebugLogger.Log($"[CountryTrafficViewModel] SetPackets called with {packets?.Count ?? 0} packets");
    }

    /// <summary>
    /// Updates all statistics and visualizations
    /// </summary>
    public async Task UpdateStatistics(NetworkStatistics statistics)
    {
        // Ensure we're on the UI thread
        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await UpdateStatistics(statistics));
            return;
        }

        if (statistics == null) return;

        // DEFENSIVE: Don't overwrite good country data with empty data from filter events
        var countryCount = statistics.CountryStatistics?.Count ?? 0;
        var currentCountryCount = _currentStatistics?.CountryStatistics?.Count ?? 0;

        if (countryCount == 0 && currentCountryCount > 0)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] SKIPPING update - would replace {currentCountryCount} countries with 0 countries");
            DebugLogger.Log($"[CountryTrafficViewModel] Preserving existing country data");
            return;
        }

        _currentStatistics = statistics;
        DebugLogger.Log($"[CountryTrafficViewModel] UpdateStatistics called with {statistics.TotalPackets} total packets, {countryCount} countries");

        // Update DataManager with statistics
        DataManager.SetStatistics(statistics);

        // Update Statistics component
        Statistics.UpdateStatistics(statistics);

        // Update TopCountries list (for legacy compatibility)
        UpdateTopCountriesList();

        // Update Visualization component
        Visualization.SetStatistics(statistics);
        Visualization.SetExcludedCountries(Filter.ExcludedCountries);
        Visualization.UpdateVisualizations();

        // Update Tables component
        Tables.UpdateTables(statistics);
    }

    /// <summary>
    /// Updates the top countries list for display
    /// </summary>
    private void UpdateTopCountriesList()
    {
        if (_currentStatistics?.CountryStatistics == null)
        {
            TopCountries.Clear();
            return;
        }

        var countries = _currentStatistics.CountryStatistics.Values.AsEnumerable();

        // Apply GlobalFilterState country/region filters (from UnifiedFilterPanel)
        countries = ApplyGlobalFilterStateCriteria(countries);

        // Apply sorting based on filter
        var sorted = Filter.SortMode switch
        {
            0 => countries.OrderByDescending(c => c.TotalPackets), // By Traffic
            1 => countries.OrderByDescending(c => c.IsHighRisk).ThenByDescending(c => c.TotalPackets), // By Risk
            2 => countries.OrderBy(c => c.CountryName), // By Name
            _ => countries.OrderByDescending(c => c.TotalPackets)
        };

        // Filter excluded countries
        var filteredSorted = sorted.Where(c => !Filter.ExcludedCountries.Contains(c.CountryCode));

        TopCountries.Clear();
        foreach (var country in filteredSorted)
        {
            TopCountries.Add(new CountryItemViewModel
            {
                CountryCode = country.CountryCode,
                CountryName = country.CountryName,
                TotalPackets = country.TotalPackets,
                TotalBytes = country.TotalBytes,
                UniqueIPCount = country.UniqueIPs.Count,
                Percentage = country.Percentage,
                IsHighRisk = country.IsHighRisk,
                IncomingPackets = country.IncomingPackets,
                OutgoingPackets = country.OutgoingPackets
            });
        }

        DebugLogger.Log($"[CountryTrafficViewModel] Updated TopCountries with {TopCountries.Count} items");
    }

    /// <summary>
    /// Applies country-specific criteria from GlobalFilterState (country, region filters from UnifiedFilterPanel).
    /// Uses ContinentData.CountryToContinentMap for region lookups.
    /// </summary>
    private IEnumerable<CountryTrafficStatistics> ApplyGlobalFilterStateCriteria(IEnumerable<CountryTrafficStatistics> countries)
    {
        if (_globalFilterState == null || !_globalFilterState.HasActiveFilters)
            return countries;

        var result = countries;

        // Use helper to collect all criteria
        var (includeCountries, includeRegions, excludeCountries, excludeRegions) =
            GlobalFilterStateHelper.CollectCountryCriteria(_globalFilterState);

        // Apply include country filter - match against country code or name
        if (includeCountries.Count > 0)
        {
            result = result.Where(c =>
                includeCountries.Contains(c.CountryCode) ||
                includeCountries.Any(ic => c.CountryName.Contains(ic, StringComparison.OrdinalIgnoreCase)));
        }

        // Apply include region filter - use ContinentData.CountryToContinentMap for lookup
        if (includeRegions.Count > 0)
        {
            result = result.Where(c =>
            {
                var continent = GetContinentForCountry(c.CountryCode);
                return includeRegions.Contains(continent) ||
                       includeRegions.Any(ir => continent.Contains(ir, StringComparison.OrdinalIgnoreCase));
            });
        }

        // Apply exclude country filter
        if (excludeCountries.Count > 0)
        {
            result = result.Where(c =>
                !excludeCountries.Contains(c.CountryCode) &&
                !excludeCountries.Any(ec => c.CountryName.Contains(ec, StringComparison.OrdinalIgnoreCase)));
        }

        // Apply exclude region filter
        if (excludeRegions.Count > 0)
        {
            result = result.Where(c =>
            {
                var continent = GetContinentForCountry(c.CountryCode);
                return !excludeRegions.Contains(continent) &&
                       !excludeRegions.Any(er => continent.Contains(er, StringComparison.OrdinalIgnoreCase));
            });
        }

        return result;
    }

    /// <summary>
    /// Gets continent code/name for a country code using ContinentData mapping.
    /// </summary>
    private static string GetContinentForCountry(string countryCode)
    {
        if (string.IsNullOrEmpty(countryCode))
            return "Unknown";

        if (countryCode == "INTERNAL") return "Internal";
        if (countryCode == "IPV6" || countryCode == "IP6") return "IPv6";

        if (ContinentData.CountryToContinentMap.TryGetValue(countryCode.ToUpperInvariant(), out var continentCode))
        {
            // Return both code and name for flexible matching
            return ContinentData.Continents.TryGetValue(continentCode, out var continent)
                ? continent.DisplayName
                : continentCode;
        }

        return "Unknown";
    }

    /// <summary>
    /// Shows detailed information for a country
    /// </summary>
    [RelayCommand]
    private async Task ShowCountryDetails(object? parameter)
    {
        // Ensure we're on the UI thread
        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await ShowCountryDetails(parameter));
            return;
        }

        if (parameter is not CountryTableItem countryItem)
            return;

        DebugLogger.Log($"[CountryTrafficViewModel] ShowCountryDetails for {countryItem.CountryName} (Code: {countryItem.CountryCode})");

        // Get packets for this country from DataManager
        var countryPackets = DataManager.GetCountryPackets(countryItem.CountryCode, countryItem.Context) ?? new List<PacketInfo>();

        // Get incoming/outgoing values from statistics
        long incomingPackets = 0;
        long outgoingPackets = 0;

        if (_currentStatistics?.CountryStatistics?.TryGetValue(countryItem.CountryCode, out var countryStats) == true)
        {
            switch (countryItem.Context)
            {
                case CountryTableContext.SourcePackets:
                case CountryTableContext.SourceBytes:
                    incomingPackets = 0;
                    outgoingPackets = countryStats.OutgoingPackets;
                    break;
                case CountryTableContext.DestinationPackets:
                case CountryTableContext.DestinationBytes:
                    incomingPackets = countryStats.IncomingPackets;
                    outgoingPackets = 0;
                    break;
                default:
                    incomingPackets = countryStats.IncomingPackets;
                    outgoingPackets = countryStats.OutgoingPackets;
                    break;
            }

            DebugLogger.Log($"[CountryTrafficViewModel] ShowCountryDetails - {countryItem.CountryName}: Incoming={incomingPackets:N0}, Outgoing={outgoingPackets:N0}");
        }

        // Create and show the details window
        var viewModel = new CountryDetailsViewModel(countryItem, countryPackets, incomingPackets, outgoingPackets);
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

    /// <summary>
    /// Shows detailed information for an active flow
    /// </summary>
    [RelayCommand]
    private async Task ShowFlowDetails(object? parameter)
    {
        // Ensure we're on the UI thread
        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await ShowFlowDetails(parameter));
            return;
        }

        if (parameter is not ActiveFlowViewModel flow)
            return;

        DebugLogger.Log($"[CountryTrafficViewModel] ShowFlowDetails for {flow.SourceCountry} -> {flow.DestinationCountry}");

        // Resolve friendly names
        var sourceName = CountryNameHelper.GetDisplayName(flow.SourceCountryCode, flow.SourceCountry);
        var destinationName = CountryNameHelper.GetDisplayName(flow.DestinationCountryCode, flow.DestinationCountry);

        // Create a country item for the flow
        var countryItem = new CountryTableItem
        {
            CountryCode = flow.SourceCountryCode,
            CountryName = sourceName,
            TotalPackets = flow.PacketCount,
            TotalBytes = flow.ByteCount,
            PacketPercentage = flow.FlowIntensity,
            BytePercentage = flow.ByteIntensity,
            Continent = flow.SourceContinent,
            Rank = 1,
            Context = CountryTableContext.CrossBorderFlow
        };

        // Get packets for this flow
        var flowPackets = GetFlowPackets(flow) ?? new List<PacketInfo>();

        // Create and show the details window
        var viewModel = new CountryDetailsViewModel(countryItem, flowPackets, 0, flow.PacketCount);
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

    /// <summary>
    /// Gets packets for a specific flow
    /// </summary>
    private List<PacketInfo>? GetFlowPackets(ActiveFlowViewModel flow)
    {
        var allPackets = DataManager.GetAllPackets();
        if (allPackets == null)
            return null;

        var outgoingIndices = DataManager.GetCountryOutgoingIndices(flow.SourceCountryCode);
        var incomingIndices = DataManager.GetCountryIncomingIndices(flow.DestinationCountryCode);

        if (outgoingIndices == null || incomingIndices == null)
            return null;

        // Intersect source outgoing and destination incoming
        var incomingSet = new HashSet<int>(incomingIndices);
        var matched = new List<int>();

        foreach (var index in outgoingIndices)
        {
            if (incomingSet.Contains(index))
                matched.Add(index);
        }

        var flowPackets = new List<PacketInfo>(matched.Count);
        foreach (var index in matched)
        {
            if (index < allPackets.Count)
                flowPackets.Add(allPackets[index]);
        }

        DebugLogger.Log($"[CountryTrafficViewModel] Found {flowPackets.Count} packets for flow");
        return flowPackets;
    }

    /// <summary>
    /// Refreshes all country data
    /// </summary>
    [RelayCommand]
    private async Task RefreshCountries()
    {
        if (_currentStatistics != null)
        {
            await UpdateStatistics(_currentStatistics);
        }
    }

    // Event handlers for component coordination

    private void OnFilterSortModeChanged(object? sender, EventArgs e)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Sort mode changed to: {Filter.SortMode}");
        UpdateTopCountriesList();
    }

    private void OnExcludedCountriesChanged(object? sender, EventArgs e)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Excluded countries changed: {Filter.ExcludedCountries.Count} excluded");
        Visualization.SetExcludedCountries(Filter.ExcludedCountries);
        Visualization.UpdateVisualizations();
    }

    private void OnDisplayCountChanged(object? sender, EventArgs e)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Display count changed");
        // Tables will automatically reflect changes through bindings
    }

    private void OnContinentChanged(object? sender, string continentCode)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Continent changed to: {continentCode}");
        // Notify view that delegated properties have changed
        OnPropertyChanged(nameof(SelectedContinentTab));
        OnPropertyChanged(nameof(SelectedContinent));
    }

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Filter service changed - waiting for statistics update");
        // MainWindowViewModel will update us with new statistics
    }

    /// <summary>
    /// Handles GlobalFilterState changes - re-applies tab-specific filters to country data.
    /// </summary>
    private void OnGlobalFilterChanged()
    {
        // Re-apply filters when global filter state changes (e.g., country/region from UnifiedFilterPanel)
        if (_currentStatistics?.CountryStatistics != null && _currentStatistics.CountryStatistics.Count > 0)
        {
            Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                UpdateTopCountriesList();
                DebugLogger.Log($"[CountryTrafficViewModel] Country list updated after global filter change");
            });
        }
    }

    // ==================== COMPATIBILITY LAYER ====================
    // Merged from CountryTrafficViewModel.Compatibility.cs for cleaner project structure.

    // ==================== STATISTICS PROPERTIES ====================

    public string CountrySummary => Statistics.CountrySummary;
    public int UniqueCountries => Statistics.UniqueCountries;
    public double InternationalPercentage => Statistics.InternationalPercentage;
    public int CrossBorderFlows => Statistics.CrossBorderFlows;
    public string TopCountry => Statistics.TopCountry;
    public int TotalCountries => Statistics.TotalCountries;
    public long TotalPackets => Statistics.TotalPackets;
    public long TotalBytes => Statistics.TotalBytes;
    public ObservableCollection<CountryTrafficItem> TopCountriesList => Statistics.TopCountriesList;
    public ObservableCollection<CountryTrafficItem> AllCountriesList => Statistics.AllCountriesList;
    public System.Collections.Generic.Dictionary<string, CountryTrafficStatistics> CountryTrafficStatistics => Statistics.CountryTrafficStatistics;

    // Risk analysis
    public int HighRiskCountryCount => Statistics.HighRiskCountryCount;
    public bool HasHighRiskTraffic => Statistics.HasHighRiskTraffic;
    public string HighRiskWarning => Statistics.HighRiskWarning;

    // Continent traffic stats
    public string NorthAmericaTraffic => Statistics.NorthAmericaTraffic;
    public string SouthAmericaTraffic => Statistics.SouthAmericaTraffic;
    public string EuropeTraffic => Statistics.EuropeTraffic;
    public string AfricaTraffic => Statistics.AfricaTraffic;
    public string AsiaTraffic => Statistics.AsiaTraffic;
    public string OceaniaTraffic => Statistics.OceaniaTraffic;
    public string InternalTraffic => Statistics.InternalTraffic;
    public string Ipv6Traffic => Statistics.Ipv6Traffic;

    // ==================== VISUALIZATION PROPERTIES ====================

    public ObservableCollection<ISeries> CountryChartSeries => Visualization.CountryChartSeries;
    public System.Collections.Generic.Dictionary<string, double> CountryMapData => Visualization.CountryMapData;

    // Continent colors
    public string NorthAmericaColor => Visualization.NorthAmericaColor;
    public string SouthAmericaColor => Visualization.SouthAmericaColor;
    public string EuropeColor => Visualization.EuropeColor;
    public string AfricaColor => Visualization.AfricaColor;
    public string AsiaColor => Visualization.AsiaColor;
    public string OceaniaColor => Visualization.OceaniaColor;
    public string InternalColor => Visualization.InternalColor;
    public string Ipv6Color => Visualization.Ipv6Color;

    // ==================== FILTER PROPERTIES ====================

    public int SortMode
    {
        get => Filter.SortMode;
        set => Filter.SortMode = value;
    }

    public ObservableCollection<string> ExcludedCountries => Filter.ExcludedCountries;
    public bool HasExcludedCountries => Filter.HasExcludedCountries;
    public string ExcludedCountriesText => Filter.ExcludedCountriesText;
    public bool ShowTop50Countries
    {
        get => Filter.ShowTop50Countries;
        set => Filter.ShowTop50Countries = value;
    }
    public int DisplayedCountryCount => Filter.DisplayedCountryCount;
    public bool ShowTop50SourceCountries
    {
        get => Filter.ShowTop50SourceCountries;
        set => Filter.ShowTop50SourceCountries = value;
    }
    public bool ShowTop50DestinationCountries
    {
        get => Filter.ShowTop50DestinationCountries;
        set => Filter.ShowTop50DestinationCountries = value;
    }
    public bool ShowAllFlows
    {
        get => Filter.ShowAllFlows;
        set => Filter.ShowAllFlows = value;
    }
    public int DisplayedFlowCount
    {
        get => Filter.DisplayedFlowCount;
        set => Filter.DisplayedFlowCount = value;
    }

    // ==================== TABLE PROPERTIES ====================

    public ObservableCollection<CountryTableItem> CountriesByPackets => Tables.CountriesByPackets;
    public ObservableCollection<CountryTableItem> CountriesByBytes => Tables.CountriesByBytes;
    public ObservableCollection<CountryTableItem> TopSourceCountriesByPackets => Tables.TopSourceCountriesByPackets;
    public ObservableCollection<CountryTableItem> TopSourceCountriesByBytes => Tables.TopSourceCountriesByBytes;
    public ObservableCollection<CountryTableItem> TopDestinationCountriesByPackets => Tables.TopDestinationCountriesByPackets;
    public ObservableCollection<CountryTableItem> TopDestinationCountriesByBytes => Tables.TopDestinationCountriesByBytes;
    public ObservableCollection<ActiveFlowViewModel> ActiveFlows => Tables.ActiveFlows;
    public ObservableCollection<ActiveFlowViewModel> ActiveFlowsByPackets => Tables.ActiveFlowsByPackets;
    public ObservableCollection<ActiveFlowViewModel> ActiveFlowsByBytes => Tables.ActiveFlowsByBytes;
    public int ActiveFlowCount => Tables.ActiveFlowCount;

    // ==================== UI STATE PROPERTIES ====================

    public bool ShowParticles
    {
        get => UIState.ShowParticles;
        set => UIState.ShowParticles = value;
    }
    public bool ShowGridLines
    {
        get => UIState.ShowGridLines;
        set => UIState.ShowGridLines = value;
    }
    public bool ShowConnections
    {
        get => UIState.ShowConnections;
        set => UIState.ShowConnections = value;
    }
    public bool EnableAnimations
    {
        get => UIState.EnableAnimations;
        set => UIState.EnableAnimations = value;
    }
    public bool ShowAnimations
    {
        get => UIState.ShowAnimations;
        set => UIState.ShowAnimations = value;
    }
    public bool ShowTrafficFlows
    {
        get => UIState.ShowTrafficFlows;
        set => UIState.ShowTrafficFlows = value;
    }
    public bool ShowCountryLabels
    {
        get => UIState.ShowCountryLabels;
        set => UIState.ShowCountryLabels = value;
    }
    public int SelectedContinentTab
    {
        get => UIState.SelectedContinentTab;
        set => UIState.SelectedContinentTab = value;
    }
    public string SelectedContinent => UIState.SelectedContinent;

    // ==================== BACKWARD-COMPATIBLE COMMANDS ====================

    public IRelayCommand ClearExclusionsCommand => Filter.ClearExclusionsCommand;
    public IRelayCommand ZoomInCommand => UIState.ZoomInCommand;
    public IRelayCommand ZoomOutCommand => UIState.ZoomOutCommand;
    public IRelayCommand ResetViewCommand => UIState.ResetViewCommand;
    public IRelayCommand NavigateToContinentCommand => UIState.NavigateToContinentCommand;

    /// <summary>
    /// Handles continent click navigation (delegates to UIState)
    /// </summary>
    public void OnContinentClicked(string continentCode)
    {
        DebugLogger.Log($"[CountryTrafficViewModel.Compatibility] OnContinentClicked called with: {continentCode}");
        UIState.OnContinentClicked(continentCode);
    }

    /// <summary>
    /// Action property for AXAML binding (Avalonia requires Action, not method)
    /// </summary>
    public Action<string> OnContinentClickedAction
    {
        get
        {
            DebugLogger.Log("[CountryTrafficViewModel.Compatibility] OnContinentClickedAction property accessed");
            return OnContinentClicked;
        }
    }

    // ==================== ITabPopulationTarget IMPLEMENTATION ====================

    /// <inheritdoc />
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[CountryTrafficViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");
        _allPackets = result.AllPackets;
        await UpdateStatistics(result.Statistics);
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
        if (_globalFilterState != null)
        {
            _globalFilterState.OnFilterChanged -= OnGlobalFilterChanged;
        }

        // Unsubscribe from filter service events
        if (_filterService != null)
        {
            _filterService.FilterChanged -= OnFilterServiceChanged;
        }

        // Unregister from filter copy service
        _filterCopyService?.UnregisterTab(TabName);

        // Unsubscribe from component events
        if (Filter != null)
        {
            Filter.SortModeChanged -= OnFilterSortModeChanged;
            Filter.ExcludedCountriesChanged -= OnExcludedCountriesChanged;
            Filter.DisplayCountChanged -= OnDisplayCountChanged;
        }

        if (UIState != null)
        {
            UIState.ContinentChanged -= OnContinentChanged;
        }

        DebugLogger.Log("[CountryTrafficViewModel] Disposed - cleaned up event handlers");
    }
}

// Helper ViewModels
public class CountryItemViewModel : ObservableObject
{
    public string CountryCode { get; set; } = "";
    public string CountryName { get; set; } = "";
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public long IncomingPackets { get; set; }
    public long OutgoingPackets { get; set; }
    public int UniqueIPCount { get; set; }
    public double Percentage { get; set; }
    public bool IsHighRisk { get; set; }

    public string BytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
    public string TotalBytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
}

public class ActiveFlowViewModel : ObservableObject
{
    public int Rank { get; set; }
    public string SourceCountry { get; set; } = "";
    public string SourceCountryCode { get; set; } = "";
    public string DestinationCountry { get; set; } = "";
    public string DestinationCountryCode { get; set; } = "";
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public string Protocol { get; set; } = "";
    public bool IsCrossBorder { get; set; }
    public bool IsHighRisk { get; set; }
    public double FlowIntensity { get; set; }
    public double ByteIntensity { get; set; }
    public string SourceContinent { get; set; } = "";
    public string DestinationContinent { get; set; } = "";

    public string BytesFormatted => NumberFormatter.FormatBytes(ByteCount);
    public string PacketsFormatted => $"{PacketCount:N0}";
    public string SourceCountryDisplayCode => CountryNameHelper.GetDisplayCode(SourceCountryCode);
    public string DestinationCountryDisplayCode => CountryNameHelper.GetDisplayCode(DestinationCountryCode);
    public string FlowDirection => $"{SourceCountryDisplayCode} -> {DestinationCountryDisplayCode}";
}
