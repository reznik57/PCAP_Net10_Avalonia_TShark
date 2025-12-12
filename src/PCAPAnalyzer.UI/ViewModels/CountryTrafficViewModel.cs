using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive.Linq;
using System.Reactive.Subjects;
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
using PCAPAnalyzer.UI.Utilities;
using DebugLogger = PCAPAnalyzer.Core.Utilities.DebugLogger;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Orchestrator ViewModel for country traffic analysis.
/// Coordinates 6 specialized component ViewModels using composition pattern.
/// Reduced from 1,675 lines to ~350 lines through component-based architecture.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling",
    Justification = "Orchestrator ViewModel coordinates 6 component VMs - high coupling is inherent to composition pattern")]
public partial class CountryTrafficViewModel : SmartFilterableTab, ITabPopulationTarget, IDisposable
{
    private readonly IDispatcherService _dispatcher;
    private readonly IGeoIPService _geoIPService;
    private readonly ITabFilterService? _filterService;
    private readonly FilterCopyService? _filterCopyService;
    private readonly GlobalFilterState? _globalFilterState;
    private NetworkStatistics? _currentStatistics;
    private IReadOnlyList<PacketInfo>? _allPackets;
    private bool _disposed;

    // Unfiltered totals for Total/Filtered pattern (stored on initial load)
    private int _unfilteredCountryCount;
    private int _unfilteredFlowCount;

    // Filter debouncing (300ms throttle to prevent update spam during rapid filter changes)
    private readonly Subject<bool> _filterTrigger = new();
    private IDisposable? _filterSubscription;

    // Component ViewModels (Composition)
    public CountryDataViewModel DataManager { get; }
    public CountryStatisticsViewModel Statistics { get; }
    public CountryVisualizationViewModel Visualization { get; }
    public CountryFilterViewModel Filter { get; }
    public CountryTableViewModel Tables { get; }
    public CountryUIStateViewModel UIState { get; }

    /// <summary>
    /// Drill-down popup for country/flow details (same pattern as Dashboard)
    /// </summary>
    public DrillDownPopupViewModel DrillDown { get; }

    /// <summary>
    /// Stats bar using unified Total/Filtered pattern (like Packet Analysis tab).
    /// </summary>
    public StatsBarControlViewModel GeographicStatsBar { get; } = new()
    {
        SectionTitle = "GEOGRAPHIC OVERVIEW",
        AccentColor = ThemeColorHelper.GetColorHex("AccentPrimary", "#58A6FF"),
        ColumnCount = 6
    };

    // Top countries list (for legacy compatibility)
    [ObservableProperty] private System.Collections.ObjectModel.ObservableCollection<CountryItemViewModel> _topCountries = [];

    // ==================== FILTERED STATISTICS (from GlobalFilterState) ====================

    /// <summary>
    /// Filtered packet count (sum of filtered countries' packets)
    /// </summary>
    [ObservableProperty] private long _filteredTotalPackets;

    /// <summary>
    /// Filtered bytes count (sum of filtered countries' bytes)
    /// </summary>
    [ObservableProperty] private long _filteredTotalBytes;

    /// <summary>
    /// Number of countries after filtering
    /// </summary>
    [ObservableProperty] private int _filteredCountryCount;

    /// <summary>
    /// Indicates if GlobalFilterState has active filters affecting this tab.
    /// Returns true for ANY active filter (not just country criteria) for Total/Filtered display.
    /// </summary>
    [ObservableProperty] private bool _isGlobalFilterActive;

    /// <summary>
    /// Percentage of packets shown after filtering
    /// </summary>
    public double FilteredPacketsPercentage => TotalPackets > 0 ? (double)FilteredTotalPackets / TotalPackets * 100 : 100;

    /// <summary>
    /// Formatted filtered bytes
    /// </summary>
    public string FilteredTotalBytesFormatted => NumberFormatter.FormatBytes(FilteredTotalBytes);

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
    /// Uses 300ms debouncing to prevent update spam during rapid filter changes.
    /// </summary>
    public new void ApplyFilters()
    {
        // Trigger debounced filter update
        _filterTrigger.OnNext(true);
    }

    /// <summary>
    /// Actually applies filters after debounce period.
    /// Called by the debounced subscription.
    /// </summary>
    private void ApplyFiltersInternal()
    {
        // Reapply filters by triggering a statistics update
        if (_currentStatistics is not null)
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
        if (_currentStatistics is not null)
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
            App.Services?.GetService<IDispatcherService>() ?? throw new InvalidOperationException("IDispatcherService not registered"),
            App.Services?.GetService<IGeoIPService>() ?? throw new InvalidOperationException("GeoIPService not registered in DI container"),
            new TabFilterService("Country Traffic", new FilterServiceCore()),
            App.Services?.GetService<ISmartFilterBuilder>() ?? new SmartFilterBuilderService(),
            App.Services?.GetService<GlobalFilterState>())
    {
    }

    public CountryTrafficViewModel(IDispatcherService dispatcher, IGeoIPService geoIPService, ITabFilterService? filterService, ISmartFilterBuilder? filterBuilder = null, GlobalFilterState? globalFilterState = null)
        : base(filterBuilder ?? new SmartFilterBuilderService())
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        _dispatcher = dispatcher;
        _geoIPService = geoIPService;
        _filterService = filterService;
        _filterCopyService = App.Services?.GetService<FilterCopyService>();
        _globalFilterState = globalFilterState;

        // Initialize component ViewModels
        DataManager = new();
        Statistics = new();
        Visualization = new();
        Filter = new();
        Tables = new();
        UIState = new();
        DrillDown = new DrillDownPopupViewModel(NavigateToPacketAnalysis, geoIPService);

        // Wire up timeline data provider for sparklines
        Tables.TimelineBucketProvider = DataManager.GetCountryTimelineBuckets;

        // Subscribe to component events
        Filter.SortModeChanged += OnFilterSortModeChanged;
        Filter.ExcludedCountriesChanged += OnExcludedCountriesChanged;
        Filter.DisplayCountChanged += OnDisplayCountChanged;
        Filter.HideInternalTrafficChanged += OnHideInternalTrafficChanged;
        UIState.ContinentChanged += OnContinentChanged;

        // Forward PropertyChanged from component VMs to this VM for delegated properties
        // This is critical for XAML bindings to update when component data changes
        Statistics.PropertyChanged += OnStatisticsPropertyChanged;
        Visualization.PropertyChanged += OnVisualizationPropertyChanged;

        // GeoIP service is initialized via DI (ServiceConfiguration.cs) - no duplicate init needed

        // Subscribe to filter service changes
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

        // Register with FilterCopyService
        _filterCopyService?.RegisterTab(TabName, this);

        // Set up filter debouncing (300ms throttle)
        _filterSubscription = _filterTrigger
            .Throttle(TimeSpan.FromMilliseconds(300))
            .ObserveOn(ReactiveUI.RxApp.MainThreadScheduler)
            .Subscribe(_ => ApplyFiltersInternal());

        DebugLogger.Log("[CountryTrafficViewModel] Initialized with component-based architecture, filter support, and 300ms debouncing");
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
    /// Sets the filtered packet set and updates statistics accordingly.
    /// Called by MainWindowViewModel when global filters are applied.
    /// </summary>
    /// <param name="packets">The packet list (filtered or full if filters cleared)</param>
    /// <param name="isFilterActive">Explicit filter state - true if filter active, false if cleared</param>
    public async Task SetFilteredPacketsAsync(IReadOnlyList<PacketInfo> packets, bool isFilterActive = true)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] SetFilteredPacketsAsync called with {packets.Count:N0} packets (isFilterActive={isFilterActive})");

        // CRITICAL: Use explicit parameter, not count comparison (which is unreliable)
        IsGlobalFilterActive = isFilterActive;

        await _dispatcher.InvokeAsync(() =>
        {
            // Update Statistics component with packet count for Total/Filtered display
            Statistics.SetFilteredState(packets.Count, IsGlobalFilterActive);

            // Update filtered packet/byte counts at ViewModel level too (for header display)
            FilteredTotalPackets = packets.Count;

            UpdateTopCountriesList();

            // Refresh stats bar to reflect new filter state
            UpdateGeographicStatsBar();
        });

        DebugLogger.Log($"[CountryTrafficViewModel] SetFilteredPacketsAsync complete - {FilteredCountryCount} countries displayed, {packets.Count:N0} packets, isFilterActive={IsGlobalFilterActive}");
    }

    /// <summary>
    /// Clears the filtered packet state, showing all data again.
    /// Called when filters are cleared.
    /// </summary>
    public void ClearFilteredPackets()
    {
        IsGlobalFilterActive = false;
        Statistics.ClearFilteredState();
        FilteredTotalPackets = _allPackets?.Count ?? 0;
        UpdateTopCountriesList();
        DebugLogger.Log("[CountryTrafficViewModel] Cleared filter state - showing all countries");
    }

    /// <summary>
    /// Updates all statistics and visualizations
    /// </summary>
    public async Task UpdateStatistics(NetworkStatistics statistics)
    {
        // Ensure we're on the UI thread
        if (!_dispatcher.CheckAccess())
        {
            await _dispatcher.InvokeAsync(async () => await UpdateStatistics(statistics));
            return;
        }

        if (statistics is null) return;

        // DEFENSIVE: Don't overwrite good country data with empty data from race conditions
        // But DO allow legitimate 0-country results from filters (e.g., filtering to Antarctica)
        var countryCount = statistics.CountryStatistics?.Count ?? 0;
        var currentCountryCount = _currentStatistics?.CountryStatistics?.Count ?? 0;

        // Only block if this looks like a data loss bug (same total packets but 0 countries)
        // Allow 0 countries if: (1) total packets also changed, or (2) GlobalFilterState is active
        var isLikelyDataLoss = countryCount == 0
            && currentCountryCount > 0
            && statistics.TotalPackets == (_currentStatistics?.TotalPackets ?? 0)
            && !IsGlobalFilterActive;

        if (isLikelyDataLoss)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] SKIPPING update - likely data loss (same packets, 0 countries)");
            DebugLogger.Log($"[CountryTrafficViewModel] Preserving existing {currentCountryCount} countries");
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

        // Update GeographicStatsBar with unified Total/Filtered pattern
        UpdateGeographicStatsBar();
    }

    /// <summary>
    /// Updates the top countries list for display
    /// </summary>
    private void UpdateTopCountriesList()
    {
        if (_currentStatistics?.CountryStatistics is null)
        {
            TopCountries.Clear();
            FilteredTotalPackets = 0;
            FilteredTotalBytes = 0;
            FilteredCountryCount = 0;
            return;
        }

        var countries = _currentStatistics.CountryStatistics.Values.AsEnumerable();

        // Apply GlobalFilterState country/region filters (from UnifiedFilterPanel)
        countries = ApplyGlobalFilterStateCriteria(countries);

        // Materialize to calculate filtered stats
        var filteredCountries = countries.ToList();

        // Calculate filtered statistics from filtered countries
        FilteredTotalPackets = filteredCountries.Sum(c => c.TotalPackets);
        FilteredTotalBytes = filteredCountries.Sum(c => c.TotalBytes);
        FilteredCountryCount = filteredCountries.Count;

        // Notify dependent computed properties
        OnPropertyChanged(nameof(FilteredPacketsPercentage));
        OnPropertyChanged(nameof(FilteredTotalBytesFormatted));

        // Apply sorting based on filter
        var sorted = Filter.SortMode switch
        {
            0 => filteredCountries.OrderByDescending(c => c.TotalPackets), // By Traffic
            1 => filteredCountries.OrderByDescending(c => c.IsHighRisk).ThenByDescending(c => c.TotalPackets), // By Risk
            2 => filteredCountries.OrderBy(c => c.CountryName), // By Name
            _ => filteredCountries.OrderByDescending(c => c.TotalPackets)
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

        DebugLogger.Log($"[CountryTrafficViewModel] Updated TopCountries with {TopCountries.Count} items, filtered stats: {FilteredTotalPackets:N0} packets, {FilteredCountryCount} countries");
    }

    /// <summary>
    /// Maps UI region names to ContinentData display names for consistent filtering.
    /// </summary>
    private static readonly Dictionary<string, string> RegionNameMapping = new(StringComparer.OrdinalIgnoreCase)
    {
        ["North America"] = "N. America",
        ["South America"] = "S. America",
        ["Middle East"] = "Asia",  // Middle East countries are mapped to Asia in ContinentData
        ["Europe"] = "Europe",
        ["Asia"] = "Asia",
        ["Africa"] = "Africa",
        ["Oceania"] = "Oceania"
    };

    /// <summary>
    /// Normalizes a region name from UI to match ContinentData display names.
    /// </summary>
    private static string NormalizeRegionName(string uiRegionName)
        => RegionNameMapping.TryGetValue(uiRegionName, out var mapped) ? mapped : uiRegionName;

    /// <summary>
    /// Checks if a country matches a direction filter (Inbound, Outbound, Internal).
    /// </summary>
    private static bool MatchesDirection(CountryTrafficStatistics country, string direction)
    {
        return direction switch
        {
            "Inbound" => country.IncomingPackets > 0,
            "Outbound" => country.OutgoingPackets > 0,
            "Internal" => country.CountryCode is "INT" or "PRIV" or "Internal" or "PRV",
            _ => false
        };
    }

    /// <summary>
    /// Applies country-specific criteria from GlobalFilterState (country, region, direction filters from UnifiedFilterPanel).
    /// Uses ContinentData.CountryToContinentMap for region lookups.
    /// </summary>
    private IEnumerable<CountryTrafficStatistics> ApplyGlobalFilterStateCriteria(IEnumerable<CountryTrafficStatistics> countries)
    {
        if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
            return countries;

        var result = countries;

        // Use helper to collect all criteria (now includes Directions)
        var (includeCountries, includeRegions, includeDirections, excludeCountries, excludeRegions, excludeDirections) =
            GlobalFilterStateHelper.CollectCountryCriteria(_globalFilterState);

        // Apply include country filter - match against country code or name
        if (includeCountries.Count > 0)
        {
            result = result.Where(c =>
                includeCountries.Contains(c.CountryCode) ||
                includeCountries.Any(ic => c.CountryName.Contains(ic, StringComparison.OrdinalIgnoreCase)));
        }

        // Apply include region filter - normalize UI names to ContinentData names
        if (includeRegions.Count > 0)
        {
            var normalizedRegions = includeRegions.Select(NormalizeRegionName).ToHashSet(StringComparer.OrdinalIgnoreCase);
            result = result.Where(c =>
            {
                var continent = GetContinentForCountry(c.CountryCode);
                return normalizedRegions.Contains(continent);
            });
        }

        // Apply include direction filter (Inbound, Outbound, Internal)
        if (includeDirections.Count > 0)
        {
            result = result.Where(c => includeDirections.Any(d => MatchesDirection(c, d)));
        }

        // Apply exclude country filter
        if (excludeCountries.Count > 0)
        {
            result = result.Where(c =>
                !excludeCountries.Contains(c.CountryCode) &&
                !excludeCountries.Any(ec => c.CountryName.Contains(ec, StringComparison.OrdinalIgnoreCase)));
        }

        // Apply exclude region filter - normalize UI names to ContinentData names
        if (excludeRegions.Count > 0)
        {
            var normalizedExcludeRegions = excludeRegions.Select(NormalizeRegionName).ToHashSet(StringComparer.OrdinalIgnoreCase);
            result = result.Where(c =>
            {
                var continent = GetContinentForCountry(c.CountryCode);
                return !normalizedExcludeRegions.Contains(continent);
            });
        }

        // Apply exclude direction filter
        if (excludeDirections.Count > 0)
        {
            result = result.Where(c => !excludeDirections.Any(d => MatchesDirection(c, d)));
        }

        return result;
    }

    /// <summary>
    /// Gets continent display name for a country code.
    /// Delegates to centralized ContinentData.GetContinentDisplayName.
    /// </summary>
    private static string GetContinentForCountry(string countryCode)
        => ContinentData.GetContinentDisplayName(countryCode);

    /// <summary>
    /// Shows detailed information for a country using inline drill-down popup (Dashboard style)
    /// </summary>
    [RelayCommand]
    private void ShowCountryDetails(object? parameter)
    {
        if (parameter is not CountryTableItem countryItem)
            return;

        DebugLogger.Log($"[CountryTrafficViewModel] ShowCountryDetails for {countryItem.CountryName} (Code: {countryItem.CountryCode})");

        // Get packets for this country from DataManager
        var countryPackets = DataManager.GetCountryPackets(countryItem.CountryCode, countryItem.Context) ?? new List<PacketInfo>();

        if (countryPackets.Count == 0)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] No packets found for {countryItem.CountryCode}");
            return;
        }

        // Use ShowForCountry which doesn't re-filter packets (they're already filtered by country)
        DrillDown.ShowForCountry(
            $"{countryItem.CountryName} ({countryItem.CountryCode})",
            countryPackets,
            countryItem.TotalPackets,
            countryItem.TotalBytes);
    }

    /// <summary>
    /// Maps normalized UI country codes back to DataManager dictionary keys.
    /// CountryTableViewModel.NormalizeCountryCode converts INT->PRIV, but DataManager uses "Internal".
    /// </summary>
    private static string MapNormalizedCodeToDataKey(string normalizedCode)
    {
        return normalizedCode switch
        {
            "PRIV" => "Internal",  // NormalizeCountryCode: INT/PRIVATE/LOCAL/LAN -> PRIV
            "IP6" => "IP6_LINK",   // NormalizeCountryCode: ??/XX -> IP6, but DataManager uses IP6_LINK
            _ => normalizedCode
        };
    }

    /// <summary>
    /// Navigation callback for DrillDown popup - navigates to Packet Analysis with filter
    /// </summary>
    private void NavigateToPacketAnalysis(string filterType, string filterValue)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] NavigateToPacketAnalysis: {filterType}={filterValue}");

        // Apply filter via GlobalFilterState
        if (_globalFilterState is not null)
        {
            switch (filterType.ToLowerInvariant())
            {
                case "ip":
                    _globalFilterState.IncludeFilters.IPs.Clear();
                    _globalFilterState.AddIncludeIP(filterValue);
                    break;
                case "port":
                    _globalFilterState.IncludeFilters.Ports.Clear();
                    _globalFilterState.AddIncludePort(filterValue);
                    break;
                case "country":
                    _globalFilterState.IncludeFilters.Countries.Clear();
                    _globalFilterState.AddIncludeCountry(filterValue);
                    break;
            }
        }

        // Navigate to Packet Analysis tab (index 1)
        // This requires wiring up navigation - for now just close the drill-down
        DrillDown.IsVisible = false;
    }

    /// <summary>
    /// Shows detailed information for an active flow using inline drill-down popup
    /// </summary>
    [RelayCommand]
    private void ShowFlowDetails(object? parameter)
    {
        if (parameter is not ActiveFlowViewModel flow)
            return;

        DebugLogger.Log($"[CountryTrafficViewModel] ShowFlowDetails for {flow.SourceCountry} -> {flow.DestinationCountry}");

        // Get packets for this flow
        var flowPackets = GetFlowPackets(flow) ?? new List<PacketInfo>();

        if (flowPackets.Count == 0)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] No packets found for flow");
            return;
        }

        // Use ShowForCountry which doesn't re-filter packets (they're already filtered by flow)
        DrillDown.ShowForCountry(
            $"{flow.SourceCountry} ({flow.SourceCountryCode}) → {flow.DestinationCountry} ({flow.DestinationCountryCode})",
            flowPackets,
            flow.PacketCount,
            flow.ByteCount);
    }

    /// <summary>
    /// Gets packets for a specific flow
    /// </summary>
    private List<PacketInfo>? GetFlowPackets(ActiveFlowViewModel flow)
    {
        var allPackets = DataManager.GetAllPackets();
        if (allPackets is null)
            return null;

        // Map normalized UI codes back to DataManager keys
        // NormalizeCountryCode converts INT->PRIV, but DataManager uses "Internal"
        var sourceKey = MapNormalizedCodeToDataKey(flow.SourceCountryCode);
        var destKey = MapNormalizedCodeToDataKey(flow.DestinationCountryCode);

        DebugLogger.Log($"[CountryTrafficViewModel] GetFlowPackets: {flow.SourceCountryCode}->{sourceKey}, {flow.DestinationCountryCode}->{destKey}");

        var outgoingIndices = DataManager.GetCountryOutgoingIndices(sourceKey);
        var incomingIndices = DataManager.GetCountryIncomingIndices(destKey);

        if (outgoingIndices is null || incomingIndices is null)
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
        if (_currentStatistics is not null)
        {
            await UpdateStatistics(_currentStatistics);
        }
    }

    // NOTE: ExportSummary, ExportToCsvAsync, ExportToJsonAsync, ExportToMarkdownAsync
    // moved to CountryTrafficViewModel.Export.cs

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

    private void OnHideInternalTrafficChanged(object? sender, EventArgs e)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Hide internal traffic changed to: {Filter.HideInternalTraffic}");
        // Refresh tables with new filter state
        if (_currentStatistics is not null)
        {
            Tables.HideInternalTraffic = Filter.HideInternalTraffic;
            Tables.UpdateTables(_currentStatistics);
        }
    }

    private void OnContinentChanged(object? sender, string continentCode)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] Continent changed to: {continentCode}");
        // Notify view that delegated properties have changed
        OnPropertyChanged(nameof(SelectedContinentTab));
        OnPropertyChanged(nameof(SelectedContinent));
    }

    /// <summary>
    /// Forwards property changes from Statistics component to parent VM.
    /// Critical for XAML bindings to delegated properties like CountryTrafficStatistics.
    /// </summary>
    private void OnStatisticsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward all Statistics property changes - these are delegated to parent VM
        if (e.PropertyName is not null)
        {
            OnPropertyChanged(e.PropertyName);
            DebugLogger.Log($"[CountryTrafficViewModel] Forwarding Statistics.{e.PropertyName} PropertyChanged");
        }
    }

    /// <summary>
    /// Forwards property changes from Visualization component to parent VM.
    /// Critical for XAML bindings to delegated properties like CountryMapData.
    /// </summary>
    private void OnVisualizationPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward all Visualization property changes - these are delegated to parent VM
        if (e.PropertyName is not null)
        {
            OnPropertyChanged(e.PropertyName);
            DebugLogger.Log($"[CountryTrafficViewModel] Forwarding Visualization.{e.PropertyName} PropertyChanged");
        }
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
        if (_currentStatistics?.CountryStatistics is not null && _currentStatistics.CountryStatistics.Count > 0)
        {
            _dispatcher.InvokeAsync(() =>
            {
                UpdateTopCountriesList();
                UpdateGeographicStatsBar();
                DebugLogger.Log($"[CountryTrafficViewModel] Country list updated after global filter change");
            });
        }
    }

    // ==================== GEOGRAPHIC STATS BAR (Total/Filtered Pattern) ====================

    /// <summary>
    /// Updates GeographicStatsBar with unified Total/Filtered display pattern.
    /// Call after filtering or when statistics change.
    /// </summary>
    private void UpdateGeographicStatsBar()
    {
        GeographicStatsBar.ClearStats();

        // Get totals from the full PCAP statistics (stored on initial load)
        var totalPackets = Statistics.UnfilteredTotalPackets > 0
            ? Statistics.UnfilteredTotalPackets
            : _currentStatistics?.TotalPackets ?? 0;
        var totalBytes = Statistics.UnfilteredTotalBytes > 0
            ? Statistics.UnfilteredTotalBytes
            : _currentStatistics?.TotalBytes ?? 0L;

        // Get filtered values from current state
        var filteredPackets = IsGlobalFilterActive ? FilteredTotalPackets : totalPackets;
        var filteredBytes = IsGlobalFilterActive ? FilteredTotalBytes : totalBytes;

        // Countries stat - with Total/Filtered pattern
        var totalCountries = _unfilteredCountryCount > 0 ? _unfilteredCountryCount : UniqueCountries;
        var filteredCountries = IsGlobalFilterActive ? UniqueCountries : totalCountries;
        TabStatsHelper.AddNumericStat(GeographicStatsBar, "COUNTRIES", "🌍",
            totalCountries, filteredCountries, IsGlobalFilterActive,
            ThemeColorHelper.GetColorHex("AccentPrimary", "#58A6FF"));

        // Packets
        TabStatsHelper.AddNumericStat(GeographicStatsBar, "PACKETS", "📦",
            totalPackets, filteredPackets, IsGlobalFilterActive,
            ThemeColorHelper.GetColorHex("SlackSuccess", "#3FB950"));

        // Traffic
        TabStatsHelper.AddBytesStat(GeographicStatsBar, "TRAFFIC", "💾",
            totalBytes, filteredBytes, IsGlobalFilterActive,
            ThemeColorHelper.GetColorHex("SlackWarning", "#D29922"));

        // Flows - with Total/Filtered pattern
        var totalFlows = _unfilteredFlowCount > 0 ? _unfilteredFlowCount : CrossBorderFlows;
        var filteredFlows = IsGlobalFilterActive ? CrossBorderFlows : totalFlows;
        TabStatsHelper.AddNumericStat(GeographicStatsBar, "FLOWS", "🔄",
            totalFlows, filteredFlows, IsGlobalFilterActive,
            ThemeColorHelper.GetColorHex("AccentPurple", "#A371F7"));

        // Top Source Country (from first item in Tables)
        var topSource = Tables.TopSourceCountriesByPackets.FirstOrDefault()?.CountryName ?? "N/A";
        TabStatsHelper.AddSimpleStat(GeographicStatsBar, "TOP SOURCE", "📤",
            topSource, null,
            ThemeColorHelper.GetColorHex("SlackDanger", "#F85149"));

        // Top Dest Country
        var topDest = Tables.TopDestinationCountriesByPackets.FirstOrDefault()?.CountryName ?? "N/A";
        TabStatsHelper.AddSimpleStat(GeographicStatsBar, "TOP DEST", "📥",
            topDest, null,
            ThemeColorHelper.GetColorHex("SlackInfo", "#58A6FF"));
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

    public bool HideInternalTraffic
    {
        get => Filter.HideInternalTraffic;
        set => Filter.HideInternalTraffic = value;
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

    // Hide countries without traffic on detailed map
    [ObservableProperty] private bool _hideCountriesWithoutTraffic;
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

    /// <summary>
    /// Handles country click on map - filters packets to show only traffic for that country.
    /// </summary>
    public void OnCountryClicked(string countryCode)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] OnCountryClicked: {countryCode}");

        if (string.IsNullOrEmpty(countryCode))
            return;

        // Get country name for display
        var countryName = CountryNameHelper.GetDisplayName(countryCode, countryCode);

        // Apply country filter via GlobalFilterState for cross-tab consistency
        if (_globalFilterState is not null)
        {
            // Clear existing countries and add this one
            _globalFilterState.IncludeFilters.Countries.Clear();
            _globalFilterState.AddIncludeCountry(countryCode);
            DebugLogger.Log($"[CountryTrafficViewModel] Applied country filter via GlobalFilterState: {countryCode}");
        }

        // Also update local filter for immediate visual feedback
        CountryFilter = countryCode;

        DebugLogger.Log($"[CountryTrafficViewModel] Filtering to country: {countryName} ({countryCode})");
    }

    /// <summary>
    /// Action property for AXAML binding - handles country icon clicks on map
    /// </summary>
    public Action<string> OnCountryClickedAction => OnCountryClicked;

    /// <summary>
    /// Handles country click on detailed world map - shows DrillDown popup with country packets.
    /// </summary>
    public void OnDetailedMapCountryClicked(string countryCode)
    {
        DebugLogger.Log($"[CountryTrafficViewModel] OnDetailedMapCountryClicked: {countryCode}");

        if (string.IsNullOrEmpty(countryCode))
            return;

        // Map UI display codes to data dictionary keys
        // UI uses "INT"/"IP6" for display, data uses "Internal"/"IP6_LINK"
        var (dataKey, displayName) = countryCode switch
        {
            "INT" => ("Internal", "Internal Traffic"),
            "IP6" => ("IP6_LINK", "IPv6 Traffic"),
            _ => (countryCode, CountryNameHelper.GetDisplayName(countryCode, countryCode))
        };

        // Debug: show what keys are in the dictionary
        var dictKeys = CountryTrafficStatistics?.Keys.ToList() ?? new List<string>();
        DebugLogger.Log($"[CountryTrafficViewModel] Dictionary has {dictKeys.Count} keys: {string.Join(", ", dictKeys.Take(20))}");
        DebugLogger.Log($"[CountryTrafficViewModel] Mapping: UI code '{countryCode}' -> data key '{dataKey}'");

        // Get country name and packets
        var countryName = displayName;

        // Try to get statistics for this country
        var stats = CountryTrafficStatistics?.GetValueOrDefault(dataKey);
        if (stats is null)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] No statistics found for {dataKey} (tried exact match)");
            // Try case-insensitive lookup
            var key = dictKeys.FirstOrDefault(k => k.Equals(dataKey, StringComparison.OrdinalIgnoreCase));
            if (key is not null)
            {
                DebugLogger.Log($"[CountryTrafficViewModel] Found case-insensitive match: {key}");
                stats = CountryTrafficStatistics![key];
            }
            else
            {
                return;
            }
        }

        // Get packets for this country from DataManager (use dataKey for lookup)
        var countryPackets = DataManager.GetCountryPacketIndices(dataKey);
        var allPackets = DataManager.GetAllPackets();

        if (countryPackets is null || allPackets is null || countryPackets.Count == 0)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] No packets found for {dataKey}");
            return;
        }

        // Build packet list from indices
        var packets = new List<PacketInfo>(countryPackets.Count);
        foreach (var index in countryPackets)
        {
            if (index < allPackets.Count)
                packets.Add(allPackets[index]);
        }

        DebugLogger.Log($"[CountryTrafficViewModel] Showing DrillDown for {countryName} ({countryCode}) with {packets.Count} packets");

        // Show DrillDown popup with country data (use ShowForCountry to avoid re-filtering by IP)
        DrillDown.ShowForCountry(
            $"{countryName} ({countryCode})",
            packets,
            stats.TotalPackets,
            stats.TotalBytes);
    }

    /// <summary>
    /// Action property for AXAML binding - handles country clicks on detailed world map
    /// </summary>
    public Action<string> OnDetailedMapCountryClickedAction => OnDetailedMapCountryClicked;

    // ==================== ITabPopulationTarget IMPLEMENTATION ====================

    /// <inheritdoc />
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log($"[CountryTrafficViewModel.PopulateFromCacheAsync] Populating from cache with {result.AllPackets.Count:N0} packets");
        SetPackets(result.AllPackets);  // Must use SetPackets to populate DataManager
        await UpdateStatistics(result.Statistics);

        // Store unfiltered totals for Total/Filtered display pattern
        // CRITICAL: Pass the ACTUAL packet/byte counts from result.Statistics,
        // NOT Statistics.TotalPackets which contains GeolocatedPackets (doubled count)
        Statistics.StoreUnfilteredTotals(result.Statistics.TotalPackets, result.Statistics.TotalBytes);
        _unfilteredCountryCount = Statistics.UniqueCountries;
        _unfilteredFlowCount = Statistics.CrossBorderFlows;
        IsGlobalFilterActive = false;

        // CRITICAL: Refresh stats bar AFTER storing unfiltered totals
        // UpdateGeographicStatsBar() was called inside UpdateStatistics() when UnfilteredTotal* were still 0
        UpdateGeographicStatsBar();
        DebugLogger.Log($"[CountryTrafficViewModel] Initial load complete - unfiltered: {Statistics.UnfilteredTotalPackets:N0} packets, {Statistics.UnfilteredTotalBytes:N0} bytes, {_unfilteredCountryCount} countries, {_unfilteredFlowCount} flows");
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

        // Dispose filter debouncing subscription
        _filterSubscription?.Dispose();
        _filterTrigger.Dispose();

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

        // Unsubscribe from component events
        if (Filter is not null)
        {
            Filter.SortModeChanged -= OnFilterSortModeChanged;
            Filter.ExcludedCountriesChanged -= OnExcludedCountriesChanged;
            Filter.DisplayCountChanged -= OnDisplayCountChanged;
            Filter.HideInternalTrafficChanged -= OnHideInternalTrafficChanged;
        }

        if (UIState is not null)
        {
            UIState.ContinentChanged -= OnContinentChanged;
        }

        DebugLogger.Log("[CountryTrafficViewModel] Disposed - cleaned up event handlers and filter debouncing");
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

    /// <summary>
    /// Indicates if this flow has traffic in both directions (bidirectional).
    /// When true, display ↔ instead of →
    /// </summary>
    public bool IsBidirectional { get; set; }

    public string BytesFormatted => NumberFormatter.FormatBytes(ByteCount);
    public string PacketsFormatted => $"{PacketCount:N0}";
    public string SourceCountryDisplayCode => CountryNameHelper.GetDisplayCode(SourceCountryCode);
    public string DestinationCountryDisplayCode => CountryNameHelper.GetDisplayCode(DestinationCountryCode);

    /// <summary>
    /// Arrow symbol based on flow direction: ↔ for bidirectional, → for unidirectional
    /// </summary>
    public string FlowArrow => IsBidirectional ? "↔" : "→";

    public string FlowDirection => $"{SourceCountryDisplayCode} {FlowArrow} {DestinationCountryDisplayCode}";
}
