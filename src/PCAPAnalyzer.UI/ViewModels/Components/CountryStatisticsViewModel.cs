using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for managing country traffic statistics, summaries, and risk analysis.
/// Handles all statistical calculations and high-risk country identification.
/// </summary>
public partial class CountryStatisticsViewModel : ObservableObject
{
    private NetworkStatistics? _currentStatistics;

    // Summary statistics
    [ObservableProperty] private string _countrySummary = "No data available";
    [ObservableProperty] private int _uniqueCountries;
    [ObservableProperty] private double _internationalPercentage;
    [ObservableProperty] private int _crossBorderFlows;
    [ObservableProperty] private string _topCountry = "N/A";

    // Risk analysis
    [ObservableProperty] private int _highRiskCountryCount;
    [ObservableProperty] private bool _hasHighRiskTraffic;
    [ObservableProperty] private string _highRiskWarning = "";

    // Totals
    [ObservableProperty] private int _totalCountries;
    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _totalBytes;

    // Continent traffic statistics
    [ObservableProperty] private string _northAmericaTraffic = "0 packets";
    [ObservableProperty] private string _southAmericaTraffic = "0 packets";
    [ObservableProperty] private string _europeTraffic = "0 packets";
    [ObservableProperty] private string _africaTraffic = "0 packets";
    [ObservableProperty] private string _asiaTraffic = "0 packets";
    [ObservableProperty] private string _oceaniaTraffic = "0 packets";
    [ObservableProperty] private string _internalTraffic = "0 packets";
    [ObservableProperty] private string _ipv6Traffic = "0 packets";

    // Country lists
    [ObservableProperty] private ObservableCollection<CountryTrafficItem> _topCountriesList = [];
    [ObservableProperty] private ObservableCollection<CountryTrafficItem> _allCountriesList = [];

    // Country traffic statistics (for map control)
    [ObservableProperty] private Dictionary<string, CountryTrafficStatistics> _countryTrafficStatistics = [];

    /// <summary>
    /// Event raised when statistics have been updated
    /// </summary>
    public event EventHandler? StatisticsUpdated;

    /// <summary>
    /// Updates all statistics based on network statistics
    /// </summary>
    public void UpdateStatistics(NetworkStatistics statistics)
    {
        if (statistics is null)
        {
            DebugLogger.Log("[CountryStatisticsViewModel] UpdateStatistics called with null statistics");
            return;
        }

        _currentStatistics = statistics;
        DebugLogger.Log($"[CountryStatisticsViewModel] UpdateStatistics called with {statistics.TotalPackets} total packets");

        // Update basic metrics
        UniqueCountries = statistics.CountryStatistics?.Count ?? 0;
        InternationalPercentage = statistics.InternationalPercentage;
        DebugLogger.Log($"[CountryStatisticsViewModel] Found {UniqueCountries} unique countries");

        // Log country statistics for debugging
        if (statistics.CountryStatistics is not null)
        {
            var countryPacketSum = statistics.CountryStatistics.Values.Sum(c => c.TotalPackets);
            var countryByteSum = statistics.CountryStatistics.Values.Sum(c => c.TotalBytes);
            DebugLogger.Log($"[CountryStatisticsViewModel] Country statistics sum: {countryPacketSum} packets, {countryByteSum} bytes");
            DebugLogger.Log($"[CountryStatisticsViewModel] Total from statistics: {statistics.TotalPackets} packets, {statistics.TotalBytes} bytes (geolocated: {statistics.GeolocatedPackets} packets, {statistics.GeolocatedBytes} bytes)");

            var expectedGeolocated = statistics.GeolocatedPackets > 0 ? statistics.GeolocatedPackets : countryPacketSum;
            if (countryPacketSum != expectedGeolocated)
            {
                DebugLogger.Log($"[CountryStatisticsViewModel] WARNING: Country packet sum ({countryPacketSum}) doesn't match geolocated total ({expectedGeolocated})");
            }
        }

        // Count cross-border flows
        CrossBorderFlows = statistics.TrafficFlows?.Count(f => f.IsCrossBorder) ?? 0;

        // Count high-risk countries
        HighRiskCountryCount = statistics.CountryStatistics?.Count(c => c.Value.IsHighRisk) ?? 0;
        HasHighRiskTraffic = HighRiskCountryCount > 0;

        if (HasHighRiskTraffic)
        {
            var highRiskNames = statistics.CountryStatistics?
                .Where(c => c.Value.IsHighRisk)
                .Select(c => c.Value.CountryName)
                .Take(3);
            HighRiskWarning = $"Traffic detected from: {string.Join(", ", highRiskNames ?? [])}";
        }
        else
        {
            HighRiskWarning = "";
        }

        // Update country summary
        var topCountryData = statistics.CountryStatistics?.Values
            .OrderByDescending(c => c.TotalPackets)
            .FirstOrDefault();

        if (topCountryData is not null)
        {
            CountrySummary = $"{UniqueCountries} countries detected • Top: {topCountryData.CountryName} ({topCountryData.Percentage:F1}%)";
            TopCountry = topCountryData.CountryName;
        }
        else
        {
            CountrySummary = "No international traffic detected";
            TopCountry = "N/A";
        }

        // Update clean map statistics
        // Use the actual totals from the statistics (which come from filtered packets)
        // NOT the sum of country statistics to avoid double counting
        TotalCountries = UniqueCountries;
        TotalPackets = statistics.GeolocatedPackets > 0 ? statistics.GeolocatedPackets : statistics.TotalPackets;
        TotalBytes = statistics.GeolocatedBytes > 0 ? statistics.GeolocatedBytes : statistics.TotalBytes;

        DebugLogger.Log($"[CountryStatisticsViewModel] Using totals from statistics: {TotalPackets} packets, {TotalBytes} bytes");

        // Update top countries list for clean map
        UpdateTopCountriesList(statistics);

        // Update country traffic statistics for ContinentMapControl
        if (_currentStatistics?.CountryStatistics is not null)
        {
            CountryTrafficStatistics = new Dictionary<string, CountryTrafficStatistics>(_currentStatistics.CountryStatistics);
            DebugLogger.Log($"[CountryStatisticsViewModel] Set CountryTrafficStatistics with {CountryTrafficStatistics.Count} countries");
            var totalPackets = CountryTrafficStatistics.Values.Sum(c => c.TotalPackets);
            DebugLogger.Log($"[CountryStatisticsViewModel] Total packets in country statistics: {totalPackets:N0}");
            // Log ALL keys for debugging
            var allKeys = string.Join(", ", CountryTrafficStatistics.Keys.OrderBy(k => k));
            DebugLogger.Log($"[CountryStatisticsViewModel] ALL keys: {allKeys}");
            // Check if DE specifically exists
            var hasDe = CountryTrafficStatistics.ContainsKey("DE");
            DebugLogger.Log($"[CountryStatisticsViewModel] Contains 'DE': {hasDe}");
        }

        // Update continent traffic statistics
        UpdateContinentTrafficStats();

        // Raise event
        StatisticsUpdated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Updates the top countries list for display
    /// </summary>
    private void UpdateTopCountriesList(NetworkStatistics statistics)
    {
        if (statistics.CountryStatistics is null || statistics.CountryStatistics.Count == 0)
        {
            TopCountriesList = new ObservableCollection<CountryTrafficItem>();
            AllCountriesList = new ObservableCollection<CountryTrafficItem>();
            return;
        }

        // Calculate percentages using PUBLIC traffic only (exclude INT and IP6)
        var publicCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6" && kvp.Key != "INTERNAL" && kvp.Key != "IPV6")
            .ToList();

        var basePackets = publicCountries.Sum(kvp => kvp.Value.TotalPackets);
        var baseBytes = publicCountries.Sum(kvp => kvp.Value.TotalBytes);

        var items = statistics.CountryStatistics
            .OrderByDescending(kvp => kvp.Value.TotalPackets)
            .Select((kvp, index) =>
            {
                var stats = kvp.Value;
                var packetPercentage = basePackets > 0 ? (stats.TotalPackets * 100.0 / basePackets) : 0;
                var bytePercentage = baseBytes > 0 ? (stats.TotalBytes * 100.0 / baseBytes) : 0;

                return new CountryTrafficItem
                {
                    Rank = index + 1,
                    CountryCode = kvp.Key,
                    CountryName = stats.CountryName,
                    PacketCount = stats.TotalPackets,
                    ByteCount = stats.TotalBytes,
                    TrafficPercentage = packetPercentage
                };
            })
            .ToList();

        TopCountriesList = new ObservableCollection<CountryTrafficItem>(items.Take(10));
        AllCountriesList = new ObservableCollection<CountryTrafficItem>(items);

        DebugLogger.Log($"[CountryStatisticsViewModel] Updated TopCountriesList with {TopCountriesList.Count} items (base: {basePackets:N0} public packets)");
    }

    /// <summary>
    /// Updates continent-level traffic statistics
    /// </summary>
    private void UpdateContinentTrafficStats()
    {
        if (_currentStatistics?.CountryStatistics is null)
        {
            NorthAmericaTraffic = "0 packets";
            SouthAmericaTraffic = "0 packets";
            EuropeTraffic = "0 packets";
            AfricaTraffic = "0 packets";
            AsiaTraffic = "0 packets";
            OceaniaTraffic = "0 packets";
            InternalTraffic = "0 packets";
            Ipv6Traffic = "0 packets";
            return;
        }

        // Aggregate by continent
        var continentPackets = new Dictionary<string, long>
        {
            ["NA"] = 0, ["SA"] = 0, ["EU"] = 0, ["AF"] = 0,
            ["AS"] = 0, ["OC"] = 0, ["INT"] = 0, ["IP6"] = 0
        };

        foreach (var kvp in _currentStatistics.CountryStatistics)
        {
            var continent = GetContinentCode(kvp.Key);
            if (continentPackets.ContainsKey(continent))
            {
                continentPackets[continent] += kvp.Value.TotalPackets;
            }
        }

        NorthAmericaTraffic = FormatPacketCount(continentPackets["NA"]);
        SouthAmericaTraffic = FormatPacketCount(continentPackets["SA"]);
        EuropeTraffic = FormatPacketCount(continentPackets["EU"]);
        AfricaTraffic = FormatPacketCount(continentPackets["AF"]);
        AsiaTraffic = FormatPacketCount(continentPackets["AS"]);
        OceaniaTraffic = FormatPacketCount(continentPackets["OC"]);
        InternalTraffic = FormatPacketCount(continentPackets["INT"]);
        Ipv6Traffic = FormatPacketCount(continentPackets["IP6"]);
    }

    /// <summary>
    /// Gets continent code from country code.
    /// Uses centralized ContinentData mapping.
    /// </summary>
    private static string GetContinentCode(string countryCode)
        => ContinentData.GetContinentCode(countryCode);

    /// <summary>
    /// Formats packet count for display
    /// </summary>
    private string FormatPacketCount(long packets)
    {
        if (packets == 0)
            return "0 packets";
        if (packets < 1000)
            return $"{packets} packets";
        if (packets < 1_000_000)
            return $"{packets / 1000.0:F1}K packets";
        return $"{packets / 1_000_000.0:F1}M packets";
    }

    /// <summary>
    /// Gets the current statistics
    /// </summary>
    public NetworkStatistics? GetCurrentStatistics()
    {
        return _currentStatistics;
    }
}
