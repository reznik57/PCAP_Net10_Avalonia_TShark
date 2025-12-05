using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for managing country table data, active flows, and source/destination lists.
/// Handles table generation, ranking, and flow display organization.
/// </summary>
public partial class CountryTableViewModel : ObservableObject
{
    private NetworkStatistics? _currentStatistics;

    /// <summary>
    /// Callback to get timeline buckets for a country.
    /// Set by parent ViewModel to enable timeline sparklines.
    /// Parameters: (countryCode, context) -> timeline bucket values
    /// </summary>
    public Func<string, CountryTableContext, IReadOnlyList<double>?>? TimelineBucketProvider { get; set; }

    // Country tables
    [ObservableProperty] private ObservableCollection<CountryTableItem> _countriesByPackets = new();
    [ObservableProperty] private ObservableCollection<CountryTableItem> _countriesByBytes = new();

    // Source/Destination tables
    [ObservableProperty] private ObservableCollection<CountryTableItem> _topSourceCountriesByPackets = new();
    [ObservableProperty] private ObservableCollection<CountryTableItem> _topSourceCountriesByBytes = new();
    [ObservableProperty] private ObservableCollection<CountryTableItem> _topDestinationCountriesByPackets = new();
    [ObservableProperty] private ObservableCollection<CountryTableItem> _topDestinationCountriesByBytes = new();

    // Active flows
    [ObservableProperty] private ObservableCollection<ActiveFlowViewModel> _activeFlows = new();
    [ObservableProperty] private ObservableCollection<ActiveFlowViewModel> _activeFlowsByPackets = new();
    [ObservableProperty] private ObservableCollection<ActiveFlowViewModel> _activeFlowsByBytes = new();
    [ObservableProperty] private int _activeFlowCount = 0;

    /// <summary>
    /// Event raised when tables have been updated
    /// </summary>
    public event EventHandler? TablesUpdated;

    /// <summary>
    /// Updates all tables based on network statistics
    /// </summary>
    public void UpdateTables(NetworkStatistics statistics)
    {
        _currentStatistics = statistics;

        if (statistics?.CountryStatistics == null)
        {
            DebugLogger.Log("[CountryTableViewModel] UpdateTables: No country statistics available");
            ClearTables();
            return;
        }

        DebugLogger.Log($"[CountryTableViewModel] UpdateTables: {statistics.CountryStatistics.Count} countries, {statistics.TotalPackets} total packets");

        // Update country tables
        UpdateCountryTables(statistics);

        // Update active flows
        UpdateActiveFlows(statistics);

        // Update source/destination tables
        UpdateSourceDestinationTables(statistics);

        TablesUpdated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Updates the main country tables (by packets and by bytes)
    /// </summary>
    private void UpdateCountryTables(NetworkStatistics statistics)
    {
        // Calculate PUBLIC traffic totals (exclude INT and IP6)
        var publicCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6" && kvp.Key != "INTERNAL" && kvp.Key != "IPV6" && kvp.Key != "PRIV" && kvp.Key != "PRV")
            .ToList();

        var totalPackets = publicCountries.Sum(kvp => kvp.Value.TotalPackets);
        var totalBytes = publicCountries.Sum(kvp => kvp.Value.TotalBytes);

        // Create country table items
        var allCountries = statistics.CountryStatistics
            .Select(kvp =>
            {
                var stats = kvp.Value;
                var continent = GetContinentForCountry(kvp.Key);
                return new CountryTableItem(
                    kvp.Key,
                    stats.CountryName,
                    continent,
                    stats.TotalPackets,
                    stats.TotalBytes,
                    totalPackets > 0 ? (stats.TotalPackets * 100.0 / totalPackets) : 0,
                    totalBytes > 0 ? (stats.TotalBytes * 100.0 / totalBytes) : 0,
                    stats.IsHighRisk
                );
            })
            .ToList();

        // Sort by packets and apply ranking
        var byPackets = allCountries
            .OrderByDescending(c => c.TotalPackets)
            .Select((item, index) => new CountryTableItem(
                item.CountryCode,
                item.CountryName,
                item.Continent,
                item.TotalPackets,
                item.TotalBytes,
                item.PacketPercentage,
                item.BytePercentage,
                item.IsHighRisk
            ) { Rank = index + 1, Context = CountryTableContext.Aggregated })
            .ToList();

        // Sort by bytes and apply ranking
        var byBytes = allCountries
            .OrderByDescending(c => c.TotalBytes)
            .Select((item, index) => new CountryTableItem(
                item.CountryCode,
                item.CountryName,
                item.Continent,
                item.TotalPackets,
                item.TotalBytes,
                item.PacketPercentage,
                item.BytePercentage,
                item.IsHighRisk
            ) { Rank = index + 1, Context = CountryTableContext.Aggregated })
            .ToList();

        // Update collections
        CountriesByPackets = new ObservableCollection<CountryTableItem>(byPackets);
        CountriesByBytes = new ObservableCollection<CountryTableItem>(byBytes);

        DebugLogger.Log($"[CountryTableViewModel] Updated tables: {byPackets.Count} countries");
    }

    /// <summary>
    /// Updates the active flows display
    /// </summary>
    private void UpdateActiveFlows(NetworkStatistics statistics)
    {
        if (statistics?.TrafficFlows == null)
        {
            DebugLogger.Log("[CountryTableViewModel] UpdateActiveFlows: No traffic flows available");
            ActiveFlows.Clear();
            ActiveFlowsByPackets.Clear();
            ActiveFlowsByBytes.Clear();
            ActiveFlowCount = 0;
            return;
        }

        DebugLogger.Log($"[CountryTableViewModel] UpdateActiveFlows: {statistics.TrafficFlows.Count} traffic flows");

        // Get all international flows (both cross-border and same-country)
        // Show any flow where both source and destination have valid country codes
        var normalizedFlows = statistics.TrafficFlows
            .Select(f =>
            {
                var sourceCode = NormalizeCountryCode(
                    CountryNameHelper.GetCode(string.IsNullOrWhiteSpace(f.SourceCountry) ? f.SourceCountryName : f.SourceCountry));
                var destinationCode = NormalizeCountryCode(
                    CountryNameHelper.GetCode(string.IsNullOrWhiteSpace(f.DestinationCountry) ? f.DestinationCountryName : f.DestinationCountry));

                return new
                {
                    Flow = f,
                    SourceCode = sourceCode,
                    DestinationCode = destinationCode
                };
            })
            .Where(x =>
                // Include ALL flows with valid country codes
                // Exclude: Same-to-same IPv6 types and INTERNAL->INTERNAL (user requirement)
                // Allow: Public->Public, INTERNAL->Public, Public->INTERNAL, Mixed IPv6 flows
                !string.IsNullOrWhiteSpace(x.SourceCode) &&
                !string.IsNullOrWhiteSpace(x.DestinationCode) &&
                // Exclude same-to-same IPv6 types
                !(IsIPv6Type(x.SourceCode) && x.SourceCode == x.DestinationCode) &&
                // Exclude INTERNAL->INTERNAL (all variations)
                !(x.SourceCode == "PRIV" && x.DestinationCode == "PRIV") &&
                !(x.SourceCode == "INT" && x.DestinationCode == "INT") &&
                !(x.SourceCode == "Internal" && x.DestinationCode == "Internal"))
            .OrderByDescending(x => x.Flow.PacketCount)
            .ToList();

        // Build a set of all flow pairs to detect bidirectional flows
        // Key format: "SOURCE->DEST" - if both A->B and B->A exist, the flow is bidirectional
        var allFlowPairs = new HashSet<string>(
            normalizedFlows.Select(x => $"{x.SourceCode}->{x.DestinationCode}"));

        // Helper to check if reverse flow exists
        bool IsBidirectionalFlow(string source, string dest) =>
            allFlowPairs.Contains($"{dest}->{source}");

        DebugLogger.Log($"[CountryTableViewModel] Filtered to {normalizedFlows.Count} international flows with valid country codes");

        var topFlows = normalizedFlows.Take(50).ToList();
        DebugLogger.Log($"[CountryTableViewModel] Displaying top {topFlows.Count} flows");

        // Calculate totals for percentage calculation
        var totalCrossBorderPackets = topFlows.Sum(x => x.Flow.PacketCount);
        var totalCrossBorderBytes = topFlows.Sum(x => x.Flow.ByteCount);

        var flows = topFlows
            .Select((x, index) => new ActiveFlowViewModel
            {
                Rank = index + 1,
                SourceCountryCode = x.SourceCode,
                DestinationCountryCode = x.DestinationCode,
                SourceCountry = GetCountryName(x.SourceCode, x.Flow.SourceCountryName),
                DestinationCountry = GetCountryName(x.DestinationCode, x.Flow.DestinationCountryName),
                PacketCount = x.Flow.PacketCount,
                ByteCount = x.Flow.ByteCount,
                Protocol = x.Flow.Protocols?.FirstOrDefault() ?? "Unknown",
                IsCrossBorder = x.Flow.IsCrossBorder,
                IsHighRisk = x.Flow.IsHighRisk,
                FlowIntensity = totalCrossBorderPackets > 0 ? (x.Flow.PacketCount * 100.0 / totalCrossBorderPackets) : 0,
                ByteIntensity = totalCrossBorderBytes > 0 ? (x.Flow.ByteCount * 100.0 / totalCrossBorderBytes) : 0,
                SourceContinent = GetContinentForCountry(x.SourceCode),
                DestinationContinent = GetContinentForCountry(x.DestinationCode),
                IsBidirectional = IsBidirectionalFlow(x.SourceCode, x.DestinationCode)
            })
            .ToList();

        ActiveFlows = new ObservableCollection<ActiveFlowViewModel>(flows);
        ActiveFlowCount = flows.Count;

        // Update sorted flow displays
        UpdateFlowsSortedDisplays();

        DebugLogger.Log($"[CountryTableViewModel] Active flows updated: {ActiveFlowCount} flows");
    }

    /// <summary>
    /// Updates the flows display by packets and bytes
    /// </summary>
    private void UpdateFlowsSortedDisplays()
    {
        // Sort by packets
        ActiveFlowsByPackets = new ObservableCollection<ActiveFlowViewModel>(
            ActiveFlows
                .OrderByDescending(f => f.PacketCount)
                .Select((flow, index) => CloneFlow(flow, index + 1)));

        // Sort by bytes
        ActiveFlowsByBytes = new ObservableCollection<ActiveFlowViewModel>(
            ActiveFlows
                .OrderByDescending(f => f.ByteCount)
                .Select((flow, index) => CloneFlow(flow, index + 1)));
    }

    /// <summary>
    /// Updates source and destination country tables
    /// </summary>
    private void UpdateSourceDestinationTables(NetworkStatistics statistics)
    {
        if (statistics?.CountryStatistics == null)
        {
            TopSourceCountriesByPackets.Clear();
            TopSourceCountriesByBytes.Clear();
            TopDestinationCountriesByPackets.Clear();
            TopDestinationCountriesByBytes.Clear();
            return;
        }

        // Calculate PUBLIC traffic totals (exclude INT and IP6)
        var publicCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6" && kvp.Key != "INTERNAL" && kvp.Key != "IPV6" && kvp.Key != "PRIV" && kvp.Key != "PRV")
            .ToList();

        // CRITICAL: Use separate totals for source/destination to get correct percentages
        var totalOutgoingPackets = publicCountries.Sum(kvp => kvp.Value.OutgoingPackets);
        var totalOutgoingBytes = publicCountries.Sum(kvp => kvp.Value.OutgoingBytes);
        var totalIncomingPackets = publicCountries.Sum(kvp => kvp.Value.IncomingPackets);
        var totalIncomingBytes = publicCountries.Sum(kvp => kvp.Value.IncomingBytes);

        DebugLogger.Log($"[CountryTableViewModel] Source/Dest totals - Outgoing: {totalOutgoingPackets:N0} pkts, {totalOutgoingBytes:N0} bytes | Incoming: {totalIncomingPackets:N0} pkts, {totalIncomingBytes:N0} bytes");

        // Debug: Show top 10 countries with their traffic
        var topCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6")
            .OrderByDescending(kvp => kvp.Value.TotalPackets)
            .Take(10)
            .ToList();
        DebugLogger.Log($"[CountryTableViewModel] Top 10 countries by total packets:");
        foreach (var country in topCountries)
        {
            var outPct = totalOutgoingPackets > 0 ? (country.Value.OutgoingPackets * 100.0 / totalOutgoingPackets) : 0;
            var inPct = totalIncomingPackets > 0 ? (country.Value.IncomingPackets * 100.0 / totalIncomingPackets) : 0;
            DebugLogger.Log($"  {country.Key} ({country.Value.CountryName}): Total={country.Value.TotalPackets:N0}, Out={country.Value.OutgoingPackets:N0} ({outPct:F1}%), In={country.Value.IncomingPackets:N0} ({inPct:F1}%)");
        }

        // Source countries
        var sourceCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Value.OutgoingPackets > 0)
            .Select(kvp => new CountryTableItem(
                kvp.Key,
                kvp.Value.CountryName,
                GetContinentForCountry(kvp.Key),
                kvp.Value.OutgoingPackets,
                kvp.Value.OutgoingBytes,
                totalOutgoingPackets > 0 ? (kvp.Value.OutgoingPackets * 100.0 / totalOutgoingPackets) : 0,
                totalOutgoingBytes > 0 ? (kvp.Value.OutgoingBytes * 100.0 / totalOutgoingBytes) : 0,
                kvp.Value.IsHighRisk
            ) { Context = CountryTableContext.SourcePackets })
            .ToList();

        // Sort source countries by packets
        var sourceByPackets = sourceCountries
            .OrderByDescending(c => c.TotalPackets)
            .Take(50)
            .Select((item, index) =>
            {
                item.Rank = index + 1;
                return item;
            })
            .ToList();

        // Sort source countries by bytes
        var sourceByBytes = sourceCountries
            .OrderByDescending(c => c.TotalBytes)
            .Take(50)
            .Select((item, index) =>
            {
                var copy = new CountryTableItem(
                    item.CountryCode,
                    item.CountryName,
                    item.Continent,
                    item.TotalPackets,
                    item.TotalBytes,
                    item.PacketPercentage,
                    item.BytePercentage,
                    item.IsHighRisk
                ) { Rank = index + 1, Context = CountryTableContext.SourceBytes };
                return copy;
            })
            .ToList();

        // Destination countries
        var destinationCountries = statistics.CountryStatistics
            .Where(kvp => kvp.Value.IncomingPackets > 0)
            .Select(kvp => new CountryTableItem(
                kvp.Key,
                kvp.Value.CountryName,
                GetContinentForCountry(kvp.Key),
                kvp.Value.IncomingPackets,
                kvp.Value.IncomingBytes,
                totalIncomingPackets > 0 ? (kvp.Value.IncomingPackets * 100.0 / totalIncomingPackets) : 0,
                totalIncomingBytes > 0 ? (kvp.Value.IncomingBytes * 100.0 / totalIncomingBytes) : 0,
                kvp.Value.IsHighRisk
            ) { Context = CountryTableContext.DestinationPackets })
            .ToList();

        // Sort destination countries by packets
        var destinationByPackets = destinationCountries
            .OrderByDescending(c => c.TotalPackets)
            .Take(50)
            .Select((item, index) =>
            {
                item.Rank = index + 1;
                return item;
            })
            .ToList();

        // Sort destination countries by bytes
        var destinationByBytes = destinationCountries
            .OrderByDescending(c => c.TotalBytes)
            .Take(50)
            .Select((item, index) =>
            {
                var copy = new CountryTableItem(
                    item.CountryCode,
                    item.CountryName,
                    item.Continent,
                    item.TotalPackets,
                    item.TotalBytes,
                    item.PacketPercentage,
                    item.BytePercentage,
                    item.IsHighRisk
                ) { Rank = index + 1, Context = CountryTableContext.DestinationBytes };
                return copy;
            })
            .ToList();

        // Populate timeline data if provider is available
        if (TimelineBucketProvider != null)
        {
            foreach (var item in sourceByPackets)
                item.TimelineBuckets = TimelineBucketProvider(item.CountryCode, item.Context);
            foreach (var item in sourceByBytes)
                item.TimelineBuckets = TimelineBucketProvider(item.CountryCode, item.Context);
            foreach (var item in destinationByPackets)
                item.TimelineBuckets = TimelineBucketProvider(item.CountryCode, item.Context);
            foreach (var item in destinationByBytes)
                item.TimelineBuckets = TimelineBucketProvider(item.CountryCode, item.Context);
        }

        // Update collections
        TopSourceCountriesByPackets = new ObservableCollection<CountryTableItem>(sourceByPackets);
        TopSourceCountriesByBytes = new ObservableCollection<CountryTableItem>(sourceByBytes);
        TopDestinationCountriesByPackets = new ObservableCollection<CountryTableItem>(destinationByPackets);
        TopDestinationCountriesByBytes = new ObservableCollection<CountryTableItem>(destinationByBytes);

        DebugLogger.Log($"[CountryTableViewModel] Updated source/destination tables with timeline data");
    }

    /// <summary>
    /// Clears all tables
    /// </summary>
    private void ClearTables()
    {
        CountriesByPackets.Clear();
        CountriesByBytes.Clear();
        TopSourceCountriesByPackets.Clear();
        TopSourceCountriesByBytes.Clear();
        TopDestinationCountriesByPackets.Clear();
        TopDestinationCountriesByBytes.Clear();
        ActiveFlows.Clear();
        ActiveFlowsByPackets.Clear();
        ActiveFlowsByBytes.Clear();
        ActiveFlowCount = 0;
    }

    /// <summary>
    /// Clones a flow with a new rank
    /// </summary>
    private static ActiveFlowViewModel CloneFlow(ActiveFlowViewModel flow, int rank)
    {
        return new ActiveFlowViewModel
        {
            Rank = rank,
            SourceCountryCode = flow.SourceCountryCode,
            DestinationCountryCode = flow.DestinationCountryCode,
            SourceCountry = flow.SourceCountry,
            DestinationCountry = flow.DestinationCountry,
            PacketCount = flow.PacketCount,
            ByteCount = flow.ByteCount,
            Protocol = flow.Protocol,
            IsCrossBorder = flow.IsCrossBorder,
            IsHighRisk = flow.IsHighRisk,
            FlowIntensity = flow.FlowIntensity,
            ByteIntensity = flow.ByteIntensity,
            SourceContinent = flow.SourceContinent,
            DestinationContinent = flow.DestinationContinent,
            IsBidirectional = flow.IsBidirectional
        };
    }

    /// <summary>
    /// Gets country name from code or name
    /// </summary>
    private string GetCountryName(string? countryCodeOrName, string? fallbackName = null)
    {
        if (string.IsNullOrEmpty(countryCodeOrName))
            return "Unknown";

        var code = countryCodeOrName.Length == 2 && countryCodeOrName.All(char.IsLetter)
            ? countryCodeOrName.ToUpperInvariant()
            : CountryNameHelper.GetCode(countryCodeOrName);

        if (_currentStatistics?.CountryStatistics?.TryGetValue(code, out var stats) == true &&
            !string.IsNullOrWhiteSpace(stats.CountryName) &&
            !string.Equals(stats.CountryName, code, StringComparison.OrdinalIgnoreCase))
        {
            return CountryNameHelper.GetDisplayName(code, stats.CountryName);
        }

        return CountryNameHelper.GetDisplayName(code, fallbackName ?? countryCodeOrName);
    }

    /// <summary>
    /// Normalizes country code for comparison
    /// </summary>
    private static string NormalizeCountryCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return "IP6";

        var normalized = code.Trim().ToUpperInvariant();

        return normalized switch
        {
            "PRV" or "INT" or "PRIVATE" or "LOCAL" or "LAN" => "PRIV",
            "??" or "XX" => "IP6",
            _ => normalized
        };
    }

    /// <summary>
    /// Gets continent display name for country code.
    /// Uses centralized ContinentData mapping.
    /// </summary>
    private static string GetContinentForCountry(string countryCode)
        => ContinentData.GetContinentDisplayName(countryCode);

    /// <summary>
    /// Checks if a country code represents an IPv6 address type
    /// </summary>
    private static bool IsIPv6Type(string code)
    {
        return code switch
        {
            "IP6" or "IP6_LINK" or "IP6_LOOP" or "IP6_MCAST" or
            "IP6_GLOBAL" or "IP6_ULA" or "IP6_SITE" or "IP6_ANY" => true,
            _ => false
        };
    }
}
