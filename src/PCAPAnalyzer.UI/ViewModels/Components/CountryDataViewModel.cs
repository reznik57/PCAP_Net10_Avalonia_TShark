using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for managing country-to-packet index mappings for performance optimization.
/// Caches packet indices by country to enable fast packet retrieval without filtering entire collections.
/// </summary>
public partial class CountryDataViewModel : ObservableObject
{
    // Performance optimization: Cache packet indices by country
    private Dictionary<string, List<int>> _countryPacketIndices = new();
    private Dictionary<string, List<int>> _countryOutgoingIndices = new();
    private Dictionary<string, List<int>> _countryIncomingIndices = new();

    private IReadOnlyList<PacketInfo>? _allPackets;
    private NetworkStatistics? _currentStatistics;

    // Track if indices are already built for current data
    private int _lastPacketCount;
    private int _lastCountryCount;

    /// <summary>
    /// Event raised when packet indices have been rebuilt
    /// </summary>
    public event EventHandler? IndicesRebuilt;

    /// <summary>
    /// Gets whether packet indices are available
    /// </summary>
    public bool HasIndices => _countryPacketIndices.Count > 0;

    /// <summary>
    /// Sets the packet collection for indexing
    /// </summary>
    public void SetPackets(IReadOnlyList<PacketInfo> packets)
    {
        _allPackets = packets;
        DebugLogger.Log($"[CountryDataViewModel] SetPackets called with {packets?.Count ?? 0} packets");

        // Build packet indices if statistics are available
        if (_currentStatistics != null)
        {
            BuildCountryPacketIndices();
        }
    }

    /// <summary>
    /// Updates the statistics used for building indices
    /// </summary>
    public void SetStatistics(NetworkStatistics? statistics)
    {
        _currentStatistics = statistics;

        // Build indices if packets are available
        if (_allPackets != null && _currentStatistics != null)
        {
            BuildCountryPacketIndices();
        }
    }

    /// <summary>
    /// Gets packet indices for a country (all traffic)
    /// </summary>
    public List<int>? GetCountryPacketIndices(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        return _countryPacketIndices.TryGetValue(countryCode, out var indices) ? indices : null;
    }

    /// <summary>
    /// Gets packet indices for outgoing traffic from a country
    /// </summary>
    public List<int>? GetCountryOutgoingIndices(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        return _countryOutgoingIndices.TryGetValue(countryCode, out var indices) ? indices : null;
    }

    /// <summary>
    /// Gets packet indices for incoming traffic to a country
    /// </summary>
    public List<int>? GetCountryIncomingIndices(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        return _countryIncomingIndices.TryGetValue(countryCode, out var indices) ? indices : null;
    }

    /// <summary>
    /// Gets all packets stored in the data manager
    /// </summary>
    public IReadOnlyList<PacketInfo>? GetAllPackets()
    {
        return _allPackets;
    }

    /// <summary>
    /// Gets packets for a specific country by context (all/outgoing/incoming)
    /// </summary>
    public List<PacketInfo>? GetCountryPackets(string countryCode, CountryTableContext context)
    {
        if (_allPackets == null || string.IsNullOrWhiteSpace(countryCode))
            return null;

        List<int>? indices = context switch
        {
            CountryTableContext.SourcePackets or CountryTableContext.SourceBytes => GetCountryOutgoingIndices(countryCode),
            CountryTableContext.DestinationPackets or CountryTableContext.DestinationBytes => GetCountryIncomingIndices(countryCode),
            _ => GetCountryPacketIndices(countryCode)
        };

        if (indices == null || indices.Count == 0)
        {
            DebugLogger.Log($"[CountryDataViewModel] No indices found for {countryCode} (context: {context})");
            return null;
        }

        var packets = new List<PacketInfo>(indices.Count);
        foreach (var index in indices)
        {
            if (index < _allPackets.Count)
                packets.Add(_allPackets[index]);
        }

        DebugLogger.Log($"[CountryDataViewModel] Retrieved {packets.Count} packets for {countryCode} (context: {context})");
        return packets;
    }

    /// <summary>
    /// Pre-builds packet indices for each country for performance optimization
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Country packet indexing requires processing geographic data, building multiple lookup dictionaries for incoming/outgoing IPs, and creating separate indices for combined and directional traffic")]
    private void BuildCountryPacketIndices()
    {
        if (_currentStatistics?.CountryStatistics == null || _allPackets == null)
        {
            DebugLogger.Log("[CountryDataViewModel] Cannot build indices - missing statistics or packets");
            return;
        }

        // OPTIMIZATION: Skip rebuild if indices are already built for current data
        var currentPacketCount = _allPackets.Count;
        var currentCountryCount = _currentStatistics.CountryStatistics.Count;

        if (_lastPacketCount == currentPacketCount &&
            _lastCountryCount == currentCountryCount &&
            _countryPacketIndices.Count > 0)
        {
            DebugLogger.Log($"[CountryDataViewModel] Skipping index rebuild - already built for {currentPacketCount} packets and {currentCountryCount} countries");
            return;
        }

        var startTime = System.DateTime.Now;
        DebugLogger.Log($"[CountryDataViewModel] Building packet indices for {_currentStatistics.CountryStatistics.Count} countries...");

        _countryPacketIndices.Clear();
        _countryOutgoingIndices.Clear();
        _countryIncomingIndices.Clear();

        // Prepare dictionaries for each country
        foreach (var country in _currentStatistics.CountryStatistics)
        {
            var countryCode = country.Key;
            _countryPacketIndices[countryCode] = new List<int>();
            _countryOutgoingIndices[countryCode] = new List<int>();
            _countryIncomingIndices[countryCode] = new List<int>();
        }

        // Build quick lookup from IP -> country code
        var combinedIpToCountry = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var outgoingIpToCountry = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var incomingIpToCountry = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in _currentStatistics.CountryStatistics)
        {
            var code = kvp.Key;
            var stats = kvp.Value;

            foreach (var ip in stats.OutgoingIPs)
            {
                if (!string.IsNullOrWhiteSpace(ip))
                    outgoingIpToCountry[ip] = code;
            }

            foreach (var ip in stats.IncomingIPs)
            {
                if (!string.IsNullOrWhiteSpace(ip))
                    incomingIpToCountry[ip] = code;
            }

            foreach (var ip in stats.UniqueIPs)
            {
                if (!string.IsNullOrWhiteSpace(ip))
                    combinedIpToCountry[ip] = code;
            }
        }

        // Helper to avoid duplicate indices
        static void TryAddIndex(List<int> list, int index)
        {
            if (list.Count == 0 || list[^1] != index)
                list.Add(index);
        }

        // Build indices for all packets
        for (int index = 0; index < _allPackets.Count; index++)
        {
            var packet = _allPackets[index];

            // Process source IP (outgoing traffic)
            if (!string.IsNullOrWhiteSpace(packet.SourceIP))
            {
                if (outgoingIpToCountry.TryGetValue(packet.SourceIP, out var srcCode))
                {
                    if (_countryOutgoingIndices.TryGetValue(srcCode, out var outgoing))
                        TryAddIndex(outgoing, index);
                    if (_countryPacketIndices.TryGetValue(srcCode, out var combined))
                        TryAddIndex(combined, index);
                }
                else if (combinedIpToCountry.TryGetValue(packet.SourceIP, out var combinedCode) &&
                         _countryPacketIndices.TryGetValue(combinedCode, out var combinedList))
                {
                    TryAddIndex(combinedList, index);
                }
            }

            // Process destination IP (incoming traffic)
            if (!string.IsNullOrWhiteSpace(packet.DestinationIP))
            {
                if (incomingIpToCountry.TryGetValue(packet.DestinationIP, out var dstCode))
                {
                    if (_countryIncomingIndices.TryGetValue(dstCode, out var incoming))
                        TryAddIndex(incoming, index);
                    if (_countryPacketIndices.TryGetValue(dstCode, out var combined))
                        TryAddIndex(combined, index);
                }
                else if (combinedIpToCountry.TryGetValue(packet.DestinationIP, out var combinedCode) &&
                         _countryPacketIndices.TryGetValue(combinedCode, out var combinedList))
                {
                    TryAddIndex(combinedList, index);
                }
            }
        }

        // Update tracking variables to prevent redundant rebuilds
        _lastPacketCount = currentPacketCount;
        _lastCountryCount = currentCountryCount;

        var totalIndices = _countryPacketIndices.Values.Sum(list => list.Count);
        var elapsed = (System.DateTime.Now - startTime).TotalSeconds;
        DebugLogger.Log($"[CountryDataViewModel] Packet indices built successfully in {elapsed:F3}s - {totalIndices:N0} total index entries");

        // Raise event
        IndicesRebuilt?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Clears all cached indices
    /// </summary>
    public void ClearIndices()
    {
        _countryPacketIndices.Clear();
        _countryOutgoingIndices.Clear();
        _countryIncomingIndices.Clear();
        DebugLogger.Log("[CountryDataViewModel] Indices cleared");
    }
}
