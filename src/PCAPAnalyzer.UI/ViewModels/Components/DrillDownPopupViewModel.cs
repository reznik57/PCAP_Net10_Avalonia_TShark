using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using Avalonia;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for drill-down detail popup shown when clicking Dashboard elements.
/// Supports IP, Port, Connection, and TimeSlice entity types.
/// </summary>
public partial class DrillDownPopupViewModel : ObservableObject
{
    private readonly Action<string, string>? _navigateWithFilter;
    private readonly IGeoIPService? _geoIPService;

    [ObservableProperty] private bool _isVisible;
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private DrillDownEntityType _entityType;

    // Summary Stats
    [ObservableProperty] private int _totalPackets;
    [ObservableProperty] private long _totalBytes;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private DateTime _firstSeen;
    [ObservableProperty] private DateTime _lastSeen;
    [ObservableProperty] private string _duration = "";
    [ObservableProperty] private int _averagePacketSize;
    [ObservableProperty] private bool _showSamplingWarning;

    // Breakdown Collections
    [ObservableProperty] private ObservableCollection<PortBreakdownItem> _topPorts = new();
    [ObservableProperty] private ObservableCollection<EndpointBreakdownItem> _connectedEndpoints = new();
    [ObservableProperty] private ObservableCollection<ConversationBreakdownItem> _topConversations = new();

    // Current filter context
    private string _currentFilterKey = "";
    private string _currentFilterValue = "";

    public DrillDownPopupViewModel(Action<string, string>? navigateWithFilter = null, IGeoIPService? geoIPService = null)
    {
        _navigateWithFilter = navigateWithFilter;
        _geoIPService = geoIPService;
    }

    /// <summary>
    /// Show popup for a country with pre-filtered packets.
    /// Unlike ShowForIP, this does NOT re-filter packets - they should already be filtered by country.
    /// </summary>
    public void ShowForCountry(string countryDisplay, IEnumerable<PacketInfo> countryPackets, long preCalculatedPacketCount, long preCalculatedByteCount)
    {
        Title = $"IP: {countryDisplay}";
        EntityType = DrillDownEntityType.IP; // Reuse IP type for country
        _currentFilterKey = "country";
        _currentFilterValue = countryDisplay;

        var packets = countryPackets.ToList();

        ShowSamplingWarning = false;

        // Use pre-calculated stats for consistency
        TotalPackets = (int)preCalculatedPacketCount;
        TotalBytes = preCalculatedByteCount;
        TotalBytesFormatted = FormatBytes(TotalBytes);
        CalculateTimeStats(packets);

        // Calculate breakdowns from already-filtered packets
        CalculatePortBreakdownForCountry(packets);
        CalculateConnectedEndpointsForCountry(packets);
        CalculateTopConversations(packets);

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for an IP address with pre-calculated stats from Dashboard for consistency.
    /// </summary>
    public void ShowForIP(string ip, IEnumerable<PacketInfo> allPackets, long preCalculatedPacketCount, long preCalculatedByteCount)
    {
        Title = $"IP: {ip}";
        EntityType = DrillDownEntityType.IP;
        _currentFilterKey = "ip";
        _currentFilterValue = ip;

        var packets = allPackets
            .Where(p => p.SourceIP == ip || p.DestinationIP == ip)
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets

        // Use pre-calculated stats from Dashboard table for consistency
        TotalPackets = (int)preCalculatedPacketCount;
        TotalBytes = preCalculatedByteCount;
        TotalBytesFormatted = FormatBytes(TotalBytes);
        CalculateTimeStats(packets);

        CalculatePortBreakdown(packets);
        CalculateConnectedEndpoints(packets, ip);
        CalculateTopConversations(packets);

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for an IP address (calculates stats from packets).
    /// </summary>
    public void ShowForIP(string ip, IEnumerable<PacketInfo> allPackets)
    {
        Title = $"IP: {ip}";
        EntityType = DrillDownEntityType.IP;
        _currentFilterKey = "ip";
        _currentFilterValue = ip;

        var packets = allPackets
            .Where(p => p.SourceIP == ip || p.DestinationIP == ip)
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets
        CalculateStatistics(packets);
        CalculatePortBreakdown(packets);
        CalculateConnectedEndpoints(packets, ip);
        CalculateTopConversations(packets);

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for a port with pre-calculated stats from Dashboard for consistency.
    /// </summary>
    public void ShowForPort(int port, string protocol, IEnumerable<PacketInfo> allPackets, long preCalculatedPacketCount, long preCalculatedByteCount)
    {
        Title = $"Port {port}/{protocol}";
        EntityType = DrillDownEntityType.Port;
        _currentFilterKey = "port";
        _currentFilterValue = port.ToString();

        // Parse protocol string to enum for filtering
        var hasProtocolFilter = Enum.TryParse<Protocol>(protocol, ignoreCase: true, out var protocolEnum);

        var packets = allPackets
            .Where(p => (p.SourcePort == port || p.DestinationPort == port)
                        && (!hasProtocolFilter || p.Protocol == protocolEnum))
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets

        // Use pre-calculated stats from Dashboard table for consistency
        TotalPackets = (int)preCalculatedPacketCount;
        TotalBytes = preCalculatedByteCount;
        TotalBytesFormatted = FormatBytes(TotalBytes);
        CalculateTimeStats(packets);

        CalculateConnectedEndpointsForPort(packets, port);
        CalculateTopConversations(packets);
        TopPorts.Clear(); // For ports, show talkers instead of ports

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for a port (calculates stats from packets).
    /// </summary>
    public void ShowForPort(int port, string protocol, IEnumerable<PacketInfo> allPackets)
    {
        Title = $"Port {port}/{protocol}";
        EntityType = DrillDownEntityType.Port;
        _currentFilterKey = "port";
        _currentFilterValue = port.ToString();

        var hasProtocolFilter = Enum.TryParse<Protocol>(protocol, ignoreCase: true, out var protocolEnum);

        var packets = allPackets
            .Where(p => (p.SourcePort == port || p.DestinationPort == port)
                        && (!hasProtocolFilter || p.Protocol == protocolEnum))
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets
        CalculateStatistics(packets);
        CalculateConnectedEndpointsForPort(packets, port);
        CalculateTopConversations(packets);
        TopPorts.Clear(); // For ports, show talkers instead of ports

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for a connection (5-tuple).
    /// </summary>
    public void ShowForConnection(string srcIP, int srcPort, string dstIP, int dstPort, IEnumerable<PacketInfo> allPackets)
    {
        Title = $"{srcIP}:{srcPort} -> {dstIP}:{dstPort}";
        EntityType = DrillDownEntityType.Connection;
        _currentFilterKey = "connection";
        _currentFilterValue = $"{srcIP}:{srcPort}-{dstIP}:{dstPort}";

        var packets = allPackets
            .Where(p => (p.SourceIP == srcIP && p.SourcePort == srcPort && p.DestinationIP == dstIP && p.DestinationPort == dstPort) ||
                        (p.SourceIP == dstIP && p.SourcePort == dstPort && p.DestinationIP == srcIP && p.DestinationPort == srcPort))
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets
        CalculateStatistics(packets);

        // Show Top Talkers (the 2 IPs with directional traffic breakdown)
        var toDestPackets = packets.Where(p => p.SourceIP == srcIP && p.SourcePort == srcPort).ToList();
        var toSrcPackets = packets.Where(p => p.SourceIP == dstIP && p.SourcePort == dstPort).ToList();

        var endpoints = new List<EndpointBreakdownItem>
        {
            new() { IP = $"{srcIP} → {dstIP}", PacketCount = toDestPackets.Count, Bytes = toDestPackets.Sum(p => (long)p.Length) },
            new() { IP = $"{dstIP} → {srcIP}", PacketCount = toSrcPackets.Count, Bytes = toSrcPackets.Sum(p => (long)p.Length) }
        };
        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints.Where(e => e.PacketCount > 0));

        // Show Top Streams (the conversation)
        CalculateTopConversations(packets);

        // Clear ports breakdown (not relevant for specific connection)
        TopPorts.Clear();

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for a stream (IP:Port pair) from Top Streams table.
    /// Filters by specific port pair to show a single TCP/UDP stream, not all connections between IPs.
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Method handles both port-specific and IP-only stream filtering with direction-aware traffic breakdown")]
    public void ShowForStream(string sourceIP, int sourcePort, string destIP, int destPort, IEnumerable<PacketInfo> allPackets, int preCalculatedPacketCount, long preCalculatedByteCount)
    {
        // Build title based on whether ports are provided
        var hasPort = sourcePort > 0 || destPort > 0;
        Title = hasPort
            ? $"Stream: {sourceIP}:{sourcePort} ↔ {destIP}:{destPort}"
            : $"Stream: {sourceIP} ↔ {destIP}";
        EntityType = DrillDownEntityType.Stream;
        _currentFilterKey = "stream";
        _currentFilterValue = hasPort
            ? $"{sourceIP}:{sourcePort}↔{destIP}:{destPort}"
            : $"{sourceIP}↔{destIP}";

        // Filter packets matching this specific stream (IP:Port pair in either direction)
        List<PacketInfo> packets;
        if (hasPort)
        {
            // Filter by specific port pair - this is a single TCP/UDP stream
            packets = allPackets
                .Where(p => (p.SourceIP == sourceIP && p.SourcePort == sourcePort && p.DestinationIP == destIP && p.DestinationPort == destPort) ||
                            (p.SourceIP == destIP && p.SourcePort == destPort && p.DestinationIP == sourceIP && p.DestinationPort == sourcePort))
                .ToList();
        }
        else
        {
            // No ports - filter by IP pair only (all connections between these IPs)
            packets = allPackets
                .Where(p => (p.SourceIP == sourceIP && p.DestinationIP == destIP) ||
                            (p.SourceIP == destIP && p.DestinationIP == sourceIP))
                .ToList();
        }

        ShowSamplingWarning = false;

        // Use pre-calculated stats for consistency with table display
        TotalPackets = preCalculatedPacketCount;
        TotalBytes = preCalculatedByteCount;
        TotalBytesFormatted = FormatBytes(TotalBytes);
        CalculateTimeStats(packets);

        // For port-specific streams, show just the 2 ports (should be ~50% each direction)
        if (hasPort)
        {
            var portItems = new List<PortBreakdownItem>();
            var srcPortPackets = packets.Where(p => p.SourcePort == sourcePort || p.DestinationPort == sourcePort).ToList();
            var dstPortPackets = packets.Where(p => p.SourcePort == destPort || p.DestinationPort == destPort).ToList();

            if (sourcePort > 0)
                portItems.Add(new PortBreakdownItem { Port = sourcePort, ServiceName = GetServiceName(sourcePort), PacketCount = srcPortPackets.Count, Bytes = srcPortPackets.Sum(p => (long)p.Length), Percentage = packets.Count > 0 ? srcPortPackets.Count * 100.0 / packets.Count : 0 });
            if (destPort > 0 && destPort != sourcePort)
                portItems.Add(new PortBreakdownItem { Port = destPort, ServiceName = GetServiceName(destPort), PacketCount = dstPortPackets.Count, Bytes = dstPortPackets.Sum(p => (long)p.Length), Percentage = packets.Count > 0 ? dstPortPackets.Count * 100.0 / packets.Count : 0 });

            TopPorts = new ObservableCollection<PortBreakdownItem>(portItems.OrderByDescending(p => p.PacketCount));
        }
        else
        {
            CalculatePortBreakdown(packets);
        }

        CalculateTopConversations(packets);

        // Show traffic breakdown by direction
        List<PacketInfo> toDestPackets, toSrcPackets;
        if (hasPort)
        {
            toDestPackets = packets.Where(p => p.SourceIP == sourceIP && p.SourcePort == sourcePort).ToList();
            toSrcPackets = packets.Where(p => p.SourceIP == destIP && p.SourcePort == destPort).ToList();
        }
        else
        {
            toDestPackets = packets.Where(p => p.SourceIP == sourceIP && p.DestinationIP == destIP).ToList();
            toSrcPackets = packets.Where(p => p.SourceIP == destIP && p.DestinationIP == sourceIP).ToList();
        }

        var endpoints = new List<EndpointBreakdownItem>
        {
            new() { IP = $"{sourceIP} → {destIP}", PacketCount = toDestPackets.Count, Bytes = toDestPackets.Sum(p => (long)p.Length) },
            new() { IP = $"{destIP} → {sourceIP}", PacketCount = toSrcPackets.Count, Bytes = toSrcPackets.Sum(p => (long)p.Length) }
        };
        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints.Where(e => e.PacketCount > 0));

        IsVisible = true;
    }

    /// <summary>
    /// Show popup for a time slice (chart click) with packets within the time window.
    /// </summary>
    public void ShowForTimeSlice(DateTime timestamp, TimeSpan window, IEnumerable<PacketInfo> allPackets)
    {
        Title = $"Time: {timestamp:HH:mm:ss}";
        EntityType = DrillDownEntityType.TimeSlice;
        _currentFilterKey = "time";
        _currentFilterValue = timestamp.ToString("HH:mm:ss");

        // Filter to exact second only (not a range)
        // Start of the clicked second (e.g., 08:21:06.000)
        var startTime = new DateTime(timestamp.Year, timestamp.Month, timestamp.Day,
                                      timestamp.Hour, timestamp.Minute, timestamp.Second, 0);
        // End of the clicked second (e.g., 08:21:06.999)
        var endTime = startTime.AddSeconds(1).AddTicks(-1);

        var packets = allPackets
            .Where(p => p.Timestamp >= startTime && p.Timestamp <= endTime)
                        .ToList();

        ShowSamplingWarning = false; // No sampling - using all packets
        CalculateStatistics(packets);
        CalculatePortBreakdown(packets);
        CalculateTopConversations(packets);

        // For time slices, show top talkers
        var endpointStats = new Dictionary<string, (int Count, long Bytes)>();
        foreach (var p in packets)
        {
            var ips = new HashSet<string>();
            if (!string.IsNullOrEmpty(p.SourceIP)) ips.Add(p.SourceIP);
            if (!string.IsNullOrEmpty(p.DestinationIP)) ips.Add(p.DestinationIP);

            foreach (var ip in ips)
            {
                if (endpointStats.TryGetValue(ip, out var stats))
                    endpointStats[ip] = (stats.Count + 1, stats.Bytes + p.Length);
                else
                    endpointStats[ip] = (1, p.Length);
            }
        }

        var endpoints = endpointStats
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new EndpointBreakdownItem
            {
                IP = kv.Key,
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes
            })
            .ToList();

        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints);

        IsVisible = true;
    }

    // ==================== COMMANDS ====================

    [RelayCommand]
    private async Task CopyToClipboard()
    {
        var topLevel = Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
            ? desktop.MainWindow
            : null;
        var clipboard = topLevel?.Clipboard;
        if (clipboard != null)
        {
            await clipboard.SetTextAsync(_currentFilterValue);
        }
    }

    [RelayCommand]
    private void FilterDashboard()
    {
        _navigateWithFilter?.Invoke("Dashboard", $"{_currentFilterKey}={_currentFilterValue}");
        Close();
    }

    [RelayCommand]
    private void ViewInPacketAnalysis()
    {
        _navigateWithFilter?.Invoke("PacketAnalysis", $"{_currentFilterKey}={_currentFilterValue}");
        Close();
    }

    [RelayCommand]
    private void Close()
    {
        IsVisible = false;
    }

    [RelayCommand]
    private void FilterByIP(string? ip)
    {
        if (!string.IsNullOrEmpty(ip))
        {
            _navigateWithFilter?.Invoke("PacketAnalysis", $"ip={ip}");
            Close();
        }
    }

    [RelayCommand]
    private void FilterByPort(int port)
    {
        if (port > 0)
        {
            _navigateWithFilter?.Invoke("PacketAnalysis", $"port={port}");
            Close();
        }
    }

    [RelayCommand]
    private void FilterByConversation(ConversationBreakdownItem? conv)
    {
        if (conv != null)
        {
            _navigateWithFilter?.Invoke("PacketAnalysis", $"conversation={conv.SourceIP}:{conv.SourcePort}-{conv.DestinationIP}:{conv.DestinationPort}");
            Close();
        }
    }

    // ==================== CALCULATION HELPERS ====================

    private void CalculateStatistics(List<PacketInfo> packets)
    {
        TotalPackets = packets.Count;
        TotalBytes = packets.Sum(p => (long)p.Length);
        TotalBytesFormatted = FormatBytes(TotalBytes);
        CalculateTimeStats(packets);
    }

    /// <summary>
    /// Calculate statistics for port view - uses Wireshark-compatible unique packet counting.
    /// Each packet is counted once regardless of whether port appears in src, dst, or both.
    /// </summary>
    private void CalculateStatisticsForPort(List<PacketInfo> packets, int port)
    {
        // Simply use the standard calculation - each packet counted once
        // This now matches Dashboard's corrected unique packet approach
        CalculateStatistics(packets);
    }

    private void CalculateTimeStats(List<PacketInfo> packets)
    {
        if (packets.Count > 0)
        {
            // Timestamps are now consistently in local time from TSharkParser
            FirstSeen = packets.Min(p => p.Timestamp);
            LastSeen = packets.Max(p => p.Timestamp);
            var durationSpan = LastSeen - FirstSeen;
            Duration = durationSpan.TotalHours >= 1
                ? $"{durationSpan.TotalHours:F1}h"
                : durationSpan.TotalMinutes >= 1
                    ? $"{durationSpan.TotalMinutes:F0}m {durationSpan.Seconds}s"
                    : $"{durationSpan.TotalSeconds:F0}s";
            AveragePacketSize = (int)(TotalBytes / packets.Count);
        }
        else
        {
            FirstSeen = LastSeen = DateTime.MinValue;
            Duration = "N/A";
            AveragePacketSize = 0;
        }
    }

    private void CalculatePortBreakdown(List<PacketInfo> packets)
    {
        // O(n) single-pass aggregation for port breakdown with packet count and bytes
        var portStats = new Dictionary<int, (int Count, long Bytes)>();
        foreach (var p in packets)
        {
            var seenPorts = new HashSet<int>();
            if (p.SourcePort > 0)
            {
                seenPorts.Add(p.SourcePort);
                var existing = portStats.GetValueOrDefault(p.SourcePort);
                portStats[p.SourcePort] = (existing.Count + 1, existing.Bytes + p.Length);
            }
            if (p.DestinationPort > 0 && !seenPorts.Contains(p.DestinationPort))
            {
                var existing = portStats.GetValueOrDefault(p.DestinationPort);
                portStats[p.DestinationPort] = (existing.Count + 1, existing.Bytes + p.Length);
            }
        }

        var ports = portStats
            .Select(kv => new PortBreakdownItem
            {
                Port = kv.Key,
                ServiceName = GetServiceName(kv.Key),
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(5)
            .ToList();

        TopPorts = new ObservableCollection<PortBreakdownItem>(ports);
    }

    private void CalculateConnectedEndpoints(List<PacketInfo> packets, string centerIP)
    {
        // Single-pass aggregation: O(n) instead of O(n × m)
        var endpointStats = new Dictionary<string, (int Count, long Bytes)>();

        foreach (var p in packets)
        {
            var otherIP = p.SourceIP == centerIP ? p.DestinationIP : p.SourceIP;
            if (string.IsNullOrEmpty(otherIP) || otherIP == centerIP) continue;

            if (endpointStats.TryGetValue(otherIP, out var stats))
                endpointStats[otherIP] = (stats.Count + 1, stats.Bytes + p.Length);
            else
                endpointStats[otherIP] = (1, p.Length);
        }

        var endpoints = endpointStats
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new EndpointBreakdownItem
            {
                IP = kv.Key,
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .ToList();

        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints);
    }

    private void CalculateConnectedEndpointsForPort(List<PacketInfo> packets, int port)
    {
        // Single-pass aggregation: O(n) instead of O(n × m)
        var endpointStats = new Dictionary<string, (int Count, long Bytes)>();

        foreach (var p in packets)
        {
            // Count each IP that appears in this packet (source and/or destination)
            var ips = new HashSet<string>();
            if (!string.IsNullOrEmpty(p.SourceIP)) ips.Add(p.SourceIP);
            if (!string.IsNullOrEmpty(p.DestinationIP)) ips.Add(p.DestinationIP);

            foreach (var ip in ips)
            {
                if (endpointStats.TryGetValue(ip, out var stats))
                    endpointStats[ip] = (stats.Count + 1, stats.Bytes + p.Length);
                else
                    endpointStats[ip] = (1, p.Length);
            }
        }

        var endpoints = endpointStats
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new EndpointBreakdownItem
            {
                IP = kv.Key,
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .ToList();

        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints);
    }

    private void CalculateTopConversations(List<PacketInfo> packets)
    {
        // Aggregate conversations by 4-tuple (srcIP:srcPort <-> dstIP:dstPort)
        var convStats = new Dictionary<string, (string SrcIP, int SrcPort, string DstIP, int DstPort, int Count, long Bytes)>();

        foreach (var p in packets)
        {
            if (string.IsNullOrEmpty(p.SourceIP) || string.IsNullOrEmpty(p.DestinationIP)) continue;

            // Normalize conversation key (smaller IP first for bidirectional matching)
            var forward = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) <= 0
                ? (p.SourceIP, p.SourcePort, p.DestinationIP, p.DestinationPort)
                : (p.DestinationIP, p.DestinationPort, p.SourceIP, p.SourcePort);

            var key = $"{forward.Item1}:{forward.Item2}-{forward.Item3}:{forward.Item4}";

            if (convStats.TryGetValue(key, out var stats))
                convStats[key] = (forward.Item1, forward.Item2, forward.Item3, forward.Item4, stats.Count + 1, stats.Bytes + p.Length);
            else
                convStats[key] = (forward.Item1, forward.Item2, forward.Item3, forward.Item4, 1, p.Length);
        }

        var conversations = convStats
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new ConversationBreakdownItem
            {
                SourceIP = kv.Value.SrcIP,
                SourcePort = kv.Value.SrcPort,
                DestinationIP = kv.Value.DstIP,
                DestinationPort = kv.Value.DstPort,
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .ToList();

        TopConversations = new ObservableCollection<ConversationBreakdownItem>(conversations);
    }

    /// <summary>
    /// Calculate port breakdown for country packets (aggregates all ports, not filtered by center IP).
    /// </summary>
    private void CalculatePortBreakdownForCountry(List<PacketInfo> packets)
    {
        var portStats = new Dictionary<int, (int Count, long Bytes)>();

        foreach (var p in packets)
        {
            // Aggregate both source and destination ports
            if (p.SourcePort > 0)
            {
                var existing = portStats.GetValueOrDefault(p.SourcePort);
                portStats[p.SourcePort] = (existing.Count + 1, existing.Bytes + p.Length);
            }
            if (p.DestinationPort > 0 && p.DestinationPort != p.SourcePort)
            {
                var existing = portStats.GetValueOrDefault(p.DestinationPort);
                portStats[p.DestinationPort] = (existing.Count + 1, existing.Bytes + p.Length);
            }
        }

        var ports = portStats
            .Select(kv => new PortBreakdownItem
            {
                Port = kv.Key,
                ServiceName = GetServiceName(kv.Key),
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(5)
            .ToList();

        TopPorts = new ObservableCollection<PortBreakdownItem>(ports);
    }

    /// <summary>
    /// Calculate connected endpoints for country packets (aggregates all IPs).
    /// </summary>
    private void CalculateConnectedEndpointsForCountry(List<PacketInfo> packets)
    {
        var endpointStats = new Dictionary<string, (int Count, long Bytes)>();

        foreach (var p in packets)
        {
            // Aggregate both source and destination IPs
            if (!string.IsNullOrEmpty(p.SourceIP))
            {
                if (endpointStats.TryGetValue(p.SourceIP, out var stats))
                    endpointStats[p.SourceIP] = (stats.Count + 1, stats.Bytes + p.Length);
                else
                    endpointStats[p.SourceIP] = (1, p.Length);
            }
            if (!string.IsNullOrEmpty(p.DestinationIP) && p.DestinationIP != p.SourceIP)
            {
                if (endpointStats.TryGetValue(p.DestinationIP, out var stats))
                    endpointStats[p.DestinationIP] = (stats.Count + 1, stats.Bytes + p.Length);
                else
                    endpointStats[p.DestinationIP] = (1, p.Length);
            }
        }

        var endpoints = endpointStats
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new EndpointBreakdownItem
            {
                IP = kv.Key,
                PacketCount = kv.Value.Count,
                Bytes = kv.Value.Bytes,
                Percentage = packets.Count > 0 ? (kv.Value.Count * 100.0 / packets.Count) : 0
            })
            .ToList();

        ConnectedEndpoints = new ObservableCollection<EndpointBreakdownItem>(endpoints);
    }

    // Use shared NumberFormatter.FormatBytes() for consistency with Dashboard
    private static string FormatBytes(long bytes) => NumberFormatter.FormatBytes(bytes);

    private static string GetServiceName(int port)
    {
        // Use the comprehensive PortDatabase for service name lookup
        return PCAPAnalyzer.Core.Security.PortDatabase.GetServiceName((ushort)port, true) ?? "";
    }
}

public enum DrillDownEntityType
{
    IP,
    Port,
    Connection,
    TimeSlice,
    Stream
}

public class PortBreakdownItem
{
    public int Port { get; set; }
    public string ServiceName { get; set; } = "";
    public int PacketCount { get; set; }
    public long Bytes { get; set; }
    public double Percentage { get; set; }
    public string BytesFormatted => FormatBytes(Bytes);

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1) { order++; len /= 1024; }
        return $"{len:F1} {sizes[order]}";
    }
}

public class EndpointBreakdownItem
{
    public string IP { get; set; } = "";
    public int PacketCount { get; set; }
    public long Bytes { get; set; }
    public double Percentage { get; set; }
    public string BytesFormatted => FormatBytes(Bytes);

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1) { order++; len /= 1024; }
        return $"{len:F1} {sizes[order]}";
    }
}

public class ConversationBreakdownItem
{
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestinationIP { get; set; } = "";
    public int DestinationPort { get; set; }
    public int PacketCount { get; set; }
    public long Bytes { get; set; }
    public double Percentage { get; set; }
    public string BytesFormatted => FormatBytes(Bytes);
    public string DisplayText => $"{SourceIP}:{SourcePort} ↔ {DestinationIP}:{DestinationPort}";

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1) { order++; len /= 1024; }
        return $"{len:F1} {sizes[order]}";
    }
}
