using System.Collections.ObjectModel;
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
    private const int MaxPacketsForAnalysis = 500_000;

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
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;

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
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;
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
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;

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
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;
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
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;
        CalculateStatistics(packets);

        // Connections don't need port/endpoint breakdown, but show conversations
        TopPorts.Clear();
        ConnectedEndpoints.Clear();
        TopConversations.Clear();

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

        var startTime = timestamp - window;
        var endTime = timestamp + window;

        var packets = allPackets
            .Where(p => p.Timestamp >= startTime && p.Timestamp <= endTime)
            .Take(MaxPacketsForAnalysis)
            .ToList();

        ShowSamplingWarning = packets.Count == MaxPacketsForAnalysis;
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
        // O(n) single-pass aggregation for port breakdown
        var portStats = new Dictionary<int, int>();
        foreach (var p in packets)
        {
            var seenPorts = new HashSet<int>();
            if (p.SourcePort > 0)
            {
                seenPorts.Add(p.SourcePort);
                portStats[p.SourcePort] = portStats.GetValueOrDefault(p.SourcePort) + 1;
            }
            if (p.DestinationPort > 0 && !seenPorts.Contains(p.DestinationPort))
            {
                portStats[p.DestinationPort] = portStats.GetValueOrDefault(p.DestinationPort) + 1;
            }
        }

        var ports = portStats
            .Select(kv => new PortBreakdownItem
            {
                Port = kv.Key,
                ServiceName = GetServiceName(kv.Key),
                PacketCount = kv.Value,
                Percentage = packets.Count > 0 ? (kv.Value * 100.0 / packets.Count) : 0
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
                Bytes = kv.Value.Bytes
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
                Bytes = kv.Value.Bytes
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
                Bytes = kv.Value.Bytes
            })
            .ToList();

        TopConversations = new ObservableCollection<ConversationBreakdownItem>(conversations);
    }

    // Use shared NumberFormatter.FormatBytes() for consistency with Dashboard
    private static string FormatBytes(long bytes) => NumberFormatter.FormatBytes(bytes);

    private static string GetServiceName(int port)
    {
        return port switch
        {
            20 or 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            67 or 68 => "DHCP",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            8080 => "HTTP-Alt",
            _ => ""
        };
    }
}

public enum DrillDownEntityType
{
    IP,
    Port,
    Connection,
    TimeSlice
}

public class PortBreakdownItem
{
    public int Port { get; set; }
    public string ServiceName { get; set; } = "";
    public int PacketCount { get; set; }
    public double Percentage { get; set; }
}

public class EndpointBreakdownItem
{
    public string IP { get; set; } = "";
    public int PacketCount { get; set; }
    public long Bytes { get; set; }
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
