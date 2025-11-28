using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Security;
using PCAPAnalyzer.Core.Utilities;
using Avalonia;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for drill-down detail popup shown when clicking Dashboard elements.
/// Supports IP, Port, Connection, and TimeSlice entity types.
/// </summary>
public partial class DrillDownPopupViewModel : ObservableObject
{
    private readonly Action<string, string>? _navigateWithFilter;
    private readonly IGeoIPService? _geoIPService;
    private readonly StreamSecurityAnalyzer _securityAnalyzer = new();
    private List<PacketInfo>? _currentStreamPackets;
    private string _currentSourceIP = "";
    private int _currentSourcePort;
    private string _currentDestIP = "";
    private int _currentDestPort;

    [ObservableProperty] private bool _isVisible;
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private DrillDownEntityType _entityType;

    // Tab selection (0 = Stream Context, 1 = Security Analysis)
    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private bool _isSecurityTabVisible;

    // Security Analysis Results
    [ObservableProperty] private int _riskScore;
    [ObservableProperty] private string _riskLevel = "";
    [ObservableProperty] private IBrush _riskLevelColor = new SolidColorBrush(Color.Parse("#8B949E"));
    [ObservableProperty] private string _encryptionStatus = "";
    [ObservableProperty] private IBrush _encryptionStatusColor = new SolidColorBrush(Color.Parse("#8B949E"));
    [ObservableProperty] private string _encryptionProtocol = "";
    [ObservableProperty] private bool _beaconingDetected;
    [ObservableProperty] private string _beaconingInterval = "";
    [ObservableProperty] private string _beaconingConfidence = "";
    [ObservableProperty] private IBrush _beaconingColor = new SolidColorBrush(Color.Parse("#4CAF50"));
    [ObservableProperty] private string _uploadDownloadRatio = "";
    [ObservableProperty] private bool _dataExfiltrationIndicator;
    [ObservableProperty] private IBrush _exfiltrationColor = new SolidColorBrush(Color.Parse("#4CAF50"));
    [ObservableProperty] private string _protocolSecurityLevel = "";
    [ObservableProperty] private IBrush _protocolSecurityColor = new SolidColorBrush(Color.Parse("#8B949E"));
    [ObservableProperty] private string _protocolSecurityReason = "";
    [ObservableProperty] private string _protocolRecommendation = "";
    [ObservableProperty] private ObservableCollection<SecurityFindingDisplay> _securityFindings = new();

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

        // Connections don't need port/endpoint breakdown, but show conversations
        TopPorts.Clear();
        ConnectedEndpoints.Clear();
        TopConversations.Clear();

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
            var srcPortCount = packets.Count(p => p.SourcePort == sourcePort || p.DestinationPort == sourcePort);
            var dstPortCount = packets.Count(p => p.SourcePort == destPort || p.DestinationPort == destPort);

            if (sourcePort > 0)
                portItems.Add(new PortBreakdownItem { Port = sourcePort, ServiceName = GetServiceName(sourcePort), PacketCount = srcPortCount, Percentage = packets.Count > 0 ? srcPortCount * 100.0 / packets.Count : 0 });
            if (destPort > 0 && destPort != sourcePort)
                portItems.Add(new PortBreakdownItem { Port = destPort, ServiceName = GetServiceName(destPort), PacketCount = dstPortCount, Percentage = packets.Count > 0 ? dstPortCount * 100.0 / packets.Count : 0 });

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

        // Store stream info for security analysis
        _currentStreamPackets = packets;
        _currentSourceIP = sourceIP;
        _currentSourcePort = sourcePort;
        _currentDestIP = destIP;
        _currentDestPort = destPort;

        // Perform security analysis
        PerformSecurityAnalysis(packets, sourceIP, sourcePort, destIP, destPort);
        IsSecurityTabVisible = true;
        SelectedTab = 0; // Default to Stream Context tab

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

    [RelayCommand]
    private void SelectStreamContextTab()
    {
        SelectedTab = 0;
    }

    [RelayCommand]
    private void SelectSecurityTab()
    {
        SelectedTab = 1;
    }

    [RelayCommand]
    private void FindSimilarStreams()
    {
        // Navigate to Packet Analysis with filter for similar traffic patterns
        // Similar = same destination port (service) OR same destination IP
        if (_currentDestPort > 0)
        {
            _navigateWithFilter?.Invoke("PacketAnalysis", $"port={_currentDestPort}");
        }
        else if (!string.IsNullOrEmpty(_currentDestIP))
        {
            _navigateWithFilter?.Invoke("PacketAnalysis", $"ip={_currentDestIP}");
        }
        Close();
    }

    // ==================== SECURITY ANALYSIS ====================

    private void PerformSecurityAnalysis(List<PacketInfo> packets, string sourceIP, int sourcePort, string destIP, int destPort)
    {
        var result = _securityAnalyzer.Analyze(packets, sourceIP, sourcePort, destIP, destPort);

        // Update risk score and level
        RiskScore = result.RiskScore;
        RiskLevel = result.RiskLevel.ToString();
        RiskLevelColor = new SolidColorBrush(GetRiskLevelColor(result.RiskLevel));

        // Update encryption status
        EncryptionStatus = GetEncryptionStatusText(result.EncryptionStatus);
        EncryptionStatusColor = new SolidColorBrush(GetEncryptionStatusColor(result.EncryptionStatus));
        EncryptionProtocol = result.EncryptionProtocol ?? "";

        // Update beaconing info
        BeaconingDetected = result.BeaconingDetected;
        BeaconingInterval = result.BeaconingDetected ? $"{result.BeaconingInterval:F1}s" : "Not detected";
        BeaconingConfidence = result.BeaconingDetected ? $"{result.BeaconingConfidence:F0}%" : "";
        BeaconingColor = new SolidColorBrush(result.BeaconingDetected ? Color.Parse("#FFA726") : Color.Parse("#4CAF50"));

        // Update data exfiltration info
        UploadDownloadRatio = double.IsInfinity(result.UploadDownloadRatio)
            ? "∞:1 (upload only)"
            : $"{result.UploadDownloadRatio:F1}:1";
        DataExfiltrationIndicator = result.DataExfiltrationIndicator;
        ExfiltrationColor = new SolidColorBrush(result.DataExfiltrationIndicator ? Color.Parse("#FFA726") : Color.Parse("#4CAF50"));

        // Update protocol security
        ProtocolSecurityLevel = ProtocolSecurityEvaluator.GetSecurityLevelString(result.ProtocolSecurityLevel);
        ProtocolSecurityColor = new SolidColorBrush(Color.Parse(ProtocolSecurityEvaluator.GetSecurityLevelColor(result.ProtocolSecurityLevel)));
        ProtocolSecurityReason = result.ProtocolSecurityReason;
        ProtocolRecommendation = result.ProtocolRecommendation;

        // Update findings
        SecurityFindings = new ObservableCollection<SecurityFindingDisplay>(
            result.Findings.Select(f => new SecurityFindingDisplay
            {
                Type = f.Type.ToString(),
                Severity = f.Severity.ToString(),
                SeverityColor = new SolidColorBrush(GetSeverityColor(f.Severity)),
                Title = f.Title,
                Description = f.Description,
                Recommendation = f.Recommendation,
                Vulnerabilities = f.Vulnerabilities.Any() ? string.Join(", ", f.Vulnerabilities) : ""
            }));
    }

    private static Color GetRiskLevelColor(StreamRiskLevel level)
    {
        return level switch
        {
            StreamRiskLevel.Critical => Color.Parse("#B71C1C"), // Dark Red
            StreamRiskLevel.High => Color.Parse("#EF5350"),     // Red
            StreamRiskLevel.Medium => Color.Parse("#FFA726"),   // Orange
            StreamRiskLevel.Low => Color.Parse("#8BC34A"),      // Light Green
            StreamRiskLevel.Safe => Color.Parse("#4CAF50"),     // Green
            _ => Color.Parse("#9E9E9E")                          // Gray
        };
    }

    private static string GetEncryptionStatusText(Core.Services.EncryptionStatus status)
    {
        return status switch
        {
            Core.Services.EncryptionStatus.Encrypted => "Encrypted",
            Core.Services.EncryptionStatus.LikelyEncrypted => "Likely Encrypted",
            Core.Services.EncryptionStatus.LikelyUnencrypted => "Likely Unencrypted",
            Core.Services.EncryptionStatus.Unencrypted => "Unencrypted",
            _ => "Unknown"
        };
    }

    private static Color GetEncryptionStatusColor(Core.Services.EncryptionStatus status)
    {
        return status switch
        {
            Core.Services.EncryptionStatus.Encrypted => Color.Parse("#4CAF50"),        // Green
            Core.Services.EncryptionStatus.LikelyEncrypted => Color.Parse("#8BC34A"),  // Light Green
            Core.Services.EncryptionStatus.LikelyUnencrypted => Color.Parse("#FFA726"),// Orange
            Core.Services.EncryptionStatus.Unencrypted => Color.Parse("#EF5350"),      // Red
            _ => Color.Parse("#9E9E9E")                                                 // Gray
        };
    }

    private static Color GetSeverityColor(StreamFindingSeverity severity)
    {
        return severity switch
        {
            StreamFindingSeverity.Critical => Color.Parse("#B71C1C"),
            StreamFindingSeverity.High => Color.Parse("#EF5350"),
            StreamFindingSeverity.Medium => Color.Parse("#FFA726"),
            StreamFindingSeverity.Low => Color.Parse("#8BC34A"),
            StreamFindingSeverity.Info => Color.Parse("#58A6FF"),
            _ => Color.Parse("#9E9E9E")
        };
    }

    private void ResetSecurityAnalysis()
    {
        IsSecurityTabVisible = false;
        SelectedTab = 0;
        RiskScore = 0;
        RiskLevel = "";
        SecurityFindings.Clear();
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

/// <summary>
/// Display model for security findings in the UI.
/// </summary>
public class SecurityFindingDisplay
{
    public string Type { get; set; } = "";
    public string Severity { get; set; } = "";
    public IBrush SeverityColor { get; set; } = new SolidColorBrush(Color.Parse("#8B949E"));
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public string Vulnerabilities { get; set; } = "";
    public bool HasVulnerabilities => !string.IsNullOrEmpty(Vulnerabilities);
}
