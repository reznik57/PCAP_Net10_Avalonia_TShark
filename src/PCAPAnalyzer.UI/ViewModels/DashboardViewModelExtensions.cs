using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Defaults;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class DashboardViewModel
    {
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
                445 => "SMB",
                3306 => "MySQL",
                3389 => "RDP",
                5432 => "PostgreSQL",
                6379 => "Redis",
                8080 => "HTTP-Alt",
                8443 => "HTTPS-Alt",
                _ => port < 1024 ? "System" : "Dynamic"
            };
        }
        
        private string ParseIP(string display)
        {
            if (string.IsNullOrEmpty(display)) return "0.0.0.0";
            var parts = display.Split(':');
            return parts.Length > 0 ? parts[0] : display;
        }
        
        private int ParsePort(string display)
        {
            if (string.IsNullOrEmpty(display)) return 0;
            var parts = display.Split(':');
            if (parts.Length > 1 && int.TryParse(parts[1], out var port))
                return port;
            return 0;
        }
        
        // New Properties for Modern Dashboard
        [ObservableProperty] private ObservableCollection<ConnectionInfo> _topConnectionsByBytes = new();
        [ObservableProperty] private ObservableCollection<ConnectionInfo> _topConnectionsByPackets = new();
        [ObservableProperty] private ObservableCollection<ConnectionInfo> _topConnectionsByBytesDisplay = new();
        [ObservableProperty] private ObservableCollection<ConnectionInfo> _topConnectionsByPacketsDisplay = new();
        // Port Activity Timeline controls (Top 5/10)
        [ObservableProperty] private bool _showTop10PortsTimeline = false;
        [ObservableProperty] private int _portTimelineDisplayCount = 5;
        [ObservableProperty] private bool _showPortActivityAsThroughput = false;
        
        // Port Tables controls (Top 10/25) - Default to Top 10
        [ObservableProperty] private bool _showTop25PortTables = false;
        [ObservableProperty] private int _portTableDisplayCount = 10;
        
        // Other tables controls (Top 10/25) - Default to Top 10
        [ObservableProperty] private bool _showTop25OtherTables = true;
        [ObservableProperty] private int _otherTableDisplayCount = 30;
        
        // Connection tables controls (Top 10/25) - Default to Top 10
        [ObservableProperty] private bool _showTop25ConnectionTables = false;
        [ObservableProperty] private int _connectionTableDisplayCount = 10;
        
        // Removed toggle - now showing both tables
        // [ObservableProperty] private bool _showConnectionsByBytes = true;
        // Removed toggle - now showing both tables
        // [ObservableProperty] private bool _showPortsByBytes = true;
        [ObservableProperty] private bool _showSourcesByBytes = true;
        [ObservableProperty] private bool _showDestinationsByBytes = true;
        
        [ObservableProperty] private int _topConnectionsCount = 0;
        
        partial void OnShowTop10PortsTimelineChanged(bool value)
        {
            PortTimelineDisplayCount = value ? 10 : 5;
            UpdatePortActivityTimeline();
        }
        
        partial void OnShowTop25PortTablesChanged(bool value)
        {
            PortTableDisplayCount = value ? 30 : 10;
            UpdatePortsDisplay();
        }
        
        partial void OnShowTop25OtherTablesChanged(bool value)
        {
            OtherTableDisplayCount = value ? 30 : 10;
            DebugLogger.Log($"[DashboardViewModel] OtherTableDisplayCount changed to: {OtherTableDisplayCount}");
            
            // Force property change notifications
            OnPropertyChanged(nameof(OtherTableDisplayCount));
            
            // Only update source and destination displays, not connections
            UpdateSourcesDisplay();
            UpdateDestinationsDisplay();
            
            // Force collection property notifications
            OnPropertyChanged(nameof(TopSourcesDisplay));
            OnPropertyChanged(nameof(TopSourcesByBytesDisplay));
            OnPropertyChanged(nameof(TopDestinationsDisplay));
            OnPropertyChanged(nameof(TopDestinationsByBytesDisplay));
        }
        
        [RelayCommand]
        private void ToggleOtherTableCount()
        {
            DebugLogger.Log($"[DashboardViewModel] ToggleOtherTableCount called. Current: {ShowTop25OtherTables}");
            ShowTop25OtherTables = !ShowTop25OtherTables;
            DebugLogger.Log($"[DashboardViewModel] ToggleOtherTableCount set to: {ShowTop25OtherTables}");
        }
        
        partial void OnShowTop25ConnectionTablesChanged(bool value)
        {
            ConnectionTableDisplayCount = value ? 30 : 10;
            // Only update connections display
            UpdateConnectionsDisplay();
        }
        
        [RelayCommand]
        private void ToggleConnectionTableCount()
        {
            ShowTop25ConnectionTables = !ShowTop25ConnectionTables;
        }
        
        partial void OnShowPortActivityAsThroughputChanged(bool value)
        {
            UpdatePortActivityTimeline();
        }
        
        [RelayCommand]
        private void TogglePortTimelineCount()
        {
            ShowTop10PortsTimeline = !ShowTop10PortsTimeline;
        }
        
        [RelayCommand]
        private void TogglePortTableCount()
        {
            ShowTop25PortTables = !ShowTop25PortTables;
        }
        
        
        [RelayCommand]
        private void TogglePortActivityMode()
        {
            ShowPortActivityAsThroughput = !ShowPortActivityAsThroughput;
        }
        
        // Port Activity Timeline Properties (Packets/Second or Throughput/Second)
        [ObservableProperty] private ObservableCollection<ISeries> _portActivitySeries = new();
        [ObservableProperty] private Axis[] _portActivityXAxes = new[] { new Axis() };
        [ObservableProperty] private Axis[] _portActivityYAxes = new[] { new Axis() };
        
        // Removed Port Pie Chart - now focusing on activity timeline
        
        // Removed toggle handler
        // partial void OnShowConnectionsByBytesChanged(bool value)
        // {
        //     UpdateConnectionsDisplay();
        // }
        
        // Removed toggle handler
        // partial void OnShowPortsByBytesChanged(bool value)
        // {
        //     UpdatePortsDisplay();
        // }
        
        partial void OnShowSourcesByBytesChanged(bool value)
        {
            UpdateSourcesDisplay();
        }
        
        partial void OnShowDestinationsByBytesChanged(bool value)
        {
            UpdateDestinationsDisplay();
        }
        
        private void UpdateModernVisualizations()
        {
            try
            {
                // Ensure we're on UI thread
                if (!_dispatcher.CheckAccess())
                {
                    _dispatcher.Post(() => UpdateModernVisualizations());
                    return;
                }
                
                UpdateConnectionsDisplay();
                UpdatePortsDisplay();
                UpdatePortActivityTimeline();
                UpdateSourcesDisplay();
                UpdateDestinationsDisplay();
                
                // Update extended collections with ranking after all display updates
                UpdateExtendedCollections();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating modern visualizations: {ex.Message}");
                DebugLogger.Log($"[DashboardViewModel] Stack trace: {ex.StackTrace}");
                // Initialize with empty data to prevent crashes
                InitializeEmptyModernData();
            }
        }
        
        private void InitializeEmptyModernData()
        {
            // Clear collections instead of replacing them (they're now managed by Statistics component)
            TopConnectionsByBytesDisplay?.Clear();
            TopConnectionsByPacketsDisplay?.Clear();
            TopPortsByBytesDisplay?.Clear();
            TopPortsByPacketsDisplay?.Clear();
            TopSourcesDisplay?.Clear();
            TopSourcesByBytesDisplay?.Clear();
            TopDestinationsDisplay?.Clear();
            TopDestinationsByBytesDisplay?.Clear();
            PortActivitySeries?.Clear();
            PortActivityXAxes = new[]
            {
                new Axis
                {
                    Labeler = _ => string.Empty,
                    LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E"))),
                    SeparatorsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("BorderSubtle", "#21262D"))),
                    TextSize = 10
                }
            };
            PortActivityYAxes = new[]
            {
                new Axis
                {
                    Name = "Packets/Second",
                    Labeler = value => $"{value:F0} pkt/s",
                    LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E"))),
                    SeparatorsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("BorderSubtle", "#21262D"))),
                    TextSize = 10,
                    MinLimit = 0
                }
            };
            TopConnectionsCount = 0;
        }

        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Connection display update requires processing and formatting multiple connection attributes including IP parsing, port extraction, and timestamp generation")]
        private void UpdateConnectionsDisplay()
        {
            try
            {
                // Ensure we're on UI thread
                if (!_dispatcher.CheckAccess())
                {
                    _dispatcher.Post(() => UpdateConnectionsDisplay());
                    return;
                }

                // Check if we have data from either source
                if ((TopConversationsByBytes == null || !TopConversationsByBytes.Any()) &&
                    (TopConversations == null || !TopConversations.Any()))
                {
                    TopConnectionsByBytesDisplay = new ObservableCollection<ConnectionInfo>();
                    TopConnectionsByPacketsDisplay = new ObservableCollection<ConnectionInfo>();
                    TopConnectionsCount = 0;
                    return;
                }

                // DASHBOARD: Aggregate by IP pair only (no ports) for high-level overview
                // Step 1: Aggregate all conversations by IP pair
                var ipPairStats = new Dictionary<string, (long Bytes, long Packets, string SrcIP, string DstIP, string Protocol)>();

                if (TopConversationsByBytes != null)
                {
                    foreach (var c in TopConversationsByBytes)
                    {
                        var srcIP = ParseIP(c.SourceDisplay);
                        var dstIP = ParseIP(c.DestinationDisplay);
                        // Create sorted key for consistent IP pair identification
                        var ips = new[] { srcIP, dstIP }.OrderBy(x => x).ToArray();
                        var ipPairKey = $"{ips[0]}↔{ips[1]}";

                        if (ipPairStats.TryGetValue(ipPairKey, out var existing))
                            ipPairStats[ipPairKey] = (existing.Bytes + c.ByteCount, existing.Packets + (long)c.PacketCount, ips[0], ips[1], existing.Protocol);
                        else
                            ipPairStats[ipPairKey] = (c.ByteCount, (long)c.PacketCount, ips[0], ips[1], c.Protocol);
                    }
                }

                // Also include conversations from packet-sorted list if not already present
                if (TopConversations != null)
                {
                    foreach (var c in TopConversations)
                    {
                        var srcIP = ParseIP(c.SourceDisplay);
                        var dstIP = ParseIP(c.DestinationDisplay);
                        var ips = new[] { srcIP, dstIP }.OrderBy(x => x).ToArray();
                        var ipPairKey = $"{ips[0]}↔{ips[1]}";

                        if (!ipPairStats.ContainsKey(ipPairKey))
                            ipPairStats[ipPairKey] = (c.ByteCount, (long)c.PacketCount, ips[0], ips[1], c.Protocol);
                    }
                }

                // Step 2: Create display lists from aggregated IP pairs
                var connectionsByBytes = ipPairStats
                    .OrderByDescending(p => p.Value.Bytes)
                    .Take(ConnectionTableDisplayCount)
                    .Select(p => new ConnectionInfo
                    {
                        SourceIP = p.Value.SrcIP,
                        SourcePort = 0, // No port for IP-pair aggregation
                        DestIP = p.Value.DstIP,
                        DestPort = 0,
                        Protocol = p.Value.Protocol,
                        ByteCount = p.Value.Bytes,
                        PacketCount = (int)p.Value.Packets,
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI sample timestamp generation, not security
                        FirstSeen = DateTime.Now.AddSeconds(-Random.Shared.Next(60, 3600)),
#pragma warning restore CA5394
                        LastSeen = DateTime.Now
                    })
                    .ToList();

                var connectionsByPackets = ipPairStats
                    .OrderByDescending(p => p.Value.Packets)
                    .Take(ConnectionTableDisplayCount)
                    .Select(p => new ConnectionInfo
                    {
                        SourceIP = p.Value.SrcIP,
                        SourcePort = 0,
                        DestIP = p.Value.DstIP,
                        DestPort = 0,
                        Protocol = p.Value.Protocol,
                        ByteCount = p.Value.Bytes,
                        PacketCount = (int)p.Value.Packets,
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI sample timestamp generation, not security
                        FirstSeen = DateTime.Now.AddSeconds(-Random.Shared.Next(60, 3600)),
#pragma warning restore CA5394
                        LastSeen = DateTime.Now
                    })
                    .ToList();

                // Calculate traffic percentages for bytes
                var maxByteTraffic = connectionsByBytes.Any() ? connectionsByBytes.Max(c => c.ByteCount) : 1;
                foreach (var conn in connectionsByBytes)
                {
                    conn.TrafficPercentage = (conn.ByteCount * 100.0) / maxByteTraffic;
                }

                // Calculate traffic percentages for packets
                var maxPacketTraffic = connectionsByPackets.Any() ? connectionsByPackets.Max(c => c.PacketCount) : 1;
                foreach (var conn in connectionsByPackets)
                {
                    conn.TrafficPercentage = (conn.PacketCount * 100.0) / maxPacketTraffic;
                }

                // Calculate percentage based on TOTAL bytes/packets from ALL traffic (not just top connections)
                // Use the statistics totals for accurate percentages
                var totalBytes = _currentStatistics?.TotalBytes ?? 0;
                var totalPackets = _currentStatistics?.TotalPackets ?? 0;

                // Update percentages for display
                foreach (var conn in connectionsByBytes)
                {
                    conn.Percentage = totalBytes > 0 ? (conn.ByteCount * 100.0) / totalBytes : 0;
                }

                foreach (var conn in connectionsByPackets)
                {
                    conn.Percentage = totalPackets > 0 ? (conn.PacketCount * 100.0) / totalPackets : 0;
                }

                // Update the display collections with properly sorted data
                TopConnectionsByBytesDisplay = new ObservableCollection<ConnectionInfo>(connectionsByBytes);
                TopConnectionsByPacketsDisplay = new ObservableCollection<ConnectionInfo>(connectionsByPackets);

                // Calculate total count from aggregated IP pairs
                TopConnectionsCount = ipPairStats.Count;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating connections: {ex.Message}");
                DebugLogger.Log($"[DashboardViewModel] Stack trace: {ex.StackTrace}");
                TopConnectionsByBytesDisplay = new ObservableCollection<ConnectionInfo>();
                TopConnectionsByPacketsDisplay = new ObservableCollection<ConnectionInfo>();
                TopConnectionsCount = 0;
            }
        }
        
        private void UpdatePortsDisplay()
        {
            try
            {
                // Ensure we're on UI thread
                if (!_dispatcher.CheckAccess())
                {
                    _dispatcher.Post(() => UpdatePortsDisplay());
                    return;
                }
                
                if (_currentStatistics?.TopPorts == null)
                {
                    // TopPortsByBytesDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>();
                    // TopPortsByPacketsDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>();
                    return;
                }
                
                // Top Ports by Bytes (10 or 25)
                var portsByBytes = _currentStatistics.TopPorts
                    .OrderByDescending(p => p.ByteCount)
                    .Take(PortTableDisplayCount)
                    .Select(p => new TopPortViewModel
                    {
                        Port = p.Port,
                        Protocol = p.Protocol,
                        ByteCount = p.ByteCount,
                        PacketCount = p.PacketCount,
                        ServiceName = GetServiceName(p.Port),
                        ByteCountFormatted = Core.Utilities.NumberFormatter.FormatBytes(p.ByteCount),
                        PacketCountFormatted = $"{p.PacketCount:N0}",
                        Percentage = (p.ByteCount * 100.0) / (_currentStatistics.TotalBytes > 0 ? _currentStatistics.TotalBytes : 1)
                    })
                    .ToList();
                
                // Top Ports by Packets (10 or 25)
                var portsByPackets = _currentStatistics.TopPorts
                    .OrderByDescending(p => p.PacketCount)
                    .Take(PortTableDisplayCount)
                    .Select(p => new TopPortViewModel
                    {
                        Port = p.Port,
                        Protocol = p.Protocol,
                        ByteCount = p.ByteCount,
                        PacketCount = p.PacketCount,
                        ServiceName = GetServiceName(p.Port),
                        ByteCountFormatted = Core.Utilities.NumberFormatter.FormatBytes(p.ByteCount),
                        PacketCountFormatted = $"{p.PacketCount:N0}",
                        Percentage = (p.PacketCount * 100.0) / (_currentStatistics.TotalPackets > 0 ? _currentStatistics.TotalPackets : 1)
                    })
                    .ToList();
                
                // TopPortsByBytesDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>(portsByBytes);
                // TopPortsByPacketsDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>(portsByPackets);
                
                // Update extended collections with ranking after setting display collections
                UpdateExtendedCollections();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating ports display: {ex.Message}");
                DebugLogger.Log($"[DashboardViewModel] Stack trace: {ex.StackTrace}");
                // TopPortsByBytesDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>();
                // TopPortsByPacketsDisplay = new ObservableCollection  // Now managed by Statistics component<TopPortViewModel>();
            }
        }
        
        private void UpdatePortActivityTimeline()
        {
            var startTime = DateTime.Now;
            try
            {
                // Initialize Port Activity Timeline Axes
                PortActivityXAxes = new Axis[]
                {
                    new Axis
                    {
                        Labeler = value =>
                        {
                            try
                            {
                                var ticks = (long)value;
                                // Check if ticks is within valid DateTime range
                                if (ticks <= 0 || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                                {
                                    return "";
                                }
                                // Display timestamps (data is already in local time from TSharkParser)
                                return new DateTime(ticks).ToString("HH:mm:ss");
                            }
                            catch (Exception ex)
                            {
                                DebugLogger.Log($"[DashboardViewModel] PortActivity XAxis labeler error: {ex.Message}");
                                return "";
                            }
                        },
                        LabelsRotation = 45,
                        UnitWidth = TimeSpan.FromMinutes(5).Ticks,
                        MinStep = TimeSpan.FromMinutes(5).Ticks,
                        TextSize = 10,
                        LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E"))),
                        SeparatorsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("BorderSubtle", "#21262D")))
                    }
                };

                // LINEAR scale - show actual packet/byte rates without logarithmic transformation
                PortActivityYAxes = new Axis[]
                {
                    new Axis
                    {
                        Name = ShowPortActivityAsThroughput ? "Throughput/s" : "Packets/s",
                        Labeler = value => {
                            if (value <= 0) return "0";
                            if (ShowPortActivityAsThroughput)
                                return FormatBytesPerSecond((long)value);
                            return value >= 1000000 ? $"{value/1000000:F0}M" :
                                   value >= 1000 ? $"{value/1000:F0}K" : $"{value:F0}";
                        },
                        TextSize = 10,
                        MinLimit = 0,
                        NamePaint = new SolidColorPaint(SKColor.Parse(ShowPortActivityAsThroughput ? ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981") : ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"))),
                        LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E"))),
                        SeparatorsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("BorderSubtle", "#21262D")))
                    }
                };

                // PRESERVE: Extract existing highlight series before creating new collection
                var existingHighlights = PortActivitySeries?
                    .Where(s => s.Name == "Highlight" || s.Name == "VerticalLine")
                    .ToList() ?? new List<ISeries>();

                // FIX: Always create NEW collection to ensure property change fires
                var newSeries = new ObservableCollection<ISeries>();

                if (_currentStatistics?.TopPorts != null)
                {
                    // Take top ports based on current display setting (5 or 10 for timeline)
                    var displayCount = PortTimelineDisplayCount;
                    var topPorts = _currentStatistics.TopPorts
                        .OrderByDescending(p => ShowPortActivityAsThroughput ? p.ByteCount : p.PacketCount)
                        .Take(displayCount)
                        .ToList();

                    // DIAGNOSTIC: Log which ports are being displayed
                    DebugLogger.Log($"[DashboardViewModel] UpdatePortActivityTimeline - Top {displayCount} ports:");
                    for (int i = 0; i < topPorts.Count; i++)
                    {
                        var port = topPorts[i];
                        DebugLogger.Log($"  [{i}] Port {port.Port}: {port.PacketCount:N0} packets, {port.ByteCount:N0} bytes");
                    }

                    var colors = new[] {
                        ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"),
                        ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
                        ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"),
                        ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"),
                        ThemeColorHelper.GetColorHex("AccentPurple", "#8B5CF6"),
                        ThemeColorHelper.GetColorHex("AccentCyan", "#06B6D4"),
                        ThemeColorHelper.GetColorHex("AccentPink", "#EC4899"),
                        ThemeColorHelper.GetColorHex("ColorOrange", "#F97316"),
                        ThemeColorHelper.GetColorHex("ColorLime", "#84CC16"),
                        ThemeColorHelper.GetColorHex("AccentIndigo", "#6366F1")
                    };

                    // Limit legend entries to top 3 ports to reduce visual clutter
                    const int MaxLegendEntries = 3;

                    // Create all series fresh to ensure View PropertyChanged fires
                    for (int i = 0; i < topPorts.Count && i < colors.Length; i++)
                    {
                        var port = topPorts[i];
                        var color = SKColor.Parse(colors[i]);
                        var points = GeneratePortActivityData(port, i, ShowPortActivityAsThroughput);

                        newSeries.Add(new LineSeries<ObservablePoint>
                        {
                            Values = points,
                            Name = $"Port {port.Port} ({GetServiceName(port.Port)})",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(color) { StrokeThickness = 2 },
                            Stroke = new SolidColorPaint(color) { StrokeThickness = 2 },
                            Fill = null, // No fill for cleaner look with many lines
                            LineSmoothness = 0,
                            // Hide from legend if beyond top 3 to reduce visual clutter
                            IsVisibleAtLegend = (i < MaxLegendEntries),
                            YToolTipLabelFormatter = (coordinate) =>
                            {
                                try
                                {
                                    var time = new DateTime((long)coordinate.Coordinate.SecondaryValue);
                                    // Use raw value directly (no logarithmic conversion)
                                    var actualValue = coordinate.Coordinate.PrimaryValue;
                                    var formattedValue = ShowPortActivityAsThroughput
                                        ? FormatBytesPerSecond((long)actualValue)
                                        : $"{actualValue:F0} pkt/s";
                                    return $"Port {port.Port} ({GetServiceName(port.Port)})\n" +
                                           $"Time: {time:HH:mm:ss}\n" +
                                           $"Rate: {formattedValue}";
                                }
                                catch
                                {
                                    return $"Port {port.Port}";
                                }
                            }
                        });
                    }
                }

                // RESTORE: Re-add highlight series to maintain mouse-over state
                foreach (var highlight in existingHighlights)
                {
                    newSeries.Add(highlight);
                }

                // FIX: Always assign NEW collection - this ensures property setter fires and View recaches data
                PortActivitySeries = newSeries;

                var elapsed = (DateTime.Now - startTime).TotalSeconds;
                DebugLogger.Log($"[DashboardViewModel] Port activity timeline updated in {elapsed:F3}s - Mode: {(ShowPortActivityAsThroughput ? "Throughput" : "Packets")}, Series: {newSeries.Count}, Highlights preserved: {existingHighlights.Count}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating port activity timeline: {ex.Message}");
            }
        }

        private string FormatBytesPerSecond(long bytesPerSecond)
        {
            return Core.Utilities.NumberFormatter.FormatBytes(bytesPerSecond) + "/s";
        }
        
        private ObservablePoint[] GeneratePortActivityData(PortStatistics port, int index, bool showThroughput)
        {
            // Use actual PCAP capture timestamps from statistics
            var points = new List<ObservablePoint>();

            // Get capture time range from statistics (keep as UTC, labeler will convert for display)
            var captureStart = _currentStatistics?.FirstPacketTime ?? DateTime.UtcNow.AddMinutes(-10);
            var captureEnd = _currentStatistics?.LastPacketTime ?? DateTime.UtcNow;
            var captureRange = (captureEnd - captureStart).TotalSeconds;

            // DIAGNOSTIC: Log data generation parameters
            var dataType = showThroughput ? "bytes" : "packets";
            var dataValue = showThroughput ? port.ByteCount : port.PacketCount;
            var baseRate = dataValue / 600.0;
            DebugLogger.Log($"  [GeneratePortActivityData] Port {port.Port} (index {index}): {dataType}={dataValue:N0}, baseRate={baseRate:F2}");

            // Use actual capture time as base, with 60 data points across the capture duration
            var baseTime = captureStart;
            var intervalSeconds = Math.Max(1, captureRange / 60); // At least 1 second per point

            for (int i = 0; i < 60; i++) // 60 data points across the capture duration
            {
                var time = baseTime.AddSeconds(i * intervalSeconds);

                if (showThroughput)
                {
                    // Simulate varying throughput rates
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI chart variation visualization, not security
                    var variation = Random.Shared.NextDouble() * 0.5 + 0.75; // 75% to 125% variation
#pragma warning restore CA5394
                    var bytesPerSecond = baseRate * variation * (1 + index * 0.1); // Slight offset per port
                    // Use RAW values (no logarithmic transformation)
                    points.Add(new ObservablePoint(time.Ticks, Math.Max(0, bytesPerSecond)));
                }
                else
                {
                    // Simulate varying packet rates
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI chart variation visualization, not security
                    var variation = Random.Shared.NextDouble() * 0.5 + 0.75; // 75% to 125% variation
#pragma warning restore CA5394
                    var packetsPerSecond = baseRate * variation * (1 + index * 0.1); // Slight offset per port
                    // Use RAW values (no logarithmic transformation)
                    points.Add(new ObservablePoint(time.Ticks, Math.Max(0, packetsPerSecond)));
                }
            }

            // DIAGNOSTIC: Log sample values (first 3 points)
            if (points.Count > 0)
            {
                var sampleValues = string.Join(", ", points.Take(3).Select(p => $"{p.Y:F2}"));
                DebugLogger.Log($"  [GeneratePortActivityData] Port {port.Port}: Sample values: {sampleValues}");
            }

            return points.ToArray();
        }
        
        // Removed UpdatePortPieChart - focusing on activity timeline instead
        
        private void UpdateSourcesDisplay()
        {
            try
            {
                // Ensure we're on UI thread
                if (!_dispatcher.CheckAccess())
                {
                    _dispatcher.Post(() => UpdateSourcesDisplay());
                    return;
                }
                
                var displayCount = OtherTableDisplayCount;
                DebugLogger.Log($"[DashboardViewModel] UpdateSourcesDisplay - displayCount: {displayCount}");
                
                // Update sources by packets
                if (TopSources != null && TopSources.Any())
                {
                    DebugLogger.Log($"[DashboardViewModel] TopSources count: {TopSources.Count}, taking: {displayCount}");
                    
                    // Clear and re-add items to ensure UI updates
                    TopSourcesDisplay.Clear();
                    foreach (var source in TopSources.Take(displayCount))
                    {
                        TopSourcesDisplay.Add(source);
                    }
                    
                    DebugLogger.Log($"[DashboardViewModel] TopSourcesDisplay count: {TopSourcesDisplay.Count}");
                }
                else
                {
                    DebugLogger.Log($"[DashboardViewModel] TopSources is null or empty");
                    TopSourcesDisplay.Clear();
                }
                
                // Update sources by bytes
                if (TopSourcesByBytes != null && TopSourcesByBytes.Any())
                {
                    DebugLogger.Log($"[DashboardViewModel] TopSourcesByBytes count: {TopSourcesByBytes.Count}, taking: {displayCount}");
                    
                    // Clear and re-add items to ensure UI updates
                    TopSourcesByBytesDisplay.Clear();
                    foreach (var source in TopSourcesByBytes.Take(displayCount))
                    {
                        TopSourcesByBytesDisplay.Add(source);
                    }
                    
                    DebugLogger.Log($"[DashboardViewModel] TopSourcesByBytesDisplay count: {TopSourcesByBytesDisplay.Count}");
                }
                else
                {
                    DebugLogger.Log($"[DashboardViewModel] TopSourcesByBytes is null or empty");
                    TopSourcesByBytesDisplay.Clear();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating sources display: {ex.Message}");
            }
        }
        
        private void UpdateDestinationsDisplay()
        {
            try
            {
                // Ensure we're on UI thread
                if (!_dispatcher.CheckAccess())
                {
                    _dispatcher.Post(() => UpdateDestinationsDisplay());
                    return;
                }
                
                var displayCount = OtherTableDisplayCount;
                DebugLogger.Log($"[DashboardViewModel] UpdateDestinationsDisplay - displayCount: {displayCount}");
                
                // Update destinations by packets
                if (TopDestinations != null && TopDestinations.Any())
                {
                    DebugLogger.Log($"[DashboardViewModel] TopDestinations count: {TopDestinations.Count}, taking: {displayCount}");
                    
                    // Clear and re-add items to ensure UI updates
                    TopDestinationsDisplay.Clear();
                    foreach (var dest in TopDestinations.Take(displayCount))
                    {
                        TopDestinationsDisplay.Add(dest);
                    }
                    
                    DebugLogger.Log($"[DashboardViewModel] TopDestinationsDisplay count: {TopDestinationsDisplay.Count}");
                }
                else
                {
                    DebugLogger.Log($"[DashboardViewModel] TopDestinations is null or empty");
                    TopDestinationsDisplay.Clear();
                }
                
                // Update destinations by bytes
                if (TopDestinationsByBytes != null && TopDestinationsByBytes.Any())
                {
                    DebugLogger.Log($"[DashboardViewModel] TopDestinationsByBytes count: {TopDestinationsByBytes.Count}, taking: {displayCount}");
                    
                    // Clear and re-add items to ensure UI updates
                    TopDestinationsByBytesDisplay.Clear();
                    foreach (var dest in TopDestinationsByBytes.Take(displayCount))
                    {
                        TopDestinationsByBytesDisplay.Add(dest);
                    }
                    
                    DebugLogger.Log($"[DashboardViewModel] TopDestinationsByBytesDisplay count: {TopDestinationsByBytesDisplay.Count}");
                }
                else
                {
                    DebugLogger.Log($"[DashboardViewModel] TopDestinationsByBytes is null or empty");
                    TopDestinationsByBytesDisplay.Clear();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error updating destinations display: {ex.Message}");
            }
        }
    }
}
