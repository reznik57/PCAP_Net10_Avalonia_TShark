using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.Kernel;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.SkiaSharpView;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.Core.Services;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class DashboardViewModel
    {
        [ObservableProperty] private ChartPopupViewModel? _chartPopupViewModel;
        [ObservableProperty] private bool _isChartPopupOpen;
        [ObservableProperty] private Control? _chartPopupHost;
        
        /// <summary>
        /// Handles click/tap on chart points for Network Traffic chart
        /// </summary>
        [RelayCommand]
        private void OnNetworkTrafficChartPointClicked(ChartPoint point)
        {
            try
            {
                // Get the timestamp from the point
                var timestamp = new DateTime((long)point.Coordinate.PrimaryValue);
                
                // Find packets within this time window (±1 second)
                var windowStart = timestamp.AddSeconds(-1);
                var windowEnd = timestamp.AddSeconds(1);
                
                var windowPackets = CurrentPackets.ToList()?
                    .Where(p => p.Timestamp >= windowStart && p.Timestamp <= windowEnd)
                    .ToList() ?? new List<PacketInfo>();
                
                if (!windowPackets.Any())
                    return;
                
                // Calculate top 10 data for this time window
                var chartData = new ChartPointData
                {
                    Timestamp = timestamp,
                    Value = point.Coordinate.SecondaryValue,
                    Series = "Network Traffic",
                    DisplayValue = NumberFormatter.FormatBytes((long)point.Coordinate.SecondaryValue),
                    PacketCount = windowPackets.Count,
                    ByteCount = windowPackets.Sum(p => (long)p.Length),
                    PacketsPerSecond = windowPackets.Count,
                    BytesPerSecond = windowPackets.Sum(p => (long)p.Length)
                };
                
                // Calculate top 10 ports - O(n) single-pass aggregation
                var portStats = new Dictionary<int, (int Count, long Bytes, string Protocol)>();
                foreach (var p in windowPackets)
                {
                    var seenPorts = new HashSet<int>();
                    if (p.SourcePort > 0)
                    {
                        seenPorts.Add(p.SourcePort);
                        if (portStats.TryGetValue(p.SourcePort, out var s))
                            portStats[p.SourcePort] = (s.Count + 1, s.Bytes + p.Length, s.Protocol);
                        else
                            portStats[p.SourcePort] = (1, p.Length, p.Protocol.ToString());
                    }
                    if (p.DestinationPort > 0 && !seenPorts.Contains(p.DestinationPort))
                    {
                        if (portStats.TryGetValue(p.DestinationPort, out var s))
                            portStats[p.DestinationPort] = (s.Count + 1, s.Bytes + p.Length, s.Protocol);
                        else
                            portStats[p.DestinationPort] = (1, p.Length, p.Protocol.ToString());
                    }
                }
                chartData.TopPorts = portStats
                    .Select(kv => new PortActivityData
                    {
                        Port = kv.Key,
                        Protocol = kv.Value.Protocol,
                        ServiceName = ThreatDisplayHelpers.GetServiceName(kv.Key),
                        PacketCount = kv.Value.Count,
                        ByteCount = kv.Value.Bytes,
                        Percentage = windowPackets.Count > 0 ? (kv.Value.Count * 100.0) / windowPackets.Count : 0
                    })
                    .OrderByDescending(p => p.ByteCount)
                    .Take(10)
                    .ToList();
                
                // Calculate top 10 source IPs
                chartData.TopSourceIPs = windowPackets
                    .GroupBy(p => p.SourceIP)
                    .Select(g => new IPAddressData
                    {
                        Address = g.Key,
                        Country = "Unknown", // Would need GeoIP lookup
                        IsInternal = NetworkFilterHelper.IsRFC1918(g.Key),
                        PacketCount = g.Count(),
                        ByteCount = g.Sum(p => (long)p.Length),
                        Percentage = (g.Count() * 100.0) / windowPackets.Count
                    })
                    .OrderByDescending(ip => ip.ByteCount)
                    .Take(10)
                    .ToList();
                
                // Calculate top 10 destination IPs
                chartData.TopDestinationIPs = windowPackets
                    .GroupBy(p => p.DestinationIP)
                    .Select(g => new IPAddressData
                    {
                        Address = g.Key,
                        Country = "Unknown", // Would need GeoIP lookup
                        IsInternal = NetworkFilterHelper.IsRFC1918(g.Key),
                        PacketCount = g.Count(),
                        ByteCount = g.Sum(p => (long)p.Length),
                        Percentage = (g.Count() * 100.0) / windowPackets.Count
                    })
                    .OrderByDescending(ip => ip.ByteCount)
                    .Take(10)
                    .ToList();
                
                // Show popup with data
                ShowChartDataPopup(chartData);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error handling chart point click: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Handles click/tap on chart points for Port Activity Timeline
        /// </summary>
        [RelayCommand]
        private void OnPortActivityChartPointClicked(ChartPoint point)
        {
            try
            {
                // Similar to network traffic but focused on port-specific data
                var timestamp = new DateTime((long)point.Coordinate.PrimaryValue);
                var windowStart = timestamp.AddSeconds(-1);
                var windowEnd = timestamp.AddSeconds(1);
                
                var windowPackets = CurrentPackets.ToList()?
                    .Where(p => p.Timestamp >= windowStart && p.Timestamp <= windowEnd)
                    .ToList() ?? new List<PacketInfo>();
                
                if (!windowPackets.Any())
                    return;
                
                var chartData = new ChartPointData
                {
                    Timestamp = timestamp,
                    Value = point.Coordinate.SecondaryValue,
                    Series = point.Context.Series?.Name ?? "Port Activity",
                    DisplayValue = ShowPortActivityAsThroughput
                        ? NumberFormatter.FormatBytes((long)point.Coordinate.SecondaryValue) + "/s"
                        : $"{point.Coordinate.SecondaryValue:F0} pkt/s",
                    PacketCount = windowPackets.Count,
                    ByteCount = windowPackets.Sum(p => (long)p.Length),
                    PacketsPerSecond = windowPackets.Count,
                    BytesPerSecond = windowPackets.Sum(p => (long)p.Length)
                };
                
                // Extract port from series name if available
                var seriesName = point.Context.Series?.Name ?? "";
                var portMatch = System.Text.RegularExpressions.Regex.Match(seriesName, @"Port (\d+)");
                if (portMatch.Success && int.TryParse(portMatch.Groups[1].Value, out var specificPort))
                {
                    // Filter packets for this specific port
                    windowPackets = windowPackets
                        .Where(p => p.SourcePort == specificPort || p.DestinationPort == specificPort)
                        .ToList();
                }
                
                // Calculate detailed port data - O(n) single-pass aggregation
                var detailedPortStats = new Dictionary<int, (int Count, long Bytes, string Protocol)>();
                foreach (var p in windowPackets)
                {
                    var seenPorts = new HashSet<int>();
                    if (p.SourcePort > 0)
                    {
                        seenPorts.Add(p.SourcePort);
                        if (detailedPortStats.TryGetValue(p.SourcePort, out var s))
                            detailedPortStats[p.SourcePort] = (s.Count + 1, s.Bytes + p.Length, s.Protocol);
                        else
                            detailedPortStats[p.SourcePort] = (1, p.Length, p.Protocol.ToString());
                    }
                    if (p.DestinationPort > 0 && !seenPorts.Contains(p.DestinationPort))
                    {
                        if (detailedPortStats.TryGetValue(p.DestinationPort, out var s))
                            detailedPortStats[p.DestinationPort] = (s.Count + 1, s.Bytes + p.Length, s.Protocol);
                        else
                            detailedPortStats[p.DestinationPort] = (1, p.Length, p.Protocol.ToString());
                    }
                }
                chartData.TopPorts = detailedPortStats
                    .Select(kv => new PortActivityData
                    {
                        Port = kv.Key,
                        Protocol = kv.Value.Protocol,
                        ServiceName = ThreatDisplayHelpers.GetServiceName(kv.Key),
                        PacketCount = kv.Value.Count,
                        ByteCount = kv.Value.Bytes,
                        Percentage = windowPackets.Count > 0 ? (kv.Value.Count * 100.0) / windowPackets.Count : 0
                    })
                    .OrderByDescending(p => ShowPortActivityAsThroughput ? p.ByteCount : p.PacketCount)
                    .Take(10)
                    .ToList();
                
                // Calculate IPs associated with these ports
                chartData.TopSourceIPs = windowPackets
                    .GroupBy(p => p.SourceIP)
                    .Select(g => new IPAddressData
                    {
                        Address = g.Key,
                        Country = "Unknown",
                        IsInternal = NetworkFilterHelper.IsRFC1918(g.Key),
                        PacketCount = g.Count(),
                        ByteCount = g.Sum(p => (long)p.Length),
                        Percentage = (g.Count() * 100.0) / windowPackets.Count
                    })
                    .OrderByDescending(ip => ip.ByteCount)
                    .Take(10)
                    .ToList();
                
                chartData.TopDestinationIPs = windowPackets
                    .GroupBy(p => p.DestinationIP)
                    .Select(g => new IPAddressData
                    {
                        Address = g.Key,
                        Country = "Unknown",
                        IsInternal = NetworkFilterHelper.IsRFC1918(g.Key),
                        PacketCount = g.Count(),
                        ByteCount = g.Sum(p => (long)p.Length),
                        Percentage = (g.Count() * 100.0) / windowPackets.Count
                    })
                    .OrderByDescending(ip => ip.ByteCount)
                    .Take(10)
                    .ToList();
                
                ShowChartDataPopup(chartData);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardViewModel] Error handling port activity chart point click: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Shows the chart data popup with the given data
        /// </summary>
        private void ShowChartDataPopup(ChartPointData data)
        {
            ChartPopupViewModel = new ChartPopupViewModel
            {
                PointData = data
            };
            
            ChartPopupViewModel.CloseCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
            {
                IsChartPopupOpen = false;
                ChartPopupViewModel = null;
            });
            
            IsChartPopupOpen = true;
        }
        
        
        /// <summary>
        /// Initialize chart interaction commands
        /// </summary>
        public void InitializeChartInteractions()
        {
            // Commands are automatically generated by the [RelayCommand] attribute
            // This method can be used for additional initialization if needed
            DebugLogger.Log("[DashboardViewModel] Chart interactions initialized");
            // Note: Command generation from RelayCommand attribute may need manual implementation
            // DebugLogger.Log($"[DashboardViewModel] OnNetworkTrafficChartPointClickedCommand: {OnNetworkTrafficChartPointClickedCommand is not null}");
            // DebugLogger.Log($"[DashboardViewModel] OnPortActivityChartPointClickedCommand: {OnPortActivityChartPointClickedCommand is not null}");
        }
        
        /// <summary>
        /// Configuration for making charts interactive
        /// </summary>
        public void ConfigureChartInteractivity()
        {
            // Configure tooltip and interaction settings for charts
            // This would be called when initializing charts
            
            // For Network Traffic Chart
            if (ThroughputSeries is not null)
            {
                foreach (var series in ThroughputSeries)
                {
                    if (series is LineSeries<TimeSeriesDataPoint> lineSeries)
                    {
                        // Enable data point selection
                        lineSeries.DataPadding = new LiveChartsCore.Drawing.LvcPoint(0.5f, 0.5f);
                    }
                }
            }
            
            // For Port Activity Timeline
            if (PortActivitySeries is not null)
            {
                foreach (var series in PortActivitySeries)
                {
                    if (series is LineSeries<LiveChartsCore.Defaults.ObservablePoint> portSeries)
                    {
                        portSeries.DataPadding = new LiveChartsCore.Drawing.LvcPoint(0.5f, 0.5f);
                    }
                }
            }
        }

    }
}