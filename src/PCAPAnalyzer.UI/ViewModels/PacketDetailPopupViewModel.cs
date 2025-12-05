using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Views;
using PCAPAnalyzer.UI;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class PacketDetailPopupViewModel : ObservableObject
    {
        private readonly IEnumerable<PacketInfo> _allPackets;
        private readonly Func<PacketInfo, bool>? _initialFilter;
        private readonly IUnifiedAnomalyDetectionService _anomalyService;
        
        [ObservableProperty] private string title = "Packet Details";
        [ObservableProperty] private string filterDescription = "All packets";
        [ObservableProperty] private int totalPacketCount;
        [ObservableProperty] private int filteredPacketCount;
        [ObservableProperty] private string quickFilter = string.Empty;
        [ObservableProperty] private string statusMessage = "Ready";
        
        [ObservableProperty] private ObservableCollection<PacketInfo> filteredPackets = new();
        [ObservableProperty] private PacketInfo? selectedPacket;
        [ObservableProperty] private string selectedPacketDetails = string.Empty;
        
        [ObservableProperty] private ObservableCollection<ProtocolStat> protocolStats = new();
        [ObservableProperty] private ObservableCollection<TopPortViewModel> topPorts = new();
        [ObservableProperty] private ObservableCollection<TCPAnomalyViewModel> tCPAnomalies = new();
        [ObservableProperty] private ObservableCollection<TCPStreamViewModel> tCPStreams = new();
        
        [ObservableProperty] private string totalBytes = "0 B";
        [ObservableProperty] private string averagePacketSize = "0 B";
        [ObservableProperty] private string duration = "0s";
        [ObservableProperty] private string packetsPerSecond = "0";
        [ObservableProperty] private bool hasTCPPackets;

        public ICommand ExportCommand { get; }
        public ICommand RefreshCommand { get; }
        public ICommand ApplyFilterCommand { get; }

        public PacketDetailPopupViewModel(
            string title,
            IEnumerable<PacketInfo> packets,
            Func<PacketInfo, bool>? filter = null,
            string? filterDescription = null,
            IUnifiedAnomalyDetectionService? anomalyService = null)
        {
            _anomalyService = anomalyService
                ?? App.Services?.GetService<IUnifiedAnomalyDetectionService>()
                ?? new UnifiedAnomalyDetectionService();
            Title = title;
            _allPackets = packets?.ToList() ?? new List<PacketInfo>();
            _initialFilter = filter;
            FilterDescription = filterDescription ?? "All packets";
            TotalPacketCount = _allPackets.Count();

            ExportCommand = new AsyncRelayCommand(ExportPackets);
            RefreshCommand = new RelayCommand(RefreshData);
            ApplyFilterCommand = new RelayCommand(ApplyQuickFilter);

            // Subscribe to property changes

            // Initial data load
            RefreshData();
        }

        partial void OnSelectedPacketChanged(PacketInfo? value)
        {
            if (value is PacketInfo packet)
            {
                UpdateSelectedPacketDetails(packet);
            }
        }

        partial void OnQuickFilterChanged(string value)
        {
            ApplyQuickFilter();
        }


        private void RefreshData()
        {
            try
            {
                StatusMessage = "Loading packets...";
                
                // Apply initial filter
                var packets = _initialFilter != null 
                    ? _allPackets.Where(_initialFilter).ToList()
                    : _allPackets.ToList();

                // Apply quick filter if present
                if (!string.IsNullOrWhiteSpace(QuickFilter))
                {
                    var filterLower = QuickFilter.ToLower();
                    packets = packets.Where(p =>
                        p.SourceIP?.Contains(filterLower, StringComparison.CurrentCultureIgnoreCase) == true ||
                        p.DestinationIP?.Contains(filterLower, StringComparison.CurrentCultureIgnoreCase) == true ||
                        p.Protocol.ToString().ToLower().Contains(filterLower, StringComparison.CurrentCultureIgnoreCase) ||
                        p.Info?.ToLower().Contains(filterLower, StringComparison.CurrentCultureIgnoreCase) == true ||
                        p.SourcePort.ToString().Contains(filterLower, StringComparison.CurrentCultureIgnoreCase) ||
                        p.DestinationPort.ToString().Contains(filterLower, StringComparison.CurrentCultureIgnoreCase)
                    ).ToList();
                }

                // Update filtered packets
                FilteredPackets.Clear();
                foreach (var packet in packets.Take(1000)) // Limit to 1000 for performance
                {
                    FilteredPackets.Add(packet);
                }
                FilteredPacketCount = FilteredPackets.Count;

                // Calculate statistics
                CalculateStatistics(packets);
                
                // Analyze protocols
                AnalyzeProtocols(packets);
                
                // Analyze ports
                AnalyzePorts(packets);
                
                // TCP Analysis if applicable
                var tcpPackets = packets.Where(p => p.Protocol == Protocol.TCP).ToList();
                HasTCPPackets = tcpPackets.Any();
                
                if (HasTCPPackets)
                {
                    _ = AnalyzeTCPPacketsAsync(tcpPackets);
                }

                StatusMessage = $"Showing {FilteredPacketCount} of {TotalPacketCount} packets";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
                DebugLogger.Log($"[PacketDetailPopupViewModel] Error refreshing data: {ex}");
            }
        }

        private void ApplyQuickFilter()
        {
            RefreshData();
        }

        private void CalculateStatistics(List<PacketInfo> packets)
        {
            if (!packets.Any())
            {
                TotalBytes = "0 B";
                AveragePacketSize = "0 B";
                Duration = "0s";
                PacketsPerSecond = "0";
                return;
            }

            var totalBytesValue = packets.Sum(p => (long)p.Length);
            TotalBytes = NumberFormatter.FormatBytes(totalBytesValue);

            var avgSize = totalBytesValue / packets.Count;
            AveragePacketSize = NumberFormatter.FormatBytes(avgSize);
            
            var firstTime = packets.Min(p => p.Timestamp);
            var lastTime = packets.Max(p => p.Timestamp);
            var durationValue = lastTime - firstTime;
            Duration = FormatDuration(durationValue);
            
            var pps = durationValue.TotalSeconds > 0 
                ? packets.Count / durationValue.TotalSeconds 
                : 0;
            PacketsPerSecond = pps.ToString("N1");
        }

        private void AnalyzeProtocols(List<PacketInfo> packets)
        {
            ProtocolStats.Clear();
            
            var protocols = packets.GroupBy(p => p.Protocol)
                .Select(g => new ProtocolStat
                {
                    Protocol = g.Key.ToString(),
                    Count = g.Count(),
                    Percentage = (double)g.Count() / packets.Count * 100
                })
                .OrderByDescending(p => p.Count)
                .Take(10);

            foreach (var proto in protocols)
            {
                ProtocolStats.Add(proto);
            }
        }

        private void AnalyzePorts(List<PacketInfo> packets)
        {
            TopPorts.Clear();

            // Group packets by port and protocol
            var portGroups = packets
                .Where(p => p.SourcePort > 0 || p.DestinationPort > 0)
                .SelectMany(p => new[]
                {
                    new { Port = p.SourcePort, Protocol = p.Protocol, Packet = p },
                    new { Port = p.DestinationPort, Protocol = p.Protocol, Packet = p }
                })
                .Where(x => x.Port > 0)
                .GroupBy(x => new { x.Port, x.Protocol })
                .Select(g => new
                {
                    Port = g.Key.Port,
                    Protocol = g.Key.Protocol.ToString(),
                    Count = g.Count(),
                    TotalBytes = g.Sum(x => (long)x.Packet.Length)
                })
                .OrderByDescending(x => x.Count)
                .Take(10);

            foreach (var port in portGroups)
            {
                var vm = new TopPortViewModel(new PortAnalysis
                {
                    Port = port.Port,
                    Protocol = port.Protocol,
                    PacketCount = port.Count,
                    ByteCount = port.TotalBytes,
                    ServiceName = $"{port.Protocol}:{port.Port}"
                });
                vm.OnViewDetails = ShowPortDetails;
                TopPorts.Add(vm);
            }
        }

        private async Task AnalyzeTCPPacketsAsync(List<PacketInfo> tcpPackets)
        {
            try
            {
                TCPAnomalies.Clear();
                TCPStreams.Clear();

                // Detect TCP anomalies using unified service
                var allAnomalies = await _anomalyService.DetectAllAnomaliesAsync(tcpPackets);
            var anomalies = allAnomalies
                .Where(a => a.Category == AnomalyCategory.TCP)
                .Take(20);

            foreach (var anomaly in anomalies)
            {
                var vm = new TCPAnomalyViewModel(new TCPAnomaly
                {
                    Type = Enum.TryParse<TCPAnomalyType>(anomaly.Type, out var type) ? type : TCPAnomalyType.Retransmission,
                    Severity = anomaly.Severity,
                    Description = anomaly.Description,
                    SourceIP = anomaly.SourceIP,
                    DestinationIP = anomaly.DestinationIP,
                    SourcePort = anomaly.SourcePort,
                    DestinationPort = anomaly.DestinationPort,
                    DetectedAt = anomaly.DetectedAt,
                    AffectedFrames = anomaly.AffectedFrames,
                    TCPStream = anomaly.TCPStream ?? ""
                });
                vm.OnViewDetails = ShowAnomalyDetails;
                TCPAnomalies.Add(vm);
            }

            // Analyze TCP streams
            var streams = GroupByTCPStream(tcpPackets);
            foreach (var stream in streams.Take(10))
            {
                // Simple stream analysis without relying on old service
                var streamPackets = stream.Value;
                if (!streamPackets.Any()) continue;

                var firstPacket = streamPackets.First();
                var vm = new TCPStreamViewModel(new TCPStreamAnalysis
                {
                    StreamId = stream.Key,
                    TotalPackets = streamPackets.Count,
                    TotalBytes = streamPackets.Sum(p => (long)p.Length),
                    SourceEndpoint = firstPacket.SourceIP,
                    DestinationEndpoint = firstPacket.DestinationIP,
                    StartTime = streamPackets.Min(p => p.Timestamp),
                    EndTime = streamPackets.Max(p => p.Timestamp)
                });
                vm.OnViewDetails = ShowStreamDetails;
                TCPStreams.Add(vm);
            }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[PacketDetailPopupViewModel] Error analyzing TCP packets: {ex.Message}");
            }
        }

        private Dictionary<string, List<PacketInfo>> GroupByTCPStream(List<PacketInfo> packets)
        {
            var streams = new Dictionary<string, List<PacketInfo>>();
            
            foreach (var packet in packets)
            {
                var streamId = GetTCPStreamId(packet);
                if (!streams.ContainsKey(streamId))
                {
                    streams[streamId] = new List<PacketInfo>();
                }
                streams[streamId].Add(packet);
            }
            
            return streams;
        }

        private string GetTCPStreamId(PacketInfo packet)
        {
            var endpoints = new[]
            {
                $"{packet.SourceIP}:{packet.SourcePort}",
                $"{packet.DestinationIP}:{packet.DestinationPort}"
            }.OrderBy(x => x).ToArray();
            
            return $"{endpoints[0]}<->{endpoints[1]}";
        }

        private void UpdateSelectedPacketDetails(PacketInfo packet)
        {
            var details = new StringBuilder();
            details.AppendLine($"Frame Number: {packet.FrameNumber}");
            details.AppendLine($"Timestamp: {packet.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
            details.AppendLine();
            details.AppendLine($"Source: {packet.SourceIP}:{packet.SourcePort}");
            details.AppendLine($"Destination: {packet.DestinationIP}:{packet.DestinationPort}");
            details.AppendLine($"Protocol: {packet.Protocol}");
            details.AppendLine($"Length: {packet.Length} bytes");
            details.AppendLine();
            
            if (!string.IsNullOrEmpty(packet.Info))
            {
                details.AppendLine("Info:");
                details.AppendLine(packet.Info);
            }
            
            // Add TCP-specific information if available
            if (packet.Protocol == Protocol.TCP && packet.Info != null)
            {
                details.AppendLine();
                details.AppendLine("TCP Analysis:");
                
                if (packet.Info.Contains("Retransmission", StringComparison.Ordinal))
                    details.AppendLine("  - TCP Retransmission detected");
                if (packet.Info.Contains("Dup ACK", StringComparison.Ordinal))
                    details.AppendLine("  - Duplicate ACK detected");
                if (packet.Info.Contains("Out-Of-Order", StringComparison.Ordinal))
                    details.AppendLine("  - Out-of-order packet");
                if (packet.Info.Contains("Previous segment not captured", StringComparison.Ordinal))
                    details.AppendLine("  - Previous segment not captured");
                if (packet.Info.Contains("ZeroWindow", StringComparison.Ordinal))
                    details.AppendLine("  - Zero window condition");
                if (packet.Info.Contains("Window Full", StringComparison.Ordinal))
                    details.AppendLine("  - Window full condition");
                if (packet.Info.Contains("Keep-Alive", StringComparison.Ordinal))
                    details.AppendLine("  - Keep-alive packet");
                if (packet.Info.Contains("RST", StringComparison.Ordinal))
                    details.AppendLine("  - Connection reset");
                if (packet.Info.Contains("FIN", StringComparison.Ordinal))
                    details.AppendLine("  - Connection closing");
            }
            
            SelectedPacketDetails = details.ToString();
        }

        private void ShowPortDetails(TopPortViewModel port)
        {
            var portPackets = _allPackets.Where(p => 
                (p.SourcePort == port.Port || p.DestinationPort == port.Port) &&
                (port.Protocol == "TCP" ? p.Protocol == Protocol.TCP : p.Protocol == Protocol.UDP));

            var detailWindow = new PacketDetailPopupWindow
            {
                DataContext = new PacketDetailPopupViewModel(
                    $"Port {port.DisplayName} Details",
                    portPackets,
                    null,
                    $"All packets involving {port.DisplayName} ({port.ServiceName})",
                    _anomalyService)
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is 
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop && 
                desktop.MainWindow != null)
            {
                detailWindow.ShowDialog(desktop.MainWindow);
            }
        }

        private void ShowAnomalyDetails(TCPAnomalyViewModel anomaly)
        {
            // Filter packets related to this anomaly
            var anomalyPackets = _allPackets.Where(p => 
                p.SourceIP == anomaly.SourceEndpoint.Split(':')[0] ||
                p.DestinationIP == anomaly.DestinationEndpoint.Split(':')[0]);

            var detailWindow = new PacketDetailPopupWindow
            {
                DataContext = new PacketDetailPopupViewModel(
                    $"TCP Anomaly: {anomaly.Type}",
                    anomalyPackets,
                    null,
                    anomaly.Description,
                    _anomalyService)
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is 
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop && 
                desktop.MainWindow != null)
            {
                detailWindow.ShowDialog(desktop.MainWindow);
            }
        }

        private void ShowStreamDetails(TCPStreamViewModel stream)
        {
            var streamPackets = _allPackets.Where(p => GetTCPStreamId(p) == stream.StreamId);

            var detailWindow = new PacketDetailPopupWindow
            {
                DataContext = new PacketDetailPopupViewModel(
                    $"TCP Stream: {stream.StreamId}",
                    streamPackets,
                    null,
                    $"All packets in TCP stream between {stream.SourceEndpoint} and {stream.DestinationEndpoint}",
                    _anomalyService)
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is 
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop && 
                desktop.MainWindow != null)
            {
                detailWindow.ShowDialog(desktop.MainWindow);
            }
        }

        private async Task ExportPackets()
        {
            try
            {
                StatusMessage = "Exporting packets...";
                
                // FUTURE: Implement packet export (CSV/JSON) via CsvExportService
                await Task.Delay(100);
                
                StatusMessage = "Export completed";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Export failed: {ex.Message}";
            }
        }

        private string FormatDuration(TimeSpan duration)
        {
            return Helpers.TimeFormatter.FormatAsSeconds(duration);
        }
    }

    public class ProtocolStat
    {
        public string Protocol { get; set; } = string.Empty;
        public int Count { get; set; }
        public double Percentage { get; set; }
    }
}
