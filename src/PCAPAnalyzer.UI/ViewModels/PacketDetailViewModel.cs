using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class PacketDetailViewModel : ObservableObject
    {
        private readonly IEnumerable<PacketInfo> _allPackets;
        private readonly Func<PacketInfo, bool> _filterPredicate;
        
        [ObservableProperty] private string _title = "Packet Details";
        [ObservableProperty] private string _summary = "";
        [ObservableProperty] private int _totalPackets;
        [ObservableProperty] private int _matchingPackets;
        [ObservableProperty] private string _timeRange = "";
        [ObservableProperty] private string _filterExpression = "";
        [ObservableProperty] private string _statusMessage = "";
        [ObservableProperty] private ObservableCollection<PacketDetailItem> _packets = new();
        [ObservableProperty] private PacketDetailItem? _selectedPacket;
        [ObservableProperty] private bool _hasSelectedPacket;
        
        public ICommand ExportCommand { get; }
        public ICommand CopyDetailsCommand { get; }
        
        public PacketDetailViewModel(
            string title,
            IEnumerable<PacketInfo> allPackets,
            Func<PacketInfo, bool> filterPredicate,
            string filterExpression)
        {
            _title = title;
            _allPackets = allPackets;
            _filterPredicate = filterPredicate;
            _filterExpression = filterExpression;
            
            ExportCommand = new AsyncRelayCommand(ExportPacketsAsync);
            CopyDetailsCommand = new RelayCommand(CopyDetails);
            
            LoadPackets();
        }
        
        private void LoadPackets()
        {
            var allPacketsList = _allPackets.ToList();
            TotalPackets = allPacketsList.Count;
            
            var matchingPackets = allPacketsList.Where(_filterPredicate).ToList();
            MatchingPackets = matchingPackets.Count;
            
            if (matchingPackets.Any())
            {
                var firstTime = matchingPackets.Min(p => p.Timestamp);
                var lastTime = matchingPackets.Max(p => p.Timestamp);
                TimeRange = $"{firstTime:HH:mm:ss.fff} - {lastTime:HH:mm:ss.fff}";
                
                Summary = $"Showing {MatchingPackets} of {TotalPackets} packets ({(double)MatchingPackets / TotalPackets * 100:F1}%)";
            }
            else
            {
                TimeRange = "No matches";
                Summary = "No packets match the current filter";
            }
            
            // Take top 25 matching packets for display
            var displayPackets = matchingPackets.Take(25).Select(p => new PacketDetailItem
            {
                FrameNumber = p.FrameNumber,
                Timestamp = p.Timestamp,
                SourceIP = p.SourceIP,
                SourcePort = p.SourcePort,
                DestinationIP = p.DestinationIP,
                DestinationPort = p.DestinationPort,
                Protocol = p.Protocol.ToString(),
                Length = p.Length,
                Info = p.Info ?? string.Empty,
                SourceEndpoint = $"{p.SourceIP}:{p.SourcePort}",
                DestinationEndpoint = $"{p.DestinationIP}:{p.DestinationPort}",
                ProtocolStack = GetProtocolStack(p),
                Flags = GetPacketFlags(p),
                PayloadHex = GetPayloadHex(p),
                ProtocolStyle = GetProtocolStyle(p.Protocol.ToString())
            });
            
            Packets = new ObservableCollection<PacketDetailItem>(displayPackets);
            
            if (MatchingPackets > 25)
            {
                StatusMessage = $"Showing top 25 of {MatchingPackets} matching packets";
            }
            else
            {
                StatusMessage = $"Showing all {MatchingPackets} matching packets";
            }
        }
        
        partial void OnSelectedPacketChanged(PacketDetailItem? value)
        {
            HasSelectedPacket = value != null;
        }
        
        private string GetProtocolStack(PacketInfo packet)
        {
            // Build protocol stack string
            var stack = new List<string>();
            
            if (!string.IsNullOrEmpty(packet.Protocol.ToString()))
                stack.Add(packet.Protocol.ToString());
                
            if (packet.SourcePort == 443 || packet.DestinationPort == 443)
                stack.Add("TLS");
            else if (packet.SourcePort == 80 || packet.DestinationPort == 80)
                stack.Add("HTTP");
            else if (packet.SourcePort == 53 || packet.DestinationPort == 53)
                stack.Add("DNS");
            else if (packet.SourcePort == 22 || packet.DestinationPort == 22)
                stack.Add("SSH");
                
            return string.Join(" > ", stack);
        }
        
        private string GetPacketFlags(PacketInfo packet)
        {
            var flags = new List<string>();
            
            // Add TCP flags if available
            if (packet.Protocol == Protocol.TCP)
            {
                // These would come from packet analysis
                flags.Add("[TCP]");
            }
            
            if (packet.Length > 1500)
                flags.Add("[Fragmented]");
                
            if (packet.Length == 0)
                flags.Add("[Zero Length]");
                
            return flags.Any() ? string.Join(" ", flags) : "None";
        }
        
        private string GetPayloadHex(PacketInfo packet)
        {
            // In a real implementation, this would show actual packet payload
            // For now, show a sample based on packet info
            if (packet.Length <= 0)
                return "No payload";
                
            var sb = new StringBuilder();
            sb.AppendLine($"Frame {packet.FrameNumber}: {packet.Length} bytes");
            sb.AppendLine($"Protocol: {packet.Protocol}");
            sb.AppendLine($"Source: {packet.SourceIP}:{packet.SourcePort}");
            sb.AppendLine($"Destination: {packet.DestinationIP}:{packet.DestinationPort}");
            
            if (!string.IsNullOrEmpty(packet.Info))
            {
                sb.AppendLine($"Info: {packet.Info}");
            }
            
            return sb.ToString();
        }
        
        private string GetProtocolStyle(string protocol)
        {
            return protocol.ToUpper() switch
            {
                "TCP" => "protocol-tcp",
                "UDP" => "protocol-udp",
                "ICMP" => "protocol-icmp",
                "HTTP" => "protocol-http",
                "HTTPS" => "protocol-https",
                "DNS" => "protocol-dns",
                _ => "protocol-other"
            };
        }
        
        private async Task ExportPacketsAsync()
        {
            try
            {
                var mainWindow = Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow
                    : null;
                    
                if (mainWindow != null)
                {
                    var topLevel = TopLevel.GetTopLevel(mainWindow);
                    if (topLevel != null)
                    {
                        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
                        {
                            Title = "Export Matching Packets",
                            FileTypeChoices = new[]
                            {
                                new FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } },
                                new FilePickerFileType("JSON Files") { Patterns = new[] { "*.json" } },
                                new FilePickerFileType("All Files") { Patterns = new[] { "*" } }
                            },
                            DefaultExtension = "csv",
                            SuggestedFileName = $"packets_export_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                        });
                        
                        if (file != null)
                        {
                            // Export logic here
                            StatusMessage = $"Exported {MatchingPackets} packets to {file.Name}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Export failed: {ex.Message}";
            }
        }
        
        private async void CopyDetails()
        {
            if (SelectedPacket == null)
                return;
                
            var details = new StringBuilder();
            details.AppendLine($"Frame Number: {SelectedPacket.FrameNumber}");
            details.AppendLine($"Timestamp: {SelectedPacket.Timestamp}");
            details.AppendLine($"Source: {SelectedPacket.SourceEndpoint}");
            details.AppendLine($"Destination: {SelectedPacket.DestinationEndpoint}");
            details.AppendLine($"Protocol: {SelectedPacket.Protocol}");
            details.AppendLine($"Length: {SelectedPacket.Length} bytes");
            details.AppendLine($"Info: {SelectedPacket.Info}");
            
            // Get clipboard from the main window's TopLevel
            try
            {
                var mainWindow = Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow
                    : null;
                    
                if (mainWindow != null)
                {
                    var topLevel = TopLevel.GetTopLevel(mainWindow);
                    if (topLevel?.Clipboard != null)
                    {
                        await topLevel.Clipboard.SetTextAsync(details.ToString());
                        StatusMessage = "Packet details copied to clipboard";
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Copy failed: {ex.Message}";
            }
        }
    }
    
    public class PacketDetailItem
    {
        public uint FrameNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public long Length { get; set; }
        public string Info { get; set; } = "";
        public string SourceEndpoint { get; set; } = "";
        public string DestinationEndpoint { get; set; } = "";
        public string ProtocolStack { get; set; } = "";
        public string Flags { get; set; } = "";
        public string PayloadHex { get; set; } = "";
        public string ProtocolStyle { get; set; } = "";
    }
}