using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Models
{
    /// <summary>
    /// Data for a single stream in the popup
    /// </summary>
    public class StreamPopupItem
    {
        public string SourceIP { get; set; } = "";
        public string DestIP { get; set; } = "";
        public string StreamKey { get; set; } = "";
        public int PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public string Color { get; set; } = "#58A6FF";
        public string Protocol { get; set; } = "TCP";

        /// <summary>
        /// Display name with fallback for empty IPs
        /// </summary>
        public string DisplayName
        {
            get
            {
                if (string.IsNullOrEmpty(SourceIP) && string.IsNullOrEmpty(DestIP))
                    return StreamKey ?? "Unknown Stream";
                if (string.IsNullOrEmpty(SourceIP))
                    return $"? → {DestIP}";
                if (string.IsNullOrEmpty(DestIP))
                    return $"{SourceIP} → ?";
                return $"{SourceIP} → {DestIP}";
            }
        }

        public string DisplayBytes => NumberFormatter.FormatBytes(ByteCount);

        /// <summary>
        /// Returns true if this stream has valid data to display
        /// </summary>
        public bool IsValid => PacketCount > 0 && (!string.IsNullOrEmpty(SourceIP) || !string.IsNullOrEmpty(DestIP));
    }

    /// <summary>
    /// View model for the Packets Over Time chart popup
    /// </summary>
    public class StreamChartPopupViewModel : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
    {
        private DateTime _timestamp;
        private int _totalPackets;
        private long _totalBytes;
        private ObservableCollection<StreamPopupItem> _streams = [];
        private CommunityToolkit.Mvvm.Input.IRelayCommand? _closeCommand;

        public DateTime Timestamp
        {
            get => _timestamp;
            set => SetProperty(ref _timestamp, value);
        }

        public int TotalPackets
        {
            get => _totalPackets;
            set => SetProperty(ref _totalPackets, value);
        }

        public long TotalBytes
        {
            get => _totalBytes;
            set => SetProperty(ref _totalBytes, value);
        }

        public ObservableCollection<StreamPopupItem> Streams
        {
            get => _streams;
            set => SetProperty(ref _streams, value);
        }

        public CommunityToolkit.Mvvm.Input.IRelayCommand? CloseCommand
        {
            get => _closeCommand;
            set => SetProperty(ref _closeCommand, value);
        }

        private CommunityToolkit.Mvvm.Input.IRelayCommand? _copyCommand;
        public CommunityToolkit.Mvvm.Input.IRelayCommand? CopyCommand
        {
            get => _copyCommand;
            set => SetProperty(ref _copyCommand, value);
        }

        public string TimeDisplay => Timestamp != default ? Timestamp.ToString("HH:mm:ss") : "";

        /// <summary>
        /// Display string for Total Bytes card (just bytes, no packet count)
        /// </summary>
        public string TotalBytesDisplay => NumberFormatter.FormatBytes(TotalBytes);

        /// <summary>
        /// Legacy display string (for backward compatibility if needed)
        /// </summary>
        public string TotalDisplay => NumberFormatter.FormatBytes(TotalBytes);

        /// <summary>
        /// Generates clipboard text for copy operation
        /// </summary>
        public string GetClipboardText()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Stream Analysis - {TimeDisplay}");
            sb.AppendLine($"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            sb.AppendLine($"Total Packets: {TotalPackets:N0}");
            sb.AppendLine($"Total Bytes: {TotalBytesDisplay}");
            sb.AppendLine();
            sb.AppendLine("Top Streams:");
            foreach (var stream in Streams.Where(s => s.IsValid))
            {
                sb.AppendLine($"  {stream.DisplayName} [{stream.Protocol}]");
                sb.AppendLine($"    Packets: {stream.PacketCount:N0} ({stream.Percentage:F1}%)");
                sb.AppendLine($"    Bytes: {stream.DisplayBytes}");
            }
            return sb.ToString();
        }
    }

    /// <summary>
    /// Represents data for a specific point in time on a chart
    /// </summary>
    public class ChartPointData
    {
        public DateTime Timestamp { get; set; }
        public double Value { get; set; }
        public string Series { get; set; } = string.Empty;
        public string DisplayValue { get; set; } = string.Empty;

        // Data available at this point in time
        public List<PortActivityData> TopPorts { get; set; } = [];
        public List<IPAddressData> TopSourceIPs { get; set; } = [];
        public List<IPAddressData> TopDestinationIPs { get; set; } = [];
        
        // Statistics for this time window
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double PacketsPerSecond { get; set; }
        public double BytesPerSecond { get; set; }
    }
    
    /// <summary>
    /// Port activity data for a specific time window
    /// </summary>
    public class PortActivityData
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string ServiceName { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public string DisplayBytes => NumberFormatter.FormatBytes(ByteCount);
    }
    
    /// <summary>
    /// IP address activity data for a specific time window
    /// </summary>
    public class IPAddressData
    {
        public string Address { get; set; } = string.Empty;
        public string Country { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public bool IsInternal { get; set; }
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
        public string DisplayBytes => NumberFormatter.FormatBytes(ByteCount);
    }
    
    /// <summary>
    /// View model for the interactive chart popup
    /// </summary>
    public class ChartPopupViewModel : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
    {
        private ChartPointData? _pointData;
        private string _selectedDataType = "Ports";
        private ObservableCollection<object> _displayItems = [];
        private CommunityToolkit.Mvvm.Input.IRelayCommand? _closeCommand;
        
        public ChartPointData? PointData
        {
            get => _pointData;
            set
            {
                if (SetProperty(ref _pointData, value))
                {
                    UpdateDisplayItems();
                }
            }
        }
        
        public string SelectedDataType
        {
            get => _selectedDataType;
            set
            {
                if (SetProperty(ref _selectedDataType, value))
                {
                    UpdateDisplayItems();
                }
            }
        }
        
        public ObservableCollection<object> DisplayItems
        {
            get => _displayItems;
            set => SetProperty(ref _displayItems, value);
        }
        
        public CommunityToolkit.Mvvm.Input.IRelayCommand? CloseCommand
        {
            get => _closeCommand;
            set => SetProperty(ref _closeCommand, value);
        }
        
        public ObservableCollection<string> DataTypes { get; } = new()
        {
            "Ports",
            "Source IPs",
            "Destination IPs"
        };
        
        public string TimeWindowDisplay => PointData is not null 
            ? $"{PointData.Timestamp:HH:mm:ss} - {PointData.Timestamp.AddSeconds(1):HH:mm:ss}"
            : "";
        
        public string TrafficSummary => PointData is not null
            ? $"{PointData.PacketCount:N0} packets ({NumberFormatter.FormatBytes(PointData.ByteCount)})"
            : "";

        private void UpdateDisplayItems()
        {
            if (PointData is null)
            {
                DisplayItems.Clear();
                return;
            }
            
            var items = new ObservableCollection<object>();
            
            switch (SelectedDataType)
            {
                case "Ports":
                    foreach (var port in PointData.TopPorts)
                        items.Add(port);
                    break;
                    
                case "Source IPs":
                    foreach (var ip in PointData.TopSourceIPs)
                        items.Add(ip);
                    break;
                    
                case "Destination IPs":
                    foreach (var ip in PointData.TopDestinationIPs)
                        items.Add(ip);
                    break;
            }

            DisplayItems = items;
        }
    }
}