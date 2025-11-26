using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Models
{
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
        public List<PortActivityData> TopPorts { get; set; } = new();
        public List<IPAddressData> TopSourceIPs { get; set; } = new();
        public List<IPAddressData> TopDestinationIPs { get; set; } = new();
        
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
        private ObservableCollection<object> _displayItems = new();
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
        
        public string TimeWindowDisplay => PointData != null 
            ? $"{PointData.Timestamp:HH:mm:ss} - {PointData.Timestamp.AddSeconds(1):HH:mm:ss}"
            : "";
        
        public string TrafficSummary => PointData != null
            ? $"{PointData.PacketCount:N0} packets ({NumberFormatter.FormatBytes(PointData.ByteCount)})"
            : "";

        private void UpdateDisplayItems()
        {
            if (PointData == null)
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