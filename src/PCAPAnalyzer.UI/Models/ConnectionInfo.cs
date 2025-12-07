using System;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Models
{
    public class ConnectionInfo
    {
        public string SourceIP { get; set; } = string.Empty;
        public int SourcePort { get; set; }
        public string DestIP { get; set; } = string.Empty;
        public int DestPort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public long ByteCount { get; set; }
        public long PacketCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        
        // Calculated properties
        public string BytesFormatted => ByteCount.ToFormattedBytes();
        public string Duration => (LastSeen - FirstSeen).ToFormattedSeconds();
        public double TrafficPercentage { get; set; } // Set by ViewModel based on max traffic
        public double Percentage { get; set; } // Set by ViewModel based on total traffic

    }
    
    public class PortInfo
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public long ByteCount { get; set; }
        public long PacketCount { get; set; }
        public double Percentage { get; set; }
        public string ServiceName { get; set; } = string.Empty;

        public string DisplayValue { get; set; } = string.Empty; // Will be set based on view mode

        public string FormatBytes() => ByteCount.ToFormattedBytes();
    }
    
    public class PortTimelinePoint
    {
        public DateTime Timestamp { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public int ActiveConnections { get; set; }
        public double Throughput { get; set; } // KB/s
    }
}