using System;
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
        public string BytesFormatted => NumberFormatter.FormatBytes(ByteCount);
        public string Duration => FormatDuration();
        public double TrafficPercentage { get; set; } // Set by ViewModel based on max traffic
        public double Percentage { get; set; } // Set by ViewModel based on total traffic

        private string FormatDuration()
        {
            var duration = LastSeen - FirstSeen;
            return PCAPAnalyzer.UI.Helpers.TimeFormatter.FormatAsSeconds(duration);
        }
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

        public string FormatBytes() => NumberFormatter.FormatBytes(ByteCount);
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