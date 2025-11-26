using System;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Event arguments for filter change events.
    /// Used by ITabFilterService and any filter-aware components.
    /// </summary>
    public class FilterChangedEventArgs : EventArgs
    {
        public PacketFilter Filter { get; }
        public FilterAction Action { get; }
        public DateTime Timestamp { get; }

        public FilterChangedEventArgs(PacketFilter filter, FilterAction action)
        {
            Filter = filter;
            Action = action;
            Timestamp = DateTime.Now;
        }
    }

    /// <summary>
    /// Types of filter actions that can occur.
    /// </summary>
    public enum FilterAction
    {
        Applied,
        Cleared,
        Modified
    }

    /// <summary>
    /// Statistics about filter effectiveness on a packet set.
    /// </summary>
    public class FilterStatistics
    {
        public long TotalPackets { get; set; }
        public long FilteredPackets { get; set; }
        public long TotalBytes { get; set; }
        public long FilteredBytes { get; set; }
        public double FilterEfficiency { get; set; }
        public int TotalProtocols { get; set; }
        public int FilteredProtocols { get; set; }
        public int TotalUniqueIPs { get; set; }
        public int FilteredUniqueIPs { get; set; }

        public string TotalBytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
        public string FilteredBytesFormatted => NumberFormatter.FormatBytes(FilteredBytes);
        public string EfficiencyPercentage => $"{FilterEfficiency * 100:F1}%";
    }
}
