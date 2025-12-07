using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    /// <summary>
    /// Extended properties for DashboardViewModel to support improved dashboard display
    /// </summary>
    public partial class DashboardViewModel
    {
        // Extended collections with ranking support (up to 30 entries)
        [ObservableProperty] private ObservableCollection<TopPortViewModelExtended> _topPortsByPacketsExtended = [];
        [ObservableProperty] private ObservableCollection<TopPortViewModelExtended> _topPortsByBytesExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topSourcesExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topSourcesByBytesExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topDestinationsExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topDestinationsByBytesExtended = [];
        [ObservableProperty] private ObservableCollection<ConnectionViewModelExtended> _topConnectionsExtended = [];
        [ObservableProperty] private ObservableCollection<ConnectionViewModelExtended> _topConnectionsByBytesExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topTotalIPsByPacketsExtended = [];
        [ObservableProperty] private ObservableCollection<EndpointViewModelExtended> _topTotalIPsByBytesExtended = [];

        /// <summary>
        /// Update extended collections with ranking information
        /// NOTE: This method now delegates to Statistics component for data access
        /// </summary>
        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Extended collections update requires synchronizing multiple observable collections for ports, sources, destinations, and connections with ranking information")]
        public void UpdateExtendedCollections()
        {
            var startTime = System.DateTime.Now;
            // Update Top Ports by Packets (up to 30)
            TopPortsByPacketsExtended.Clear();
            var portsByPackets = Statistics?.TopPortsByPacketsDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < portsByPackets.Count; i++)
            {
                var port = portsByPackets[i];
                TopPortsByPacketsExtended.Add(new TopPortViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Port = port.Port,
                    Protocol = port.Protocol,
                    ServiceName = port.ServiceName,
                    PacketCount = port.PacketCount,
                    PacketCountFormatted = port.PacketCountFormatted,
                    ByteCount = port.ByteCount,
                    ByteCountFormatted = port.ByteCountFormatted,
                    Percentage = port.Percentage
                });
            }

            // Update Top Ports by Bytes (up to 30)
            TopPortsByBytesExtended.Clear();
            var portsByBytes = Statistics?.TopPortsByBytesDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < portsByBytes.Count; i++)
            {
                var port = portsByBytes[i];
                TopPortsByBytesExtended.Add(new TopPortViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Port = port.Port,
                    Protocol = port.Protocol,
                    ServiceName = port.ServiceName,
                    PacketCount = port.PacketCount,
                    PacketCountFormatted = port.PacketCountFormatted,
                    ByteCount = port.ByteCount,
                    ByteCountFormatted = port.ByteCountFormatted,
                    Percentage = port.Percentage
                });
            }

            // Update Top Sources by Packets (up to 30)
            TopSourcesExtended.Clear();
            var sourcesByPackets = Statistics?.TopSourcesDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < sourcesByPackets.Count; i++)
            {
                var source = sourcesByPackets[i];
                TopSourcesExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Address = source.Address,
                    PacketCount = source.PacketCount,
                    ByteCount = source.ByteCount,
                    Percentage = source.Percentage,
                    Country = source.Country,
                    CountryCode = source.CountryCode
                });
            }

            // Update Top Sources by Bytes (up to 30)
            TopSourcesByBytesExtended.Clear();
            var sourcesByBytes = Statistics?.TopSourcesByBytesDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < sourcesByBytes.Count; i++)
            {
                var source = sourcesByBytes[i];
                TopSourcesByBytesExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Address = source.Address,
                    PacketCount = source.PacketCount,
                    ByteCount = source.ByteCount,
                    Percentage = source.Percentage,
                    Country = source.Country,
                    CountryCode = source.CountryCode
                });
            }

            // Update Top Destinations by Packets (up to 30)
            TopDestinationsExtended.Clear();
            var destsByPackets = Statistics?.TopDestinationsDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < destsByPackets.Count; i++)
            {
                var dest = destsByPackets[i];
                TopDestinationsExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Address = dest.Address,
                    PacketCount = dest.PacketCount,
                    ByteCount = dest.ByteCount,
                    Percentage = dest.Percentage,
                    Country = dest.Country,
                    CountryCode = dest.CountryCode
                });
            }

            // Update Top Destinations by Bytes (up to 30)
            TopDestinationsByBytesExtended.Clear();
            var destsByBytes = Statistics?.TopDestinationsByBytesDisplay?.Take(30).ToList() ?? new();
            for (int i = 0; i < destsByBytes.Count; i++)
            {
                var dest = destsByBytes[i];
                TopDestinationsByBytesExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{i + 1}",
                    Address = dest.Address,
                    PacketCount = dest.PacketCount,
                    ByteCount = dest.ByteCount,
                    Percentage = dest.Percentage,
                    Country = dest.Country,
                    CountryCode = dest.CountryCode
                });
            }

            // Update Top Connections by Packets (up to 30)
            TopConnectionsExtended.Clear();
            var connsByPackets = Statistics?.TopConversations?.Take(30).ToList() ?? new();
            var totalPackets = _currentStatistics?.TotalPackets ?? 1;  // Use total packets from all traffic
            for (int i = 0; i < connsByPackets.Count; i++)
            {
                var conn = connsByPackets[i];
                var percentage = totalPackets > 0 ? (conn.PacketCount * 100.0 / totalPackets) : 0;  // % of TOTAL traffic
                TopConnectionsExtended.Add(new ConnectionViewModelExtended
                {
                    Rank = $"{i + 1}",
                    SourceIP = conn.SourceAddress,
                    SourcePort = conn.SourcePort,
                    DestinationIP = conn.DestinationAddress,
                    DestinationPort = conn.DestinationPort,
                    Protocol = conn.Protocol,
                    PacketCount = conn.PacketCount,
                    ByteCount = conn.ByteCount,
                    Percentage = percentage
                });
            }

            // Update Top Connections by Bytes (up to 30)
            TopConnectionsByBytesExtended.Clear();
            var connsByBytes = Statistics?.TopConversationsByBytes?.Take(30).ToList() ?? new();
            var totalBytes = _currentStatistics?.TotalBytes ?? 1;  // Use total bytes from all traffic
            for (int i = 0; i < connsByBytes.Count; i++)
            {
                var conn = connsByBytes[i];
                var percentage = totalBytes > 0 ? (conn.ByteCount * 100.0 / totalBytes) : 0;  // % of TOTAL traffic
                TopConnectionsByBytesExtended.Add(new ConnectionViewModelExtended
                {
                    Rank = $"{i + 1}",
                    SourceIP = conn.SourceAddress,
                    SourcePort = conn.SourcePort,
                    DestinationIP = conn.DestinationAddress,
                    DestinationPort = conn.DestinationPort,
                    Protocol = conn.Protocol,
                    PacketCount = conn.PacketCount,
                    ByteCount = conn.ByteCount,
                    Percentage = percentage
                });
            }

            // Update Top Total IPs by Packets (up to 30) - directly from Statistics component
            TopTotalIPsByPacketsExtended.Clear();
            var totalIPsByPackets = Statistics?.TopTotalIPsByPacketsExtended?.Take(30).ToList() ?? new();
            for (int i = 0; i < totalIPsByPackets.Count; i++)
            {
                var ip = totalIPsByPackets[i];
                TopTotalIPsByPacketsExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{ip.Rank}",
                    Address = ip.Address,
                    PacketCount = ip.PacketCount,
                    ByteCount = ip.ByteCount,
                    BytesFormatted = ip.BytesFormatted,
                    Percentage = ip.Percentage,
                    Country = ip.Country,
                    CountryCode = ip.CountryCode
                });
            }

            // Update Top Total IPs by Bytes (up to 30) - directly from Statistics component
            TopTotalIPsByBytesExtended.Clear();
            var totalIPsByBytes = Statistics?.TopTotalIPsByBytesExtended?.Take(30).ToList() ?? new();
            for (int i = 0; i < totalIPsByBytes.Count; i++)
            {
                var ip = totalIPsByBytes[i];
                TopTotalIPsByBytesExtended.Add(new EndpointViewModelExtended
                {
                    Rank = $"{ip.Rank}",
                    Address = ip.Address,
                    PacketCount = ip.PacketCount,
                    ByteCount = ip.ByteCount,
                    BytesFormatted = ip.BytesFormatted,
                    Percentage = ip.Percentage,
                    Country = ip.Country,
                    CountryCode = ip.CountryCode
                });
            }

            var elapsed = (System.DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardViewModel] UpdateExtendedCollections completed in {elapsed:F3}s - TotalIPsByPackets: {TopTotalIPsByPacketsExtended.Count}, TotalIPsByBytes: {TopTotalIPsByBytesExtended.Count}");
        }
    }

    /// <summary>
    /// Extended Port View Model with Ranking
    /// </summary>
    public class TopPortViewModelExtended : TopPortViewModel
    {
        public string Rank { get; set; } = "";
    }

    /// <summary>
    /// Extended Endpoint View Model with Ranking
    /// </summary>
    public class EndpointViewModelExtended : EndpointViewModel
    {
        public new string Rank { get; set; } = "";
    }

    /// <summary>
    /// Extended Connection View Model with Ranking
    /// </summary>
    public class ConnectionViewModelExtended
    {
        public string Rank { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double Percentage { get; set; }
    }
}