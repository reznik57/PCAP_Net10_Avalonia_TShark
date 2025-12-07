using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces.Statistics
{
    /// <summary>
    /// Pure calculation service for statistics computation.
    /// All methods are synchronous and have no side effects.
    /// </summary>
    public interface IStatisticsCalculator
    {
        /// <summary>
        /// Calculates protocol distribution statistics from packets.
        /// </summary>
        Dictionary<string, ProtocolStatistics> CalculateProtocolStatistics(
            List<PacketInfo> packets,
            IReadOnlyDictionary<string, string> protocolColors);

        /// <summary>
        /// Calculates top endpoints by packet count.
        /// </summary>
        List<EndpointStatistics> CalculateTopEndpoints(List<PacketInfo> packets, bool isSource);

        /// <summary>
        /// Calculates top conversations between endpoint pairs.
        /// </summary>
        (List<ConversationStatistics> TopConversations, int TotalCount) CalculateTopConversations(List<PacketInfo> packets);

        /// <summary>
        /// Calculates top ports with Wireshark-compatible unique packet counting.
        /// </summary>
        (List<PortStatistics> TopPorts, int UniqueCount) CalculateTopPortsWithCount(
            List<PacketInfo> packets,
            IReadOnlyDictionary<int, string> wellKnownPorts);

        /// <summary>
        /// Calculates service-level statistics based on well-known ports.
        /// </summary>
        Dictionary<string, ServiceStatistics> CalculateServiceStatistics(
            List<PacketInfo> packets,
            IReadOnlyDictionary<int, string> wellKnownPorts);

        /// <summary>
        /// Determines if an IP address is in private/internal address space (RFC1918).
        /// </summary>
        bool IsInternalIP(string ipAddress);
    }
}
