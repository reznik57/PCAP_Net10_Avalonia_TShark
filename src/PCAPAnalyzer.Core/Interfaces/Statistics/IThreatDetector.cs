using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces.Statistics
{
    /// <summary>
    /// Heuristic-based threat detection service.
    /// Detects common network security threats from packet analysis.
    /// </summary>
    public interface IThreatDetector
    {
        /// <summary>
        /// Detects port scanning activity based on unique port counts and timing.
        /// </summary>
        List<SecurityThreat> DetectPortScanning(List<PacketInfo> packets);

        /// <summary>
        /// Detects usage of unencrypted protocols (Telnet, FTP, HTTP).
        /// </summary>
        List<SecurityThreat> DetectSuspiciousProtocols(List<PacketInfo> packets);

        /// <summary>
        /// Detects anomalous traffic patterns based on packet size distribution.
        /// Uses 3-sigma threshold for outlier detection.
        /// </summary>
        List<SecurityThreat> DetectAnomalousTraffic(List<PacketInfo> packets);

        /// <summary>
        /// Detects potential DDoS attacks based on traffic volume to single destinations.
        /// </summary>
        List<SecurityThreat> DetectPotentialDDoS(List<PacketInfo> packets);
    }
}
