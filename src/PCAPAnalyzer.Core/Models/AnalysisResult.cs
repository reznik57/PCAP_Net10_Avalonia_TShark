using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    /// <summary>
    /// Complete analysis result container - immutable after creation.
    /// Contains all data for ALL tabs (Dashboard, Threats, VoiceQoS, CountryTraffic, etc.).
    /// Designed for session-only caching with aggressive GC on disposal.
    /// </summary>
    public class AnalysisResult
    {
        // ============================================================================
        // CORE PACKET DATA
        // ============================================================================

        /// <summary>
        /// All packets loaded from PCAP file. Memory footprint: ~250 bytes per packet.
        /// For 10M packets: ~2.5GB memory.
        /// </summary>
        public List<PacketInfo> AllPackets { get; init; } = new();

        // ============================================================================
        // COMPREHENSIVE STATISTICS (Dashboard Tab)
        // ============================================================================

        /// <summary>
        /// Complete network statistics including protocol breakdown, top talkers,
        /// conversations, GeoIP data (CountryStatistics), traffic flows, etc.
        /// </summary>
        public NetworkStatistics Statistics { get; init; } = new();

        // ============================================================================
        // SECURITY THREATS (Threats Tab)
        // ============================================================================

        /// <summary>
        /// All detected security threats from UnifiedAnomalyDetectionService.
        /// Includes insecure ports, anomalies, suspicious traffic patterns.
        /// </summary>
        public List<SecurityThreat> Threats { get; init; } = new();

        // ============================================================================
        // COUNTRY TRAFFIC (CountryTraffic Tab)
        // ============================================================================

        /// <summary>
        /// Per-country traffic statistics with incoming/outgoing breakdown.
        /// Key: CountryCode (e.g., "US", "CN"), Value: CountryTrafficStatistics.
        /// </summary>
        public Dictionary<string, CountryTrafficStatistics> CountryTraffic { get; init; } = new();

        /// <summary>
        /// Cross-border traffic flows for map visualization.
        /// </summary>
        public List<TrafficFlowDirection> TrafficFlows { get; init; } = new();

        // ============================================================================
        // VOICEQOS DATA (VoiceQoS Tab)
        // ============================================================================

        /// <summary>
        /// Complete VoiceQoS analysis including QoS traffic, latency, jitter data.
        /// </summary>
        public VoiceQoSAnalysisResult? VoiceQoSData { get; init; }

        /// <summary>
        /// Time-series data for VoiceQoS charts (latency/jitter over time).
        /// </summary>
        public VoiceQoSTimeSeriesData? VoiceQoSTimeSeries { get; init; }

        // ============================================================================
        // METADATA
        // ============================================================================

        /// <summary>
        /// Full path to the analyzed PCAP file.
        /// </summary>
        public string FilePath { get; init; } = "";

        /// <summary>
        /// SHA256 hash of the PCAP file for cache validation.
        /// Used to detect if file changed between sessions.
        /// </summary>
        public string FileHash { get; init; } = "";

        /// <summary>
        /// Timestamp when analysis completed.
        /// </summary>
        public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;

        /// <summary>
        /// Total time taken for complete analysis (all phases).
        /// </summary>
        public TimeSpan AnalysisDuration { get; init; }

        /// <summary>
        /// Total number of packets analyzed.
        /// </summary>
        public long TotalPackets { get; init; }

        /// <summary>
        /// Total bytes across all packets.
        /// </summary>
        public long TotalBytes { get; init; }

        // ============================================================================
        // COMPUTED PROPERTIES
        // ============================================================================

        /// <summary>
        /// Estimates total memory usage in GB for this cached result.
        /// Formula: (packets * 250 bytes + total_bytes) / 1GB
        /// </summary>
        public double EstimatedMemoryGB =>
            (AllPackets.Count * 250.0 + TotalBytes) / (1024.0 * 1024 * 1024);

        /// <summary>
        /// Human-readable summary for logging.
        /// </summary>
        public override string ToString()
        {
            return $"AnalysisResult[{System.IO.Path.GetFileName(FilePath)}, " +
                   $"{TotalPackets:N0} packets, {EstimatedMemoryGB:F2}GB, " +
                   $"{Threats.Count} threats, {CountryTraffic.Count} countries]";
        }
    }
}
