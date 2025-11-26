using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Interfaces.Statistics
{
    /// <summary>
    /// GeoIP enrichment service for adding geographic data to statistics.
    /// </summary>
    public interface IGeoIPEnricher
    {
        /// <summary>
        /// Samples packets for efficient processing of large datasets.
        /// Uses stratified sampling to maintain representativeness.
        /// </summary>
        List<PacketInfo> SamplePackets(List<PacketInfo> packets, int maxSamples);

        /// <summary>
        /// Enriches endpoints with country, city, and risk information.
        /// </summary>
        Task UpdateEndpointCountriesAsync(List<EndpointStatistics> endpoints);

        /// <summary>
        /// Extracts count of unique IP addresses from packets.
        /// </summary>
        int ExtractUniqueIPs(List<PacketInfo> packets);

        /// <summary>
        /// Reports initial progress for GeoIP enrichment phase.
        /// </summary>
        void ReportInitialProgress(IProgress<AnalysisProgress>? progress, int totalUniqueIPs);

        /// <summary>
        /// Enriches conversations with source/destination country and cross-border detection.
        /// </summary>
        Task UpdateConversationCountriesAsync(List<ConversationStatistics> conversations);
    }
}
