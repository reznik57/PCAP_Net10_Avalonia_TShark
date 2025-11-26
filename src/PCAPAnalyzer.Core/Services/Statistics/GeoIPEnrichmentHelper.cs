using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// GeoIP enrichment helpers for statistics computation.
    /// Extracted from StatisticsService to reduce file size.
    /// </summary>
    internal static class GeoIPEnrichmentHelper
    {
        public static List<PacketInfo> SamplePackets(List<PacketInfo> packets, int maxSamples)
        {
            if (packets.Count <= maxSamples)
                return packets;

            var result = new List<PacketInfo>(maxSamples);
            var step = packets.Count / maxSamples;

            for (int i = 0; i < maxSamples; i++)
            {
                result.Add(packets[i * step]);
            }

            return result;
        }

        public static async Task UpdateEndpointCountriesAsync(
            List<EndpointStatistics> endpoints,
            IGeoIPService geoIPService)
        {
            if (endpoints == null || geoIPService == null) return;

            var tasks = endpoints.Select(async endpoint =>
            {
                if (geoIPService.IsPublicIP(endpoint.Address))
                {
                    var location = await geoIPService.GetLocationAsync(endpoint.Address);
                    if (location != null)
                    {
                        endpoint.Country = location.CountryName;
                        endpoint.CountryCode = location.CountryCode;
                        endpoint.City = location.City;
                        endpoint.IsHighRisk = geoIPService.IsHighRiskCountry(location.CountryCode);
                    }
                }
                else
                {
                    endpoint.Country = "Private Network";
                    endpoint.CountryCode = "Local";
                    endpoint.City = "Internal";
                    endpoint.IsHighRisk = false;
                }
            }).ToList();

            await Task.WhenAll(tasks);
        }

        public static int ExtractUniqueIPs(List<PacketInfo> packets)
        {
            var uniqueIPs = new HashSet<string>();
            foreach (var packet in packets)
            {
                if (!string.IsNullOrEmpty(packet.SourceIP))
                    uniqueIPs.Add(packet.SourceIP);
                if (!string.IsNullOrEmpty(packet.DestinationIP))
                    uniqueIPs.Add(packet.DestinationIP);
            }
            return uniqueIPs.Count;
        }

        public static void ReportInitialProgress(IProgress<AnalysisProgress>? progress, int totalUniqueIPs)
        {
            progress?.Report(new AnalysisProgress
            {
                Phase = "Analyzing Data",
                Percent = 50,
                Detail = "Enriching with geographic data...",
                SubPhase = "GeoIP Lookups",
                UniqueIPsProcessed = 0,
                TotalUniqueIPs = totalUniqueIPs
            });
        }

        public static async Task UpdateConversationCountriesAsync(
            List<ConversationStatistics> conversations,
            IGeoIPService geoIPService)
        {
            if (conversations == null || geoIPService == null) return;

            var tasks = conversations.Select(async conversation =>
            {
                if (geoIPService.IsPublicIP(conversation.SourceAddress))
                {
                    var srcLocation = await geoIPService.GetLocationAsync(conversation.SourceAddress);
                    if (srcLocation != null)
                    {
                        conversation.SourceCountry = srcLocation.CountryName;
                    }
                }
                else
                {
                    conversation.SourceCountry = "Private Network";
                }

                if (geoIPService.IsPublicIP(conversation.DestinationAddress))
                {
                    var dstLocation = await geoIPService.GetLocationAsync(conversation.DestinationAddress);
                    if (dstLocation != null)
                    {
                        conversation.DestinationCountry = dstLocation.CountryName;
                    }
                }
                else
                {
                    conversation.DestinationCountry = "Private Network";
                }

                conversation.IsCrossBorder = conversation.SourceCountry != conversation.DestinationCountry;
                conversation.IsHighRisk = (geoIPService.IsPublicIP(conversation.SourceAddress) &&
                                          geoIPService.IsHighRiskCountry(conversation.SourceCountry)) ||
                                         (geoIPService.IsPublicIP(conversation.DestinationAddress) &&
                                          geoIPService.IsHighRiskCountry(conversation.DestinationCountry));
            }).ToList();

            await Task.WhenAll(tasks);
        }
    }
}
