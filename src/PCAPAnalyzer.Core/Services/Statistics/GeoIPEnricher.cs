using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// GeoIP enrichment service for adding geographic data to statistics.
    /// Implements IGeoIPEnricher for DI injection and testability.
    /// </summary>
    public class GeoIPEnricher : IGeoIPEnricher
    {
        private readonly IGeoIPService _geoIPService;

        public GeoIPEnricher(IGeoIPService geoIPService)
        {
            _geoIPService = geoIPService ?? throw new ArgumentNullException(nameof(geoIPService));
        }

        public List<PacketInfo> SamplePackets(List<PacketInfo> packets, int maxSamples)
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

        public async Task UpdateEndpointCountriesAsync(List<EndpointStatistics> endpoints)
        {
            if (endpoints is null || _geoIPService is null) return;

            var tasks = endpoints.Select(async endpoint =>
            {
                try
                {
                    if (_geoIPService.IsPublicIP(endpoint.Address))
                    {
                        var location = await _geoIPService.GetLocationAsync(endpoint.Address);
                        if (location is not null)
                        {
                            endpoint.Country = location.CountryName;
                            endpoint.CountryCode = location.CountryCode;
                            endpoint.City = location.City;
                            endpoint.IsHighRisk = _geoIPService.IsHighRiskCountry(location.CountryCode);
                        }
                    }
                    else
                    {
                        endpoint.Country = "Private Network";
                        endpoint.CountryCode = "Local";
                        endpoint.City = "Internal";
                        endpoint.IsHighRisk = false;
                    }
                }
                catch
                {
                    // Continue with partial data on lookup failure
                    endpoint.Country ??= "Unknown";
                    endpoint.CountryCode ??= "??";
                }
            }).ToList();

            await Task.WhenAll(tasks);
        }

        public int ExtractUniqueIPs(List<PacketInfo> packets)
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

        public void ReportInitialProgress(IProgress<AnalysisProgress>? progress, int totalUniqueIPs)
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

        public async Task UpdateConversationCountriesAsync(List<ConversationStatistics> conversations)
        {
            if (conversations is null || _geoIPService is null) return;

            var tasks = conversations.Select(async conversation =>
            {
                try
                {
                    if (_geoIPService.IsPublicIP(conversation.SourceAddress))
                    {
                        var srcLocation = await _geoIPService.GetLocationAsync(conversation.SourceAddress);
                        if (srcLocation is not null)
                        {
                            conversation.SourceCountry = srcLocation.CountryName;
                        }
                    }
                    else
                    {
                        conversation.SourceCountry = "Private Network";
                    }

                    if (_geoIPService.IsPublicIP(conversation.DestinationAddress))
                    {
                        var dstLocation = await _geoIPService.GetLocationAsync(conversation.DestinationAddress);
                        if (dstLocation is not null)
                        {
                            conversation.DestinationCountry = dstLocation.CountryName;
                        }
                    }
                    else
                    {
                        conversation.DestinationCountry = "Private Network";
                    }

                    conversation.IsCrossBorder = conversation.SourceCountry != conversation.DestinationCountry;
                    conversation.IsHighRisk = (_geoIPService.IsPublicIP(conversation.SourceAddress) &&
                                              _geoIPService.IsHighRiskCountry(conversation.SourceCountry ?? "")) ||
                                             (_geoIPService.IsPublicIP(conversation.DestinationAddress) &&
                                              _geoIPService.IsHighRiskCountry(conversation.DestinationCountry ?? ""));
                }
                catch
                {
                    // Continue with partial data on lookup failure
                    conversation.SourceCountry ??= "Unknown";
                    conversation.DestinationCountry ??= "Unknown";
                }
            }).ToList();

            await Task.WhenAll(tasks);
        }
    }
}
