using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces.Statistics;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services.Statistics;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    public interface IStatisticsService
    {
        NetworkStatistics CalculateStatistics(IEnumerable<PacketInfo> packets);
        Task<NetworkStatistics> CalculateStatisticsAsync(IEnumerable<PacketInfo> packets, object? geoIPStage = null, object? flowStage = null);
        Task<NetworkStatistics> EnrichWithGeoAsync(NetworkStatistics statistics, IEnumerable<PacketInfo> packets, IProgress<AnalysisProgress>? progress = null);
        List<TimeSeriesDataPoint> GenerateTimeSeries(IEnumerable<PacketInfo> packets, TimeSpan interval);
        List<SecurityThreat> DetectThreats(IEnumerable<PacketInfo> packets);
        List<ExpertInsight> GenerateInsights(NetworkStatistics stats);
    }

    public class StatisticsService : IStatisticsService
    {
        private readonly IInsecurePortDetector _insecurePortDetector;
        private readonly IGeoIPService _geoIPService;
        private readonly IPacketSizeAnalyzer _packetSizeAnalyzer;
        private readonly IStatisticsCalculator _statisticsCalculator;
        private readonly IGeoIPEnricher _geoIPEnricher;
        private readonly IThreatDetector _threatDetector;
        private readonly ITimeSeriesGenerator _timeSeriesGenerator;

        private static readonly FrozenDictionary<int, string> WellKnownPorts = new Dictionary<int, string>
        {
            { 20, "FTP Data" }, { 21, "FTP Control" }, { 22, "SSH" }, { 23, "Telnet" },
            { 25, "SMTP" }, { 53, "DNS" }, { 67, "DHCP Server" }, { 68, "DHCP Client" },
            { 80, "HTTP" }, { 110, "POP3" }, { 143, "IMAP" }, { 443, "HTTPS" },
            { 445, "SMB" }, { 3306, "MySQL" }, { 3389, "RDP" }, { 5432, "PostgreSQL" },
            { 6379, "Redis" }, { 8080, "HTTP Alternate" }, { 8443, "HTTPS Alternate" },
            { 27017, "MongoDB" }
        }.ToFrozenDictionary();

        private static readonly FrozenDictionary<string, string> ProtocolColors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "TCP", "#3B82F6" },    // Blue
            { "UDP", "#10B981" },    // Green
            { "ICMP", "#F59E0B" },   // Amber
            { "HTTP", "#8B5CF6" },   // Purple
            { "HTTPS", "#EC4899" },  // Pink
            { "DNS", "#14B8A6" },    // Teal
            { "SSH", "#F97316" },    // Orange
            { "FTP", "#EF4444" },    // Red
            { "SMTP", "#6366F1" },   // Indigo
            { "Other", "#6B7280" }   // Gray
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

        public StatisticsService(
            IGeoIPService geoIPService,
            IStatisticsCalculator statisticsCalculator,
            IGeoIPEnricher geoIPEnricher,
            IThreatDetector threatDetector,
            ITimeSeriesGenerator timeSeriesGenerator,
            IInsecurePortDetector? insecurePortDetector = null,
            IPacketSizeAnalyzer? packetSizeAnalyzer = null)
        {
            _geoIPService = geoIPService ?? throw new ArgumentNullException(nameof(geoIPService));
            _statisticsCalculator = statisticsCalculator ?? throw new ArgumentNullException(nameof(statisticsCalculator));
            _geoIPEnricher = geoIPEnricher ?? throw new ArgumentNullException(nameof(geoIPEnricher));
            _threatDetector = threatDetector ?? throw new ArgumentNullException(nameof(threatDetector));
            _timeSeriesGenerator = timeSeriesGenerator ?? throw new ArgumentNullException(nameof(timeSeriesGenerator));
            _insecurePortDetector = insecurePortDetector ?? new InsecurePortDetector();
            _packetSizeAnalyzer = packetSizeAnalyzer ?? new PacketSizeAnalyzer();
        }

        public NetworkStatistics CalculateStatistics(IEnumerable<PacketInfo> packets)
        {
            if (packets is null)
                return new NetworkStatistics();

            var packetList = packets as List<PacketInfo> ?? packets.ToList();
            if (!packetList.Any())
                return new NetworkStatistics();

            try
            {
                var stats = new NetworkStatistics
                {
                    TotalPackets = packetList.Count,
                    TotalBytes = packetList.Sum(static p => (long)p.Length),
                    FirstPacketTime = packetList.Min(p => p.Timestamp),
                    LastPacketTime = packetList.Max(p => p.Timestamp)
                };

                // Use injected calculator service
                stats.ProtocolStats = _statisticsCalculator.CalculateProtocolStatistics(packetList, ProtocolColors);

                stats.AllUniqueIPs = new HashSet<string>();
                foreach (var packet in packetList)
                {
                    if (!string.IsNullOrEmpty(packet.SourceIP))
                        stats.AllUniqueIPs.Add(packet.SourceIP);
                    if (!string.IsNullOrEmpty(packet.DestinationIP))
                        stats.AllUniqueIPs.Add(packet.DestinationIP);
                }

                stats.TopSources = _statisticsCalculator.CalculateTopEndpoints(packetList, true);
                stats.TopDestinations = _statisticsCalculator.CalculateTopEndpoints(packetList, false);

                var (topConversations, totalConversationCount) = _statisticsCalculator.CalculateTopConversations(packetList);
                stats.TopConversations = topConversations;
                stats.TotalConversationCount = totalConversationCount;

                // Calculate directional stream count (4-tuple) for Packet Analysis tab compatibility
                stats.TotalStreamCount = CalculateDirectionalStreamCount(packetList);

                var (topPorts, uniquePortCount) = _statisticsCalculator.CalculateTopPortsWithCount(packetList, WellKnownPorts);
                stats.TopPorts = topPorts;
                stats.UniquePortCount = uniquePortCount;

                stats.ServiceStats = _statisticsCalculator.CalculateServiceStatistics(packetList, WellKnownPorts);

                // Detect threats first for time series
                stats.DetectedThreats = DetectThreats(packetList);

                // Generate time series with pre-detected threats
                var timeSeries = _timeSeriesGenerator.GenerateTimeSeriesWithMetrics(packetList, TimeSpan.FromSeconds(1), stats.DetectedThreats);
                stats.ThroughputTimeSeries = timeSeries.ThroughputSeries;
                stats.PacketsPerSecondTimeSeries = timeSeries.PacketsSeries;
                stats.AnomaliesPerSecondTimeSeries = timeSeries.AnomaliesSeries;

                stats.ThreatsPerSecondTimeSeries = _timeSeriesGenerator.GenerateTrafficThreatsTimeSeries(
                    packetList,
                    stats.FirstPacketTime,
                    stats.LastPacketTime,
                    TimeSpan.FromSeconds(1));

                stats.PacketSizeDistribution = _packetSizeAnalyzer.CalculateDistribution(packetList);

                return stats;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[StatisticsService] Error calculating statistics: {ex.Message}");
                DebugLogger.Log($"[StatisticsService] Stack trace: {ex.StackTrace}");
                return new NetworkStatistics
                {
                    TotalPackets = packetList.Count,
                    TotalBytes = packetList.Sum(static p => (long)p.Length)
                };
            }
        }

        public async Task<NetworkStatistics> CalculateStatisticsAsync(IEnumerable<PacketInfo> packets, object? geoIPStage = null, object? flowStage = null)
        {
            if (packets is null)
                return await Task.Run(() => CalculateStatistics(Array.Empty<PacketInfo>()));

            var packetCollection = packets as List<PacketInfo> ?? packets.ToList();
            var statsTask = Task.Run(() => CalculateStatistics(packetCollection));

            Task<Dictionary<string, CountryTrafficStatistics>>? countryTask = null;
            Task<List<TrafficFlowDirection>>? flowTask = null;
            Task<List<CountryRiskProfile>>? riskTask = null;

            var stats = await statsTask;

            if (stats.IsGeoIPEnriched)
            {
                DebugLogger.Log($"[StatisticsService] ✓ GeoIP already enriched at {stats.GeoIPEnrichmentTimestamp:yyyy-MM-dd HH:mm:ss} - skipping");
                return stats;
            }

            if (_geoIPService is not null && packetCollection.Count > 0)
            {
                DebugLogger.Log($"[StatisticsService] Starting GeoIP analysis for {packetCollection.Count} packets");

                countryTask = _geoIPService.AnalyzeCountryTrafficAsync(packetCollection, geoIPStage);
                flowTask = _geoIPService.AnalyzeTrafficFlowsAsync(packetCollection, flowStage);
                riskTask = _geoIPService.GetHighRiskCountriesAsync();
            }
            else
            {
                return stats;
            }

            if (countryTask is not null || flowTask is not null || riskTask is not null)
            {
                try
                {
                    var geoTimeoutSeconds = packetCollection.Count switch
                    {
                        > 2_000_000 => 30,
                        > 1_000_000 => 20,
                        > 250_000 => 12,
                        _ => 5
                    };

                    using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(geoTimeoutSeconds));

                    if (countryTask is not null)
                    {
                        stats.CountryStatistics = await countryTask.WaitAsync(cts.Token);
                        if (stats.CountryStatistics is not null)
                        {
                            stats.GeolocatedPackets = stats.CountryStatistics.Values.Sum(c => c.TotalPackets);
                            stats.GeolocatedBytes = stats.CountryStatistics.Values.Sum(c => c.TotalBytes);
                        }
                    }

                    if (flowTask is not null)
                        stats.TrafficFlows = await flowTask.WaitAsync(cts.Token);

                    if (riskTask is not null)
                        stats.HighRiskCountries = await riskTask.WaitAsync(cts.Token);

                    // Quick international vs domestic calculation
                    CalculateInternationalDomestic(packetCollection, stats);

                    // Parallel endpoint enrichment
                    await Task.WhenAll(
                        _geoIPEnricher.UpdateEndpointCountriesAsync(stats.TopSources),
                        _geoIPEnricher.UpdateEndpointCountriesAsync(stats.TopDestinations),
                        _geoIPEnricher.UpdateConversationCountriesAsync(stats.TopConversations)
                    );

                    stats.IsGeoIPEnriched = true;
                    stats.GeoIPEnrichmentTimestamp = DateTime.UtcNow;
                }
                catch (OperationCanceledException)
                {
                    DebugLogger.Log("[StatisticsService] Country detection timed out");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[StatisticsService] Error adding country detection: {ex.Message}");
                }
            }

            return stats;
        }

        public async Task<NetworkStatistics> EnrichWithGeoAsync(NetworkStatistics statistics, IEnumerable<PacketInfo> packets, IProgress<AnalysisProgress>? progress = null)
        {
            if (statistics is null)
                throw new ArgumentNullException(nameof(statistics));

            if (_geoIPService is null)
                return statistics;

            var packetCollection = packets as List<PacketInfo> ?? packets.ToList();
            if (packetCollection.Count == 0)
                return statistics;

            // ✅ FIX: Guard against duplicate GeoIP enrichment (was causing 2x AnalyzeCountryTrafficAsync calls)
            if (statistics.IsGeoIPEnriched)
            {
                DebugLogger.Log($"[StatisticsService] ✓ GeoIP already enriched at {statistics.GeoIPEnrichmentTimestamp:HH:mm:ss} - skipping EnrichWithGeoAsync");
                return statistics;
            }

            var totalUniqueIPs = _geoIPEnricher.ExtractUniqueIPs(packetCollection);
            DebugLogger.Log($"[GeoIP Enrichment] Processing {totalUniqueIPs:N0} unique IPs...");

            _geoIPEnricher.ReportInitialProgress(progress, totalUniqueIPs);

            var enrichmentStopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var countryTask = _geoIPService.AnalyzeCountryTrafficAsync(packetCollection);
                var flowTask = _geoIPService.AnalyzeTrafficFlowsAsync(packetCollection);
                var riskTask = _geoIPService.GetHighRiskCountriesAsync();

                var geoTimeoutSeconds = packetCollection.Count switch
                {
                    > 2_000_000 => 30,
                    > 1_000_000 => 20,
                    > 250_000 => 12,
                    _ => 5
                };

                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(geoTimeoutSeconds));

                // Progress monitoring task
                var monitoringTask = MonitorEnrichmentProgress(countryTask, progress, totalUniqueIPs, enrichmentStopwatch, geoTimeoutSeconds, cts.Token);

                if (countryTask is not null)
                {
                    statistics.CountryStatistics = await countryTask.WaitAsync(cts.Token);
                    if (statistics.CountryStatistics is not null)
                    {
                        statistics.GeolocatedPackets = statistics.CountryStatistics.Values.Sum(static c => c.TotalPackets);
                        statistics.GeolocatedBytes = statistics.CountryStatistics.Values.Sum(static c => c.TotalBytes);
                    }
                }

                if (flowTask is not null)
                    statistics.TrafficFlows = await flowTask.WaitAsync(cts.Token);

                if (riskTask is not null)
                    statistics.HighRiskCountries = await riskTask.WaitAsync(cts.Token);

                CalculateInternationalDomestic(packetCollection, statistics);

                enrichmentStopwatch.Stop();
                progress?.Report(new AnalysisProgress
                {
                    Phase = "Analyzing Data",
                    Percent = 60,
                    Detail = $"GeoIP enrichment complete ({totalUniqueIPs:N0} IPs in {enrichmentStopwatch.Elapsed.TotalSeconds:F1}s)",
                    SubPhase = "GeoIP Lookups",
                    UniqueIPsProcessed = totalUniqueIPs,
                    TotalUniqueIPs = totalUniqueIPs
                });

                DebugLogger.Log($"[GeoIP Enrichment] Complete in {enrichmentStopwatch.Elapsed.TotalSeconds:F1}s");
            }
            catch (OperationCanceledException)
            {
                DebugLogger.Log("[StatisticsService] Geo enrichment timed out");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[StatisticsService] Error enriching statistics with GeoIP: {ex.Message}");
            }

            return statistics;
        }

        private async Task MonitorEnrichmentProgress(
            Task<Dictionary<string, CountryTrafficStatistics>> countryTask,
            IProgress<AnalysisProgress>? progress,
            int totalUniqueIPs,
            System.Diagnostics.Stopwatch stopwatch,
            int geoTimeoutSeconds,
            System.Threading.CancellationToken cancellationToken)
        {
            var lastReportedCount = 0;
            var reportInterval = 100;

            while (!countryTask.IsCompleted && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(500, cancellationToken);

                var elapsed = stopwatch.Elapsed.TotalSeconds;
                var estimatedProcessed = Math.Min(totalUniqueIPs, (int)(totalUniqueIPs * elapsed / geoTimeoutSeconds));

                if (estimatedProcessed - lastReportedCount >= reportInterval)
                {
                    lastReportedCount = estimatedProcessed;
                    var percentComplete = totalUniqueIPs > 0 ? (estimatedProcessed * 100 / totalUniqueIPs) : 0;
                    var overallPercent = 50 + (percentComplete / 10);

                    try
                    {
                        progress?.Report(new AnalysisProgress
                        {
                            Phase = "Analyzing Data",
                            Percent = overallPercent,
                            Detail = $"Enriching {estimatedProcessed:N0}/{totalUniqueIPs:N0} IPs ({percentComplete}%)",
                            SubPhase = "GeoIP Lookups",
                            UniqueIPsProcessed = estimatedProcessed,
                            TotalUniqueIPs = totalUniqueIPs
                        });
                    }
                    catch { /* Ignore progress reporting errors */ }
                }
            }
        }

        private void CalculateInternationalDomestic(List<PacketInfo> packetCollection, NetworkStatistics stats)
        {
            var sampleSize = Math.Min(1000, packetCollection.Count);
            if (sampleSize == 0)
            {
                stats.InternationalPackets = 0;
                stats.DomesticPackets = packetCollection.Count;
                return;
            }

            var sample = packetCollection.Take(sampleSize);
            var internationalCount = 0;
            var domesticCount = 0;

            foreach (var packet in sample)
            {
                var srcPublic = _geoIPService.IsPublicIP(packet.SourceIP);
                var dstPublic = _geoIPService.IsPublicIP(packet.DestinationIP);

                if (srcPublic || dstPublic)
                {
                    if (srcPublic && dstPublic)
                        internationalCount++;
                    else
                        domesticCount++;
                }
                else
                {
                    domesticCount++;
                }
            }

            var ratio = sampleSize > 0 ? (double)packetCollection.Count / sampleSize : 0;
            stats.InternationalPackets = (long)(internationalCount * ratio);
            stats.DomesticPackets = (long)(domesticCount * ratio);
        }

        public List<TimeSeriesDataPoint> GenerateTimeSeries(IEnumerable<PacketInfo> packets, TimeSpan interval)
        {
            var packetList = packets?.ToList() ?? new List<PacketInfo>();
            var threats = DetectThreats(packetList);
            var result = _timeSeriesGenerator.GenerateTimeSeriesWithMetrics(packetList, interval, threats);
            return result.ThroughputSeries;
        }

        public List<SecurityThreat> DetectThreats(IEnumerable<PacketInfo> packets)
        {
            var threats = new List<SecurityThreat>();
            var packetList = packets?.ToList() ?? new List<PacketInfo>();

            // Detect insecure ports and services
            if (_insecurePortDetector is not null)
            {
                var insecurePortThreats = _insecurePortDetector.DetectInsecurePorts(packetList);
                if (insecurePortThreats is not null)
                {
                    foreach (var threat in insecurePortThreats)
                    {
                        if (threat is null) continue;

                        var affectedPackets = new List<long>();
                        if (threat.Metadata?.ContainsKey("PacketNumbers") == true)
                        {
                            var packetNumbers = threat.Metadata["PacketNumbers"];
                            if (packetNumbers is List<uint> uintList)
                                affectedPackets = uintList.Select(p => (long)p).ToList();
                            else if (packetNumbers is IEnumerable<object> objList)
                                affectedPackets = objList.Select(p => Convert.ToInt64(p)).ToList();
                        }

                        threats.Add(new SecurityThreat
                        {
                            ThreatId = threat.Id,
                            DetectedAt = threat.FirstSeen,
                            Severity = threat.Severity,
                            Type = threat.ThreatName,
                            Description = threat.Description,
                            SourceAddress = threat.AffectedIPs?.FirstOrDefault() ?? "",
                            DestinationAddress = threat.AffectedIPs?.Skip(1).FirstOrDefault() ?? "",
                            AffectedPackets = affectedPackets,
                            Evidence = threat.Metadata ?? new Dictionary<string, object>(),
                            Recommendation = threat.Mitigations?.FirstOrDefault() ?? "Review security configuration"
                        });
                    }
                }
            }

            // Use injected threat detector service
            threats.AddRange(_threatDetector.DetectPortScanning(packetList));
            threats.AddRange(_threatDetector.DetectSuspiciousProtocols(packetList));
            threats.AddRange(_threatDetector.DetectAnomalousTraffic(packetList));
            threats.AddRange(_threatDetector.DetectPotentialDDoS(packetList));

            return threats;
        }

        public List<ExpertInsight> GenerateInsights(NetworkStatistics stats)
        {
            var insights = new List<ExpertInsight>();

            // Analyze high traffic volume
            if (stats.TotalPackets >= 100_000)
            {
                var duration = (stats.LastPacketTime - stats.FirstPacketTime).TotalHours;
                if (duration > 0)
                {
                    var packetsPerHour = stats.TotalPackets / duration;
                    insights.Add(new ExpertInsight
                    {
                        GeneratedAt = DateTime.Now,
                        Category = "Performance",
                        Title = "High Traffic Volume Detected",
                        Description = $"Captured {stats.TotalPackets:N0} packets over {duration:F1} hours ({packetsPerHour:N0} packets/hour)",
                        Severity = InsightSeverity.Info,
                        Recommendations = new List<string>
                        {
                            "Monitor network performance and bandwidth usage",
                            "Consider implementing traffic shaping if needed",
                            "Review application traffic patterns for optimization"
                        }
                    });
                }
            }

            // Analyze protocol distribution
            if (stats.ProtocolStats is not null && stats.ProtocolStats.Any())
            {
                var httpPercentage = stats.ProtocolStats
                    .Where(p => p.Key == "HTTP")
                    .Select(p => p.Value.Percentage)
                    .FirstOrDefault();

                if (httpPercentage > 20)
                {
                    insights.Add(new ExpertInsight
                    {
                        GeneratedAt = DateTime.Now,
                        Category = "Security",
                        Title = "High Unencrypted HTTP Traffic",
                        Description = $"{httpPercentage:F1}% of traffic is unencrypted HTTP",
                        Severity = InsightSeverity.Warning,
                        Recommendations = new List<string>
                        {
                            "Implement HTTPS for all web services",
                            "Use HTTP Strict Transport Security (HSTS)",
                            "Consider implementing a Web Application Firewall"
                        }
                    });
                }

                var protocolCount = stats.ProtocolStats.Count;
                if (protocolCount >= 2)
                {
                    var topProtocol = stats.ProtocolStats.OrderByDescending(p => p.Value.PacketCount).First();
                    insights.Add(new ExpertInsight
                    {
                        GeneratedAt = DateTime.Now,
                        Category = "Network",
                        Title = "Protocol Distribution Analysis",
                        Description = $"Detected {protocolCount} protocols. {topProtocol.Key} is dominant with {topProtocol.Value.Percentage:F1}%",
                        Severity = InsightSeverity.Info,
                        Recommendations = new List<string>
                        {
                            "Review protocol usage for security compliance",
                            "Ensure only necessary protocols are allowed",
                            "Consider implementing protocol filtering"
                        }
                    });
                }
            }

            // Analyze top talkers
            if (stats.TopSources is not null && stats.TopSources.Any())
            {
                var topSource = stats.TopSources.First();
                if (topSource.Percentage > 30)
                {
                    insights.Add(new ExpertInsight
                    {
                        GeneratedAt = DateTime.Now,
                        Category = "Network",
                        Title = "Dominant Traffic Source",
                        Description = $"{topSource.Address} accounts for {topSource.Percentage:F1}% of traffic",
                        Severity = InsightSeverity.Info,
                        Recommendations = new List<string>
                        {
                            "Verify if this traffic pattern is expected",
                            "Consider load balancing if this is a server",
                            "Monitor for potential bandwidth issues"
                        }
                    });
                }
            }

            // Analyze threats
            if (stats.DetectedThreats is not null && stats.DetectedThreats.Any())
            {
                var criticalThreats = stats.DetectedThreats.Count(t => t.Severity == ThreatSeverity.Critical);
                if (criticalThreats > 0)
                {
                    insights.Add(new ExpertInsight
                    {
                        GeneratedAt = DateTime.Now,
                        Category = "Security",
                        Title = "Critical Security Threats Detected",
                        Description = $"{criticalThreats} critical security threats require immediate attention",
                        Severity = InsightSeverity.Critical,
                        Recommendations = new List<string>
                        {
                            "Review and respond to critical threats immediately",
                            "Implement additional security monitoring",
                            "Consider engaging security team for incident response"
                        },
                        SupportingData = new Dictionary<string, object>
                        {
                            { "CriticalThreats", criticalThreats },
                            { "TotalThreats", stats.DetectedThreats.Count }
                        }
                    });
                }
            }

            return insights;
        }

        /// <summary>
        /// Calculate directional stream count (unique 4-tuple: SrcIP, SrcPort, DstIP, DstPort).
        /// This matches the calculation used by Packet Analysis tab for consistency.
        /// Note: This is different from TotalConversationCount which groups bidirectionally.
        /// </summary>
        private static int CalculateDirectionalStreamCount(List<PacketInfo> packets)
        {
            try
            {
                // Count ALL directional streams (TCP + UDP + other) - not just TCP
                // A stream is a unique 4-tuple (SrcIP, SrcPort, DstIP, DstPort) - DIRECTIONAL
                return packets
                    .Where(p => p.SourcePort > 0 && p.DestinationPort > 0) // Must have ports
                    .Select(p => (p.SourceIP, p.SourcePort, p.DestinationIP, p.DestinationPort))
                    .Distinct()
                    .Count();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[StatisticsService] Error calculating directional streams: {ex.Message}");
                return 0;
            }
        }
    }
}
