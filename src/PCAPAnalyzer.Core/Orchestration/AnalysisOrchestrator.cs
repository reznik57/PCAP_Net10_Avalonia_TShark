using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Caching;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Orchestration
{
    /// <summary>
    /// Central orchestrator for complete PCAP analysis with preloading for ALL tabs.
    ///
    /// Workflow:
    /// 1. Load ALL packets from TShark (2.5M-40M packets, 70-90s)
    /// 2. Parallel analysis: Statistics + GeoIP, Threats, VoiceQoS
    /// 3. Cache complete result in SessionAnalysisCache
    /// 4. Return AnalysisResult for instant tab switching
    ///
    /// Design Goals:
    /// - NO cancellation during analysis (user requirement)
    /// - Memory unlimited (10-20GB acceptable)
    /// - Session-only cache (no SQLite persistence)
    /// - Tabs disabled during load, instant after
    /// </summary>
    public class AnalysisOrchestrator
    {
        private readonly ITSharkService _tsharkService;
        private readonly IStatisticsService _statisticsService;
        private readonly IUnifiedAnomalyDetectionService _anomalyService;
        private readonly IGeoIPService _geoIPService;
        private readonly ISessionAnalysisCache _sessionCache;
        private readonly PCAPAnalyzer.Core.Services.OsFingerprinting.IOsFingerprintService _osFingerprintService;

        public AnalysisOrchestrator(
            ITSharkService tsharkService,
            IStatisticsService statisticsService,
            IUnifiedAnomalyDetectionService anomalyService,
            IGeoIPService geoIPService,
            ISessionAnalysisCache sessionCache,
            PCAPAnalyzer.Core.Services.OsFingerprinting.IOsFingerprintService osFingerprintService)
        {
            _tsharkService = tsharkService ?? throw new ArgumentNullException(nameof(tsharkService));
            _statisticsService = statisticsService ?? throw new ArgumentNullException(nameof(statisticsService));
            _anomalyService = anomalyService ?? throw new ArgumentNullException(nameof(anomalyService));
            _geoIPService = geoIPService ?? throw new ArgumentNullException(nameof(geoIPService));
            _sessionCache = sessionCache ?? throw new ArgumentNullException(nameof(sessionCache));
            _osFingerprintService = osFingerprintService ?? throw new ArgumentNullException(nameof(osFingerprintService));
        }

        /// <summary>
        /// Main analysis entry point. Returns complete AnalysisResult with ALL tabs preloaded.
        ///
        /// Performance:
        /// - 300MB file (2.5M packets): ~70s
        /// - 5GB file (40M packets): ~90s
        /// - Memory: 10-20GB peak
        /// </summary>
        /// <param name="pcapPath">Full path to PCAP file</param>
        /// <param name="progress">Progress reporting callback</param>
        /// <param name="cancellationToken">Cancellation token (NOT used per requirements)</param>
        /// <returns>Complete analysis result ready for caching</returns>
        public async Task<AnalysisResult> AnalyzeFileAsync(
            string pcapPath,
            IProgress<AnalysisProgress>? progress,
            CancellationToken cancellationToken)
        {
            // Create progress coordinator for smooth 0-100% progression
            var coordinator = new ProgressCoordinator(progress);
            var stopwatch = Stopwatch.StartNew();

            // Initialize time-based progress estimates from file size
            var fileInfo = new System.IO.FileInfo(pcapPath);
            var fileSizeMB = fileInfo.Length / (1024.0 * 1024.0);
            coordinator.InitializeTimeEstimates(fileSizeMB);

            try
            {
                // ========================================================================
                // PHASE 1: LOAD ALL PACKETS (2-50% overall)
                // ========================================================================
                // Note: String pools are reset in TSharkService/ParallelTSharkService.StartAnalysisAsync()

                var allPackets = await LoadAllPacketsAsync(pcapPath, coordinator, cancellationToken);

                DebugLogger.Log($"[AnalysisOrchestrator] Loaded {allPackets.Count:N0} packets");

                // Calculate metrics after packet loading
                var totalBytes = allPackets.Sum(p => (long)p.Length);
                var totalMB = totalBytes / (1024.0 * 1024.0);
                coordinator.SetTotalPackets(allPackets.Count);
                coordinator.SetTotalMegabytes(totalMB);

                // ========================================================================
                // PHASE 2: PARALLEL ANALYSIS (50-92% overall)
                // ========================================================================

                var (statistics, threats, anomalies, voiceQoS) = await AnalyzeInParallelAsync(allPackets, coordinator, cancellationToken);

                DebugLogger.Log($"[AnalysisOrchestrator] Analysis complete: {statistics.CountryStatistics.Count} countries, " +
                                  $"{threats.Count} threats, {anomalies.Count} anomalies, VoiceQoS={voiceQoS != null}");

                // ========================================================================
                // PHASE 3: BUILD RESULT & CACHE (92-100% overall)
                // ========================================================================

                coordinator.ReportFinalizing(0, "Building analysis result and caching...");

                var fileHash = ComputeFileHash(pcapPath);
                var voiceQoSTimeSeries = GenerateVoiceQoSTimeSeries(allPackets);

                var result = new AnalysisResult
                {
                    // Core data
                    AllPackets = allPackets,
                    Statistics = statistics,
                    Threats = threats,
                    Anomalies = anomalies,

                    // Tab-specific data
                    CountryTraffic = statistics.CountryStatistics,
                    TrafficFlows = statistics.TrafficFlows,
                    VoiceQoSData = voiceQoS,
                    VoiceQoSTimeSeries = voiceQoSTimeSeries,

                    // Metadata
                    FilePath = pcapPath,
                    FileHash = fileHash,
                    AnalyzedAt = DateTime.UtcNow,
                    AnalysisDuration = stopwatch.Elapsed,
                    TotalPackets = allPackets.Count,
                    TotalBytes = allPackets.Sum(p => (long)p.Length)
                };

                // Cache for instant tab switching
                _sessionCache.Set(result);

                coordinator.ReportFinalizing(50, "Cached analysis results");

                coordinator.ReportComplete($"Analysis complete: {result.TotalPackets:N0} packets, {result.EstimatedMemoryGB:F2}GB cached");

                // ========================================================================
                // PERFORMANCE SUMMARY
                // ========================================================================

                var totalTime = stopwatch.Elapsed.TotalSeconds;
                var packetsPerSecond = totalTime > 0 ? (long)(result.TotalPackets / totalTime) : 0;

                // Build comprehensive performance summary (only show phases with actual time)
                var performanceSummary = new List<string>();

                var countingTime = GetPhaseDuration(coordinator, "Counting Packets");
                if (countingTime > 0.1)
                    performanceSummary.Add($"├─ 1. Packet Counting: {countingTime:F1}s ({result.TotalPackets:N0} packets detected via TShark)");

                var loadingTime = GetPhaseDuration(coordinator, "Loading Packets");
                if (loadingTime > 0.1)
                {
                    var loadPps = loadingTime > 0 ? (long)(result.TotalPackets / loadingTime) : 0;
                    performanceSummary.Add($"├─ 2. Packet Loading: {loadingTime:F1}s ({loadPps:N0} packets/sec streaming)");
                }

                var statsTime = GetPhaseDuration(coordinator, "Analyzing Data");
                if (statsTime > 0.1)
                    performanceSummary.Add($"├─ 3. Statistics & GeoIP: {statsTime:F1}s ({result.Statistics.AllUniqueIPs.Count:N0} IPs, {result.Statistics.CountryStatistics.Count} countries)");

                var threatsTime = GetPhaseDuration(coordinator, "Threat Detection");
                if (threatsTime > 0.1)
                    performanceSummary.Add($"├─ 4. Threat Detection: {threatsTime:F1}s ({result.Threats.Count} threats found across 7 detectors)");

                var voiceTime = GetPhaseDuration(coordinator, "VoiceQoS Analysis");
                if (voiceTime > 0.1)
                    performanceSummary.Add($"├─ 5. VoiceQoS Analysis: {voiceTime:F1}s ({result.VoiceQoSData?.QoSTraffic?.Count ?? 0:N0} RTP connections analyzed)");

                DebugLogger.Log($"\n[PERFORMANCE SUMMARY]");
                foreach (var line in performanceSummary)
                    DebugLogger.Log(line);
                DebugLogger.Log($"└─ ✓ Total Analysis Time: {totalTime:F1}s ({packetsPerSecond:N0} packets/sec average)\n");

                return result;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisOrchestrator] Analysis failed: {ex.Message}");
                throw;
            }
        }

        // ============================================================================
        // PRIVATE HELPERS
        // ============================================================================

        /// <summary>
        /// PHASE 1: Load all packets from TShark using streaming API.
        /// Uses exact pattern from API_REFERENCE_FOR_AGENTS.md.
        /// </summary>
        private async Task<List<PacketInfo>> LoadAllPacketsAsync(
            string pcapPath,
            ProgressCoordinator coordinator,
            CancellationToken cancellationToken)
        {
            // ========================================================================
            // PHASE 1A: Get ACTUAL packet count for accurate progress (0-2%)
            // ========================================================================

            coordinator.ReportCounting("Getting exact packet count for accurate progress...");

            var actualTotal = await _tsharkService.GetTotalPacketCountAsync(pcapPath, coordinator);
            coordinator.StopPhase("Counting Packets");

            if (actualTotal == 0)
            {
                // Fallback to file size estimation if counting fails
                var fileSize = new System.IO.FileInfo(pcapPath).Length;
                actualTotal = (long)(fileSize / 500); // ~500 bytes avg per packet
                DebugLogger.Log($"[AnalysisOrchestrator] Packet count failed, using estimate: {actualTotal:N0}");
            }
            else
            {
                DebugLogger.Log($"[AnalysisOrchestrator] Actual packet count: {actualTotal:N0}");
            }

            var fileInfo = new System.IO.FileInfo(pcapPath);
            var estimatedTotalMB = fileInfo.Length / (1024.0 * 1024.0);
            var allPackets = new List<PacketInfo>((int)actualTotal);

            coordinator.SetTotalPackets(actualTotal);
            coordinator.SetTotalMegabytes(estimatedTotalMB);

            DebugLogger.Log($"[AnalysisOrchestrator] File size: {fileInfo.Length:N0} bytes, packets: {actualTotal:N0}");

            // ========================================================================
            // PHASE 1B: Stream packets from TShark (2-50%)
            // ========================================================================

            // Start TShark streaming
            await _tsharkService.StartAnalysisAsync(pcapPath, cancellationToken);

            // Clear OS fingerprint service for new analysis
            _osFingerprintService.Clear();

            // Read all packets from channel with real-time metrics
            await foreach (var packet in _tsharkService.PacketReader.ReadAllAsync(cancellationToken))
            {
                allPackets.Add(packet);

                // Process OS fingerprinting data inline during packet loading
                if (packet.OsFingerprintData.HasValue)
                {
                    _osFingerprintService.ProcessPacket(
                        packet.OsFingerprintData.Value,
                        packet.FrameNumber,
                        packet.Timestamp,
                        packet.SourceIP,
                        packet.DestinationIP,
                        packet.SourcePort,
                        packet.DestinationPort,
                        packet.TcpFlags
                    );
                }

                // Report progress every 100k packets
                if (allPackets.Count % 100000 == 0)
                {
                    coordinator.ReportLoading(allPackets.Count, $"Loaded {allPackets.Count:N0} / {actualTotal:N0} packets...");
                }
            }

            // Stop TShark process
            await _tsharkService.StopAnalysisAsync();
            coordinator.StopPhase("Loading Packets");

            // Finalize OS fingerprinting analysis (signature matching)
            await _osFingerprintService.FinalizeAnalysisAsync();

            // Log OS fingerprint parsing stats
            var packetsWithOsData = allPackets.Count(p => p.OsFingerprintData.HasValue);
            DebugLogger.Log($"[AnalysisOrchestrator] OS fingerprinting: {packetsWithOsData:N0}/{allPackets.Count:N0} packets had fingerprint data, {_osFingerprintService.HostCount} hosts detected");

            DebugLogger.Log($"[AnalysisOrchestrator] Packet loading complete: {allPackets.Count:N0} packets");

            // CRITICAL: Sort packets by frame number if using parallel processing
            // (ParallelTSharkService may return packets out-of-order from different chunks)
            if (_tsharkService.GetType().Name == "ParallelTSharkService")
            {
                allPackets.Sort((a, b) => a.FrameNumber.CompareTo(b.FrameNumber));
                DebugLogger.Log($"[AnalysisOrchestrator] Sorted {allPackets.Count:N0} packets");
            }

            return allPackets;
        }

        /// <summary>
        /// PHASE 2: Run parallel analysis across all services.
        /// Uses exact APIs from API_REFERENCE_FOR_AGENTS.md.
        /// </summary>
        private async Task<(NetworkStatistics statistics, List<SecurityThreat> threats, List<NetworkAnomaly> anomalies, VoiceQoSAnalysisResult? voiceQoS)>
            AnalyzeInParallelAsync(
                List<PacketInfo> allPackets,
                ProgressCoordinator coordinator,
                CancellationToken cancellationToken)
        {
            // Create child progress reporters for each parallel task
            var statisticsProgress = coordinator.CreateChildProgress(AnalysisPhase.Statistics);
            var threatsProgress = coordinator.CreateChildProgress(AnalysisPhase.Threats);
            var voiceQoSProgress = coordinator.CreateChildProgress(AnalysisPhase.VoiceQoS);

            // Statistics analysis (includes GeoIP enrichment via EnrichWithGeoAsync)
            // Maps to 50-65% overall
            var statisticsTask = Task.Run(async () =>
            {
                coordinator.ReportStatistics(0, "Starting statistics analysis...");
                var stats = await _statisticsService.CalculateStatisticsAsync(allPackets);

                // Enrich with GeoIP data (CountryStatistics, TrafficFlows)
                coordinator.ReportStatistics(50, "Enriching with GeoIP data...");
                stats = await _statisticsService.EnrichWithGeoAsync(stats, allPackets, null); // Don't pass child progress to avoid interference

                return stats;
            }, cancellationToken);

            // Threat detection using UnifiedAnomalyDetectionService
            // Maps to 65-80% overall
            var threatsTask = Task.Run(async () =>
            {
                coordinator.ReportThreats(0, "Starting threat detection...");

                // Use DetectAllAnomaliesAsync from IUnifiedAnomalyDetectionService
                var anomalies = await _anomalyService.DetectAllAnomaliesAsync(allPackets, null); // Don't pass child progress

                // Convert NetworkAnomaly to SecurityThreat for compatibility
                var threats = ConvertAномaliesToThreats(anomalies);
                coordinator.ReportThreats(100, $"Threat detection complete: {threats.Count} threats found", threats.Count);

                // Return both raw anomalies (for Anomalies tab) and converted threats (for Threats tab)
                return (threats, anomalies);
            }, cancellationToken);

            // VoiceQoS analysis (extract QoS-marked packets)
            // Maps to 80-92% overall
            var voiceQoSTask = Task.Run(() =>
            {
                coordinator.ReportVoiceQoS(0, "Starting VoiceQoS analysis...");
                var result = ExtractVoiceQoSData(allPackets, null); // Don't pass child progress
                coordinator.ReportVoiceQoS(100, "VoiceQoS analysis complete");
                return result;
            }, cancellationToken);

            // Wait for all parallel tasks
            await Task.WhenAll(statisticsTask, threatsTask, voiceQoSTask);

            // Stop all parallel phases
            coordinator.StopPhase("Analyzing Data");
            coordinator.StopPhase("Threat Detection");
            coordinator.StopPhase("VoiceQoS Analysis");

            var threatsResult = await threatsTask;
            return (
                statistics: await statisticsTask,
                threats: threatsResult.threats,
                anomalies: threatsResult.anomalies,
                voiceQoS: await voiceQoSTask
            );
        }

        /// <summary>
        /// Converts NetworkAnomaly objects to SecurityThreat objects for backward compatibility.
        /// </summary>
        private List<SecurityThreat> ConvertAномaliesToThreats(List<NetworkAnomaly> anomalies)
        {
            return anomalies.Select(a => new SecurityThreat
            {
                ThreatId = a.Id,
                DetectedAt = a.DetectedAt,
                Severity = ConvertSeverity(a.Severity),
                Type = a.Type,
                Description = a.Description,
                SourceAddress = a.SourceIP,
                DestinationAddress = a.DestinationIP,
                AffectedPackets = a.AffectedFrames,
                Evidence = a.Evidence,
                Recommendation = a.Recommendation,
                IsFalsePositive = false
            }).ToList();
        }

        /// <summary>
        /// Converts AnomalySeverity to ThreatSeverity.
        /// </summary>
        private ThreatSeverity ConvertSeverity(AnomalySeverity severity)
        {
            return severity switch
            {
                AnomalySeverity.Low => ThreatSeverity.Low,
                AnomalySeverity.Medium => ThreatSeverity.Medium,
                AnomalySeverity.High => ThreatSeverity.High,
                AnomalySeverity.Critical => ThreatSeverity.Critical,
                _ => ThreatSeverity.Low
            };
        }

        /// <summary>
        /// Extracts VoiceQoS data from packets (QoS markings, latency, jitter).
        /// </summary>
        private VoiceQoSAnalysisResult? ExtractVoiceQoSData(List<PacketInfo> packets, IProgress<AnalysisProgress>? progress = null)
        {
            var sw = Stopwatch.StartNew();

            // ========================================================================
            // PHASE 1: Filter QoS packets
            // ========================================================================

            DebugLogger.Log($"[VoiceQoS Analysis] Filtering QoS packets from {packets.Count:N0} total...");

            // Filter QoS-marked packets (DSCP values for voice: EF=46, AF41=34, etc.)
            var qosPackets = packets.Where(p => IsQoSPacket(p)).ToList();

            if (qosPackets.Count == 0)
            {
                DebugLogger.Log("[VoiceQoS Analysis] No QoS packets found");
                return null;
            }

            var qosPercent = (qosPackets.Count * 100.0) / packets.Count;
            DebugLogger.Log($"[VoiceQoS Analysis] Found {qosPackets.Count:N0} QoS packets ({qosPercent:F2}%)");

            DebugLogger.Log($"[VoiceQoS Analysis] Grouping {qosPackets.Count:N0} QoS packets into connections...");

            var connections = qosPackets
                .GroupBy(p => $"{p.SourceIP}:{p.SourcePort}-{p.DestinationIP}:{p.DestinationPort}")
                .ToList();

            DebugLogger.Log($"[VoiceQoS Analysis] Grouped into {connections.Count:N0} RTP connections");

            DebugLogger.Log($"[VoiceQoS Analysis] Calculating quality metrics for {connections.Count:N0} connections...");

            var qosTraffic = new List<VoiceQoSTrafficItem>();
            var highLatency = new List<VoiceQoSLatencyItem>();
            var highJitter = new List<VoiceQoSJitterItem>();

            foreach (var conn in connections)
            {
                var connPackets = conn.OrderBy(p => p.Timestamp).ToList();
                if (connPackets.Count == 0) continue;

                var first = connPackets.First();

                // QoS traffic item
                qosTraffic.Add(new VoiceQoSTrafficItem
                {
                    SourceIP = first.SourceIP,
                    DestinationIP = first.DestinationIP,
                    Protocol = first.Protocol.ToString(),
                    PacketCount = connPackets.Count,
                    TotalBytes = connPackets.Sum(p => (long)p.Length),
                    FirstSeen = connPackets.First().Timestamp,
                    LastSeen = connPackets.Last().Timestamp,
                    QoSType = "VoIP",
                    PortRange = $"{first.SourcePort}-{first.DestinationPort}",
                    DscpMarking = "EF", // Simplified
                    DscpValue = 46
                });

                // Calculate latency/jitter (simplified - real implementation would analyze ACKs)
                var latencies = CalculateLatencies(connPackets);
                var jitters = CalculateJitters(latencies);

                if (latencies.Any() && latencies.Average() > 150) // High latency threshold: 150ms
                {
                    highLatency.Add(new VoiceQoSLatencyItem
                    {
                        SourceIP = first.SourceIP,
                        DestinationIP = first.DestinationIP,
                        Protocol = first.Protocol.ToString(),
                        AverageLatency = latencies.Average(),
                        MaxLatency = latencies.Max(),
                        MinLatency = latencies.Min(),
                        P5Latency = Percentile(latencies, 5),
                        P95Latency = Percentile(latencies, 95),
                        PacketCount = connPackets.Count,
                        FirstSeen = connPackets.First().Timestamp,
                        LastSeen = connPackets.Last().Timestamp,
                        PortRange = $"{first.SourcePort}-{first.DestinationPort}"
                    });
                }

                if (jitters.Any() && jitters.Average() > 30) // High jitter threshold: 30ms
                {
                    highJitter.Add(new VoiceQoSJitterItem
                    {
                        SourceIP = first.SourceIP,
                        DestinationIP = first.DestinationIP,
                        Protocol = first.Protocol.ToString(),
                        AverageJitter = jitters.Average(),
                        MaxJitter = jitters.Max(),
                        MinJitter = jitters.Min(),
                        P5Jitter = Percentile(jitters, 5),
                        P95Jitter = Percentile(jitters, 95),
                        PacketCount = connPackets.Count,
                        FirstSeen = connPackets.First().Timestamp,
                        LastSeen = connPackets.Last().Timestamp,
                        PortRange = $"{first.SourcePort}-{first.DestinationPort}"
                    });
                }
            }

            sw.Stop();

            DebugLogger.Log($"[VoiceQoS Analysis] Complete: {connections.Count:N0} connections analyzed in {sw.Elapsed.TotalSeconds:F1}s");
            DebugLogger.Log($"[VoiceQoS Analysis] High latency: {highLatency.Count}, High jitter: {highJitter.Count}");

            return new VoiceQoSAnalysisResult
            {
                QoSTraffic = qosTraffic,
                HighLatencyConnections = highLatency,
                HighJitterConnections = highJitter,
                AnalysisTimestamp = DateTime.UtcNow
            };
        }

        /// <summary>
        /// Generates VoiceQoS time-series data for charting.
        /// </summary>
        private VoiceQoSTimeSeriesData? GenerateVoiceQoSTimeSeries(List<PacketInfo> packets)
        {
            var qosPackets = packets.Where(p => IsQoSPacket(p)).OrderBy(p => p.Timestamp).ToList();

            if (qosPackets.Count == 0)
                return null;

            var startTime = qosPackets.First().Timestamp;
            var endTime = qosPackets.Last().Timestamp;
            var duration = endTime - startTime;

            // Use 1-second buckets for time-series
            var interval = TimeSpan.FromSeconds(1);
            var buckets = new Dictionary<DateTime, List<PacketInfo>>();

            foreach (var packet in qosPackets)
            {
                var bucketTime = new DateTime(
                    packet.Timestamp.Year,
                    packet.Timestamp.Month,
                    packet.Timestamp.Day,
                    packet.Timestamp.Hour,
                    packet.Timestamp.Minute,
                    packet.Timestamp.Second);

                if (!buckets.ContainsKey(bucketTime))
                    buckets[bucketTime] = new List<PacketInfo>();

                buckets[bucketTime].Add(packet);
            }

            var dataPoints = new List<VoiceQoSTimeSeriesPoint>();

            foreach (var bucket in buckets.OrderBy(b => b.Key))
            {
                var latencies = CalculateLatencies(bucket.Value);
                var jitters = CalculateJitters(latencies);

                dataPoints.Add(new VoiceQoSTimeSeriesPoint
                {
                    Timestamp = bucket.Key,
                    QoSPacketCount = bucket.Value.Count,
                    LatencyMin = latencies.Any() ? latencies.Min() : 0,
                    LatencyAvg = latencies.Any() ? latencies.Average() : 0,
                    LatencyMax = latencies.Any() ? latencies.Max() : 0,
                    LatencyP5 = Percentile(latencies, 5),
                    LatencyP95 = Percentile(latencies, 95),
                    JitterMin = jitters.Any() ? jitters.Min() : 0,
                    JitterAvg = jitters.Any() ? jitters.Average() : 0,
                    JitterMax = jitters.Any() ? jitters.Max() : 0,
                    JitterP5 = Percentile(jitters, 5),
                    JitterP95 = Percentile(jitters, 95),
                    ActiveConnections = bucket.Value.Select(p => $"{p.SourceIP}:{p.SourcePort}").Distinct().Count()
                });
            }

            return new VoiceQoSTimeSeriesData
            {
                DataPoints = dataPoints,
                StartTime = startTime,
                EndTime = endTime,
                Interval = interval,
                TotalQoSPackets = qosPackets.Count,
                OverallAvgLatency = dataPoints.Any() ? dataPoints.Average(d => d.LatencyAvg) : 0,
                OverallAvgJitter = dataPoints.Any() ? dataPoints.Average(d => d.JitterAvg) : 0
            };
        }

        // ============================================================================
        // UTILITY METHODS
        // ============================================================================

        /// <summary>
        /// Checks if packet is QoS-marked (VoIP traffic).
        /// Simplified: Check common VoIP ports (5060, 5061 SIP, 16384-32767 RTP).
        /// </summary>
        private bool IsQoSPacket(PacketInfo packet)
        {
            // SIP ports
            if (packet.SourcePort == 5060 || packet.DestinationPort == 5060 ||
                packet.SourcePort == 5061 || packet.DestinationPort == 5061)
                return true;

            // RTP port range
            if ((packet.SourcePort >= 16384 && packet.SourcePort <= 32767) ||
                (packet.DestinationPort >= 16384 && packet.DestinationPort <= 32767))
                return true;

            return false;
        }

        /// <summary>
        /// Calculates inter-packet latencies (simplified).
        /// Real implementation would analyze TCP ACKs or RTCP reports.
        /// </summary>
        private List<double> CalculateLatencies(List<PacketInfo> packets)
        {
            var latencies = new List<double>();

            for (int i = 1; i < packets.Count; i++)
            {
                var delta = (packets[i].Timestamp - packets[i - 1].Timestamp).TotalMilliseconds;
                if (delta > 0 && delta < 5000) // Filter unrealistic values
                    latencies.Add(delta);
            }

            return latencies;
        }

        /// <summary>
        /// Calculates jitter from latency values.
        /// Jitter = variance in latency.
        /// </summary>
        private List<double> CalculateJitters(List<double> latencies)
        {
            var jitters = new List<double>();

            for (int i = 1; i < latencies.Count; i++)
            {
                var jitter = Math.Abs(latencies[i] - latencies[i - 1]);
                jitters.Add(jitter);
            }

            return jitters;
        }

        /// <summary>
        /// Calculates percentile value from a list of doubles.
        /// </summary>
        private double Percentile(List<double> values, int percentile)
        {
            if (values.Count == 0) return 0;

            var sorted = values.OrderBy(v => v).ToList();
            var index = (int)Math.Ceiling((percentile / 100.0) * sorted.Count) - 1;
            index = Math.Max(0, Math.Min(index, sorted.Count - 1));

            return sorted[index];
        }

        /// <summary>
        /// Helper to get phase duration in seconds from coordinator
        /// </summary>
        private double GetPhaseDuration(ProgressCoordinator coordinator, string phaseName)
        {
            return coordinator.PhaseDurations.TryGetValue(phaseName, out var duration)
                ? duration.TotalSeconds
                : 0.0;
        }

        /// <summary>
        /// Computes SHA256 hash of a file for cache validation.
        /// </summary>
        private string ComputeFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = System.IO.File.OpenRead(filePath);
                var hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisOrchestrator] Failed to compute file hash: {ex.Message}");
                return Guid.NewGuid().ToString(); // Fallback to unique ID
            }
        }
    }

    /// <summary>
    /// Progress information for UI updates during analysis.
    /// Enhanced with real-time metrics for comprehensive user feedback.
    /// </summary>
    public class AnalysisProgress
    {
        /// <summary>
        /// Current phase: "Loading Packets", "Analyzing Data", "Finalizing", "Complete"
        /// </summary>
        public string Phase { get; set; } = "";

        /// <summary>
        /// Progress percentage (0-100)
        /// </summary>
        public int Percent { get; set; }

        /// <summary>
        /// Detailed status message
        /// </summary>
        public string Detail { get; set; } = "";

        // ============ REAL-TIME METRICS (Enhanced Progress Visualization) ============

        /// <summary>
        /// Total packets analyzed so far
        /// </summary>
        public long PacketsAnalyzed { get; set; }

        /// <summary>
        /// Total packets expected (0 if unknown)
        /// </summary>
        public long TotalPackets { get; set; }

        /// <summary>
        /// Packets per second processing rate
        /// </summary>
        public long PacketsPerSecond { get; set; }

        /// <summary>
        /// Total megabytes analyzed so far (traffic volume)
        /// </summary>
        public double MegabytesAnalyzed { get; set; }

        /// <summary>
        /// Total megabytes expected (0 if unknown)
        /// </summary>
        public double TotalMegabytes { get; set; }

        /// <summary>
        /// Elapsed time since analysis started
        /// </summary>
        public TimeSpan ElapsedTime { get; set; }

        /// <summary>
        /// Estimated remaining time (TimeSpan.Zero if unknown)
        /// </summary>
        public TimeSpan RemainingTime { get; set; }

        /// <summary>
        /// Sub-phase detail (e.g., "Enriching 500/2,500 IPs with GeoIP data")
        /// </summary>
        public string? SubPhase { get; set; }

        /// <summary>
        /// Number of threats detected so far (real-time threat counter)
        /// </summary>
        public int ThreatsDetected { get; set; }

        /// <summary>
        /// Number of unique IPs processed (GeoIP enrichment progress)
        /// </summary>
        public int UniqueIPsProcessed { get; set; }

        /// <summary>
        /// Total unique IPs to process (0 if unknown)
        /// </summary>
        public int TotalUniqueIPs { get; set; }

        public override string ToString()
        {
            return $"{Phase} ({Percent}%): {Detail}";
        }

        /// <summary>
        /// Calculates remaining time based on current progress rate
        /// </summary>
        public void CalculateRemainingTime()
        {
            if (PacketsAnalyzed > 0 && TotalPackets > 0 && ElapsedTime.TotalSeconds > 0)
            {
                var remainingPackets = TotalPackets - PacketsAnalyzed;
                var packetsPerSecond = PacketsAnalyzed / ElapsedTime.TotalSeconds;

                if (packetsPerSecond > 0)
                {
                    var remainingSeconds = remainingPackets / packetsPerSecond;
                    RemainingTime = TimeSpan.FromSeconds(remainingSeconds);
                }
                else
                {
                    RemainingTime = TimeSpan.Zero;
                }
            }
            else if (Percent > 0 && Percent < 100 && ElapsedTime.TotalSeconds > 0)
            {
                // Fallback: estimate based on percentage progress
                var timePerPercent = ElapsedTime.TotalSeconds / Percent;
                var remainingPercent = 100 - Percent;
                var remainingSeconds = timePerPercent * remainingPercent;
                RemainingTime = TimeSpan.FromSeconds(remainingSeconds);
            }
            else
            {
                RemainingTime = TimeSpan.Zero;
            }
        }
    }
}
