using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    [Obsolete("Use IUnifiedAnomalyDetectionService with NetworkAnomaly model instead. This interface will be removed in a future version.")]
    public interface ISpecializedTrafficAnomalyService
    {
        [Obsolete("Use DetectVoIPAnomaliesAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectVoIPAnomalies(IEnumerable<PacketInfo> packets);

        [Obsolete("Use DetectIoTAnomaliesAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectIoTAnomalies(IEnumerable<PacketInfo> packets);

        [Obsolete("Use DetectDNSTunnelingAnomaliesAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectDNSTunnelingAnomalies(IEnumerable<PacketInfo> packets);

        [Obsolete("Use DetectCryptominingTrafficAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectCryptominingTraffic(IEnumerable<PacketInfo> packets);

        [Obsolete("Use DetectDataExfiltrationAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectDataExfiltration(IEnumerable<PacketInfo> packets);

        [Obsolete("Use DetectAllSpecializedAnomaliesAsync instead. This sync method blocks on async operations.")]
        List<SpecializedAnomaly> DetectAllSpecializedAnomalies(IEnumerable<PacketInfo> packets);

        // Async versions
        Task<List<SpecializedAnomaly>> DetectVoIPAnomaliesAsync(IEnumerable<PacketInfo> packets);
        Task<List<SpecializedAnomaly>> DetectIoTAnomaliesAsync(IEnumerable<PacketInfo> packets);
        Task<List<SpecializedAnomaly>> DetectDNSTunnelingAnomaliesAsync(IEnumerable<PacketInfo> packets);
        Task<List<SpecializedAnomaly>> DetectCryptominingTrafficAsync(IEnumerable<PacketInfo> packets);
        Task<List<SpecializedAnomaly>> DetectDataExfiltrationAsync(IEnumerable<PacketInfo> packets);
        Task<List<SpecializedAnomaly>> DetectAllSpecializedAnomaliesAsync(IEnumerable<PacketInfo> packets);
    }

    [Obsolete("Use UnifiedAnomalyDetectionService with NetworkAnomaly model instead. This class will be removed in a future version.")]
    public class SpecializedTrafficAnomalyService : ISpecializedTrafficAnomalyService
    {
        private readonly IUnifiedAnomalyDetectionService _unifiedService;

        public SpecializedTrafficAnomalyService(IUnifiedAnomalyDetectionService unifiedService)
        {
            _unifiedService = unifiedService ?? throw new ArgumentNullException(nameof(unifiedService));
        }

        // Sync methods - kept for backward compatibility but marked obsolete
        [Obsolete("Use DetectAllSpecializedAnomaliesAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectAllSpecializedAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectAllAnomaliesAsync(SafePackets(packets)).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        [Obsolete("Use DetectVoIPAnomaliesAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectVoIPAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.VoIP).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        [Obsolete("Use DetectIoTAnomaliesAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectIoTAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.IoT).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        [Obsolete("Use DetectDNSTunnelingAnomaliesAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectDNSTunnelingAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Application).GetAwaiter().GetResult()
                .Where(anomaly => string.Equals(anomaly.Type, "DNS Tunneling", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
        }

        [Obsolete("Use DetectCryptominingTrafficAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectCryptominingTraffic(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security).GetAwaiter().GetResult()
                .Where(anomaly => anomaly.Type.Contains("Cryptomining", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
        }

        [Obsolete("Use DetectDataExfiltrationAsync instead. This sync method blocks on async operations.")]
        public List<SpecializedAnomaly> DetectDataExfiltration(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security).GetAwaiter().GetResult()
                .Where(anomaly =>
                    anomaly.Type.Contains("Exfiltration", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(anomaly.Type, "Beaconing", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
        }

        // Async versions - proper implementations
        public async Task<List<SpecializedAnomaly>> DetectAllSpecializedAnomaliesAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectAllAnomaliesAsync(SafePackets(packets));
            return MapSpecialized(anomalies);
        }

        public async Task<List<SpecializedAnomaly>> DetectVoIPAnomaliesAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.VoIP);
            return MapSpecialized(anomalies);
        }

        public async Task<List<SpecializedAnomaly>> DetectIoTAnomaliesAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.IoT);
            return MapSpecialized(anomalies);
        }

        public async Task<List<SpecializedAnomaly>> DetectDNSTunnelingAnomaliesAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Application);
            return anomalies
                .Where(anomaly => string.Equals(anomaly.Type, "DNS Tunneling", StringComparison.OrdinalIgnoreCase))
                .Select(LegacyAnomalyMapper.ToSpecializedAnomaly)
                .Where(anomaly => anomaly != null)
                .Select(anomaly => anomaly!)
                .OrderByDescending(anomaly => anomaly.Severity)
                .ThenBy(anomaly => anomaly.DetectedAt)
                .ToList();
        }

        public async Task<List<SpecializedAnomaly>> DetectCryptominingTrafficAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security);
            return anomalies
                .Where(anomaly => anomaly.Type.Contains("Cryptomining", StringComparison.OrdinalIgnoreCase))
                .Select(LegacyAnomalyMapper.ToSpecializedAnomaly)
                .Where(anomaly => anomaly != null)
                .Select(anomaly => anomaly!)
                .OrderByDescending(anomaly => anomaly.Severity)
                .ThenBy(anomaly => anomaly.DetectedAt)
                .ToList();
        }

        public async Task<List<SpecializedAnomaly>> DetectDataExfiltrationAsync(IEnumerable<PacketInfo> packets)
        {
            var anomalies = await _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security);
            return anomalies
                .Where(anomaly =>
                    anomaly.Type.Contains("Exfiltration", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(anomaly.Type, "Beaconing", StringComparison.OrdinalIgnoreCase))
                .Select(LegacyAnomalyMapper.ToSpecializedAnomaly)
                .Where(anomaly => anomaly != null)
                .Select(anomaly => anomaly!)
                .OrderByDescending(anomaly => anomaly.Severity)
                .ThenBy(anomaly => anomaly.DetectedAt)
                .ToList();
        }

        private static IEnumerable<PacketInfo> SafePackets(IEnumerable<PacketInfo> packets)
            => packets ?? Enumerable.Empty<PacketInfo>();

        private static List<SpecializedAnomaly> MapSpecialized(IEnumerable<NetworkAnomaly> anomalies)
            => anomalies
                .Select(LegacyAnomalyMapper.ToSpecializedAnomaly)
                .Where(anomaly => anomaly != null)
                .Select(anomaly => anomaly!)
                .OrderByDescending(anomaly => anomaly.Severity)
                .ThenBy(anomaly => anomaly.DetectedAt)
                .ToList();
    }
}
