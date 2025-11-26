using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    [Obsolete("Use IUnifiedAnomalyDetectionService with NetworkAnomaly model instead. This interface will be removed in a future version.")]
    public interface ISpecializedTrafficAnomalyService
    {
        List<SpecializedAnomaly> DetectVoIPAnomalies(IEnumerable<PacketInfo> packets);
        List<SpecializedAnomaly> DetectIoTAnomalies(IEnumerable<PacketInfo> packets);
        List<SpecializedAnomaly> DetectDNSTunnelingAnomalies(IEnumerable<PacketInfo> packets);
        List<SpecializedAnomaly> DetectCryptominingTraffic(IEnumerable<PacketInfo> packets);
        List<SpecializedAnomaly> DetectDataExfiltration(IEnumerable<PacketInfo> packets);
        List<SpecializedAnomaly> DetectAllSpecializedAnomalies(IEnumerable<PacketInfo> packets);
    }

    [Obsolete("Use UnifiedAnomalyDetectionService with NetworkAnomaly model instead. This class will be removed in a future version.")]
    public class SpecializedTrafficAnomalyService : ISpecializedTrafficAnomalyService
    {
        private readonly IUnifiedAnomalyDetectionService _unifiedService;

        public SpecializedTrafficAnomalyService(IUnifiedAnomalyDetectionService unifiedService)
        {
            _unifiedService = unifiedService ?? throw new ArgumentNullException(nameof(unifiedService));
        }

        public List<SpecializedAnomaly> DetectAllSpecializedAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectAllAnomaliesAsync(SafePackets(packets)).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        public List<SpecializedAnomaly> DetectVoIPAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.VoIP).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        public List<SpecializedAnomaly> DetectIoTAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.IoT).GetAwaiter().GetResult();
            return MapSpecialized(anomalies);
        }

        public List<SpecializedAnomaly> DetectDNSTunnelingAnomalies(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Application).GetAwaiter().GetResult()
                .Where(anomaly => string.Equals(anomaly.Type, "DNS Tunneling", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
        }

        public List<SpecializedAnomaly> DetectCryptominingTraffic(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security).GetAwaiter().GetResult()
                .Where(anomaly => anomaly.Type.Contains("Cryptomining", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
        }

        public List<SpecializedAnomaly> DetectDataExfiltration(IEnumerable<PacketInfo> packets)
        {
            var anomalies = _unifiedService.DetectByCategoryAsync(SafePackets(packets), AnomalyCategory.Security).GetAwaiter().GetResult()
                .Where(anomaly =>
                    anomaly.Type.Contains("Exfiltration", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(anomaly.Type, "Beaconing", StringComparison.OrdinalIgnoreCase));
            return MapSpecialized(anomalies);
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
