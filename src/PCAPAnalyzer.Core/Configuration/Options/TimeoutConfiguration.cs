using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Configuration.Options
{
    /// <summary>
    /// Configuration for timeout-related settings.
    /// Loaded from config/timeouts.json via IOptions pattern.
    /// </summary>
    public class TimeoutConfiguration
    {
        /// <summary>
        /// TShark process timeout in milliseconds. Default: 2 minutes.
        /// </summary>
        public int TSharkProcessMs { get; set; } = 120_000;

        /// <summary>
        /// GeoIP lookup timeout in milliseconds. Default: 5 seconds.
        /// </summary>
        public int GeoIPLookupMs { get; set; } = 5_000;

        /// <summary>
        /// GeoIP timeout based on packet count thresholds.
        /// Key: packet count threshold, Value: timeout in seconds.
        /// </summary>
        public Dictionary<int, int> GeoIPTimeoutByPacketCount { get; set; } = new()
        {
            { 250_000, 12 },
            { 1_000_000, 20 },
            { 2_000_000, 30 }
        };

        /// <summary>
        /// UI render delay in milliseconds. Default: 100ms.
        /// </summary>
        public int RenderDelayMs { get; set; } = 100;

        /// <summary>
        /// Export status message auto-clear delay in milliseconds.
        /// </summary>
        public int ExportStatusClearMs { get; set; } = 5_000;

        /// <summary>
        /// Analysis cache expiration in days. Default: 30 days.
        /// </summary>
        public int AnalysisCacheExpirationDays { get; set; } = 30;

        /// <summary>
        /// Progress report interval in milliseconds.
        /// </summary>
        public int ProgressReportIntervalMs { get; set; } = 500;

        /// <summary>
        /// Gets the appropriate GeoIP timeout for a given packet count.
        /// </summary>
        public int GetGeoIPTimeoutSeconds(int packetCount)
        {
            foreach (var threshold in GeoIPTimeoutByPacketCount)
            {
                if (packetCount > threshold.Key)
                    return threshold.Value;
            }
            return GeoIPLookupMs / 1000;
        }
    }
}
