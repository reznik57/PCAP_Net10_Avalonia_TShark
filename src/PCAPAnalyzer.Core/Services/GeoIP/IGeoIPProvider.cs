using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.GeoIP
{
    /// <summary>
    /// Interface for GeoIP data providers using the Strategy pattern.
    /// Implementations can use different data sources (MMDB, SQLite, API, etc.)
    /// </summary>
    public interface IGeoIPProvider
    {
        /// <summary>
        /// Provider name for identification
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Initialize the provider with necessary resources
        /// </summary>
        Task<bool> InitializeAsync();

        /// <summary>
        /// Lookup geolocation information for an IP address
        /// </summary>
        Task<GeoLocation?> LookupAsync(string ipAddress);

        /// <summary>
        /// Check if the provider is ready to serve requests
        /// </summary>
        bool IsReady { get; }

        /// <summary>
        /// Get database statistics (if applicable)
        /// </summary>
        Task<GeoIPDatabaseStats?> GetStatsAsync();

        /// <summary>
        /// Cleanup resources
        /// </summary>
        Task DisposeAsync();
    }

    /// <summary>
    /// GeoIP database statistics
    /// </summary>
    public class GeoIPDatabaseStats
    {
        public string Provider { get; set; } = string.Empty;
        public int TotalRecords { get; set; }
        public System.DateTime LastUpdate { get; set; }
        public bool IsLoaded { get; set; }
        public long DatabaseSizeBytes { get; set; }
    }
}
