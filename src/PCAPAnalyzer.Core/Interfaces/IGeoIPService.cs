using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Service interface for GeoIP location lookups and traffic analysis.
    /// Implementations provide geographic data for IP addresses and analyze traffic patterns.
    /// </summary>
    public interface IGeoIPService : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Gets geographic location for an IP address asynchronously.
        /// </summary>
        Task<GeoLocation?> GetLocationAsync(string ipAddress);

        /// <summary>
        /// DEPRECATED: Gets geographic location synchronously (blocks calling thread).
        /// Use GetLocationAsync() instead to avoid blocking.
        /// </summary>
        [Obsolete("Use GetLocationAsync() instead to avoid blocking the calling thread.")]
        GeoLocation? GetLocation(string ipAddress);

        /// <summary>
        /// Analyzes network traffic and groups by country.
        /// </summary>
        /// <param name="packets">Packet collection to analyze</param>
        /// <param name="progressStage">Optional UI progress stage for timing instrumentation</param>
        Task<Dictionary<string, CountryTrafficStatistics>> AnalyzeCountryTrafficAsync(IEnumerable<PacketInfo> packets, object? progressStage = null);

        /// <summary>
        /// Analyzes traffic flows between countries.
        /// </summary>
        /// <param name="packets">Packet collection to analyze</param>
        /// <param name="progressStage">Optional UI progress stage for timing instrumentation</param>
        Task<List<TrafficFlowDirection>> AnalyzeTrafficFlowsAsync(IEnumerable<PacketInfo> packets, object? progressStage = null);

        /// <summary>
        /// Gets list of high-risk countries with threat profiles.
        /// </summary>
        Task<List<CountryRiskProfile>> GetHighRiskCountriesAsync();

        /// <summary>
        /// Checks if an IP address is public (routable on the Internet).
        /// </summary>
        bool IsPublicIP(string ipAddress);

        /// <summary>
        /// Checks if a country code is classified as high-risk.
        /// </summary>
        bool IsHighRiskCountry(string countryCode);

        /// <summary>
        /// Initializes the GeoIP service and loads necessary databases.
        /// </summary>
        Task InitializeAsync();

        /// <summary>
        /// Updates the GeoIP database to the latest version.
        /// </summary>
        Task<bool> UpdateDatabaseAsync();
    }
}
