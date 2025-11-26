using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Configuration.Options
{
    /// <summary>
    /// Configuration for country-related settings.
    /// Loaded from config/countries.json via IOptions pattern.
    /// </summary>
    public class CountryConfiguration
    {
        /// <summary>
        /// ISO 3166-1 alpha-2 country codes considered high-risk.
        /// </summary>
        public HashSet<string> HighRiskCountries { get; set; } = new();

        /// <summary>
        /// Country code to continent name mappings.
        /// </summary>
        public Dictionary<string, string> ContinentMappings { get; set; } = new();
    }
}
