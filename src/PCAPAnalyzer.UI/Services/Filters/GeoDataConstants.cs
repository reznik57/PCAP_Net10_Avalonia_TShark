using System;
using System.Collections.Frozen;
using System.Collections.Generic;

namespace PCAPAnalyzer.UI.Services.Filters;

/// <summary>
/// Static geographic data for continent and region lookups.
/// Extracted from SmartFilterBuilderService for better organization and reusability.
///
/// Provides:
/// - Continent code → Country codes mapping (EU, AS, NA, SA, AF, OC)
/// - Region name → Continent code lookup
/// - Utility methods for geographic classification
/// </summary>
public static class GeoDataConstants
{
    #region Continent Countries

    /// <summary>
    /// Frozen dictionary mapping continent codes to their country codes.
    /// Using FrozenDictionary for optimal read performance.
    /// </summary>
    public static readonly FrozenDictionary<string, FrozenSet<string>> ContinentCountries =
        BuildContinentCountries();

    /// <summary>
    /// European Union + associated European countries.
    /// </summary>
    private static readonly string[] EuropeCountries =
    [
        "DE", "GB", "FR", "IT", "ES", "NL", "BE", "CH", "AT", "PL", "SE", "NO", "DK", "FI", "IE",
        "PT", "GR", "CZ", "HU", "RO", "BG", "HR", "RS", "SK", "SI", "LT", "LV", "EE", "LU", "MT",
        "IS", "UA", "BY", "MD", "AL", "MK", "BA", "ME", "XK", "AD", "LI", "MC", "SM", "VA"
    ];

    /// <summary>
    /// Asian countries including Middle East and Central Asia.
    /// </summary>
    private static readonly string[] AsiaCountries =
    [
        "CN", "JP", "IN", "KR", "ID", "TH", "MY", "SG", "PH", "VN", "BD", "PK", "AF", "IR", "IQ",
        "SA", "AE", "IL", "JO", "LB", "SY", "YE", "OM", "KW", "QA", "BH", "KZ", "UZ", "TM", "TJ",
        "KG", "MN", "NP", "BT", "LK", "MM", "LA", "KH", "BN", "TL", "MV", "RU", "TR", "GE", "AM",
        "AZ", "CY", "PS", "TW", "HK", "MO", "KP"
    ];

    /// <summary>
    /// North American countries including Central America and Caribbean.
    /// </summary>
    private static readonly string[] NorthAmericaCountries =
    [
        "US", "CA", "MX", "GT", "CU", "HT", "DO", "HN", "NI", "SV", "CR", "PA", "JM", "TT", "BB",
        "BS", "BZ", "GD", "AG", "DM", "KN", "LC", "VC", "GL", "BM", "PR", "VI", "AW", "CW", "SX"
    ];

    /// <summary>
    /// South American countries.
    /// </summary>
    private static readonly string[] SouthAmericaCountries =
    [
        "BR", "AR", "CO", "PE", "VE", "CL", "EC", "BO", "PY", "UY", "GY", "SR", "GF", "FK"
    ];

    /// <summary>
    /// African countries.
    /// </summary>
    private static readonly string[] AfricaCountries =
    [
        "NG", "ET", "EG", "CD", "ZA", "TZ", "KE", "UG", "DZ", "SD", "MA", "AO", "GH", "MZ", "MG",
        "CM", "CI", "NE", "BF", "ML", "MW", "ZM", "SN", "SO", "TD", "ZW", "GN", "RW", "BJ", "TN",
        "BI", "SS", "TG", "SL", "LY", "LR", "MR", "ER", "GM", "BW", "GA", "LS", "GW", "GQ", "MU",
        "SZ", "DJ", "RE", "KM", "CV", "YT", "ST", "SC", "CF", "CG", "NA", "EH"
    ];

    /// <summary>
    /// Oceania countries including Australia and Pacific Islands.
    /// </summary>
    private static readonly string[] OceaniaCountries =
    [
        "AU", "PG", "NZ", "FJ", "SB", "NC", "PF", "VU", "WS", "KI", "FM", "TO", "PW", "CK", "NU",
        "TV", "NR", "MH", "GU", "MP", "AS", "PN", "TK", "NF", "CC", "CX", "WF"
    ];

    private static FrozenDictionary<string, FrozenSet<string>> BuildContinentCountries()
    {
        return new Dictionary<string, FrozenSet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["EU"] = EuropeCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            ["AS"] = AsiaCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            ["NA"] = NorthAmericaCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            ["SA"] = SouthAmericaCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            ["AF"] = AfricaCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            ["OC"] = OceaniaCountries.ToFrozenSet(StringComparer.OrdinalIgnoreCase)
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    #endregion

    #region Region Name Mapping

    /// <summary>
    /// Maps region names (various formats) to continent codes.
    /// Handles common variations like "North America" vs "NorthAmerica".
    /// </summary>
    public static readonly FrozenDictionary<string, string> RegionToContinentCode =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Europe"] = "EU",
            ["European Union"] = "EU",
            ["EU"] = "EU",
            ["Asia"] = "AS",
            ["Asian"] = "AS",
            ["AS"] = "AS",
            ["NorthAmerica"] = "NA",
            ["North America"] = "NA",
            ["NA"] = "NA",
            ["SouthAmerica"] = "SA",
            ["South America"] = "SA",
            ["SA"] = "SA",
            ["Africa"] = "AF",
            ["African"] = "AF",
            ["AF"] = "AF",
            ["Oceania"] = "OC",
            ["Australia"] = "OC",
            ["Pacific"] = "OC",
            ["OC"] = "OC"
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    #endregion

    #region Utility Methods

    /// <summary>
    /// Gets all country codes for a given region name.
    /// Returns empty set if region is not recognized.
    /// </summary>
    /// <param name="regionName">Region name (e.g., "Europe", "Asia", "North America")</param>
    /// <returns>Set of country codes belonging to the region</returns>
    public static FrozenSet<string> GetCountriesForRegion(string regionName)
    {
        if (string.IsNullOrWhiteSpace(regionName))
            return FrozenSet<string>.Empty;

        if (!RegionToContinentCode.TryGetValue(regionName, out var continentCode))
            return FrozenSet<string>.Empty;

        return ContinentCountries.GetValueOrDefault(continentCode) ?? FrozenSet<string>.Empty;
    }

    /// <summary>
    /// Gets all country codes for multiple regions.
    /// Useful for building filters that span multiple regions.
    /// </summary>
    /// <param name="regions">List of region names</param>
    /// <returns>Combined set of all country codes</returns>
    public static HashSet<string> GetCountriesForRegions(IEnumerable<string> regions)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var region in regions)
        {
            if (RegionToContinentCode.TryGetValue(region, out var continentCode) &&
                ContinentCountries.TryGetValue(continentCode, out var countries))
            {
                foreach (var country in countries)
                {
                    result.Add(country);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Gets the continent code for a country code.
    /// Returns null if country is not found in any continent.
    /// </summary>
    /// <param name="countryCode">ISO 3166-1 alpha-2 country code</param>
    /// <returns>Continent code (EU, AS, NA, SA, AF, OC) or null</returns>
    public static string? GetContinentForCountry(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        foreach (var (continentCode, countries) in ContinentCountries)
        {
            if (countries.Contains(countryCode))
                return continentCode;
        }

        return null;
    }

    /// <summary>
    /// Checks if a country code belongs to a specific region.
    /// </summary>
    public static bool IsCountryInRegion(string countryCode, string regionName)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || string.IsNullOrWhiteSpace(regionName))
            return false;

        var countries = GetCountriesForRegion(regionName);
        return countries.Contains(countryCode);
    }

    /// <summary>
    /// Gets all valid continent codes.
    /// </summary>
    public static IEnumerable<string> GetAllContinentCodes() => ContinentCountries.Keys;

    /// <summary>
    /// Gets all valid region names (including aliases).
    /// </summary>
    public static IEnumerable<string> GetAllRegionNames() => RegionToContinentCode.Keys;

    #endregion
}
