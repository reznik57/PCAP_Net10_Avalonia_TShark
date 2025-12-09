using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.GeoIP;

/// <summary>
/// ISO 3166-1 alpha-2 country code validation and friendly name lookup.
/// Extracted from UnifiedGeoIPService to reduce file size and centralize country data.
/// </summary>
public static class ISO3166Data
{
    /// <summary>
    /// ISO 3166-1 alpha-2 country codes for validation.
    /// Invalid codes from malformed GeoIP data are mapped to "XX" (Unknown).
    /// </summary>
    public static readonly HashSet<string> ValidCountryCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        // A
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
        // B
        "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ",
        // C
        "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ",
        // D
        "DE", "DJ", "DK", "DM", "DO", "DZ",
        // E
        "EC", "EE", "EG", "EH", "ER", "ES", "ET",
        // F
        "FI", "FJ", "FK", "FM", "FO", "FR",
        // G
        "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY",
        // H
        "HK", "HM", "HN", "HR", "HT", "HU",
        // I
        "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
        // J
        "JE", "JM", "JO", "JP",
        // K
        "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
        // L
        "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
        // M
        "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
        // N
        "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
        // O
        "OM",
        // P
        "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
        // Q
        "QA",
        // R
        "RE", "RO", "RS", "RU", "RW",
        // S
        "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ",
        // T
        "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ",
        // U
        "UA", "UG", "UM", "US", "UY", "UZ",
        // V
        "VA", "VC", "VE", "VG", "VI", "VN", "VU",
        // W
        "WF", "WS",
        // Y
        "YE", "YT",
        // Z
        "ZA", "ZM", "ZW",
        // Special codes used internally
        "XX", // Unknown
        "INT", "INTERNAL", // Internal/private network
        "IP6", "IP6_LINK", "IP6_LOOP", "IP6_MCAST", "IP6_ULA", "IP6_SITE", "IP6_ANY", "IP6_GLOBAL", "IP6_MAPPED", // IPv6 types
        "PRIV", "PRV", "LOCAL", "LAN" // Private network aliases
    };

    /// <summary>
    /// Validates and normalizes a country code.
    /// Returns "XX" (Unknown) for invalid or malformed codes.
    /// </summary>
    public static string ValidateCountryCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return "XX";

        var normalized = code.Trim().ToUpperInvariant();
        return ValidCountryCodes.Contains(normalized) ? normalized : "XX";
    }

    /// <summary>
    /// Checks if a code is a valid ISO 3166-1 alpha-2 or internal code.
    /// </summary>
    public static bool IsValidCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;
        return ValidCountryCodes.Contains(code.Trim().ToUpperInvariant());
    }

    /// <summary>
    /// Gets friendly display name for country/pseudo-country codes.
    /// Returns the code itself for standard ISO country codes.
    /// </summary>
    public static string GetFriendlyName(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return "Unknown";

        return code switch
        {
            // IPv4 Private/Internal
            "Internal" or "PRIV" or "PRV" or "INT" or "INTERNAL" => "Internal Network",
            "LOCAL" or "LAN" => "Local Network",

            // IPv6 Specific Types
            "IP6" => "IPv6 Traffic",
            "IP6_LINK" => "IPv6 Link-Local",
            "IP6_LOOP" => "IPv6 Loopback",
            "IP6_MCAST" => "IPv6 Multicast",
            "IP6_GLOBAL" => "IPv6 Global",
            "IP6_ULA" => "IPv6 Unique Local",
            "IP6_SITE" => "IPv6 Site-Local",
            "IP6_ANY" => "IPv6 Anycast",
            "IP6_MAPPED" => "IPv6 Mapped",

            // Unknown
            "XX" => "Unknown",

            // Default: return the code as-is (regular country codes)
            _ => code
        };
    }
}
