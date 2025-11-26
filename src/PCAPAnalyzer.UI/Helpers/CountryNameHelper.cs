using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PCAPAnalyzer.UI.Helpers
{
    internal static class CountryNameHelper
    {
        private static readonly Dictionary<string, string> CustomCodeToName = new(StringComparer.OrdinalIgnoreCase)
        {
            // IPv4 Private/Internal
            ["PRIV"] = "Internal Network",
            ["PRV"] = "Internal Network",
            ["INT"] = "Internal Network",

            // IPv6 Specific Types
            ["IP6"] = "IPv6 Traffic",
            ["IP6_LINK"] = "IPv6 Link-Local",
            ["IP6_LOOP"] = "IPv6 Loopback",
            ["IP6_MCAST"] = "IPv6 Multicast",
            ["IP6_GLOBAL"] = "IPv6 Global",
            ["IP6_ULA"] = "IPv6 Unique Local",
            ["IP6_SITE"] = "IPv6 Site-Local",
            ["IP6_ANY"] = "IPv6 Anycast",

            // Generic/Unknown
            ["XX"] = "Unknown",
            ["XK"] = "Kosovo"
        };

        private static readonly Dictionary<string, string> CustomNameToCode = new(StringComparer.OrdinalIgnoreCase)
        {
            // IPv4 Private/Internal
            ["Internal Network"] = "PRIV",
            ["Internal"] = "PRIV",
            ["Private Network"] = "PRIV",
            ["Local" ] = "PRIV",
            ["Local Network"] = "PRIV",

            // IPv6 Types
            ["IPv6 Traffic"] = "IP6",
            ["IPv6"] = "IP6",
            ["IPv6 Space"] = "IP6",
            ["IPv6 Link-Local"] = "IP6_LINK",
            ["IPv6 Loopback"] = "IP6_LOOP",
            ["IPv6 Multicast"] = "IP6_MCAST",
            ["IPv6 Global"] = "IP6_GLOBAL",
            ["IPv6 Unique Local"] = "IP6_ULA",
            ["IPv6 Site-Local"] = "IP6_SITE",
            ["IPv6 Anycast"] = "IP6_ANY",

            // Generic
            ["Unknown"] = "XX",
            ["Kosovo"] = "XK"
        };

        private static readonly Lazy<Dictionary<string, string>> CodeToNameLazy = new(BuildCodeToNameMap);
        private static readonly Lazy<Dictionary<string, string>> NameToCodeLazy = new(BuildNameToCodeMap);

        private static Dictionary<string, string> BuildCodeToNameMap()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var culture in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
            {
                try
                {
                    var region = new RegionInfo(culture.Name);
                    map[region.TwoLetterISORegionName] = region.EnglishName;
                }
                catch (ArgumentException)
                {
                    // Ignore cultures without region information
                }
            }

            foreach (var (code, name) in CustomCodeToName)
            {
                map[code] = name;
            }

            return map;
        }

        private static Dictionary<string, string> BuildNameToCodeMap()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var culture in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
            {
                try
                {
                    var region = new RegionInfo(culture.Name);
                    map[region.EnglishName] = region.TwoLetterISORegionName;
                    map[region.NativeName] = region.TwoLetterISORegionName;
                    map[region.DisplayName] = region.TwoLetterISORegionName;
                }
                catch (ArgumentException)
                {
                    // Ignore cultures without region information
                }
            }

            foreach (var (name, code) in CustomNameToCode)
            {
                map[name] = code;
            }

            return map;
        }

        private static string NormalizeInternalCode(string code)
        {
            return code switch
            {
                "PRV" => "PRIV",
                "INT" => "PRIV",
                "PRIVATE" => "PRIV",
                "INTERNAL" => "PRIV",
                _ => code
            };
        }

        public static string GetDisplayName(string? countryCode, string? fallbackName = null)
        {
            if (string.IsNullOrWhiteSpace(countryCode))
            {
                return fallbackName ?? string.Empty;
            }

            var normalizedCode = NormalizeInternalCode(countryCode.Trim().ToUpperInvariant());

            if (CustomCodeToName.TryGetValue(normalizedCode, out var customName))
            {
                return customName;
            }

            if (CodeToNameLazy.Value.TryGetValue(normalizedCode, out var name))
            {
                return name;
            }

            if (!string.IsNullOrWhiteSpace(fallbackName) &&
                !string.Equals(fallbackName, normalizedCode, StringComparison.OrdinalIgnoreCase))
            {
                return fallbackName;
            }

            return normalizedCode;
        }

        public static string GetDisplayCode(string? countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode))
            {
                return "IPv6";
            }

            var normalized = countryCode.Trim().ToUpperInvariant();

            return normalized switch
            {
                // IPv4 Private/Internal
                "PRIV" or "PRV" or "INT" or "PRIVATE" => "INT",

                // IPv6 Specific Types (show descriptive codes)
                "IP6_LINK" => "IPv6-LL",
                "IP6_LOOP" => "IPv6-LB",
                "IP6_MCAST" => "IPv6-MC",
                "IP6_GLOBAL" => "IPv6-GL",
                "IP6_ULA" => "IPv6-ULA",
                "IP6_SITE" => "IPv6-SL",
                "IP6_ANY" => "IPv6-ANY",

                // Generic IPv6
                "IP6" or "??" or "XX" => "IPv6",

                _ => normalized
            };
        }

        public static string GetCode(string? countryNameOrCode)
        {
            if (string.IsNullOrWhiteSpace(countryNameOrCode))
            {
                return "IP6";
            }

            var trimmed = countryNameOrCode.Trim();

            if (trimmed.Length >= 2 && trimmed.All(char.IsLetter))
            {
                var normalized = trimmed.ToUpperInvariant();
                if (normalized is "XX" or "??")
                {
                    return "IP6";
                }

                return NormalizeInternalCode(normalized);
            }

            if (CustomNameToCode.TryGetValue(trimmed, out var customCode))
            {
                return NormalizeInternalCode(customCode);
            }

            if (NameToCodeLazy.Value.TryGetValue(trimmed, out var code))
            {
                return NormalizeInternalCode(code.ToUpperInvariant());
            }

            return "IP6";
        }
    }
}
