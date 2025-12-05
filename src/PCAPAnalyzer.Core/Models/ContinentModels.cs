using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    /// <summary>
    /// Represents a continent with its countries and geographic data
    /// </summary>
    public class Continent
    {
        public string Code { get; set; } = "";
        public string Name { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public double CenterLatitude { get; set; }
        public double CenterLongitude { get; set; }
        public double BoundingBoxNorth { get; set; }
        public double BoundingBoxSouth { get; set; }
        public double BoundingBoxEast { get; set; }
        public double BoundingBoxWest { get; set; }
        public List<Country> Countries { get; set; } = new();
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public Dictionary<string, long> ProtocolBreakdown { get; set; } = new();
        public string PrimaryColor { get; set; } = "#4A90E2";
        public string AccentColor { get; set; } = "#357ABD";
    }

    /// <summary>
    /// Represents a country with enhanced geographic and network data
    /// </summary>
    public class Country
    {
        public string Code { get; set; } = "";
        public string Name { get; set; } = "";
        public string ContinentCode { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public string Capital { get; set; } = "";
        public long Population { get; set; }
        public double Area { get; set; } // in km²
        public long TotalPackets { get; set; }
        public long IncomingPackets { get; set; }
        public long OutgoingPackets { get; set; }
        public long TotalBytes { get; set; }
        public Dictionary<string, long> ProtocolBreakdown { get; set; } = new();
        public List<string> TopPorts { get; set; } = new();
        public double ThreatLevel { get; set; } // 0.0 to 1.0
        public bool IsHighRisk { get; set; }
        public DateTime LastActivity { get; set; }
    }

    /// <summary>
    /// Represents a traffic flow between countries/continents
    /// </summary>
    public class GeographicTrafficFlow
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string SourceCountryCode { get; set; } = "";
        public string DestinationCountryCode { get; set; } = "";
        public double SourceLatitude { get; set; }
        public double SourceLongitude { get; set; }
        public double DestinationLatitude { get; set; }
        public double DestinationLongitude { get; set; }
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public Protocol PrimaryProtocol { get; set; }
        public double Intensity { get; set; } // 0.0 to 1.0
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public bool IsActive { get; set; }
        public string FlowType { get; set; } = "Normal"; // Normal, Attack, Suspicious
        public double AnimationProgress { get; set; } // For animated flows
    }

    /// <summary>
    /// Heat map data for geographic visualization
    /// </summary>
    public class GeoHeatMapPoint
    {
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public double Intensity { get; set; } // 0.0 to 1.0
        public string CountryCode { get; set; } = "";
        public long PacketCount { get; set; }
        public string PrimaryProtocol { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Visual style for continent/country rendering
    /// </summary>
    public class MapVisualizationStyle
    {
        public string Name { get; set; } = "Default";
        public bool ShowContinentBorders { get; set; } = true;
        public bool ShowCountryBorders { get; set; } = true;
        public bool ShowTrafficFlows { get; set; } = true;
        public bool ShowHeatMap { get; set; }
        public bool ShowParticles { get; set; } = true;
        public bool ShowLabels { get; set; } = true;
        public bool ShowStatistics { get; set; } = true;
        public bool AnimateFlows { get; set; } = true;
        public bool Use3DEffect { get; set; }
        public double FlowCurvature { get; set; } = 0.3; // How curved the flow lines are
        public int ParticleCount { get; set; } = 100;
        public double AnimationSpeed { get; set; } = 1.0;
        public string ColorScheme { get; set; } = "Default"; // Default, Dark, Light, Cyber, Threat
    }

    /// <summary>
    /// Static data for continents and their properties
    /// </summary>
    public static class ContinentData
    {
        public static readonly Dictionary<string, Continent> Continents = new()
        {
            ["AF"] = new Continent
            {
                Code = "AF",
                Name = "Africa",
                DisplayName = "Africa",
                CenterLatitude = -1.0,
                CenterLongitude = 20.0,
                BoundingBoxNorth = 37.0,
                BoundingBoxSouth = -35.0,
                BoundingBoxEast = 52.0,
                BoundingBoxWest = -18.0,
                PrimaryColor = "#E67E22",
                AccentColor = "#D35400"
            },
            ["AS"] = new Continent
            {
                Code = "AS",
                Name = "Asia",
                DisplayName = "Asia",
                CenterLatitude = 30.0,
                CenterLongitude = 90.0,
                BoundingBoxNorth = 70.0,
                BoundingBoxSouth = -10.0,
                BoundingBoxEast = 150.0,
                BoundingBoxWest = 40.0,
                PrimaryColor = "#E74C3C",
                AccentColor = "#C0392B"
            },
            ["EU"] = new Continent
            {
                Code = "EU",
                Name = "Europe",
                DisplayName = "Europe",
                CenterLatitude = 50.0,
                CenterLongitude = 10.0,
                BoundingBoxNorth = 71.0,
                BoundingBoxSouth = 36.0,
                BoundingBoxEast = 40.0,
                BoundingBoxWest = -10.0,
                PrimaryColor = "#3498DB",
                AccentColor = "#2980B9"
            },
            ["NA"] = new Continent
            {
                Code = "NA",
                Name = "North America",
                DisplayName = "North America",
                CenterLatitude = 50.0,
                CenterLongitude = -100.0,
                BoundingBoxNorth = 75.0,
                BoundingBoxSouth = 15.0,
                BoundingBoxEast = -50.0,
                BoundingBoxWest = -170.0,
                PrimaryColor = "#2ECC71",
                AccentColor = "#27AE60"
            },
            ["SA"] = new Continent
            {
                Code = "SA",
                Name = "South America",
                DisplayName = "South America",
                CenterLatitude = -15.0,
                CenterLongitude = -60.0,
                BoundingBoxNorth = 14.0,
                BoundingBoxSouth = -56.0,
                BoundingBoxEast = -34.0,
                BoundingBoxWest = -82.0,
                PrimaryColor = "#F39C12",
                AccentColor = "#E67E22"
            },
            ["OC"] = new Continent
            {
                Code = "OC",
                Name = "Oceania",
                DisplayName = "Oceania",
                CenterLatitude = -25.0,
                CenterLongitude = 140.0,
                BoundingBoxNorth = 29.0,
                BoundingBoxSouth = -53.0,
                BoundingBoxEast = 180.0,
                BoundingBoxWest = 112.0,
                PrimaryColor = "#9B59B6",
                AccentColor = "#8E44AD"
            },
            ["INT"] = new Continent
            {
                Code = "INT",
                Name = "Internal",
                DisplayName = "Internal Network",
                CenterLatitude = 0.0,
                CenterLongitude = 0.0,
                BoundingBoxNorth = 0.0,
                BoundingBoxSouth = 0.0,
                BoundingBoxEast = 0.0,
                BoundingBoxWest = 0.0,
                PrimaryColor = "#6C757D",
                AccentColor = "#495057"
            },
            ["IP6"] = new Continent
            {
                Code = "IP6",
                Name = "IPv6",
                DisplayName = "IPv6 Space",
                CenterLatitude = 0.0,
                CenterLongitude = 0.0,
                BoundingBoxNorth = 0.0,
                BoundingBoxSouth = 0.0,
                BoundingBoxEast = 0.0,
                BoundingBoxWest = 0.0,
                PrimaryColor = "#6366F1",
                AccentColor = "#4338CA"
            }
        };

        /// <summary>
        /// Get country to continent mapping
        /// </summary>
        public static readonly Dictionary<string, string> CountryToContinentMap = new()
        {
            // Europe
            ["DE"] = "EU", ["GB"] = "EU", ["FR"] = "EU", ["IT"] = "EU", ["ES"] = "EU",
            ["NL"] = "EU", ["BE"] = "EU", ["CH"] = "EU", ["AT"] = "EU", ["PL"] = "EU",
            ["SE"] = "EU", ["NO"] = "EU", ["DK"] = "EU", ["FI"] = "EU", ["IE"] = "EU",
            ["PT"] = "EU", ["GR"] = "EU", ["CZ"] = "EU", ["HU"] = "EU", ["RO"] = "EU",
            ["BG"] = "EU", ["HR"] = "EU", ["RS"] = "EU", ["SK"] = "EU", ["SI"] = "EU",
            ["LT"] = "EU", ["LV"] = "EU", ["EE"] = "EU", ["LU"] = "EU", ["MT"] = "EU",
            ["IS"] = "EU", ["UA"] = "EU", ["BY"] = "EU", ["MD"] = "EU", ["AL"] = "EU",
            ["MK"] = "EU", ["BA"] = "EU", ["ME"] = "EU", ["XK"] = "EU", ["AD"] = "EU",
            ["LI"] = "EU", ["MC"] = "EU", ["SM"] = "EU", ["VA"] = "EU",
            
            // Asia
            ["CN"] = "AS", ["JP"] = "AS", ["IN"] = "AS", ["KR"] = "AS", ["ID"] = "AS",
            ["TH"] = "AS", ["MY"] = "AS", ["SG"] = "AS", ["PH"] = "AS", ["VN"] = "AS",
            ["BD"] = "AS", ["PK"] = "AS", ["AF"] = "AS", ["IR"] = "AS", ["IQ"] = "AS",
            ["SA"] = "AS", ["AE"] = "AS", ["IL"] = "AS", ["JO"] = "AS", ["LB"] = "AS",
            ["SY"] = "AS", ["YE"] = "AS", ["OM"] = "AS", ["KW"] = "AS", ["QA"] = "AS",
            ["BH"] = "AS", ["KZ"] = "AS", ["UZ"] = "AS", ["TM"] = "AS", ["TJ"] = "AS",
            ["KG"] = "AS", ["MN"] = "AS", ["NP"] = "AS", ["BT"] = "AS", ["LK"] = "AS",
            ["MM"] = "AS", ["LA"] = "AS", ["KH"] = "AS", ["BN"] = "AS", ["TL"] = "AS",
            ["MV"] = "AS", ["RU"] = "AS", ["TR"] = "AS", ["GE"] = "AS", ["AM"] = "AS",
            ["AZ"] = "AS", ["CY"] = "AS", ["PS"] = "AS", ["TW"] = "AS", ["HK"] = "AS",
            ["MO"] = "AS", ["KP"] = "AS",
            
            // North America
            ["US"] = "NA", ["CA"] = "NA", ["MX"] = "NA", ["GT"] = "NA", ["CU"] = "NA",
            ["HT"] = "NA", ["DO"] = "NA", ["HN"] = "NA", ["NI"] = "NA", ["SV"] = "NA",
            ["CR"] = "NA", ["PA"] = "NA", ["JM"] = "NA", ["TT"] = "NA", ["BB"] = "NA",
            ["BS"] = "NA", ["BZ"] = "NA", ["GD"] = "NA", ["AG"] = "NA", ["DM"] = "NA",
            ["KN"] = "NA", ["LC"] = "NA", ["VC"] = "NA", ["GL"] = "NA", ["BM"] = "NA",
            ["PR"] = "NA", ["VI"] = "NA", ["AW"] = "NA", ["CW"] = "NA", ["SX"] = "NA",
            
            // South America
            ["BR"] = "SA", ["AR"] = "SA", ["CO"] = "SA", ["PE"] = "SA", ["VE"] = "SA",
            ["CL"] = "SA", ["EC"] = "SA", ["BO"] = "SA", ["PY"] = "SA", ["UY"] = "SA",
            ["GY"] = "SA", ["SR"] = "SA", ["GF"] = "SA", ["FK"] = "SA",
            
            // Africa
            ["NG"] = "AF", ["ET"] = "AF", ["EG"] = "AF", ["CD"] = "AF", ["ZA"] = "AF",
            ["TZ"] = "AF", ["KE"] = "AF", ["UG"] = "AF", ["DZ"] = "AF", ["SD"] = "AF",
            ["MA"] = "AF", ["AO"] = "AF", ["GH"] = "AF", ["MZ"] = "AF", ["MG"] = "AF",
            ["CM"] = "AF", ["CI"] = "AF", ["NE"] = "AF", ["BF"] = "AF", ["ML"] = "AF",
            ["MW"] = "AF", ["ZM"] = "AF", ["SN"] = "AF", ["SO"] = "AF", ["TD"] = "AF",
            ["ZW"] = "AF", ["GN"] = "AF", ["RW"] = "AF", ["BJ"] = "AF", ["TN"] = "AF",
            ["BI"] = "AF", ["SS"] = "AF", ["TG"] = "AF", ["SL"] = "AF", ["LY"] = "AF",
            ["LR"] = "AF", ["MR"] = "AF", ["ER"] = "AF", ["GM"] = "AF", ["BW"] = "AF",
            ["GA"] = "AF", ["LS"] = "AF", ["GW"] = "AF", ["GQ"] = "AF", ["MU"] = "AF",
            ["SZ"] = "AF", ["DJ"] = "AF", ["RE"] = "AF", ["KM"] = "AF", ["CV"] = "AF",
            ["YT"] = "AF", ["ST"] = "AF", ["SC"] = "AF", ["CF"] = "AF", ["CG"] = "AF",
            ["NA"] = "AF", ["EH"] = "AF",
            
            // Oceania
            ["AU"] = "OC", ["PG"] = "OC", ["NZ"] = "OC", ["FJ"] = "OC", ["SB"] = "OC",
            ["NC"] = "OC", ["PF"] = "OC", ["VU"] = "OC", ["WS"] = "OC", ["KI"] = "OC",
            ["FM"] = "OC", ["TO"] = "OC", ["PW"] = "OC", ["CK"] = "OC", ["NU"] = "OC",
            ["TV"] = "OC", ["NR"] = "OC", ["MH"] = "OC", ["GU"] = "OC", ["MP"] = "OC",
            ["AS"] = "OC", ["PN"] = "OC", ["TK"] = "OC", ["NF"] = "OC", ["CC"] = "OC",
            ["CX"] = "OC", ["WF"] = "OC",

            // Special buckets
            ["PRIV"] = "INT",
            ["PRV"] = "INT",
            ["INT"] = "INT",
            ["IP6"] = "IP6"

            // Note: Antarctica (AQ) is intentionally excluded
        };

        /// <summary>
        /// Gets the continent code for a country code.
        /// Returns "Unknown" if not found.
        /// </summary>
        public static string GetContinentCode(string countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode))
                return "Unknown";

            return CountryToContinentMap.TryGetValue(countryCode.ToUpperInvariant(), out var code)
                ? code
                : "Unknown";
        }

        /// <summary>
        /// Gets the continent name for a country code.
        /// Returns "Unknown" if not found.
        /// </summary>
        public static string GetContinentName(string countryCode)
        {
            var code = GetContinentCode(countryCode);
            if (code == "Unknown")
                return "Unknown";

            return Continents.TryGetValue(code, out var continent)
                ? continent.Name
                : code; // Return code if continent not defined
        }

        /// <summary>
        /// Gets the continent display name for a country code.
        /// Handles special cases like Internal and IPv6.
        /// Uses abbreviated names suitable for UI display (e.g., "N. America" instead of "North America").
        /// </summary>
        public static string GetContinentDisplayName(string countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode))
                return "Unknown";

            var upper = countryCode.ToUpperInvariant();

            // Handle special cases first
            if (upper is "INT" or "PRIV" or "PRV" or "INTERNAL")
                return "Internal";
            if (upper is "IP6" or "IP6_LINK" or "IP6_LOOP" or "IP6_MCAST" or
                "IP6_GLOBAL" or "IP6_ULA" or "IP6_SITE" or "IP6_ANY" or "IPV6")
                return "IPv6";

            // Get continent code, then map to abbreviated display name
            var code = GetContinentCode(countryCode);
            return code switch
            {
                "NA" => "N. America",
                "SA" => "S. America",
                "EU" => "Europe",
                "AS" => "Asia",
                "AF" => "Africa",
                "OC" => "Oceania",
                "INT" => "Internal",
                "IP6" => "IPv6",
                _ => Continents.TryGetValue(code, out var continent) ? continent.Name : "Unknown"
            };
        }
    }
}

