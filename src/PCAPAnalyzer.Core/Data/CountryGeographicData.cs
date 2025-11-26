using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Data
{
    /// <summary>
    /// Geographic coordinate data for countries within continents.
    /// Coordinates are normalized (0-1) within continent bounds for rendering.
    /// </summary>
    public static class CountryGeographicData
    {
        /// <summary>
        /// Get normalized position of country within its continent.
        /// Returns (x, y) where 0,0 is top-left and 1,1 is bottom-right of continent bounds.
        /// </summary>
        public static (double x, double y)? GetCountryPosition(string countryCode, string continentCode)
        {
            return continentCode switch
            {
                "EU" => GetEuropePosition(countryCode),
                "AS" => GetAsiaPosition(countryCode),
                "AF" => GetAfricaPosition(countryCode),
                "NA" => GetNorthAmericaPosition(countryCode),
                "SA" => GetSouthAmericaPosition(countryCode),
                "OC" => GetOceaniaPosition(countryCode),
                _ => null
            };
        }

        /// <summary>
        /// Get country flag emoji from ISO 3166-1 alpha-2 code.
        /// </summary>
        public static string GetCountryFlag(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode) || countryCode.Length != 2)
                return "🌍";

            // Convert country code to regional indicator symbols
            // A = U+1F1E6, Z = U+1F1FF
            var first = char.ConvertFromUtf32(0x1F1E6 + (countryCode[0] - 'A'));
            var second = char.ConvertFromUtf32(0x1F1E6 + (countryCode[1] - 'A'));
            return first + second;
        }

        /// <summary>
        /// Get continent code for a country.
        /// Returns "EU", "AS", "AF", "NA", "SA", "OC" or null if unknown.
        /// </summary>
        public static string? GetContinentForCountry(string countryCode)
        {
            if (GetEuropePosition(countryCode) != null) return "EU";
            if (GetAsiaPosition(countryCode) != null) return "AS";
            if (GetAfricaPosition(countryCode) != null) return "AF";
            if (GetNorthAmericaPosition(countryCode) != null) return "NA";
            if (GetSouthAmericaPosition(countryCode) != null) return "SA";
            if (GetOceaniaPosition(countryCode) != null) return "OC";
            return null;
        }

        #region Europe Positions (Normalized 0-1 within Europe bounds)

        private static (double x, double y)? GetEuropePosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                // Western Europe
                ["PT"] = (0.05, 0.55),   // Portugal - moved south
                ["ES"] = (0.12, 0.57),   // Spain - moved south
                ["FR"] = (0.20, 0.45),   // France
                ["BE"] = (0.23, 0.38),   // Belgium
                ["NL"] = (0.24, 0.35),   // Netherlands
                ["LU"] = (0.24, 0.42),   // Luxembourg
                ["GB"] = (0.15, 0.32),   // United Kingdom
                ["IE"] = (0.08, 0.30),   // Ireland

                // Central Europe
                ["DE"] = (0.35, 0.38),   // Germany
                ["CH"] = (0.30, 0.48),   // Switzerland
                ["AT"] = (0.38, 0.48),   // Austria
                ["CZ"] = (0.40, 0.42),   // Czech Republic
                ["PL"] = (0.48, 0.35),   // Poland
                ["SK"] = (0.48, 0.45),   // Slovakia
                ["HU"] = (0.48, 0.48),   // Hungary
                ["SI"] = (0.42, 0.50),   // Slovenia
                ["HR"] = (0.44, 0.53),   // Croatia - corrected: extends along Adriatic coast

                // Northern Europe
                ["NO"] = (0.30, 0.15),   // Norway - corrected: west of Sweden
                ["SE"] = (0.42, 0.20),   // Sweden
                ["FI"] = (0.58, 0.12),   // Finland - corrected: east of Sweden, further north
                ["DK"] = (0.35, 0.32),   // Denmark
                ["IS"] = (0.02, 0.10),   // Iceland

                // Southern Europe
                ["IT"] = (0.38, 0.55),   // Italy - corrected: slightly more east and south
                ["GR"] = (0.56, 0.65),   // Greece - corrected: eastern Mediterranean, more east and south
                ["AL"] = (0.48, 0.58),   // Albania
                ["MK"] = (0.50, 0.58),   // North Macedonia
                ["BG"] = (0.56, 0.52),   // Bulgaria - corrected: more north, east of Romania
                ["RO"] = (0.54, 0.50),   // Romania
                ["RS"] = (0.48, 0.54),   // Serbia
                ["BA"] = (0.45, 0.54),   // Bosnia and Herzegovina
                ["ME"] = (0.47, 0.56),   // Montenegro
                ["MT"] = (0.42, 0.72),   // Malta - corrected: south of Sicily, very southern Mediterranean
                ["CY"] = (0.72, 0.68),   // Cyprus - corrected: far east Mediterranean

                // Eastern Europe
                ["EE"] = (0.55, 0.22),   // Estonia
                ["LV"] = (0.55, 0.28),   // Latvia
                ["LT"] = (0.52, 0.32),   // Lithuania
                ["BY"] = (0.58, 0.35),   // Belarus
                ["UA"] = (0.62, 0.45),   // Ukraine
                ["MD"] = (0.58, 0.48),   // Moldova
                ["RU"] = (0.70, 0.35),   // Russia (European part)
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion

        #region Asia Positions

        private static (double x, double y)? GetAsiaPosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                // Middle East
                ["TR"] = (0.15, 0.35),   // Turkey
                ["SY"] = (0.18, 0.40),   // Syria
                ["LB"] = (0.18, 0.42),   // Lebanon
                ["IL"] = (0.17, 0.44),   // Israel
                ["PS"] = (0.17, 0.45),   // Palestine
                ["JO"] = (0.18, 0.46),   // Jordan
                ["SA"] = (0.22, 0.52),   // Saudi Arabia
                ["YE"] = (0.24, 0.58),   // Yemen
                ["OM"] = (0.28, 0.54),   // Oman
                ["AE"] = (0.27, 0.52),   // UAE
                ["QA"] = (0.26, 0.50),   // Qatar
                ["BH"] = (0.26, 0.49),   // Bahrain
                ["KW"] = (0.24, 0.47),   // Kuwait
                ["IQ"] = (0.22, 0.42),   // Iraq
                ["IR"] = (0.26, 0.42),   // Iran

                // Central Asia
                ["KZ"] = (0.35, 0.30),   // Kazakhstan
                ["UZ"] = (0.32, 0.35),   // Uzbekistan
                ["TM"] = (0.30, 0.38),   // Turkmenistan
                ["KG"] = (0.36, 0.35),   // Kyrgyzstan
                ["TJ"] = (0.35, 0.38),   // Tajikistan
                ["AF"] = (0.32, 0.42),   // Afghanistan
                ["PK"] = (0.35, 0.46),   // Pakistan

                // South Asia
                ["IN"] = (0.40, 0.52),   // India
                ["BD"] = (0.45, 0.52),   // Bangladesh
                ["NP"] = (0.43, 0.48),   // Nepal
                ["BT"] = (0.45, 0.48),   // Bhutan
                ["LK"] = (0.42, 0.60),   // Sri Lanka
                ["MV"] = (0.38, 0.62),   // Maldives

                // Southeast Asia
                ["MM"] = (0.48, 0.52),   // Myanmar
                ["TH"] = (0.50, 0.54),   // Thailand
                ["LA"] = (0.51, 0.52),   // Laos
                ["VN"] = (0.53, 0.54),   // Vietnam
                ["KH"] = (0.52, 0.56),   // Cambodia
                ["MY"] = (0.52, 0.60),   // Malaysia
                ["SG"] = (0.52, 0.62),   // Singapore
                ["BN"] = (0.56, 0.60),   // Brunei
                ["ID"] = (0.55, 0.64),   // Indonesia
                ["TL"] = (0.60, 0.66),   // Timor-Leste
                ["PH"] = (0.60, 0.56),   // Philippines

                // East Asia
                ["CN"] = (0.55, 0.42),   // China
                ["MN"] = (0.52, 0.32),   // Mongolia
                ["KP"] = (0.62, 0.38),   // North Korea
                ["KR"] = (0.63, 0.40),   // South Korea
                ["JP"] = (0.68, 0.40),   // Japan
                ["TW"] = (0.62, 0.50),   // Taiwan
                ["HK"] = (0.56, 0.52),   // Hong Kong
                ["MO"] = (0.56, 0.52),   // Macau
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion

        #region Africa Positions

        private static (double x, double y)? GetAfricaPosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                // North Africa
                ["MA"] = (0.25, 0.15),   // Morocco
                ["DZ"] = (0.35, 0.18),   // Algeria
                ["TN"] = (0.42, 0.14),   // Tunisia
                ["LY"] = (0.48, 0.18),   // Libya
                ["EG"] = (0.58, 0.18),   // Egypt

                // West Africa
                ["MR"] = (0.22, 0.25),   // Mauritania
                ["ML"] = (0.30, 0.28),   // Mali
                ["NE"] = (0.40, 0.28),   // Niger
                ["TD"] = (0.48, 0.30),   // Chad
                ["SN"] = (0.18, 0.30),   // Senegal
                ["GM"] = (0.18, 0.30),   // Gambia
                ["GW"] = (0.18, 0.32),   // Guinea-Bissau
                ["GN"] = (0.20, 0.34),   // Guinea
                ["SL"] = (0.18, 0.36),   // Sierra Leone
                ["LR"] = (0.20, 0.38),   // Liberia
                ["CI"] = (0.24, 0.38),   // Ivory Coast
                ["BF"] = (0.28, 0.32),   // Burkina Faso
                ["GH"] = (0.28, 0.38),   // Ghana
                ["TG"] = (0.30, 0.38),   // Togo
                ["BJ"] = (0.32, 0.36),   // Benin
                ["NG"] = (0.36, 0.36),   // Nigeria
                ["CM"] = (0.42, 0.38),   // Cameroon

                // Central Africa
                ["CF"] = (0.48, 0.38),   // Central African Republic
                ["SS"] = (0.58, 0.38),   // South Sudan
                ["SD"] = (0.58, 0.28),   // Sudan
                ["ER"] = (0.68, 0.30),   // Eritrea
                ["DJ"] = (0.70, 0.32),   // Djibouti
                ["ET"] = (0.68, 0.36),   // Ethiopia
                ["SO"] = (0.72, 0.40),   // Somalia
                ["KE"] = (0.68, 0.45),   // Kenya
                ["UG"] = (0.62, 0.45),   // Uganda
                ["RW"] = (0.60, 0.48),   // Rwanda
                ["BI"] = (0.60, 0.50),   // Burundi
                ["TZ"] = (0.65, 0.50),   // Tanzania
                ["CG"] = (0.48, 0.48),   // Congo
                ["CD"] = (0.52, 0.50),   // DR Congo
                ["GA"] = (0.42, 0.48),   // Gabon
                ["GQ"] = (0.40, 0.45),   // Equatorial Guinea
                ["AO"] = (0.45, 0.58),   // Angola

                // Southern Africa
                ["NA"] = (0.42, 0.65),   // Namibia
                ["BW"] = (0.52, 0.68),   // Botswana
                ["ZW"] = (0.58, 0.65),   // Zimbabwe
                ["ZM"] = (0.58, 0.58),   // Zambia
                ["MW"] = (0.65, 0.58),   // Malawi
                ["MZ"] = (0.68, 0.62),   // Mozambique
                ["ZA"] = (0.52, 0.75),   // South Africa
                ["LS"] = (0.55, 0.75),   // Lesotho
                ["SZ"] = (0.60, 0.72),   // Eswatini
                ["MG"] = (0.75, 0.65),   // Madagascar
                ["MU"] = (0.78, 0.68),   // Mauritius
                ["SC"] = (0.78, 0.48),   // Seychelles
                ["KM"] = (0.72, 0.58),   // Comoros
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion

        #region North America Positions

        private static (double x, double y)? GetNorthAmericaPosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                ["CA"] = (0.45, 0.25),   // Canada
                ["US"] = (0.45, 0.50),   // United States
                ["MX"] = (0.40, 0.72),   // Mexico

                // Central America
                ["GT"] = (0.38, 0.82),   // Guatemala
                ["BZ"] = (0.40, 0.80),   // Belize
                ["SV"] = (0.38, 0.84),   // El Salvador
                ["HN"] = (0.40, 0.83),   // Honduras
                ["NI"] = (0.40, 0.86),   // Nicaragua
                ["CR"] = (0.40, 0.88),   // Costa Rica
                ["PA"] = (0.42, 0.90),   // Panama

                // Caribbean
                ["CU"] = (0.48, 0.75),   // Cuba
                ["JM"] = (0.48, 0.78),   // Jamaica
                ["HT"] = (0.50, 0.78),   // Haiti
                ["DO"] = (0.52, 0.78),   // Dominican Republic
                ["PR"] = (0.54, 0.78),   // Puerto Rico
                ["BS"] = (0.50, 0.72),   // Bahamas
                ["TT"] = (0.54, 0.85),   // Trinidad and Tobago
                ["BB"] = (0.56, 0.84),   // Barbados
                ["LC"] = (0.55, 0.84),   // Saint Lucia
                ["GD"] = (0.54, 0.86),   // Grenada
                ["VC"] = (0.55, 0.84),   // Saint Vincent
                ["DM"] = (0.55, 0.82),   // Dominica
                ["AG"] = (0.56, 0.80),   // Antigua and Barbuda
                ["KN"] = (0.56, 0.79),   // Saint Kitts and Nevis
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion

        #region South America Positions

        private static (double x, double y)? GetSouthAmericaPosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                ["CO"] = (0.35, 0.20),   // Colombia
                ["VE"] = (0.45, 0.20),   // Venezuela
                ["GY"] = (0.52, 0.22),   // Guyana
                ["SR"] = (0.55, 0.22),   // Suriname
                ["GF"] = (0.58, 0.22),   // French Guiana
                ["EC"] = (0.30, 0.28),   // Ecuador
                ["PE"] = (0.30, 0.45),   // Peru
                ["BR"] = (0.55, 0.48),   // Brazil
                ["BO"] = (0.40, 0.55),   // Bolivia
                ["PY"] = (0.48, 0.65),   // Paraguay
                ["CL"] = (0.32, 0.68),   // Chile
                ["AR"] = (0.42, 0.72),   // Argentina
                ["UY"] = (0.52, 0.72),   // Uruguay
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion

        #region Oceania Positions

        private static (double x, double y)? GetOceaniaPosition(string countryCode)
        {
            var positions = new Dictionary<string, (double x, double y)>
            {
                ["AU"] = (0.45, 0.65),   // Australia
                ["NZ"] = (0.75, 0.75),   // New Zealand
                ["PG"] = (0.60, 0.45),   // Papua New Guinea
                ["FJ"] = (0.80, 0.55),   // Fiji
                ["NC"] = (0.72, 0.60),   // New Caledonia
                ["SB"] = (0.68, 0.48),   // Solomon Islands
                ["VU"] = (0.75, 0.55),   // Vanuatu
                ["WS"] = (0.88, 0.50),   // Samoa
                ["TO"] = (0.85, 0.58),   // Tonga
                ["PF"] = (0.92, 0.52),   // French Polynesia
                ["KI"] = (0.88, 0.45),   // Kiribati
                ["FM"] = (0.72, 0.40),   // Micronesia
                ["MH"] = (0.78, 0.40),   // Marshall Islands
                ["PW"] = (0.68, 0.42),   // Palau
                ["NR"] = (0.75, 0.45),   // Nauru
                ["TV"] = (0.82, 0.46),   // Tuvalu
            };

            return positions.TryGetValue(countryCode, out var pos) ? pos : null;
        }

        #endregion
    }
}
