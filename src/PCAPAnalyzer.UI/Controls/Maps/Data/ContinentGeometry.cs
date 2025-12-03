using Avalonia;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Controls.Maps.Data
{
    /// <summary>
    /// Provides cached StreamGeometry definitions for continent shapes.
    /// All coordinates are in 800x400 canvas space for consistent rendering.
    /// </summary>
    public static class ContinentGeometry
    {
        private static StreamGeometry? _northAmericaGeometry;
        private static StreamGeometry? _southAmericaGeometry;
        private static StreamGeometry? _europeGeometry;
        private static StreamGeometry? _africaGeometry;
        private static StreamGeometry? _asiaGeometry;
        private static StreamGeometry? _oceaniaGeometry;

        /// <summary>
        /// Returns cached StreamGeometry for North America (Canada, USA, Mexico)
        /// Simplified angular design with 17 points - wide Canadian top narrowing to Central America
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetNorthAmericaGeometry()
        {
            if (_northAmericaGeometry != null)
                return _northAmericaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular North America - wide top (Alaska/Canada), narrow bottom (Central America)
                context.BeginFigure(new Point(50, 100), true); // Alaska west
                context.LineTo(new Point(80, 60));   // Alaska north
                context.LineTo(new Point(160, 60));  // Canadian Arctic
                context.LineTo(new Point(220, 80));  // Eastern Canada
                context.LineTo(new Point(250, 100)); // Newfoundland
                context.LineTo(new Point(245, 130)); // US East Coast
                context.LineTo(new Point(230, 160)); // Florida
                context.LineTo(new Point(200, 180)); // Gulf of Mexico
                context.LineTo(new Point(170, 190)); // Central America
                context.LineTo(new Point(150, 185)); // Central America west
                context.LineTo(new Point(140, 170)); // Mexico west coast
                context.LineTo(new Point(130, 150)); // California
                context.LineTo(new Point(100, 140)); // Pacific Northwest
                context.LineTo(new Point(70, 130));  // Alaska panhandle
                context.LineTo(new Point(55, 120));  // Alaska southwest
                context.LineTo(new Point(50, 110));  // Return to start area
                context.EndFigure(true);
            }
            _northAmericaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for South America
        /// Simplified angular design with 14 points - inverted triangle, wide north to narrow south
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetSouthAmericaGeometry()
        {
            if (_southAmericaGeometry != null)
                return _southAmericaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular South America - inverted triangle shape
                context.BeginFigure(new Point(170, 195), true); // Northwest Colombia/Panama
                context.LineTo(new Point(210, 190)); // North Venezuela
                context.LineTo(new Point(240, 200)); // Northeast Brazil
                context.LineTo(new Point(238, 235)); // Eastern Brazil bulge
                context.LineTo(new Point(230, 270)); // Southeast Brazil
                context.LineTo(new Point(215, 295)); // Uruguay
                context.LineTo(new Point(200, 315)); // Argentina south
                context.LineTo(new Point(185, 312)); // Patagonia tip
                context.LineTo(new Point(175, 300)); // Chile south
                context.LineTo(new Point(170, 270)); // Central Chile
                context.LineTo(new Point(168, 235)); // Peru
                context.LineTo(new Point(172, 210)); // Ecuador/Colombia west
                context.LineTo(new Point(170, 200)); // Return to start
                context.EndFigure(true);
            }
            _southAmericaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Europe
        /// Simplified angular design with 14 points - Scandinavian peninsula with Mediterranean coast
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetEuropeGeometry()
        {
            if (_europeGeometry != null)
                return _europeGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular Europe - Scandinavia north, compact Mediterranean south
                context.BeginFigure(new Point(390, 80), true); // Norway west
                context.LineTo(new Point(410, 60));  // Northern Scandinavia
                context.LineTo(new Point(440, 65));  // Sweden/Finland
                context.LineTo(new Point(470, 85));  // Russia northwest
                context.LineTo(new Point(470, 110)); // Baltic states
                context.LineTo(new Point(460, 135)); // Eastern Europe
                context.LineTo(new Point(440, 150)); // Balkans
                context.LineTo(new Point(410, 150)); // Greece/Mediterranean
                context.LineTo(new Point(385, 145)); // Italy
                context.LineTo(new Point(370, 135)); // Iberian Peninsula
                context.LineTo(new Point(370, 115)); // France
                context.LineTo(new Point(375, 95));  // British Isles
                context.LineTo(new Point(385, 85));  // North Sea coast
                context.EndFigure(true);
            }
            _europeGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Africa
        /// Simplified angular design with 16 points - rectangular north bulk with Horn protrusion, narrow south
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetAfricaGeometry()
        {
            if (_africaGeometry != null)
                return _africaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular Africa - rectangular bulk with distinctive Horn of Africa
                context.BeginFigure(new Point(410, 168), true); // Northwest Morocco
                context.LineTo(new Point(480, 165)); // North coast Mediterranean
                context.LineTo(new Point(510, 170)); // Egypt
                context.LineTo(new Point(530, 185)); // Horn of Africa protrusion
                context.LineTo(new Point(525, 210)); // Somalia
                context.LineTo(new Point(520, 250)); // East Africa
                context.LineTo(new Point(510, 295)); // Mozambique
                context.LineTo(new Point(490, 330)); // South Africa east
                context.LineTo(new Point(470, 340)); // Cape of Good Hope
                context.LineTo(new Point(450, 335)); // South Africa west
                context.LineTo(new Point(435, 310)); // Namibia
                context.LineTo(new Point(430, 270)); // Angola
                context.LineTo(new Point(420, 230)); // Congo
                context.LineTo(new Point(410, 200)); // West Africa
                context.LineTo(new Point(415, 180)); // Northwest coast
                context.EndFigure(true);
            }
            _africaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Asia
        /// Simplified angular design with 23 points - massive Siberian expanse, eastern peninsulas, Indian subcontinent
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetAsiaGeometry()
        {
            if (_asiaGeometry != null)
                return _asiaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular Asia - largest continent with eastern complexity
                context.BeginFigure(new Point(470, 85), true);  // Ural Mountains west
                context.LineTo(new Point(530, 65));   // Western Siberia
                context.LineTo(new Point(620, 60));   // Central Siberia
                context.LineTo(new Point(710, 75));   // Eastern Siberia
                context.LineTo(new Point(750, 100));  // Kamchatka
                context.LineTo(new Point(748, 130));  // Sea of Okhotsk
                context.LineTo(new Point(730, 150));  // Japan/Korea area
                context.LineTo(new Point(710, 170));  // East China coast
                context.LineTo(new Point(685, 200));  // Southeast coast
                context.LineTo(new Point(672, 230));  // Indochina peninsula
                context.LineTo(new Point(665, 240));  // Malaysia
                context.LineTo(new Point(650, 230));  // Indonesia area
                context.LineTo(new Point(630, 215));  // Bay of Bengal
                context.LineTo(new Point(615, 190));  // Indian subcontinent east
                context.LineTo(new Point(605, 165));  // India south tip
                context.LineTo(new Point(600, 145));  // India west coast
                context.LineTo(new Point(585, 140));  // Arabian Sea
                context.LineTo(new Point(570, 135));  // Arabian Peninsula
                context.LineTo(new Point(555, 125));  // Middle East
                context.LineTo(new Point(535, 110));  // Turkey/Caucasus
                context.LineTo(new Point(520, 100));  // Black Sea area
                context.LineTo(new Point(480, 95));   // Eastern Europe border
                context.EndFigure(true);
            }
            _asiaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Oceania (Australia + New Zealand)
        /// Simplified angular design with 12 points - simplified rectangular Australia with rounded corners
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetOceaniaGeometry()
        {
            if (_oceaniaGeometry != null)
                return _oceaniaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Angular Australia - simplified angular rectangle with corner variations
                context.BeginFigure(new Point(660, 260), true); // North Queensland
                context.LineTo(new Point(720, 250)); // Northern Territory
                context.LineTo(new Point(755, 265)); // Northeast corner
                context.LineTo(new Point(760, 300)); // East coast
                context.LineTo(new Point(755, 335)); // Southeast corner (Victoria)
                context.LineTo(new Point(720, 345)); // South coast
                context.LineTo(new Point(670, 345)); // South Australia
                context.LineTo(new Point(645, 335)); // Southwest corner
                context.LineTo(new Point(640, 300)); // West coast
                context.LineTo(new Point(642, 270)); // Northwest coast
                context.LineTo(new Point(650, 260)); // Northern coast return
                context.EndFigure(true);
            }
            _oceaniaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Gets geometry for specified continent code
        /// </summary>
        public static StreamGeometry? GetGeometry(string continentCode)
        {
            return continentCode switch
            {
                "NA" => GetNorthAmericaGeometry(),
                "SA" => GetSouthAmericaGeometry(),
                "EU" => GetEuropeGeometry(),
                "AF" => GetAfricaGeometry(),
                "AS" => GetAsiaGeometry(),
                "OC" => GetOceaniaGeometry(),
                _ => null
            };
        }
    }
}
