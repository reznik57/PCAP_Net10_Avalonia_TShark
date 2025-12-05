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
        /// Smooth curved design - recognizable continental outline
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetNorthAmericaGeometry()
        {
            if (_northAmericaGeometry != null)
                return _northAmericaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth North America with realistic curves
                context.BeginFigure(new Point(45, 95), true); // Alaska west
                context.QuadraticBezierTo(new Point(50, 55), new Point(85, 50));    // Alaska curve
                context.QuadraticBezierTo(new Point(120, 48), new Point(155, 55));  // Canadian Arctic
                context.QuadraticBezierTo(new Point(190, 62), new Point(220, 72));  // Hudson Bay area
                context.QuadraticBezierTo(new Point(245, 80), new Point(255, 95));  // Labrador
                context.QuadraticBezierTo(new Point(260, 105), new Point(252, 120)); // East coast north
                context.QuadraticBezierTo(new Point(245, 135), new Point(235, 150)); // East coast south
                context.QuadraticBezierTo(new Point(228, 165), new Point(215, 175)); // Florida
                context.QuadraticBezierTo(new Point(200, 185), new Point(180, 188)); // Gulf coast
                context.QuadraticBezierTo(new Point(165, 190), new Point(155, 185)); // Central America
                context.QuadraticBezierTo(new Point(145, 178), new Point(138, 168)); // Mexico west
                context.QuadraticBezierTo(new Point(130, 155), new Point(125, 145)); // Baja California
                context.QuadraticBezierTo(new Point(105, 140), new Point(85, 135));  // Pacific coast
                context.QuadraticBezierTo(new Point(65, 125), new Point(52, 115));   // Alaska south
                context.QuadraticBezierTo(new Point(45, 105), new Point(45, 95));    // Close
                context.EndFigure(true);
            }
            _northAmericaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for South America
        /// Smooth curved design - distinctive Brazilian bulge and southern tip
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetSouthAmericaGeometry()
        {
            if (_southAmericaGeometry != null)
                return _southAmericaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth South America with realistic curves
                context.BeginFigure(new Point(168, 195), true); // Colombia/Panama
                context.QuadraticBezierTo(new Point(190, 188), new Point(210, 192)); // Venezuela coast
                context.QuadraticBezierTo(new Point(230, 195), new Point(242, 205)); // Guyana
                context.QuadraticBezierTo(new Point(250, 220), new Point(248, 240)); // Brazil bulge east
                context.QuadraticBezierTo(new Point(245, 260), new Point(235, 278)); // Brazil south
                context.QuadraticBezierTo(new Point(225, 292), new Point(212, 305)); // Uruguay
                context.QuadraticBezierTo(new Point(200, 318), new Point(190, 325)); // Argentina east
                context.QuadraticBezierTo(new Point(182, 330), new Point(178, 320)); // Tierra del Fuego
                context.QuadraticBezierTo(new Point(175, 310), new Point(172, 295)); // Chile south
                context.QuadraticBezierTo(new Point(168, 270), new Point(165, 245)); // Chile central
                context.QuadraticBezierTo(new Point(162, 225), new Point(165, 210)); // Peru
                context.QuadraticBezierTo(new Point(168, 200), new Point(168, 195)); // Ecuador
                context.EndFigure(true);
            }
            _southAmericaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Europe
        /// Smooth curved design - Scandinavian peninsula, Mediterranean coast, British Isles
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetEuropeGeometry()
        {
            if (_europeGeometry != null)
                return _europeGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth Europe with realistic curves
                context.BeginFigure(new Point(385, 82), true); // Norway west coast
                context.QuadraticBezierTo(new Point(395, 55), new Point(415, 52)); // Northern Norway
                context.QuadraticBezierTo(new Point(435, 50), new Point(450, 60)); // Finland
                context.QuadraticBezierTo(new Point(470, 70), new Point(478, 88)); // Russia border
                context.QuadraticBezierTo(new Point(480, 105), new Point(475, 120)); // Baltic
                context.QuadraticBezierTo(new Point(468, 135), new Point(455, 148)); // Eastern Europe
                context.QuadraticBezierTo(new Point(440, 158), new Point(420, 155)); // Balkans
                context.QuadraticBezierTo(new Point(405, 152), new Point(395, 148)); // Greece/Italy boot
                context.QuadraticBezierTo(new Point(380, 145), new Point(368, 138)); // Italy
                context.QuadraticBezierTo(new Point(358, 130), new Point(355, 118)); // Iberia
                context.QuadraticBezierTo(new Point(355, 105), new Point(362, 95));  // France
                context.QuadraticBezierTo(new Point(370, 85), new Point(378, 80));   // Britain/Ireland
                context.QuadraticBezierTo(new Point(382, 80), new Point(385, 82));   // Close
                context.EndFigure(true);
            }
            _europeGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Africa
        /// Smooth curved design - distinctive Horn of Africa, Cape of Good Hope
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetAfricaGeometry()
        {
            if (_africaGeometry != null)
                return _africaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth Africa with realistic curves
                context.BeginFigure(new Point(405, 168), true); // Morocco
                context.QuadraticBezierTo(new Point(440, 162), new Point(475, 165)); // North coast
                context.QuadraticBezierTo(new Point(500, 168), new Point(515, 175)); // Egypt/Sinai
                context.QuadraticBezierTo(new Point(530, 180), new Point(538, 195)); // Horn of Africa
                context.QuadraticBezierTo(new Point(535, 212), new Point(528, 230)); // Somalia coast
                context.QuadraticBezierTo(new Point(522, 255), new Point(518, 280)); // East Africa
                context.QuadraticBezierTo(new Point(512, 305), new Point(498, 325)); // Mozambique
                context.QuadraticBezierTo(new Point(485, 340), new Point(468, 345)); // South Africa
                context.QuadraticBezierTo(new Point(452, 342), new Point(440, 332)); // Cape
                context.QuadraticBezierTo(new Point(428, 318), new Point(422, 295)); // Namibia
                context.QuadraticBezierTo(new Point(418, 268), new Point(415, 240)); // Angola
                context.QuadraticBezierTo(new Point(410, 215), new Point(405, 195)); // West Africa bulge
                context.QuadraticBezierTo(new Point(402, 180), new Point(405, 168)); // Senegal
                context.EndFigure(true);
            }
            _africaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Asia
        /// Smooth curved design - Siberia, Indian subcontinent, Southeast Asia
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetAsiaGeometry()
        {
            if (_asiaGeometry != null)
                return _asiaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth Asia with realistic curves - largest continent
                context.BeginFigure(new Point(478, 88), true);  // Urals (connects to Europe)
                context.QuadraticBezierTo(new Point(520, 60), new Point(580, 55)); // Western Siberia
                context.QuadraticBezierTo(new Point(640, 52), new Point(700, 60)); // Central Siberia
                context.QuadraticBezierTo(new Point(740, 70), new Point(758, 95)); // Eastern Siberia
                context.QuadraticBezierTo(new Point(765, 115), new Point(755, 135)); // Kamchatka
                context.QuadraticBezierTo(new Point(745, 152), new Point(725, 165)); // Sea of Okhotsk
                context.QuadraticBezierTo(new Point(708, 178), new Point(690, 195)); // China coast
                context.QuadraticBezierTo(new Point(678, 215), new Point(668, 235)); // Southeast Asia
                context.QuadraticBezierTo(new Point(660, 248), new Point(648, 245)); // Malaysia
                context.QuadraticBezierTo(new Point(632, 238), new Point(620, 225)); // Indonesia tip
                context.QuadraticBezierTo(new Point(608, 210), new Point(598, 192)); // Bay of Bengal
                context.QuadraticBezierTo(new Point(592, 175), new Point(590, 160)); // India south
                context.QuadraticBezierTo(new Point(588, 148), new Point(580, 142)); // India west
                context.QuadraticBezierTo(new Point(565, 138), new Point(550, 135)); // Arabian Peninsula
                context.QuadraticBezierTo(new Point(530, 128), new Point(515, 118)); // Middle East
                context.QuadraticBezierTo(new Point(500, 108), new Point(485, 95));  // Turkey/Caucasus
                context.QuadraticBezierTo(new Point(480, 90), new Point(478, 88));   // Close
                context.EndFigure(true);
            }
            _asiaGeometry = geometry;
            return geometry;
        }

        /// <summary>
        /// Returns cached StreamGeometry for Oceania (Australia + New Zealand)
        /// Smooth curved design - distinctive Australian coastline with Gulf of Carpentaria
        /// Coordinates in 800x400 canvas space
        /// </summary>
        public static StreamGeometry GetOceaniaGeometry()
        {
            if (_oceaniaGeometry != null)
                return _oceaniaGeometry;

            var geometry = new StreamGeometry();
            using (var context = geometry.Open())
            {
                // Smooth Australia with realistic curves
                context.BeginFigure(new Point(655, 262), true); // Cape York
                context.QuadraticBezierTo(new Point(680, 255), new Point(705, 258)); // Gulf of Carpentaria
                context.QuadraticBezierTo(new Point(728, 258), new Point(745, 268)); // Arnhem Land
                context.QuadraticBezierTo(new Point(760, 278), new Point(765, 295)); // Queensland coast
                context.QuadraticBezierTo(new Point(768, 315), new Point(760, 335)); // Great Barrier Reef
                context.QuadraticBezierTo(new Point(750, 350), new Point(730, 355)); // NSW/Victoria
                context.QuadraticBezierTo(new Point(705, 358), new Point(680, 355)); // South coast
                context.QuadraticBezierTo(new Point(655, 350), new Point(638, 340)); // Great Australian Bight
                context.QuadraticBezierTo(new Point(625, 325), new Point(625, 305)); // Western Australia south
                context.QuadraticBezierTo(new Point(628, 285), new Point(638, 272)); // Western Australia north
                context.QuadraticBezierTo(new Point(648, 262), new Point(655, 262)); // Kimberley
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
