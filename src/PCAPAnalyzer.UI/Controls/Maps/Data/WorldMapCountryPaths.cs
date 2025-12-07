using System.Collections.Generic;
using Avalonia;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Controls.Maps.Data;

/// <summary>
/// Provides simplified country border paths for the detailed world map.
/// All coordinates are in 800x400 canvas space (Mercator-style projection).
/// Major countries have recognizable outlines; smaller countries use markers.
/// </summary>
public static class WorldMapCountryPaths
{
    // Canvas dimensions
    public const double CanvasWidth = 800;
    public const double CanvasHeight = 400;

    // Cache for country geometries
    private static readonly Dictionary<string, StreamGeometry> _countryGeometries = [];
    private static readonly Dictionary<string, Point> _countryCentroids = [];

    /// <summary>
    /// Gets the geometry for a country, or null if not defined.
    /// </summary>
    public static StreamGeometry? GetCountryGeometry(string countryCode)
    {
        if (_countryGeometries.TryGetValue(countryCode, out var geometry))
            return geometry;

        geometry = CreateCountryGeometry(countryCode);
        if (geometry is not null)
            _countryGeometries[countryCode] = geometry;

        return geometry;
    }

    /// <summary>
    /// Gets the centroid position for a country (for marker placement).
    /// </summary>
    public static Point GetCountryCentroid(string countryCode)
    {
        if (_countryCentroids.TryGetValue(countryCode, out var centroid))
            return centroid;

        centroid = CalculateCountryCentroid(countryCode);
        _countryCentroids[countryCode] = centroid;
        return centroid;
    }

    /// <summary>
    /// Creates geometry for a specific country.
    /// </summary>
    private static StreamGeometry? CreateCountryGeometry(string countryCode)
    {
        return countryCode switch
        {
            // North America
            "US" => CreateUSGeometry(),
            "CA" => CreateCanadaGeometry(),
            "MX" => CreateMexicoGeometry(),

            // South America
            "BR" => CreateBrazilGeometry(),
            "AR" => CreateArgentinaGeometry(),
            "CO" => CreateColombiaGeometry(),
            "PE" => CreatePeruGeometry(),
            "CL" => CreateChileGeometry(),
            "VE" => CreateVenezuelaGeometry(),

            // Europe
            "DE" => CreateGermanyGeometry(),
            "FR" => CreateFranceGeometry(),
            "GB" => CreateUKGeometry(),
            "ES" => CreateSpainGeometry(),
            "IT" => CreateItalyGeometry(),
            "PL" => CreatePolandGeometry(),
            "UA" => CreateUkraineGeometry(),
            "SE" => CreateSwedenGeometry(),
            "NO" => CreateNorwayGeometry(),
            "FI" => CreateFinlandGeometry(),

            // Asia
            "RU" => CreateRussiaGeometry(),
            "CN" => CreateChinaGeometry(),
            "IN" => CreateIndiaGeometry(),
            "JP" => CreateJapanGeometry(),
            "KR" => CreateSouthKoreaGeometry(),
            "ID" => CreateIndonesiaGeometry(),
            "SA" => CreateSaudiArabiaGeometry(),
            "IR" => CreateIranGeometry(),
            "TR" => CreateTurkeyGeometry(),
            "TH" => CreateThailandGeometry(),

            // Africa
            "EG" => CreateEgyptGeometry(),
            "ZA" => CreateSouthAfricaGeometry(),
            "NG" => CreateNigeriaGeometry(),
            "DZ" => CreateAlgeriaGeometry(),
            "ET" => CreateEthiopiaGeometry(),

            // Oceania
            "AU" => CreateAustraliaGeometry(),
            "NZ" => CreateNewZealandGeometry(),

            _ => null
        };
    }

    #region North America

    private static StreamGeometry CreateUSGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Continental US simplified outline
        ctx.BeginFigure(new Point(90, 120), true);
        ctx.LineTo(new Point(95, 110));
        ctx.LineTo(new Point(120, 105));
        ctx.LineTo(new Point(145, 100));
        ctx.LineTo(new Point(175, 100));
        ctx.LineTo(new Point(195, 105));
        ctx.LineTo(new Point(210, 115));
        ctx.LineTo(new Point(215, 125));
        ctx.LineTo(new Point(210, 145));
        ctx.LineTo(new Point(195, 155));
        ctx.LineTo(new Point(175, 160));
        ctx.LineTo(new Point(155, 160));
        ctx.LineTo(new Point(130, 155));
        ctx.LineTo(new Point(105, 145));
        ctx.LineTo(new Point(90, 135));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateCanadaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(65, 50), true);
        ctx.LineTo(new Point(85, 45));
        ctx.LineTo(new Point(120, 42));
        ctx.LineTo(new Point(155, 45));
        ctx.LineTo(new Point(185, 50));
        ctx.LineTo(new Point(210, 60));
        ctx.LineTo(new Point(220, 75));
        ctx.LineTo(new Point(210, 95));
        ctx.LineTo(new Point(195, 100));
        ctx.LineTo(new Point(145, 95));
        ctx.LineTo(new Point(100, 100));
        ctx.LineTo(new Point(70, 90));
        ctx.LineTo(new Point(55, 70));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateMexicoGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(105, 155), true);
        ctx.LineTo(new Point(130, 155));
        ctx.LineTo(new Point(145, 165));
        ctx.LineTo(new Point(155, 175));
        ctx.LineTo(new Point(150, 190));
        ctx.LineTo(new Point(135, 195));
        ctx.LineTo(new Point(120, 190));
        ctx.LineTo(new Point(105, 180));
        ctx.LineTo(new Point(95, 170));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    #region South America

    private static StreamGeometry CreateBrazilGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(200, 215), true);
        ctx.LineTo(new Point(235, 210));
        ctx.LineTo(new Point(250, 225));
        ctx.LineTo(new Point(252, 255));
        ctx.LineTo(new Point(240, 285));
        ctx.LineTo(new Point(215, 300));
        ctx.LineTo(new Point(190, 290));
        ctx.LineTo(new Point(175, 265));
        ctx.LineTo(new Point(175, 235));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateArgentinaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(185, 295), true);
        ctx.LineTo(new Point(205, 295));
        ctx.LineTo(new Point(210, 320));
        ctx.LineTo(new Point(200, 350));
        ctx.LineTo(new Point(185, 365));
        ctx.LineTo(new Point(175, 350));
        ctx.LineTo(new Point(175, 320));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateColombiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(160, 195), true);
        ctx.LineTo(new Point(185, 195));
        ctx.LineTo(new Point(195, 210));
        ctx.LineTo(new Point(190, 230));
        ctx.LineTo(new Point(170, 235));
        ctx.LineTo(new Point(155, 220));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreatePeruGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(155, 235), true);
        ctx.LineTo(new Point(175, 235));
        ctx.LineTo(new Point(180, 260));
        ctx.LineTo(new Point(175, 285));
        ctx.LineTo(new Point(160, 280));
        ctx.LineTo(new Point(150, 260));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateChileGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Long thin country along west coast
        ctx.BeginFigure(new Point(170, 285), true);
        ctx.LineTo(new Point(178, 285));
        ctx.LineTo(new Point(180, 320));
        ctx.LineTo(new Point(178, 355));
        ctx.LineTo(new Point(172, 370));
        ctx.LineTo(new Point(168, 355));
        ctx.LineTo(new Point(166, 320));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateVenezuelaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(185, 195), true);
        ctx.LineTo(new Point(215, 195));
        ctx.LineTo(new Point(225, 205));
        ctx.LineTo(new Point(220, 220));
        ctx.LineTo(new Point(200, 225));
        ctx.LineTo(new Point(185, 215));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    #region Europe

    private static StreamGeometry CreateGermanyGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(410, 85), true);
        ctx.LineTo(new Point(425, 82));
        ctx.LineTo(new Point(438, 88));
        ctx.LineTo(new Point(440, 105));
        ctx.LineTo(new Point(432, 118));
        ctx.LineTo(new Point(418, 115));
        ctx.LineTo(new Point(408, 102));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateFranceGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(380, 95), true);
        ctx.LineTo(new Point(405, 90));
        ctx.LineTo(new Point(415, 105));
        ctx.LineTo(new Point(412, 125));
        ctx.LineTo(new Point(395, 135));
        ctx.LineTo(new Point(375, 125));
        ctx.LineTo(new Point(372, 108));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateUKGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Great Britain island
        ctx.BeginFigure(new Point(375, 70), true);
        ctx.LineTo(new Point(385, 65));
        ctx.LineTo(new Point(392, 72));
        ctx.LineTo(new Point(390, 88));
        ctx.LineTo(new Point(382, 95));
        ctx.LineTo(new Point(372, 90));
        ctx.LineTo(new Point(370, 78));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateSpainGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(355, 115), true);
        ctx.LineTo(new Point(390, 112));
        ctx.LineTo(new Point(395, 125));
        ctx.LineTo(new Point(390, 142));
        ctx.LineTo(new Point(365, 145));
        ctx.LineTo(new Point(350, 135));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateItalyGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Boot shape
        ctx.BeginFigure(new Point(418, 115), true);
        ctx.LineTo(new Point(430, 112));
        ctx.LineTo(new Point(440, 125));
        ctx.LineTo(new Point(445, 145));
        ctx.LineTo(new Point(438, 155));
        ctx.LineTo(new Point(425, 152));
        ctx.LineTo(new Point(420, 140));
        ctx.LineTo(new Point(415, 125));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreatePolandGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(438, 80), true);
        ctx.LineTo(new Point(465, 78));
        ctx.LineTo(new Point(472, 92));
        ctx.LineTo(new Point(468, 105));
        ctx.LineTo(new Point(450, 108));
        ctx.LineTo(new Point(435, 98));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateUkraineGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(468, 90), true);
        ctx.LineTo(new Point(510, 88));
        ctx.LineTo(new Point(520, 100));
        ctx.LineTo(new Point(515, 115));
        ctx.LineTo(new Point(490, 118));
        ctx.LineTo(new Point(465, 108));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateSwedenGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(425, 45), true);
        ctx.LineTo(new Point(435, 42));
        ctx.LineTo(new Point(442, 55));
        ctx.LineTo(new Point(440, 75));
        ctx.LineTo(new Point(430, 82));
        ctx.LineTo(new Point(420, 72));
        ctx.LineTo(new Point(418, 55));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateNorwayGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(408, 40), true);
        ctx.LineTo(new Point(425, 35));
        ctx.LineTo(new Point(430, 48));
        ctx.LineTo(new Point(422, 70));
        ctx.LineTo(new Point(410, 75));
        ctx.LineTo(new Point(402, 60));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateFinlandGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(445, 38), true);
        ctx.LineTo(new Point(465, 35));
        ctx.LineTo(new Point(475, 48));
        ctx.LineTo(new Point(470, 68));
        ctx.LineTo(new Point(455, 72));
        ctx.LineTo(new Point(442, 58));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    #region Asia

    private static StreamGeometry CreateRussiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Massive country spanning top of map
        ctx.BeginFigure(new Point(480, 30), true);
        ctx.LineTo(new Point(550, 25));
        ctx.LineTo(new Point(650, 30));
        ctx.LineTo(new Point(750, 40));
        ctx.LineTo(new Point(780, 55));
        ctx.LineTo(new Point(770, 80));
        ctx.LineTo(new Point(700, 90));
        ctx.LineTo(new Point(600, 95));
        ctx.LineTo(new Point(520, 100));
        ctx.LineTo(new Point(475, 90));
        ctx.LineTo(new Point(465, 65));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateChinaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(600, 100), true);
        ctx.LineTo(new Point(670, 95));
        ctx.LineTo(new Point(720, 110));
        ctx.LineTo(new Point(730, 140));
        ctx.LineTo(new Point(710, 170));
        ctx.LineTo(new Point(660, 175));
        ctx.LineTo(new Point(610, 165));
        ctx.LineTo(new Point(585, 140));
        ctx.LineTo(new Point(580, 115));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateIndiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(580, 150), true);
        ctx.LineTo(new Point(620, 145));
        ctx.LineTo(new Point(635, 165));
        ctx.LineTo(new Point(630, 200));
        ctx.LineTo(new Point(605, 215));
        ctx.LineTo(new Point(575, 200));
        ctx.LineTo(new Point(565, 175));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateJapanGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Main islands
        ctx.BeginFigure(new Point(738, 105), true);
        ctx.LineTo(new Point(755, 100));
        ctx.LineTo(new Point(765, 115));
        ctx.LineTo(new Point(760, 140));
        ctx.LineTo(new Point(745, 150));
        ctx.LineTo(new Point(732, 138));
        ctx.LineTo(new Point(730, 120));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateSouthKoreaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(720, 120), true);
        ctx.LineTo(new Point(732, 118));
        ctx.LineTo(new Point(738, 130));
        ctx.LineTo(new Point(732, 145));
        ctx.LineTo(new Point(718, 142));
        ctx.LineTo(new Point(715, 130));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateIndonesiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // Archipelago - main islands
        ctx.BeginFigure(new Point(650, 220), true);
        ctx.LineTo(new Point(700, 215));
        ctx.LineTo(new Point(740, 225));
        ctx.LineTo(new Point(750, 240));
        ctx.LineTo(new Point(720, 250));
        ctx.LineTo(new Point(670, 248));
        ctx.LineTo(new Point(645, 238));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateSaudiArabiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(490, 145), true);
        ctx.LineTo(new Point(530, 140));
        ctx.LineTo(new Point(550, 160));
        ctx.LineTo(new Point(545, 185));
        ctx.LineTo(new Point(515, 195));
        ctx.LineTo(new Point(485, 180));
        ctx.LineTo(new Point(480, 160));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateIranGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(530, 120), true);
        ctx.LineTo(new Point(570, 115));
        ctx.LineTo(new Point(585, 135));
        ctx.LineTo(new Point(575, 160));
        ctx.LineTo(new Point(545, 165));
        ctx.LineTo(new Point(525, 150));
        ctx.LineTo(new Point(520, 135));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateTurkeyGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(460, 118), true);
        ctx.LineTo(new Point(520, 115));
        ctx.LineTo(new Point(535, 125));
        ctx.LineTo(new Point(530, 140));
        ctx.LineTo(new Point(495, 145));
        ctx.LineTo(new Point(460, 138));
        ctx.LineTo(new Point(455, 128));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateThailandGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(650, 165), true);
        ctx.LineTo(new Point(670, 162));
        ctx.LineTo(new Point(678, 180));
        ctx.LineTo(new Point(672, 205));
        ctx.LineTo(new Point(658, 210));
        ctx.LineTo(new Point(648, 195));
        ctx.LineTo(new Point(645, 178));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    #region Africa

    private static StreamGeometry CreateEgyptGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(460, 145), true);
        ctx.LineTo(new Point(495, 142));
        ctx.LineTo(new Point(500, 165));
        ctx.LineTo(new Point(490, 185));
        ctx.LineTo(new Point(462, 182));
        ctx.LineTo(new Point(455, 162));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateSouthAfricaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(445, 310), true);
        ctx.LineTo(new Point(490, 305));
        ctx.LineTo(new Point(505, 325));
        ctx.LineTo(new Point(495, 355));
        ctx.LineTo(new Point(465, 360));
        ctx.LineTo(new Point(440, 345));
        ctx.LineTo(new Point(435, 325));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateNigeriaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(400, 195), true);
        ctx.LineTo(new Point(425, 192));
        ctx.LineTo(new Point(435, 210));
        ctx.LineTo(new Point(428, 230));
        ctx.LineTo(new Point(405, 232));
        ctx.LineTo(new Point(395, 215));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateAlgeriaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(375, 145), true);
        ctx.LineTo(new Point(420, 142));
        ctx.LineTo(new Point(430, 165));
        ctx.LineTo(new Point(420, 195));
        ctx.LineTo(new Point(385, 198));
        ctx.LineTo(new Point(370, 175));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateEthiopiaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(490, 205), true);
        ctx.LineTo(new Point(520, 202));
        ctx.LineTo(new Point(532, 220));
        ctx.LineTo(new Point(525, 245));
        ctx.LineTo(new Point(498, 248));
        ctx.LineTo(new Point(485, 228));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    #region Oceania

    private static StreamGeometry CreateAustraliaGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(new Point(680, 280), true);
        ctx.LineTo(new Point(750, 275));
        ctx.LineTo(new Point(770, 295));
        ctx.LineTo(new Point(765, 330));
        ctx.LineTo(new Point(730, 350));
        ctx.LineTo(new Point(685, 345));
        ctx.LineTo(new Point(665, 320));
        ctx.LineTo(new Point(670, 295));
        ctx.EndFigure(true);
        return geometry;
    }

    private static StreamGeometry CreateNewZealandGeometry()
    {
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        // North and South islands combined
        ctx.BeginFigure(new Point(778, 330), true);
        ctx.LineTo(new Point(790, 325));
        ctx.LineTo(new Point(795, 345));
        ctx.LineTo(new Point(788, 370));
        ctx.LineTo(new Point(775, 365));
        ctx.LineTo(new Point(772, 345));
        ctx.EndFigure(true);
        return geometry;
    }

    #endregion

    /// <summary>
    /// Calculates centroid position for a country.
    /// For countries with geometry, calculates from bounds.
    /// For others, uses world coordinate mapping.
    /// </summary>
    private static Point CalculateCountryCentroid(string countryCode)
    {
        // Try to get from geometry first
        var geometry = GetCountryGeometry(countryCode);
        if (geometry is not null)
        {
            var bounds = geometry.Bounds;
            return new Point(bounds.X + bounds.Width / 2, bounds.Y + bounds.Height / 2);
        }

        // Fall back to manual coordinates from CountryGeographicData
        // Map normalized continent coordinates to world map coordinates
        return GetDefaultCentroid(countryCode);
    }

    /// <summary>
    /// Gets default centroid for countries without custom geometry.
    /// Uses approximate world coordinates.
    /// </summary>
    private static Point GetDefaultCentroid(string countryCode)
    {
        // Default centroids for common countries without full geometry
        Dictionary<string, Point> centroids = new()
        {
            // Additional European countries
            ["NL"] = new Point(405, 78),
            ["BE"] = new Point(400, 88),
            ["AT"] = new Point(435, 108),
            ["CH"] = new Point(415, 110),
            ["CZ"] = new Point(445, 95),
            ["PT"] = new Point(355, 130),
            ["GR"] = new Point(462, 135),
            ["IE"] = new Point(360, 72),
            ["DK"] = new Point(418, 70),
            ["HU"] = new Point(455, 105),
            ["RO"] = new Point(472, 108),

            // Additional Asian countries
            ["VN"] = new Point(680, 175),
            ["PH"] = new Point(720, 185),
            ["MY"] = new Point(665, 215),
            ["SG"] = new Point(668, 225),
            ["PK"] = new Point(565, 155),
            ["BD"] = new Point(615, 165),
            ["KZ"] = new Point(560, 85),
            ["UZ"] = new Point(545, 100),
            ["AE"] = new Point(530, 175),
            ["IL"] = new Point(485, 148),

            // Additional African countries
            ["MA"] = new Point(365, 150),
            ["TN"] = new Point(418, 145),
            ["LY"] = new Point(445, 160),
            ["KE"] = new Point(510, 245),
            ["TZ"] = new Point(505, 260),
            ["GH"] = new Point(390, 210),
            ["CI"] = new Point(378, 212),
            ["SN"] = new Point(355, 195),
            ["AO"] = new Point(448, 270),
            ["CD"] = new Point(465, 250),

            // Additional Americas
            ["GT"] = new Point(130, 185),
            ["CU"] = new Point(162, 175),
            ["DO"] = new Point(180, 178),
            ["EC"] = new Point(155, 235),
            ["BO"] = new Point(175, 275),
            ["PY"] = new Point(195, 290),
            ["UY"] = new Point(198, 305),

            // Additional Oceania
            ["PG"] = new Point(752, 245),
            ["FJ"] = new Point(795, 280),
        };

        return centroids.TryGetValue(countryCode, out var centroid)
            ? centroid
            : new Point(400, 200); // Default center
    }

    /// <summary>
    /// Gets all country codes that have defined geometries.
    /// </summary>
    public static IEnumerable<string> GetCountriesWithGeometry()
    {
        return new[]
        {
            // North America
            "US", "CA", "MX",
            // South America
            "BR", "AR", "CO", "PE", "CL", "VE",
            // Europe
            "DE", "FR", "GB", "ES", "IT", "PL", "UA", "SE", "NO", "FI",
            // Asia
            "RU", "CN", "IN", "JP", "KR", "ID", "SA", "IR", "TR", "TH",
            // Africa
            "EG", "ZA", "NG", "DZ", "ET",
            // Oceania
            "AU", "NZ"
        };
    }
}
