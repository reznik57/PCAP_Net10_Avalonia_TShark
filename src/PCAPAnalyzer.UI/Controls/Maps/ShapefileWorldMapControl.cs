using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;
using NetTopologySuite.Geometries;
using NetTopologySuite.IO.Esri;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Helpers;
using NtsCoordinate = NetTopologySuite.Geometries.Coordinate;
using NtsGeometry = NetTopologySuite.Geometries.Geometry;
using AvaloniaPoint = Avalonia.Point;

namespace PCAPAnalyzer.UI.Controls.Maps;

/// <summary>
/// World map control that renders countries from Natural Earth shapefiles.
/// Provides accurate country borders with traffic-based coloring and interaction.
/// </summary>
public class ShapefileWorldMapControl : Control
{
    #region Fields

    private readonly DispatcherTimer _animationTimer;
    private double _animationPhase;
    private string? _hoveredCountryCode;
    private bool _isLoaded;

    // Cached country data from shapefile
    private readonly List<CountryShape> _countries = [];
    private Rect _geoBounds; // Geographic bounds (lon/lat)

    // Zoom and pan state
    private double _zoomLevel = 1.0;
    private AvaloniaPoint _panOffset = new(0, 0);
    private AvaloniaPoint? _lastPanPoint;
    private bool _isPanning;
    private const double MinZoom = 0.5;
    private const double MaxZoom = 8.0;
    private const double ZoomStep = 0.25;

    // Zoom control button rects (calculated on render)
    private Rect _zoomInButtonRect;
    private Rect _zoomOutButtonRect;
    private Rect _zoomResetButtonRect;

    // Special traffic indicator rect (Internal = all non-routable traffic)
    private Rect _internalTrafficRect;

    // Rendering
    private static readonly IBrush BorderBrush = new SolidColorBrush(Color.FromRgb(55, 65, 81));
    private static readonly IBrush DefaultLandBrush = new SolidColorBrush(Color.FromRgb(75, 85, 99));

    /// <summary>
    /// Mapping from ISO_A3 codes to ISO_A2 codes for countries where Natural Earth
    /// uses "-99" for ISO_A2 due to overseas territories or disputed status.
    /// See: https://github.com/nvkelso/natural-earth-vector/issues/284
    /// </summary>
    private static readonly Dictionary<string, string> IsoA3ToA2Mapping = new(StringComparer.OrdinalIgnoreCase)
    {
        // Countries with overseas territories causing "-99" in ISO_A2
        ["FRA"] = "FR",  // France (overseas: Guiana, Guadeloupe, Martinique, Réunion, Mayotte)
        ["NOR"] = "NO",  // Norway (Svalbard, Jan Mayen)
        ["NLD"] = "NL",  // Netherlands (Caribbean territories)
        ["DNK"] = "DK",  // Denmark (Greenland, Faroe Islands)
        ["GBR"] = "GB",  // United Kingdom (overseas territories)
        ["USA"] = "US",  // United States (territories)
        ["AUS"] = "AU",  // Australia (external territories)
        ["NZL"] = "NZ",  // New Zealand (associated states)
        ["PRT"] = "PT",  // Portugal (Azores, Madeira)
        ["ESP"] = "ES",  // Spain (Canary Islands, Ceuta, Melilla)
        ["FIN"] = "FI",  // Finland (Åland)

        // Disputed/special status countries
        ["KOS"] = "XK",  // Kosovo
        ["SDS"] = "SS",  // South Sudan
        ["SOM"] = "SO",  // Somalia (Somaliland)
        ["CYN"] = "CY",  // Northern Cyprus (uses Cyprus code)
        ["TWN"] = "TW",  // Taiwan
    };

    // Traffic intensity colors (gray -> blue -> green -> amber -> red)
    private static readonly Color[] TrafficColors =
    {
        Color.FromRgb(107, 114, 128), // Gray - no/minimal traffic
        Color.FromRgb(59, 130, 246),  // Blue - low
        Color.FromRgb(16, 185, 129),  // Green - medium-low
        Color.FromRgb(245, 158, 11),  // Amber - medium
        Color.FromRgb(239, 68, 68),   // Red - high
    };

    #endregion

    #region Styled Properties

    public static readonly StyledProperty<string?> ShapefilePathProperty =
        AvaloniaProperty.Register<ShapefileWorldMapControl, string?>(nameof(ShapefilePath));

    public static readonly StyledProperty<Dictionary<string, CountryTrafficStatistics>?> TrafficDataProperty =
        AvaloniaProperty.Register<ShapefileWorldMapControl, Dictionary<string, CountryTrafficStatistics>?>(
            nameof(TrafficData));

    public static readonly StyledProperty<Action<string>?> CountryClickedProperty =
        AvaloniaProperty.Register<ShapefileWorldMapControl, Action<string>?>(nameof(CountryClicked));

    public static readonly StyledProperty<bool> ShowAnimationsProperty =
        AvaloniaProperty.Register<ShapefileWorldMapControl, bool>(nameof(ShowAnimations), true);

    public static readonly StyledProperty<bool> HideCountriesWithoutTrafficProperty =
        AvaloniaProperty.Register<ShapefileWorldMapControl, bool>(nameof(HideCountriesWithoutTraffic), false);

    // Read-only direct properties for hover state (exposed for XAML binding)
    public static readonly DirectProperty<ShapefileWorldMapControl, string?> HoveredCountryCodeProperty =
        AvaloniaProperty.RegisterDirect<ShapefileWorldMapControl, string?>(
            nameof(HoveredCountryCode), o => o.HoveredCountryCode);

    public static readonly DirectProperty<ShapefileWorldMapControl, string?> HoveredCountryNameProperty =
        AvaloniaProperty.RegisterDirect<ShapefileWorldMapControl, string?>(
            nameof(HoveredCountryName), o => o.HoveredCountryName);

    public static readonly DirectProperty<ShapefileWorldMapControl, CountryTrafficStatistics?> HoveredCountryStatsProperty =
        AvaloniaProperty.RegisterDirect<ShapefileWorldMapControl, CountryTrafficStatistics?>(
            nameof(HoveredCountryStats), o => o.HoveredCountryStats);

    #endregion

    #region Properties

    public string? ShapefilePath
    {
        get => GetValue(ShapefilePathProperty);
        set => SetValue(ShapefilePathProperty, value);
    }

    public Dictionary<string, CountryTrafficStatistics>? TrafficData
    {
        get => GetValue(TrafficDataProperty);
        set => SetValue(TrafficDataProperty, value);
    }

    public Action<string>? CountryClicked
    {
        get => GetValue(CountryClickedProperty);
        set => SetValue(CountryClickedProperty, value);
    }

    public bool ShowAnimations
    {
        get => GetValue(ShowAnimationsProperty);
        set => SetValue(ShowAnimationsProperty, value);
    }

    public bool HideCountriesWithoutTraffic
    {
        get => GetValue(HideCountriesWithoutTrafficProperty);
        set => SetValue(HideCountriesWithoutTrafficProperty, value);
    }

    // Backing fields for direct properties
    private string? _exposedHoveredCountryCode;
    private string? _exposedHoveredCountryName;
    private CountryTrafficStatistics? _exposedHoveredCountryStats;

    public string? HoveredCountryCode
    {
        get => _exposedHoveredCountryCode;
        private set => SetAndRaise(HoveredCountryCodeProperty, ref _exposedHoveredCountryCode, value);
    }

    public string? HoveredCountryName
    {
        get => _exposedHoveredCountryName;
        private set => SetAndRaise(HoveredCountryNameProperty, ref _exposedHoveredCountryName, value);
    }

    public CountryTrafficStatistics? HoveredCountryStats
    {
        get => _exposedHoveredCountryStats;
        private set => SetAndRaise(HoveredCountryStatsProperty, ref _exposedHoveredCountryStats, value);
    }

    #endregion

    #region Constructor

    static ShapefileWorldMapControl()
    {
        ShapefilePathProperty.Changed.AddClassHandler<ShapefileWorldMapControl>(OnShapefilePathChanged);
        TrafficDataProperty.Changed.AddClassHandler<ShapefileWorldMapControl>(OnTrafficDataChanged);
    }

    public ShapefileWorldMapControl()
    {
        ClipToBounds = true;

        _animationTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(50)
        };
        _animationTimer.Tick += (_, _) =>
        {
            _animationPhase += 0.1;
            if (_animationPhase > Math.PI * 2)
                _animationPhase -= Math.PI * 2;
            InvalidateVisual();
        };
    }

    #endregion

    #region Property Changed Handlers

    private static void OnShapefilePathChanged(ShapefileWorldMapControl control, AvaloniaPropertyChangedEventArgs args)
    {
        var path = args.NewValue as string;
        if (!string.IsNullOrEmpty(path))
        {
            control.LoadShapefile(path);
        }
    }

    private static void OnTrafficDataChanged(ShapefileWorldMapControl control, AvaloniaPropertyChangedEventArgs args)
    {
        control.InvalidateVisual();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        if (ShowAnimations)
            _animationTimer.Start();

        // Auto-load shapefile if path is set
        if (!_isLoaded && !string.IsNullOrEmpty(ShapefilePath))
        {
            LoadShapefile(ShapefilePath);
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _animationTimer.Stop();
        base.OnDetachedFromVisualTree(e);
    }

    #endregion

    #region Shapefile Loading

    /// <summary>
    /// Loads country shapes from a Natural Earth shapefile.
    /// Uses NetTopologySuite.IO.Esri.Shapefile for modern, efficient shapefile reading.
    /// </summary>
    private void LoadShapefile(string shapefilePath)
    {
        try
        {
            // Resolve path relative to application base directory
            var resolvedPath = shapefilePath;
            if (!Path.IsPathRooted(shapefilePath))
            {
                var baseDir = AppContext.BaseDirectory;
                resolvedPath = Path.Combine(baseDir, shapefilePath);
            }

            if (!File.Exists(resolvedPath))
            {
                DebugLogger.Log($"[ShapefileWorldMap] Shapefile not found: {resolvedPath}");
                return;
            }

            _countries.Clear();

            double minX = double.MaxValue, minY = double.MaxValue;
            double maxX = double.MinValue, maxY = double.MinValue;

            // Use the new NetTopologySuite.IO.Esri API - cleaner and more efficient
            foreach (var feature in Shapefile.ReadAllFeatures(resolvedPath))
            {
                var geometry = feature.Geometry;
                if (geometry is null) continue;

                // Access attributes directly by name - no manual index tracking needed
                var isoA2 = GetAttributeString(feature.Attributes, "ISO_A2");
                var isoA2Eh = GetAttributeString(feature.Attributes, "ISO_A2_EH"); // v5.0.0+ "expected homeland" fix
                var isoA3 = GetAttributeString(feature.Attributes, "ISO_A3");
                var name = GetAttributeString(feature.Attributes, "NAME")
                        ?? GetAttributeString(feature.Attributes, "ADMIN");

                // Resolve country code with fallback chain:
                // 1. ISO_A2 if valid (not "-99")
                // 2. ISO_A2_EH if available (Natural Earth v5.0.0+ fix for overseas territories)
                // 3. Map ISO_A3 to ISO_A2 using our mapping (France FRA→FR, Norway NOR→NO, etc.)
                // 4. Fall back to ISO_A3 as last resort
                var countryCode = ResolveCountryCode(isoA2, isoA2Eh, isoA3);

                if (string.IsNullOrEmpty(countryCode) || countryCode == "-99")
                    continue;

                var countryShape = new CountryShape
                {
                    IsoCode = countryCode,
                    Name = name ?? countryCode,
                    NtsGeometry = geometry
                };

                _countries.Add(countryShape);

                // Track bounds
                var env = geometry.EnvelopeInternal;
                minX = Math.Min(minX, env.MinX);
                minY = Math.Min(minY, env.MinY);
                maxX = Math.Max(maxX, env.MaxX);
                maxY = Math.Max(maxY, env.MaxY);
            }

            _geoBounds = new Rect(minX, minY, maxX - minX, maxY - minY);
            _isLoaded = true;

            DebugLogger.Log($"[ShapefileWorldMap] Loaded {_countries.Count} countries from {Path.GetFileName(resolvedPath)}");
            DebugLogger.Log($"[ShapefileWorldMap] Geographic bounds: {_geoBounds}");

            InvalidateVisual();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ShapefileWorldMap] Error loading shapefile: {ex.Message}");
        }
    }

    /// <summary>
    /// Safely extracts a string attribute from feature attributes.
    /// Handles null values and trims whitespace/NULL characters from DBF fields.
    /// </summary>
    private static string? GetAttributeString(NetTopologySuite.Features.IAttributesTable? attributes, string name)
    {
        if (attributes is null) return null;
        try
        {
            var value = attributes[name];
            return value?.ToString()?.Trim().TrimEnd('\0');
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the best ISO A2 country code using a fallback chain.
    /// Handles Natural Earth's "-99" placeholder for countries with overseas territories.
    /// </summary>
    private static string? ResolveCountryCode(string? isoA2, string? isoA2Eh, string? isoA3)
    {
        // 1. Use ISO_A2 if valid
        if (!string.IsNullOrEmpty(isoA2) && isoA2 != "-99")
            return isoA2;

        // 2. Use ISO_A2_EH (Natural Earth v5.0.0+ "expected homeland" fix)
        if (!string.IsNullOrEmpty(isoA2Eh) && isoA2Eh != "-99")
            return isoA2Eh;

        // 3. Map ISO_A3 to ISO_A2 using our mapping table
        if (!string.IsNullOrEmpty(isoA3) && isoA3 != "-99" && IsoA3ToA2Mapping.TryGetValue(isoA3, out var mappedCode))
            return mappedCode;

        // 4. Fall back to ISO_A3 (3-letter code) - better than nothing
        return isoA3;
    }

    #endregion

    #region Rendering

    private bool _loggedTrafficData;

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
        if (bounds.Width <= 0 || bounds.Height <= 0)
            return;

        // Log TrafficData once to verify binding
        if (!_loggedTrafficData && TrafficData is not null && TrafficData.Count > 0)
        {
            _loggedTrafficData = true;
            var keys = string.Join(", ", TrafficData.Keys.Take(15));
            DebugLogger.Log($"[ShapefileWorldMap] Render: TrafficData has {TrafficData.Count} keys: {keys}");
        }

        // Draw ocean background
        DrawOceanBackground(context, bounds);

        if (!_isLoaded || _countries.Count == 0)
        {
            DrawLoadingMessage(context, bounds);
            return;
        }

        // Calculate projection parameters
        var projection = CalculateProjection(bounds);

        // Draw all countries (optionally filtering out non-traffic countries)
        foreach (var country in _countries)
        {
            // Skip countries without traffic if filter is enabled
            if (HideCountriesWithoutTraffic)
            {
                var isoCode = country.IsoCode?.Trim().TrimEnd('\0');
                if (string.IsNullOrEmpty(isoCode) || TrafficData?.ContainsKey(isoCode) != true)
                    continue;
            }
            DrawCountry(context, country, projection);
        }

        // Draw hover highlight (tooltip is now in XAML, outside map bounds)
        if (!string.IsNullOrEmpty(_hoveredCountryCode))
        {
            // Compare trimmed codes - shapefile DBF fields have NULL padding
            var hoveredCountry = _countries.FirstOrDefault(c =>
                c.IsoCode?.Trim().TrimEnd('\0').Equals(_hoveredCountryCode, StringComparison.OrdinalIgnoreCase) == true);

            if (hoveredCountry is not null)
            {
                DrawCountryHighlight(context, hoveredCountry, projection);
            }
            else
            {
                DebugLogger.Log($"[ShapefileWorldMap] Hover country not found in _countries: {_hoveredCountryCode}");
            }
        }

        // Draw zoom controls (bottom-left corner)
        DrawZoomControls(context, bounds);

        // Draw special traffic indicators (INT and IP6) at bottom-right
        DrawSpecialTrafficIndicators(context, bounds);
    }

    private void DrawZoomControls(DrawingContext context, Rect bounds)
    {
        var buttonSize = 28;
        var buttonSpacing = 4;
        var margin = 12;
        var startX = margin;
        var startY = bounds.Height - margin - buttonSize * 3 - buttonSpacing * 2;

        var bgBrush = new SolidColorBrush(Color.FromArgb(220, 30, 41, 59));
        var hoverBrush = new SolidColorBrush(Color.FromArgb(240, 51, 65, 85));
        var borderPen = new Pen(new SolidColorBrush(Color.FromRgb(75, 85, 99)), 1);
        var textBrush = Brushes.White;
        var typeface = new Typeface("Inter", FontStyle.Normal, FontWeight.Bold);

        // Zoom In button (+)
        _zoomInButtonRect = new Rect(startX, startY, buttonSize, buttonSize);
        context.DrawRectangle(bgBrush, borderPen, new RoundedRect(_zoomInButtonRect, 4));
        var plusText = new FormattedText("+", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 16, textBrush);
        context.DrawText(plusText, new AvaloniaPoint(startX + (buttonSize - plusText.Width) / 2, startY + (buttonSize - plusText.Height) / 2));

        // Zoom Out button (-)
        _zoomOutButtonRect = new Rect(startX, startY + buttonSize + buttonSpacing, buttonSize, buttonSize);
        context.DrawRectangle(bgBrush, borderPen, new RoundedRect(_zoomOutButtonRect, 4));
        var minusText = new FormattedText("−", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 16, textBrush);
        context.DrawText(minusText, new AvaloniaPoint(startX + (buttonSize - minusText.Width) / 2, startY + buttonSize + buttonSpacing + (buttonSize - minusText.Height) / 2));

        // Reset button (⌂ or R)
        _zoomResetButtonRect = new Rect(startX, startY + (buttonSize + buttonSpacing) * 2, buttonSize, buttonSize);
        context.DrawRectangle(bgBrush, borderPen, new RoundedRect(_zoomResetButtonRect, 4));
        var resetText = new FormattedText("⌂", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 14, textBrush);
        context.DrawText(resetText, new AvaloniaPoint(startX + (buttonSize - resetText.Width) / 2, startY + (buttonSize + buttonSpacing) * 2 + (buttonSize - resetText.Height) / 2));

        // Zoom level indicator
        var zoomText = new FormattedText($"{_zoomLevel:F1}x", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, new Typeface("Inter"), 10, new SolidColorBrush(Color.FromRgb(156, 163, 175)));
        context.DrawText(zoomText, new AvaloniaPoint(startX + buttonSize + 6, startY + buttonSize + buttonSpacing + (buttonSize - zoomText.Height) / 2));
    }

    private void DrawSpecialTrafficIndicators(DrawingContext context, Rect bounds)
    {
        // Single pill for all non-routable traffic (Internal IPv4 + IPv6 link-local/ULA/etc.)
        var pillWidth = 75;
        var pillHeight = 32;
        var margin = 14;
        var startX = bounds.Width - margin - pillWidth;
        var startY = bounds.Height - margin - pillHeight;

        var bgBrush = new SolidColorBrush(Color.FromArgb(180, 30, 41, 59));
        var labelTypeface = new Typeface("Inter", FontStyle.Normal, FontWeight.SemiBold);

        // Combined Internal Traffic indicator (IPv4 private + all non-routable IPv6)
        _internalTrafficRect = new Rect(startX, startY, pillWidth, pillHeight);
        var combinedStats = GetCombinedInternalStats();
        var intIntensity = combinedStats.totalPackets > 0 ? GetTrafficIntensityForPackets(combinedStats.totalPackets, combinedStats.percentage) : 0;
        var isIntHovered = _hoveredCountryCode == "INT";

        DrawTrafficPill(context, _internalTrafficRect, "🏠 Internal", intIntensity, isIntHovered, bgBrush, labelTypeface);
    }

    /// <summary>
    /// Combines all non-routable traffic stats (Internal + IPv6 link-local, ULA, etc.)
    /// </summary>
    private (long totalPackets, double percentage) GetCombinedInternalStats()
    {
        if (TrafficData is null) return (0, 0);

        // Keys for non-routable traffic
        string[] nonRoutableKeys = ["Internal", "IP6_LINK", "IP6_LOOP", "IP6_ULA", "IP6_SITE", "IP6_MCAST"];

        long totalPackets = 0;
        double totalPercentage = 0;

        foreach (var key in nonRoutableKeys)
        {
            if (TrafficData.TryGetValue(key, out var stats))
            {
                totalPackets += stats.TotalPackets;
                totalPercentage += stats.Percentage;
            }
        }

        return (totalPackets, totalPercentage);
    }

    /// <summary>
    /// Gets traffic intensity based on combined packet count and percentage.
    /// </summary>
    private static int GetTrafficIntensityForPackets(long packets, double percentage)
    {
        if (percentage >= 10) return 4;
        if (percentage >= 5) return 3;
        if (percentage >= 1) return 2;
        if (packets > 0) return 1;
        return 0;
    }

    /// <summary>
    /// Draws a pill-shaped traffic indicator with color-only visualization (no numbers).
    /// Color intensity reflects traffic volume relative to total.
    /// </summary>
    private void DrawTrafficPill(DrawingContext context, Rect rect, string label, int intensity,
        bool isHovered, IBrush defaultBg, Typeface typeface)
    {
        var cornerRadius = rect.Height / 2; // Full pill shape

        // Background: gradient based on traffic intensity
        IBrush fillBrush;
        if (intensity > 0)
        {
            // Create a subtle gradient from the intensity color
            var baseColor = TrafficColors[Math.Clamp(intensity, 0, TrafficColors.Length - 1)];
            fillBrush = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.FromArgb(240, baseColor.R, baseColor.G, baseColor.B), 0),
                    new GradientStop(Color.FromArgb(200, (byte)(baseColor.R * 0.7), (byte)(baseColor.G * 0.7), (byte)(baseColor.B * 0.7)), 1)
                }
            };
        }
        else
        {
            fillBrush = defaultBg;
        }

        // Border: brighter on hover
        var borderColor = isHovered
            ? Color.FromRgb(200, 210, 220)
            : Color.FromRgb(75, 85, 99);
        var borderPen = new Pen(new SolidColorBrush(borderColor), isHovered ? 2 : 1);

        // Draw pill background
        context.DrawRectangle(fillBrush, borderPen, new RoundedRect(rect, cornerRadius));

        // Glow effect for high traffic when hovered
        if (isHovered && intensity >= 3)
        {
            var glowBrush = new SolidColorBrush(Color.FromArgb(60, 255, 255, 255));
            var glowRect = rect.Inflate(2);
            context.DrawRectangle(glowBrush, null, new RoundedRect(glowRect, cornerRadius + 2));
        }

        // Label text - centered
        var labelText = new FormattedText(label, System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 11, Brushes.White);
        var textX = rect.X + (rect.Width - labelText.Width) / 2;
        var textY = rect.Y + (rect.Height - labelText.Height) / 2;
        context.DrawText(labelText, new AvaloniaPoint(textX, textY));

        // Traffic intensity indicator bar at bottom (subtle)
        if (intensity > 0)
        {
            var barHeight = 3;
            var barWidth = rect.Width * 0.6 * (intensity / 4.0); // Scale by intensity
            var barX = rect.X + (rect.Width - barWidth) / 2;
            var barY = rect.Y + rect.Height - barHeight - 4;
            var barColor = new SolidColorBrush(Color.FromArgb(150, 255, 255, 255));
            context.DrawRectangle(barColor, null, new RoundedRect(new Rect(barX, barY, barWidth, barHeight), 1.5));
        }
    }

    private int GetTrafficIntensityForStats(CountryTrafficStatistics stats)
    {
        if (stats.Percentage >= 10) return 4;
        if (stats.Percentage >= 5) return 3;
        if (stats.Percentage >= 1) return 2;
        if (stats.Percentage >= 0.1) return 1;
        return 0;
    }

    private void DrawOceanBackground(DrawingContext context, Rect bounds)
    {
        var gradient = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Color.FromRgb(15, 23, 42), 0),
                new GradientStop(Color.FromRgb(30, 41, 59), 0.5),
                new GradientStop(Color.FromRgb(51, 65, 85), 1)
            }
        };
        context.FillRectangle(gradient, bounds);
    }

    private void DrawLoadingMessage(DrawingContext context, Rect bounds)
    {
        var text = new FormattedText(
            "Loading map...",
            System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            new Typeface("Inter"),
            14,
            Brushes.White);

        context.DrawText(text, new AvaloniaPoint(
            bounds.Width / 2 - text.Width / 2,
            bounds.Height / 2 - text.Height / 2));
    }

    private void DrawCountry(DrawingContext context, CountryShape country, ProjectionParams projection)
    {
        var avaloniaGeometry = ConvertToAvaloniaGeometry(country.NtsGeometry, projection);
        if (avaloniaGeometry is null) return;

        var brush = GetCountryBrush(country.IsoCode);
        var pen = new Pen(BorderBrush, 0.5);

        context.DrawGeometry(brush, pen, avaloniaGeometry);

        // Pulsing effect for high-traffic countries
        if (ShowAnimations)
        {
            var intensity = GetTrafficIntensity(country.IsoCode);
            if (intensity > 0.7)
            {
                var pulse = (Math.Sin(_animationPhase * 2) + 1) / 2;
                var glowAlpha = (byte)(40 * pulse);
                var glowBrush = new SolidColorBrush(Color.FromArgb(glowAlpha, 239, 68, 68));
                context.DrawGeometry(glowBrush, null, avaloniaGeometry);
            }
        }

        // Cache the geometry for hit testing
        country.CachedGeometry = avaloniaGeometry;
    }

    private void DrawCountryHighlight(DrawingContext context, CountryShape country, ProjectionParams projection)
    {
        var geometry = country.CachedGeometry ?? ConvertToAvaloniaGeometry(country.NtsGeometry, projection);
        if (geometry is null) return;

        // Glow effect
        var glowPen = new Pen(new SolidColorBrush(Color.FromArgb(100, 255, 255, 255)), 3);
        context.DrawGeometry(null, glowPen, geometry);

        // Bright border
        var highlightPen = new Pen(Brushes.White, 1.5);
        context.DrawGeometry(null, highlightPen, geometry);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling",
        Justification = "Tooltip rendering inherently requires multiple Avalonia drawing types")]
    private void DrawTooltip(DrawingContext context, CountryShape country, Rect bounds)
    {
        // Trim IsoCode - shapefile DBF fields are fixed-width with padding
        var isoCode = country.IsoCode?.Trim() ?? "";
        DebugLogger.Log($"[ShapefileWorldMap] DrawTooltip called for: {isoCode}, bounds: {bounds.Width}x{bounds.Height}");

        var stats = TrafficData?.GetValueOrDefault(isoCode);

        // Build tooltip content
        var countryName = !string.IsNullOrEmpty(country.Name) ? country.Name : isoCode;

        var typeface = new Typeface("Inter", FontStyle.Normal, FontWeight.Bold);
        var typefaceNormal = new Typeface("Inter");
        var dimColor = new SolidColorBrush(Color.FromRgb(156, 163, 175));
        var brightColor = new SolidColorBrush(Color.FromRgb(229, 231, 235));

        var titleText = new FormattedText(countryName, System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 13, Brushes.White);

        // Calculate tooltip dimensions based on content
        var tooltipWidth = 220;
        var tooltipHeight = stats is not null ? 130 : 50;

        // Position tooltip on the RIGHT side of the map (doesn't obscure map)
        var tooltipX = bounds.Width - tooltipWidth - 15;
        var tooltipY = 15;

        // Draw background with gradient
        var bgRect = new Rect(tooltipX, tooltipY, tooltipWidth, tooltipHeight);
        var bgBrush = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Color.FromArgb(250, 30, 41, 59), 0),
                new GradientStop(Color.FromArgb(250, 15, 23, 42), 1)
            }
        };
        context.DrawRectangle(bgBrush, new Pen(BorderBrush, 1), new RoundedRect(bgRect, 8));

        // Draw title with country code badge
        context.DrawText(titleText, new AvaloniaPoint(tooltipX + 12, tooltipY + 10));

        var codeText = new FormattedText($"({isoCode})", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typefaceNormal, 10, dimColor);
        context.DrawText(codeText, new AvaloniaPoint(tooltipX + 14 + titleText.Width, tooltipY + 12));

        if (stats is null)
        {
            var noDataText = new FormattedText("No traffic data", System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, typefaceNormal, 10, dimColor);
            context.DrawText(noDataText, new AvaloniaPoint(tooltipX + 12, tooltipY + 30));
            return;
        }

        // Traffic percentage badge (top right)
        if (stats.Percentage > 0)
        {
            var percentText = $"{stats.Percentage:F1}%";
            var percentBadge = new FormattedText(percentText, System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, typefaceNormal, 9, Brushes.White);
            var badgeRect = new Rect(tooltipX + tooltipWidth - 45, tooltipY + 10, 35, 18);
            var badgeBrush = GetIntensityBrush(GetTrafficIntensity(isoCode));
            context.DrawRectangle(badgeBrush, null, new RoundedRect(badgeRect, 4));
            context.DrawText(percentBadge, new AvaloniaPoint(tooltipX + tooltipWidth - 42, tooltipY + 12));
        }

        var yOffset = tooltipY + 34;

        // Packets row
        DrawStatRow(context, "📦 Packets:", $"{stats.TotalPackets:N0}", tooltipX + 12, yOffset, tooltipWidth - 24, typefaceNormal, dimColor, brightColor);
        yOffset += 16;

        // Bytes row
        DrawStatRow(context, "💾 Bytes:", stats.TotalBytes.ToFormattedBytes(), tooltipX + 12, yOffset, tooltipWidth - 24, typefaceNormal, dimColor, brightColor);
        yOffset += 16;

        // Unique IPs row
        var ipCount = stats.UniqueIPs?.Count ?? 0;
        DrawStatRow(context, "🖥️ Unique IPs:", $"{ipCount:N0}", tooltipX + 12, yOffset, tooltipWidth - 24, typefaceNormal, dimColor, brightColor);
        yOffset += 16;

        // Direction breakdown
        var inOut = $"↓{stats.IncomingPackets:N0}  ↑{stats.OutgoingPackets:N0}";
        DrawStatRow(context, "📊 In/Out:", inOut, tooltipX + 12, yOffset, tooltipWidth - 24, typefaceNormal, dimColor, brightColor);
        yOffset += 16;

        // Top protocol (if available)
        if (stats.ProtocolBreakdown?.Count > 0)
        {
            var topProto = stats.ProtocolBreakdown.OrderByDescending(p => p.Value).First();
            DrawStatRow(context, "🔌 Top Proto:", $"{topProto.Key} ({topProto.Value:N0})", tooltipX + 12, yOffset, tooltipWidth - 24, typefaceNormal, dimColor, brightColor);
        }

        // Click hint at bottom
        var hintText = new FormattedText("Click for details", System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, new Typeface("Inter", FontStyle.Italic), 9, new SolidColorBrush(Color.FromRgb(100, 116, 139)));
        context.DrawText(hintText, new AvaloniaPoint(tooltipX + tooltipWidth / 2 - hintText.Width / 2, tooltipY + tooltipHeight - 16));
    }

    private static void DrawStatRow(DrawingContext context, string label, string value, double x, double y, double width, Typeface typeface, IBrush labelBrush, IBrush valueBrush)
    {
        var labelText = new FormattedText(label, System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 10, labelBrush);
        context.DrawText(labelText, new AvaloniaPoint(x, y));

        var valueText = new FormattedText(value, System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight, typeface, 10, valueBrush);
        context.DrawText(valueText, new AvaloniaPoint(x + width - valueText.Width, y));
    }

    #endregion

    #region Projection & Geometry Conversion

    private ProjectionParams CalculateProjection(Rect screenBounds)
    {
        // Use Equirectangular projection (simpler, good for world maps)
        // Geographic bounds: typically -180 to 180 (lon), -90 to 90 (lat)

        const double geoMinX = -180;
        const double geoMaxX = 180;
        const double geoMinY = -60;  // Cut off Antarctica for better view
        const double geoMaxY = 85;   // Cut off Arctic for better view

        var geoWidth = geoMaxX - geoMinX;
        var geoHeight = geoMaxY - geoMinY;

        // Calculate scale to fit with some padding
        var padding = 20;
        var availableWidth = screenBounds.Width - padding * 2;
        var availableHeight = screenBounds.Height - padding * 2;

        var scaleX = availableWidth / geoWidth;
        var scaleY = availableHeight / geoHeight;
        var baseScale = Math.Min(scaleX, scaleY);

        // Apply zoom level
        var scale = baseScale * _zoomLevel;

        // Center the map with pan offset
        var offsetX = padding + (availableWidth - geoWidth * baseScale) / 2 + _panOffset.X;
        var offsetY = padding + (availableHeight - geoHeight * baseScale) / 2 + _panOffset.Y;

        // Adjust for zoom center (keep center when zooming)
        var centerX = screenBounds.Width / 2;
        var centerY = screenBounds.Height / 2;
        offsetX = centerX - (centerX - offsetX) * _zoomLevel;
        offsetY = centerY - (centerY - offsetY) * _zoomLevel;

        return new ProjectionParams
        {
            Scale = scale,
            OffsetX = offsetX,
            OffsetY = offsetY,
            GeoMinX = geoMinX,
            GeoMaxY = geoMaxY
        };
    }

    private AvaloniaPoint ProjectPoint(double lon, double lat, ProjectionParams projection)
    {
        // Equirectangular projection
        var x = (lon - projection.GeoMinX) * projection.Scale + projection.OffsetX;
        var y = (projection.GeoMaxY - lat) * projection.Scale + projection.OffsetY;
        return new AvaloniaPoint(x, y);
    }

    private StreamGeometry? ConvertToAvaloniaGeometry(NtsGeometry ntsGeometry, ProjectionParams projection)
    {
        var geometry = new StreamGeometry();

        try
        {
            using var ctx = geometry.Open();

            if (ntsGeometry is Polygon polygon)
            {
                DrawPolygon(ctx, polygon, projection);
            }
            else if (ntsGeometry is MultiPolygon multiPolygon)
            {
                foreach (var poly in multiPolygon.Geometries.OfType<Polygon>())
                {
                    DrawPolygon(ctx, poly, projection);
                }
            }
        }
        catch
        {
            return null;
        }

        return geometry;
    }

    private void DrawPolygon(StreamGeometryContext ctx, Polygon polygon, ProjectionParams projection)
    {
        // Draw exterior ring
        DrawRing(ctx, polygon.ExteriorRing.Coordinates, projection);

        // Draw interior rings (holes)
        foreach (var hole in polygon.InteriorRings)
        {
            DrawRing(ctx, hole.Coordinates, projection);
        }
    }

    private void DrawRing(StreamGeometryContext ctx, NtsCoordinate[] coordinates, ProjectionParams projection)
    {
        if (coordinates.Length < 3) return;

        var firstPoint = ProjectPoint(coordinates[0].X, coordinates[0].Y, projection);
        ctx.BeginFigure(firstPoint, true);

        for (int i = 1; i < coordinates.Length; i++)
        {
            var point = ProjectPoint(coordinates[i].X, coordinates[i].Y, projection);
            ctx.LineTo(point);
        }

        ctx.EndFigure(true);
    }

    #endregion

    #region Mouse Interaction

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);

        var pos = e.GetPosition(this);

        // Handle panning when dragging
        if (_isPanning && _lastPanPoint.HasValue)
        {
            var delta = pos - _lastPanPoint.Value;
            _panOffset = new AvaloniaPoint(_panOffset.X + delta.X, _panOffset.Y + delta.Y);
            _lastPanPoint = pos;
            InvalidateVisual();
            return; // Don't do hover detection while panning
        }

        var previousHovered = _hoveredCountryCode;
        _hoveredCountryCode = HitTestCountry(pos);

        if (_hoveredCountryCode != previousHovered)
        {
            // Update exposed properties for XAML binding
            HoveredCountryCode = _hoveredCountryCode;

            if (_hoveredCountryCode is not null)
            {
                // Special handling for Internal (all non-routable traffic)
                if (_hoveredCountryCode == "INT")
                {
                    HoveredCountryName = "Internal Traffic";
                    // Get combined stats for Internal indicator
                    var combined = GetCombinedInternalStats();
                    HoveredCountryStats = combined.totalPackets > 0
                        ? new CountryTrafficStatistics
                        {
                            CountryCode = "INT",
                            CountryName = "Internal Traffic",
                            TotalPackets = combined.totalPackets,
                            Percentage = combined.percentage
                        }
                        : null;
                }
                else
                {
                    // Get country name from shapefile data
                    var country = _countries.FirstOrDefault(c =>
                        c.IsoCode?.Trim().TrimEnd('\0').Equals(_hoveredCountryCode, StringComparison.OrdinalIgnoreCase) == true);
                    HoveredCountryName = country?.Name ?? _hoveredCountryCode;

                    // Get traffic stats for regular country
                    HoveredCountryStats = TrafficData?.GetValueOrDefault(_hoveredCountryCode);
                }

                if (TrafficData is not null)
                {
                    var hasData = HoveredCountryStats is not null;
                    DebugLogger.Log($"[ShapefileWorldMap] Hover: '{_hoveredCountryCode}' -> name='{HoveredCountryName}', hasData={hasData}");
                }
            }
            else
            {
                HoveredCountryName = null;
                HoveredCountryStats = null;
            }

            Cursor = _hoveredCountryCode is not null ? new Cursor(StandardCursorType.Hand) : Cursor.Default;
            InvalidateVisual();
        }
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        _hoveredCountryCode = null;
        HoveredCountryCode = null;
        HoveredCountryName = null;
        HoveredCountryStats = null;
        Cursor = Cursor.Default;
        InvalidateVisual();
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);

        var point = e.GetCurrentPoint(this);
        var pos = point.Position;
        var isLeftButton = point.Properties.IsLeftButtonPressed;
        var isMiddleButton = point.Properties.IsMiddleButtonPressed;

        // Check zoom control buttons first
        if (isLeftButton)
        {
            if (_zoomInButtonRect.Contains(pos))
            {
                ZoomIn();
                e.Handled = true;
                return;
            }
            if (_zoomOutButtonRect.Contains(pos))
            {
                ZoomOut();
                e.Handled = true;
                return;
            }
            if (_zoomResetButtonRect.Contains(pos))
            {
                ResetZoom();
                e.Handled = true;
                return;
            }
        }

        // Start panning with middle mouse button OR left-click when NOT over a country
        if (isMiddleButton || (isLeftButton && string.IsNullOrEmpty(_hoveredCountryCode)))
        {
            _isPanning = true;
            _lastPanPoint = pos;
            Cursor = new Cursor(StandardCursorType.SizeAll);
            e.Handled = true;
            return;
        }

        DebugLogger.Log($"[ShapefileWorldMap] OnPointerPressed: hovered={_hoveredCountryCode ?? "null"}, leftButton={isLeftButton}, handlerBound={CountryClicked is not null}");

        if (!string.IsNullOrEmpty(_hoveredCountryCode) && isLeftButton)
        {
            DebugLogger.Log($"[ShapefileWorldMap] Invoking CountryClicked for: {_hoveredCountryCode}");
            CountryClicked?.Invoke(_hoveredCountryCode);
            e.Handled = true;
        }
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        if (_isPanning)
        {
            _isPanning = false;
            _lastPanPoint = null;
            Cursor = Cursor.Default;
        }
    }

    protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
    {
        base.OnPointerWheelChanged(e);

        // Mouse wheel zoom
        var delta = e.Delta.Y;
        if (delta > 0)
            ZoomIn();
        else if (delta < 0)
            ZoomOut();

        e.Handled = true;
    }

    private void ZoomIn()
    {
        _zoomLevel = Math.Min(MaxZoom, _zoomLevel + ZoomStep);
        InvalidateVisual();
    }

    private void ZoomOut()
    {
        _zoomLevel = Math.Max(MinZoom, _zoomLevel - ZoomStep);
        // Reset pan when zooming out to 1.0
        if (_zoomLevel <= 1.0)
            _panOffset = new AvaloniaPoint(0, 0);
        InvalidateVisual();
    }

    private void ResetZoom()
    {
        _zoomLevel = 1.0;
        _panOffset = new AvaloniaPoint(0, 0);
        InvalidateVisual();
    }

    private string? HitTestCountry(AvaloniaPoint screenPos)
    {
        // Check Internal traffic indicator first
        if (_internalTrafficRect.Contains(screenPos))
            return "INT";

        // Check cached geometries for hit testing
        foreach (var country in _countries)
        {
            if (country.CachedGeometry?.FillContains(screenPos) == true)
            {
                var raw = country.IsoCode ?? "";
                var trimmed = raw.Trim().TrimEnd('\0'); // Also trim NULL chars from DBF
                return trimmed;
            }
        }
        return null;
    }

    #endregion

    #region Helper Methods

    private IBrush GetCountryBrush(string countryCode)
    {
        var intensity = GetTrafficIntensity(countryCode);
        if (intensity <= 0)
            return DefaultLandBrush;

        return GetIntensityBrush(intensity);
    }

    private double GetTrafficIntensity(string countryCode)
    {
        // Trim country code - shapefile DBF fields are fixed-width with padding
        var trimmedCode = countryCode?.Trim();
        if (string.IsNullOrEmpty(trimmedCode) || TrafficData is null || !TrafficData.TryGetValue(trimmedCode, out var stats))
            return 0;

        var percentage = stats.Percentage;
        if (percentage < 0.1) return 0.15;
        if (percentage < 1) return 0.3;
        if (percentage < 5) return 0.5;
        if (percentage < 10) return 0.75;
        return 1.0;
    }

    private static IBrush GetIntensityBrush(double intensity)
    {
        var colorIndex = (int)(intensity * (TrafficColors.Length - 1));
        colorIndex = Math.Clamp(colorIndex, 0, TrafficColors.Length - 1);
        return new SolidColorBrush(TrafficColors[colorIndex]);
    }

    #endregion

    #region Nested Types

    private class CountryShape
    {
        public required string IsoCode { get; set; }
        public required string Name { get; set; }
        public required NtsGeometry NtsGeometry { get; set; }
        public StreamGeometry? CachedGeometry { get; set; }
    }

    private struct ProjectionParams
    {
        public double Scale;
        public double OffsetX;
        public double OffsetY;
        public double GeoMinX;
        public double GeoMaxY;
    }

    #endregion
}
