using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Input;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Data;
using PCAPAnalyzer.UI.Controls.Base;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Modern continent map control extending UnifiedMapControl.
    /// Supports drill-down from world view to continent view.
    /// Replaces legacy ContinentMapControl with cleaner architecture.
    /// </summary>
    public class ContinentMapControlV2 : UnifiedMapControl
    {
        #region Fields

        private readonly Dictionary<string, ContinentVisual> _continentVisuals = new();
        private readonly List<TrafficFlowAnimation> _trafficFlows = new();
        private Continent? _selectedContinent;
        private bool _isDrillDownMode;
        private readonly Dictionary<string, CountryIconInfo> _countryIcons = new();
        private string? _hoveredCountryCode;

        // Cached continent geometries for performance
        private StreamGeometry? _northAmericaGeometry;
        private StreamGeometry? _southAmericaGeometry;
        private StreamGeometry? _europeGeometry;
        private StreamGeometry? _africaGeometry;
        private StreamGeometry? _asiaGeometry;
        private StreamGeometry? _oceaniaGeometry;

        #endregion

        #region Styled Properties

        public static readonly StyledProperty<Dictionary<string, CountryTrafficStatistics>?> TrafficDataProperty =
            AvaloniaProperty.Register<ContinentMapControlV2, Dictionary<string, CountryTrafficStatistics>?>(
                nameof(TrafficData));

        public static readonly StyledProperty<List<GeographicTrafficFlow>?> TrafficFlowsProperty =
            AvaloniaProperty.Register<ContinentMapControlV2, List<GeographicTrafficFlow>?>(
                nameof(TrafficFlows));

        public static readonly StyledProperty<string?> FocusContinentProperty =
            AvaloniaProperty.Register<ContinentMapControlV2, string?>(nameof(FocusContinent));

        public static readonly StyledProperty<MapVisualizationStyle?> VisualizationStyleProperty =
            AvaloniaProperty.Register<ContinentMapControlV2, MapVisualizationStyle?>(
                nameof(VisualizationStyle), new MapVisualizationStyle());

        public static readonly StyledProperty<Action<string>?> ContinentClickedProperty =
            AvaloniaProperty.Register<ContinentMapControlV2, Action<string>?>(nameof(ContinentClicked));

        #endregion

        #region Properties

        public Dictionary<string, CountryTrafficStatistics>? TrafficData
        {
            get => GetValue(TrafficDataProperty);
            set => SetValue(TrafficDataProperty, value);
        }

        public List<GeographicTrafficFlow>? TrafficFlows
        {
            get => GetValue(TrafficFlowsProperty);
            set => SetValue(TrafficFlowsProperty, value);
        }

        public string? FocusContinent
        {
            get => GetValue(FocusContinentProperty);
            set => SetValue(FocusContinentProperty, value);
        }

        public MapVisualizationStyle? VisualizationStyle
        {
            get => GetValue(VisualizationStyleProperty);
            set => SetValue(VisualizationStyleProperty, value);
        }

        public Action<string>? ContinentClicked
        {
            get => GetValue(ContinentClickedProperty);
            set => SetValue(ContinentClickedProperty, value);
        }

        #endregion

        #region Constructor

        static ContinentMapControlV2()
        {
            TrafficDataProperty.Changed.AddClassHandler<ContinentMapControlV2>(OnTrafficDataChanged);
            TrafficFlowsProperty.Changed.AddClassHandler<ContinentMapControlV2>(OnTrafficFlowsChanged);
            FocusContinentProperty.Changed.AddClassHandler<ContinentMapControlV2>(OnFocusContinentChanged);
        }

        public ContinentMapControlV2()
        {
            InitializeContinents();
        }

        #endregion

        #region Initialization

        private void InitializeContinents()
        {
            foreach (var continent in ContinentData.Continents.Values)
            {
                _continentVisuals[continent.Code] = new ContinentVisual
                {
                    Continent = continent,
                    Bounds = new Rect(0, 0, 100, 100), // Will be calculated on render
                    IsHighlighted = false
                };
            }
        }

        #endregion

        #region Rendering

        protected override void RenderMap(DrawingContext context, Rect bounds)
        {
            if (_isDrillDownMode && _selectedContinent != null)
            {
                RenderContinentView(context, bounds, _selectedContinent);
            }
            else
            {
                RenderWorldView(context, bounds);
            }
        }

        private void RenderWorldView(DrawingContext context, Rect bounds)
        {
            // Render continents with geographic shapes
            RenderContinentShapes(context, bounds);

            // Render public traffic statistics overlay - REMOVED per user request
            // RenderPublicTrafficStats(context, bounds);

            // Render traffic flows if enabled
            if (ShowTrafficFlows && VisualizationStyle?.ShowTrafficFlows == true)
            {
                RenderTrafficFlows(context);
            }
        }

        /// <summary>
        /// Renders continents with recognizable geographic silhouettes
        /// </summary>
        private void RenderContinentShapes(DrawingContext context, Rect bounds)
        {
            // Calculate scale to fit map within bounds
            var mapWidth = bounds.Width;
            var mapHeight = bounds.Height;
            var scaleX = mapWidth / 800.0;  // Design width
            var scaleY = mapHeight / 400.0; // Design height
            var scale = Math.Min(scaleX, scaleY);

            // Center the map
            var offsetX = (mapWidth - 800 * scale) / 2;
            var offsetY = (mapHeight - 400 * scale) / 2;

            // Render each continent
            RenderContinent(context, "NA", GetNorthAmericaGeometry(), scale, offsetX, offsetY);
            RenderContinent(context, "SA", GetSouthAmericaGeometry(), scale, offsetX, offsetY);
            RenderContinent(context, "EU", GetEuropeGeometry(), scale, offsetX, offsetY);
            RenderContinent(context, "AF", GetAfricaGeometry(), scale, offsetX, offsetY);
            RenderContinent(context, "AS", GetAsiaGeometry(), scale, offsetX, offsetY);
            RenderContinent(context, "OC", GetOceaniaGeometry(), scale, offsetX, offsetY);

            // Render special regions (INT, IP6) as legend boxes
            RenderSpecialRegions(context, bounds);
        }

        /// <summary>
        /// Renders a single continent with traffic-based coloring
        /// </summary>
        private void RenderContinent(DrawingContext context, string continentCode, StreamGeometry? geometry,
            double scale, double offsetX, double offsetY)
        {
            if (geometry == null || ExcludedCountries.Contains(continentCode))
                return;

            if (!_continentVisuals.TryGetValue(continentCode, out var visual))
                return;

            // Calculate traffic intensity (for fill color brightness)
            var trafficValue = GetContinentTrafficValue(continentCode);

            // Calculate global traffic percentage (for border color heat map)
            var globalPercentage = GetContinentGlobalPercentage(continentCode);

            // Get base color and apply traffic intensity
            var fillColor = GetTrafficIntensityColor(continentCode, trafficValue);

            // Apply pulse animation if enabled
            if (ShowAnimations && trafficValue > 0)
            {
                var pulse = Math.Sin(AnimationPhase);
                var brightness = 0.8 + (pulse + 1) / 2 * 0.2;
                fillColor = AdjustBrightness(fillColor, brightness);
            }

            // Create gradient fill for depth
            var gradientBrush = CreateContinentGradient(fillColor, trafficValue);

            // Border styling - use heat map colors based on continent's GLOBAL traffic percentage
            var borderColor = visual.IsHighlighted
                ? Color.FromRgb(255, 215, 0) // Gold highlight
                : GetTrafficBorderColor(globalPercentage); // Aggregate traffic from all countries

            var borderThickness = visual.IsHighlighted ? 2.5 : 2.0; // Thicker border to show traffic color
            var pen = new Pen(new SolidColorBrush(borderColor), borderThickness);

            // Apply transform for positioning and scaling
            using (context.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(offsetX, offsetY)))
            {
                // Draw continent shape
                context.DrawGeometry(gradientBrush, pen, geometry);

                // Add glow effect for high traffic
                if (trafficValue > 0.5)
                {
                    var glowColor = Color.FromArgb((byte)(80 * trafficValue), fillColor.R, fillColor.G, fillColor.B);
                    var glowPen = new Pen(new SolidColorBrush(glowColor), 3);
                    context.DrawGeometry(null, glowPen, geometry);
                }
            }

            // Draw continent label if enabled
            if (ShowCountryLabels)
            {
                var labelPos = GetContinentLabelPosition(continentCode, scale, offsetX, offsetY);
                DrawContinentLabel(context, visual.Continent.DisplayName, labelPos, trafficValue);
            }
        }

        /// <summary>
        /// Creates gradient fill for continent based on traffic intensity
        /// </summary>
        private IBrush CreateContinentGradient(Color baseColor, double intensity)
        {
            // Single color for low traffic, gradient for high traffic
            if (intensity < 0.1)
            {
                return new SolidColorBrush(baseColor);
            }

            // Create radial gradient for visual interest
            var darkerColor = AdjustBrightness(baseColor, 0.7);
            return new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops = new GradientStops
                {
                    new GradientStop(baseColor, 0),
                    new GradientStop(darkerColor, 1)
                }
            };
        }

        /// <summary>
        /// Gets traffic-intensity based color for continent
        /// </summary>
        private Color GetTrafficIntensityColor(string continentCode, double trafficValue)
        {
            // Get base continent color
            var baseColor = ContinentData.Continents.TryGetValue(continentCode, out var continent)
                ? Color.Parse(continent.PrimaryColor)
                : Color.FromRgb(139, 148, 158);

            if (trafficValue < 0.01)
            {
                // Very low traffic - dim considerably
                return AdjustBrightness(baseColor, 0.2);
            }
            else if (trafficValue < 0.1)
            {
                // Low traffic - dim
                return AdjustBrightness(baseColor, 0.4);
            }
            else if (trafficValue < 0.3)
            {
                // Medium traffic - moderate brightness
                return AdjustBrightness(baseColor, 0.7);
            }
            else
            {
                // High traffic - full brightness with saturation boost
                return AdjustBrightness(baseColor, 1.0 + trafficValue * 0.3);
            }
        }

        /// <summary>
        /// Returns heat map color for traffic intensity borders (independent of continent color)
        /// Color scale: Cyan (< 1%) -> Blue (< 5%) -> Green (< 10%) -> Yellow (< 20%) -> Orange (< 50%) -> Red (>= 50%)
        /// </summary>
        private Color GetTrafficBorderColor(double trafficValue)
        {
            if (trafficValue < 0.01)
            {
                // < 1% - Cyan (very low)
                return Color.FromRgb(34, 211, 238); // #22D3EE
            }
            else if (trafficValue < 0.05)
            {
                // 1-5% - Blue
                return Color.FromRgb(59, 130, 246); // #3B82F6
            }
            else if (trafficValue < 0.10)
            {
                // 5-10% - Green
                return Color.FromRgb(34, 197, 94); // #22C55E
            }
            else if (trafficValue < 0.20)
            {
                // 10-20% - Yellow
                return Color.FromRgb(234, 179, 8); // #EAB308
            }
            else if (trafficValue < 0.50)
            {
                // 20-50% - Orange
                return Color.FromRgb(249, 115, 22); // #F97316
            }
            else
            {
                // >= 50% - Red (very high)
                return Color.FromRgb(239, 68, 68); // #EF4444
            }
        }

        /// <summary>
        /// Renders public traffic statistics (total packets and bytes, excluding INT/IP6)
        /// </summary>
        private void RenderPublicTrafficStats(DrawingContext context, Rect bounds)
        {
            if (TrafficData == null) return;

            // Calculate public traffic totals (exclude INT and IP6)
            var publicTrafficData = TrafficData.Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6").ToList();
            var totalPackets = publicTrafficData.Sum(c => c.Value.TotalPackets);
            var totalBytes = publicTrafficData.Sum(c => c.Value.TotalBytes);
            var countryCount = publicTrafficData.Count;

            // Format statistics - one line per metric
            var headerText = "Public Traffic:";
            var packetsText = $"  Packets: {totalPackets:N0}";
            var bytesText = $"  Bytes: {FormatBytes(totalBytes)}";
            var countriesText = $"  Countries: {countryCount}";

            // Position in bottom-left corner (below all content)
            var x = 20;
            var y = bounds.Height - 100; // 100px from bottom to fit 4 lines + padding

            // Create formatted text objects
            var lineSpacing = 4;
            var header = new FormattedText(headerText, System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Bold), 13, Brushes.White);
            var line1 = new FormattedText(packetsText, System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal), 12, Brushes.White);
            var line2 = new FormattedText(bytesText, System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal), 12, Brushes.White);
            var line3 = new FormattedText(countriesText, System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal), 12, Brushes.White);

            var maxWidth = Math.Max(Math.Max(header.Width, line1.Width), Math.Max(line2.Width, line3.Width));
            var totalHeight = header.Height + line1.Height + line2.Height + line3.Height + (lineSpacing * 3);

            var bgRect = new Rect(x - 8, y - 6, maxWidth + 16, totalHeight + 12);
            var bgBrush = new SolidColorBrush(Color.FromArgb(220, 30, 35, 42));
            var borderBrush = new SolidColorBrush(Color.FromRgb(59, 130, 246)); // Blue accent
            context.DrawRectangle(bgBrush, new Pen(borderBrush, 2), bgRect, 6, 6);

            // Draw text lines
            var currentY = y;
            context.DrawText(header, new Point(x, currentY));
            currentY += header.Height + lineSpacing;
            context.DrawText(line1, new Point(x, currentY));
            currentY += line1.Height + lineSpacing;
            context.DrawText(line2, new Point(x, currentY));
            currentY += line2.Height + lineSpacing;
            context.DrawText(line3, new Point(x, currentY));
        }

        /// <summary>
        /// Renders special regions (Internal, IPv6) as legend boxes
        /// Positioned in bottom center area to avoid ALL continent overlap
        /// </summary>
        private void RenderSpecialRegions(DrawingContext context, Rect bounds)
        {
            // Position boxes horizontally in bottom margin area, below all continents
            // Map canvas is 800x400, boxes positioned at bottom (y=360) side-by-side
            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);
            var offsetX = (bounds.Width - 800 * scale) / 2;
            var offsetY = (bounds.Height - 400 * scale) / 2;

            var boxWidth = 120 * scale;
            var boxHeight = 35 * scale;
            var horizontalSpacing = 20 * scale;

            // Position boxes side-by-side in bottom area
            var internalX = offsetX + (480 * scale);
            var ipv6X = offsetX + (620 * scale);
            var bottomY = offsetY + (360 * scale);

            // Internal traffic - left box
            if (!ExcludedCountries.Contains("INT"))
            {
                RenderLegendBox(context, "INT", "Internal", internalX, bottomY, boxWidth, boxHeight);
            }

            // IPv6 traffic - right box
            if (!ExcludedCountries.Contains("IP6"))
            {
                RenderLegendBox(context, "IP6", "IPv6 Space", ipv6X, bottomY, boxWidth, boxHeight);
            }
        }

        /// <summary>
        /// Renders a legend box for special regions
        /// </summary>
        private void RenderLegendBox(DrawingContext context, string code, string label,
            double x, double y, double width, double height)
        {
            if (!_continentVisuals.TryGetValue(code, out var visual))
                return;

            var trafficValue = GetContinentTrafficValue(code);
            var fillColor = GetTrafficIntensityColor(code, trafficValue);

            var brush = new SolidColorBrush(fillColor);
            var border = visual.IsHighlighted
                ? new Pen(new SolidColorBrush(Color.FromRgb(255, 215, 0)), 2)
                : new Pen(new SolidColorBrush(Color.FromArgb(100, 139, 148, 158)), 1);

            var rect = new Rect(x, y, width, height);
            context.DrawRectangle(brush, border, rect, 6, 6);

            // Draw label
            var text = new FormattedText(
                label,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI", FontStyle.Normal, FontWeight.SemiBold),
                11,
                Brushes.White);

            var textX = x + (width - text.Width) / 2;
            var textY = y + (height - text.Height) / 2;
            context.DrawText(text, new Point(textX, textY));

            // Store bounds for hit testing
            visual.Bounds = rect;
        }

        /// <summary>
        /// Gets label position for a continent (geometric center of bounding box)
        /// </summary>
        private Point GetContinentLabelPosition(string continentCode, double scale, double offsetX, double offsetY)
        {
            // Calculate geometric centers from actual continent shape bounding boxes
            // These are the visual centers of the simplified angular geometries
            var positions = new Dictionary<string, (double x, double y)>
            {
                ["NA"] = (150, 120),  // North America - centered on main landmass
                ["SA"] = (185, 240),  // South America - centered vertically
                ["EU"] = (440, 110),  // Europe - centered on main peninsula
                ["AF"] = (475, 210),  // Africa - centered on continent body
                ["AS"] = (600, 150),  // Asia - centered on massive landmass
                ["OC"] = (720, 310)   // Oceania - centered on Australia region
            };

            if (positions.TryGetValue(continentCode, out var pos))
            {
                return new Point(pos.x * scale + offsetX, pos.y * scale + offsetY);
            }

            return new Point(0, 0);
        }

        /// <summary>
        /// Draws continent label with background
        /// </summary>
        private void DrawContinentLabel(DrawingContext context, string label, Point position, double intensity)
        {
            var text = new FormattedText(
                label,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Bold),
                13,
                Brushes.White);

            // Background for readability
            var padding = 4;
            var bgRect = new Rect(
                position.X - text.Width / 2 - padding,
                position.Y - text.Height / 2 - padding,
                text.Width + padding * 2,
                text.Height + padding * 2);

            var bgOpacity = (byte)(180 + intensity * 75);
            var bgBrush = new SolidColorBrush(Color.FromArgb(bgOpacity, 0, 0, 0));
            context.DrawRectangle(bgBrush, null, bgRect, 4, 4);

            // Draw text
            var textPos = new Point(position.X - text.Width / 2, position.Y - text.Height / 2);
            context.DrawText(text, textPos);
        }

        private void RenderContinentView(DrawingContext context, Rect bounds, Continent continent)
        {
            // Fill background with continent color
            var bgColor = Color.Parse(continent.PrimaryColor);
            bgColor = Color.FromArgb(64, bgColor.R, bgColor.G, bgColor.B);
            context.FillRectangle(new SolidColorBrush(bgColor), bounds);

            // Draw continent shape silhouette
            var mapBounds = new Rect(20, 60, bounds.Width - 40, bounds.Height - 80);
            DrawContinentShape(context, mapBounds, continent.Code);

            // Draw continent name
            var title = new FormattedText(
                continent.DisplayName,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Arial", FontStyle.Normal, FontWeight.Bold),
                24,
                Brushes.White);

            context.DrawText(title, new Point(20, 20));

            // Clear previous icon data
            _countryIcons.Clear();

            // Render countries geographically with flag icons and collision detection
            if (TrafficData != null)
            {
                var continentCountries = TrafficData
                    .Where(kvp => GetContinentForCountry(kvp.Key) == continent.Code)
                    .OrderByDescending(kvp => kvp.Value.TotalBytes) // Render high-traffic countries first
                    .ToList();

                // Calculate initial positions
                var countryPositions = new List<(string code, Point initial, CountryTrafficStatistics stats)>();
                foreach (var (countryCode, stats) in continentCountries)
                {
                    var position = CountryGeographicData.GetCountryPosition(countryCode, continent.Code);
                    if (!position.HasValue)
                        continue;

                    // Convert normalized (0-1) position to actual pixel position
                    var x = mapBounds.X + position.Value.x * mapBounds.Width;
                    var y = mapBounds.Y + position.Value.y * mapBounds.Height;
                    countryPositions.Add((countryCode, new Point(x, y), stats));
                }

                // Apply collision detection to resolve overlaps
                var resolvedPositions = ResolveIconCollisions(countryPositions, mapBounds);

                // Draw all countries with resolved positions
                // Calculate totals for PUBLIC traffic only (exclude INT/IP6)
                var publicTrafficData = TrafficData.Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6").ToList();
                var totalBytes = publicTrafficData.Sum(c => c.Value.TotalBytes);
                var totalPackets = publicTrafficData.Sum(c => c.Value.TotalPackets);

                foreach (var (countryCode, center) in resolvedPositions)
                {
                    var stats = continentCountries.First(c => c.Key == countryCode).Value;
                    var intensity = totalBytes > 0 ? stats.TotalBytes / (double)totalBytes : 0;

                    // Draw icon and store info for tooltips
                    DrawCountryIconWithInfo(context, countryCode, center, stats, totalPackets, totalBytes);
                }
            }

            // Render tooltip if hovering over a country
            RenderCountryTooltip(context, bounds);
        }

        /// <summary>
        /// Resolves icon collisions using force-directed layout with minimum spacing
        /// </summary>
        private List<(string code, Point position)> ResolveIconCollisions(
            List<(string code, Point initial, CountryTrafficStatistics stats)> countries,
            Rect mapBounds)
        {
            const double minSpacing = 35; // Minimum pixels between icon centers (reduced for better density)
            const int maxIterations = 30; // Fewer iterations for faster convergence
            const double repulsionStrength = 1.5; // Reduced repulsion for tighter clustering
            const double attractionStrength = 0.8; // Stronger pull toward geographic position

            var positions = countries.Select(c => (c.code, position: c.initial, c.stats)).ToList();

            // Iteratively resolve collisions
            for (int iteration = 0; iteration < maxIterations; iteration++)
            {
                var forces = new Dictionary<string, Point>();
                foreach (var country in positions)
                {
                    forces[country.code] = new Point(0, 0);
                }

                // Calculate repulsion forces between overlapping icons
                for (int i = 0; i < positions.Count; i++)
                {
                    for (int j = i + 1; j < positions.Count; j++)
                    {
                        var dx = positions[j].position.X - positions[i].position.X;
                        var dy = positions[j].position.Y - positions[i].position.Y;
                        var distance = Math.Sqrt(dx * dx + dy * dy);

                        if (distance < minSpacing && distance > 0.1)
                        {
                            // Repel icons away from each other
                            var force = repulsionStrength * (minSpacing - distance) / distance;
                            var forceX = force * dx;
                            var forceY = force * dy;

                            var current_i = forces[positions[i].code];
                            forces[positions[i].code] = new Point(current_i.X - forceX, current_i.Y - forceY);

                            var current_j = forces[positions[j].code];
                            forces[positions[j].code] = new Point(current_j.X + forceX, current_j.Y + forceY);
                        }
                    }
                }

                // Apply attraction back to original geographic position
                var initialPositions = countries.ToDictionary(c => c.code, c => c.initial);
                foreach (var country in positions)
                {
                    var originalPos = initialPositions[country.code];
                    var dx = originalPos.X - country.position.X;
                    var dy = originalPos.Y - country.position.Y;

                    var current = forces[country.code];
                    forces[country.code] = new Point(
                        current.X + dx * attractionStrength,
                        current.Y + dy * attractionStrength);
                }

                // Apply forces and clamp to map bounds
                for (int i = 0; i < positions.Count; i++)
                {
                    var force = forces[positions[i].code];
                    var newX = Math.Clamp(positions[i].position.X + force.X, mapBounds.Left + 20, mapBounds.Right - 20);
                    var newY = Math.Clamp(positions[i].position.Y + force.Y, mapBounds.Top + 20, mapBounds.Bottom - 20);

                    positions[i] = (positions[i].code, new Point(newX, newY), positions[i].stats);
                }
            }

            return positions.Select(p => (p.code, p.position)).ToList();
        }

        private void DrawCountryIcon(DrawingContext context, string countryCode, Point center, CountryTrafficStatistics stats, double intensity)
        {
            if (TrafficData == null) return;

            // Calculate percentages for color determination - EXCLUDE internal/IPv6 from totals (public traffic only)
            var publicTrafficData = TrafficData.Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6").ToList();
            var totalPackets = publicTrafficData.Sum(c => c.Value.TotalPackets);
            var totalBytes = publicTrafficData.Sum(c => c.Value.TotalBytes);
            var packetPercentage = totalPackets > 0 ? (double)stats.TotalPackets / totalPackets : 0;
            var bytePercentage = totalBytes > 0 ? (double)stats.TotalBytes / totalBytes : 0;

            // Adaptive icon sizing based on continent population - reduced for better geography
            var continentCode = GetContinentForCountry(countryCode);
            var countriesInContinent = TrafficData.Keys.Count(k => GetContinentForCountry(k) == continentCode);

            // Smaller, more uniform icons for cleaner look and better geographic accuracy
            var baseSize = countriesInContinent > 15 ? 16 : 20; // Reduced from 20/30
            var maxSize = countriesInContinent > 15 ? 24 : 30;  // Reduced from 35/50

            // Use combined traffic percentage for sizing
            var avgPercentage = (packetPercentage + bytePercentage) / 2;
            var sizeMultiplier = 1 + Math.Min(avgPercentage * 1.2, 0.8); // Less size variation
            var iconSize = Math.Clamp(baseSize * sizeMultiplier, baseSize * 0.9, maxSize);
            var radius = iconSize / 2;

            // Apply pulse animation if enabled
            if (ShowAnimations && stats.TotalBytes > 0)
            {
                var pulse = Math.Sin(AnimationPhase);
                var pulseScale = 1 + (pulse + 1) / 2 * 0.15;
                radius *= pulseScale;
            }

            // Get heat map colors for both metrics
            var packetColor = GetCountryHeatMapColor(packetPercentage);
            var byteColor = GetCountryHeatMapColor(bytePercentage);

            // Draw LEFT semicircle (packets) - 90° to 270°
            var leftSemiGeometry = new StreamGeometry();
            using (var ctx = leftSemiGeometry.Open())
            {
                ctx.BeginFigure(new Point(center.X, center.Y - radius), true);
                ctx.ArcTo(new Point(center.X, center.Y + radius), new Size(radius, radius),
                          0, false, SweepDirection.Clockwise);
                ctx.LineTo(center);
                ctx.EndFigure(true);
            }
            context.DrawGeometry(new SolidColorBrush(packetColor), null, leftSemiGeometry);

            // Draw RIGHT semicircle (bytes) - 270° to 90°
            var rightSemiGeometry = new StreamGeometry();
            using (var ctx = rightSemiGeometry.Open())
            {
                ctx.BeginFigure(new Point(center.X, center.Y + radius), true);
                ctx.ArcTo(new Point(center.X, center.Y - radius), new Size(radius, radius),
                          0, false, SweepDirection.Clockwise);
                ctx.LineTo(center);
                ctx.EndFigure(true);
            }
            context.DrawGeometry(new SolidColorBrush(byteColor), null, rightSemiGeometry);

            // Draw border around entire circle for visibility
            var borderColor = Color.FromArgb(255, 220, 220, 220);
            var borderPen = new Pen(new SolidColorBrush(borderColor), 2);
            context.DrawEllipse(null, borderPen, center, radius, radius);

            // Draw country code in center - use white text for visibility
            var avgColorValue = (packetColor.R + packetColor.G + packetColor.B + byteColor.R + byteColor.G + byteColor.B) / 6;
            var textColor = avgColorValue > 128 ? Brushes.Black : Brushes.White;
            var codeText = new FormattedText(
                countryCode,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Arial", FontStyle.Normal, FontWeight.Bold),
                Math.Max(9, radius * 0.6),
                textColor);

            var codeX = center.X - codeText.Width / 2;
            var codeY = center.Y - codeText.Height / 2;
            context.DrawText(codeText, new Point(codeX, codeY));

            // NO TEXT LABELS BELOW ICONS - removed for clean design
            // Tooltips will provide detailed information on hover
        }

        /// <summary>
        /// Returns heat map color for country traffic intensity
        /// Color scale: Grey (< 0.1%) -> Cyan (< 1%) -> Blue (< 3%) -> Green (< 5%) -> Yellow (< 10%) -> Red (>= 10%)
        /// </summary>
        private Color GetCountryHeatMapColor(double percentage)
        {
            if (percentage < 0.001)
            {
                // < 0.1% - Grey (very low/negligible)
                return Color.FromRgb(107, 114, 128); // #6B7280
            }
            else if (percentage < 0.01)
            {
                // 0.1-1% - Cyan (low)
                return Color.FromRgb(34, 211, 238); // #22D3EE
            }
            else if (percentage < 0.03)
            {
                // 1-3% - Blue
                return Color.FromRgb(59, 130, 246); // #3B82F6
            }
            else if (percentage < 0.05)
            {
                // 3-5% - Green
                return Color.FromRgb(34, 197, 94); // #22C55E
            }
            else if (percentage < 0.10)
            {
                // 5-10% - Yellow
                return Color.FromRgb(234, 179, 8); // #EAB308
            }
            else
            {
                // >= 10% - Red (high traffic)
                return Color.FromRgb(239, 68, 68); // #EF4444
            }
        }

        /// <summary>
        /// Draws country icon with SPLIT colors (left=packets, right=bytes) and stores info for tooltips/hit testing
        /// </summary>
        private void DrawCountryIconWithInfo(DrawingContext context, string countryCode, Point center,
            CountryTrafficStatistics stats, long totalPackets, long totalBytes)
        {
            if (TrafficData == null) return;

            // Calculate percentages - percentages are relative to PUBLIC traffic only (exclude INT/IP6)
            var packetPercentage = totalPackets > 0 ? (double)stats.TotalPackets / totalPackets : 0;
            var bytePercentage = totalBytes > 0 ? (double)stats.TotalBytes / totalBytes : 0;

            // Adaptive icon sizing - use average of both percentages for sizing
            var continentCode = GetContinentForCountry(countryCode);
            var countriesInContinent = TrafficData.Keys.Count(k => GetContinentForCountry(k) == continentCode);
            var baseSize = countriesInContinent > 15 ? 20 : 30;
            var maxSize = countriesInContinent > 15 ? 35 : 50;

            var avgPercentage = (packetPercentage + bytePercentage) / 2;
            var sizeMultiplier = 1 + Math.Min(avgPercentage * 2, 1.0);
            var iconSize = Math.Clamp(baseSize * sizeMultiplier, baseSize * 0.8, maxSize);
            var radius = iconSize / 2;

            // Apply pulse animation if enabled
            if (ShowAnimations && stats.TotalBytes > 0)
            {
                var pulse = Math.Sin(AnimationPhase);
                var pulseScale = 1 + (pulse + 1) / 2 * 0.15;
                radius *= pulseScale;
            }

            // Get heat map colors for BOTH metrics (packets and bytes)
            var packetColor = GetCountryHeatMapColor(packetPercentage);
            var byteColor = GetCountryHeatMapColor(bytePercentage);

            // Highlight if hovered
            var isHovered = _hoveredCountryCode == countryCode;

            // Draw glow for hovered country - use blended color for glow
            if (isHovered)
            {
                var glowR = (byte)((packetColor.R + byteColor.R) / 2);
                var glowG = (byte)((packetColor.G + byteColor.G) / 2);
                var glowB = (byte)((packetColor.B + byteColor.B) / 2);
                var glowBrush = new SolidColorBrush(Color.FromArgb(180, glowR, glowG, glowB));
                context.DrawEllipse(glowBrush, null, center, radius + 8, radius + 8);
            }

            // Draw LEFT semicircle (packets) - 90° to 270°
            var leftSemiGeometry = new StreamGeometry();
            using (var ctx = leftSemiGeometry.Open())
            {
                ctx.BeginFigure(new Point(center.X, center.Y - radius), true);
                ctx.ArcTo(new Point(center.X, center.Y + radius), new Size(radius, radius),
                          0, false, SweepDirection.Clockwise);
                ctx.LineTo(center);
                ctx.EndFigure(true);
            }
            context.DrawGeometry(new SolidColorBrush(packetColor), null, leftSemiGeometry);

            // Draw RIGHT semicircle (bytes) - 270° to 90°
            var rightSemiGeometry = new StreamGeometry();
            using (var ctx = rightSemiGeometry.Open())
            {
                ctx.BeginFigure(new Point(center.X, center.Y + radius), true);
                ctx.ArcTo(new Point(center.X, center.Y - radius), new Size(radius, radius),
                          0, false, SweepDirection.Clockwise);
                ctx.LineTo(center);
                ctx.EndFigure(true);
            }
            context.DrawGeometry(new SolidColorBrush(byteColor), null, rightSemiGeometry);

            // Draw border around entire circle
            var borderColor = isHovered ? Color.FromRgb(255, 255, 255) : Color.FromRgb(220, 220, 220);
            var borderThickness = isHovered ? 3.0 : 2.0;
            var borderPen = new Pen(new SolidColorBrush(borderColor), borderThickness);
            context.DrawEllipse(null, borderPen, center, radius, radius);

            // Draw country code - calculate appropriate text color based on both semicircles
            var avgColorValue = (packetColor.R + packetColor.G + packetColor.B + byteColor.R + byteColor.G + byteColor.B) / 6;
            var textColor = avgColorValue > 128 ? Brushes.Black : Brushes.White;
            var codeText = new FormattedText(
                countryCode,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Arial", FontStyle.Normal, FontWeight.Bold),
                Math.Max(9, radius * 0.6),
                textColor);

            var codeX = center.X - codeText.Width / 2;
            var codeY = center.Y - codeText.Height / 2;
            context.DrawText(codeText, new Point(codeX, codeY));

            // Store icon info for tooltips and hit testing
            _countryIcons[countryCode] = new CountryIconInfo
            {
                CountryCode = countryCode,
                Center = center,
                Radius = radius,
                Stats = stats,
                PacketPercentage = packetPercentage * 100,
                BytePercentage = bytePercentage * 100
            };
        }

        /// <summary>
        /// Renders tooltip for hovered country
        /// </summary>
        private void RenderCountryTooltip(DrawingContext context, Rect bounds)
        {
            if (string.IsNullOrEmpty(_hoveredCountryCode) || !_countryIcons.TryGetValue(_hoveredCountryCode, out var iconInfo))
                return;

            // Use country code with flag emoji and full name for display
            var countryFlag = CountryGeographicData.GetCountryFlag(_hoveredCountryCode);
            var countryFullName = CountryNameHelper.GetDisplayName(_hoveredCountryCode, _hoveredCountryCode);
            // countryFullName already includes the code, so just prepend flag
            var countryDisplay = $"{countryFlag} {countryFullName}";
            var stats = iconInfo.Stats;

            // Format tooltip text
            var tooltipLines = new[]
            {
                countryDisplay,
                $"Packets: {iconInfo.PacketPercentage:F1}% ({stats.TotalPackets:N0} packets)",
                $"Bytes: {iconInfo.BytePercentage:F1}% ({FormatBytes(stats.TotalBytes)})",
                $"Unique IPs: {stats.UniqueIPs.Count}"
            };

            // Calculate tooltip size
            var tooltipTexts = tooltipLines.Select(line => new FormattedText(
                line,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal),
                12,
                Brushes.White)).ToList();

            var maxWidth = tooltipTexts.Max(t => t.Width);
            var totalHeight = tooltipTexts.Sum(t => t.Height) + (tooltipLines.Length - 1) * 4 + 16; // padding

            // Position tooltip near icon but avoid edges
            var tooltipX = Math.Clamp(iconInfo.Center.X + iconInfo.Radius + 15, 10, bounds.Width - maxWidth - 20);
            var tooltipY = Math.Clamp(iconInfo.Center.Y - totalHeight / 2, 10, bounds.Height - totalHeight - 10);

            // Draw tooltip background
            var tooltipRect = new Rect(tooltipX - 8, tooltipY - 8, maxWidth + 16, totalHeight);
            var bgBrush = new SolidColorBrush(Color.FromArgb(240, 30, 35, 42)); // Semi-transparent dark
            var borderBrush = new SolidColorBrush(Color.FromRgb(100, 100, 100));
            context.DrawRectangle(bgBrush, new Pen(borderBrush, 1), tooltipRect, 6, 6);

            // Draw tooltip text lines
            var currentY = tooltipY;
            for (int i = 0; i < tooltipTexts.Count; i++)
            {
                var text = tooltipTexts[i];
                // Bold first line (country name)
                if (i == 0)
                {
                    text = new FormattedText(
                        tooltipLines[i],
                        System.Globalization.CultureInfo.CurrentCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Bold),
                        13,
                        Brushes.White);
                }

                context.DrawText(text, new Point(tooltipX, currentY));
                currentY += text.Height + 4;
            }
        }

        private void RenderTrafficFlows(DrawingContext context)
        {
            foreach (var flow in _trafficFlows.Where(f => f.IsActive))
            {
                var sourceContinentCode = GetContinentForCountry(flow.Flow.SourceCountryCode);
                var destContinentCode = GetContinentForCountry(flow.Flow.DestinationCountryCode);

                if (sourceContinentCode == null || destContinentCode == null)
                    continue;

                if (!_continentVisuals.TryGetValue(sourceContinentCode, out var sourceVisual) ||
                    !_continentVisuals.TryGetValue(destContinentCode, out var destVisual))
                    continue;

                var startPoint = sourceVisual.Bounds.Center;
                var endPoint = destVisual.Bounds.Center;

                // Draw curved line
                var intensity = Math.Min(1.0, flow.Flow.Intensity);
                var color = Color.FromArgb(
                    (byte)(intensity * 200),
                    100, 200, 255);

                var pen = new Pen(new SolidColorBrush(color), 2);

                // Simple bezier curve
                var controlPoint = new Point(
                    (startPoint.X + endPoint.X) / 2,
                    Math.Min(startPoint.Y, endPoint.Y) - 50);

                var geometry = new PathGeometry
                {
                    Figures = new PathFigures
                    {
                        new PathFigure
                        {
                            StartPoint = startPoint,
                            Segments = new PathSegments
                            {
                                new QuadraticBezierSegment
                                {
                                    Point1 = controlPoint,
                                    Point2 = endPoint
                                }
                            }
                        }
                    }
                };

                context.DrawGeometry(null, pen, geometry);
            }
        }

        /// <summary>
        /// Updates hit testing bounds for continents based on their geometry
        /// </summary>
        private void UpdateContinentBounds(Rect bounds, double scale, double offsetX, double offsetY)
        {
            // Approximate bounding boxes for continents in 800x400 space
            var continentBounds = new Dictionary<string, Rect>
            {
                ["NA"] = new Rect(20, 40, 180, 160),    // North America
                ["SA"] = new Rect(140, 200, 120, 180),  // South America
                ["EU"] = new Rect(390, 50, 140, 110),   // Europe
                ["AF"] = new Rect(400, 160, 140, 180),  // Africa
                ["AS"] = new Rect(530, 60, 230, 180),   // Asia
                ["OC"] = new Rect(640, 240, 140, 120)   // Oceania
            };

            foreach (var (code, localBounds) in continentBounds)
            {
                if (_continentVisuals.TryGetValue(code, out var visual))
                {
                    // Transform to screen coordinates
                    visual.Bounds = new Rect(
                        localBounds.X * scale + offsetX,
                        localBounds.Y * scale + offsetY,
                        localBounds.Width * scale,
                        localBounds.Height * scale);
                }
            }
        }

        #endregion

        #region Animation

        protected override void UpdateAnimations()
        {
            // Update traffic flow animations
            foreach (var flow in _trafficFlows)
            {
                flow.Progress = (flow.Progress + 0.02) % 1.0;
            }
        }

        #endregion

        #region Interaction

        protected override void OnPointerPressed(PointerPressedEventArgs e)
        {
            // Don't call base - we disable pan/zoom functionality
            // base.OnPointerPressed(e);

            // Only handle left click for continent selection
            if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
                return;

            var point = e.GetPosition(this);

            // Transform mouse position accounting for zoom/pan
            var transformedX = (point.X - PanOffset.X) / ZoomLevel;
            var transformedY = (point.Y - PanOffset.Y) / ZoomLevel;
            var transformedPos = new Point(transformedX, transformedY);

            // Hit test continents
            var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);
            var offsetX = (bounds.Width - 800 * scale) / 2;
            var offsetY = (bounds.Height - 400 * scale) / 2;

            UpdateContinentBounds(bounds, scale, offsetX, offsetY);

            foreach (var visual in _continentVisuals.Values)
            {
                if (visual.Bounds.Contains(transformedPos))
                {
                    DebugLogger.Log($"[ContinentMapControlV2] Continent clicked: {visual.Continent.Code} ('{visual.Continent.DisplayName}')");
                    DebugLogger.Log($"[ContinentMapControlV2] ContinentClicked delegate is {(ContinentClicked == null ? "NULL" : "ASSIGNED")}");

                    if (ContinentClicked != null)
                    {
                        DebugLogger.Log($"[ContinentMapControlV2] Invoking ContinentClicked with code: {visual.Continent.Code}");
                        ContinentClicked.Invoke(visual.Continent.Code);
                    }
                    else
                    {
                        DebugLogger.Log("[ContinentMapControlV2] WARNING: ContinentClicked delegate is null - navigation will not work!");
                    }

                    e.Handled = true;
                    return;
                }
            }
        }

        protected override void OnCountryClicked(string countryCode)
        {
            var continentCode = GetContinentForCountry(countryCode);
            if (continentCode != null)
            {
                FocusContinent = continentCode;
                ContinentClicked?.Invoke(continentCode);
            }
        }

        protected override void UpdateHoveredCountry(Point mousePosition)
        {
            // Transform mouse position
            var transformedX = (mousePosition.X - PanOffset.X) / ZoomLevel;
            var transformedY = (mousePosition.Y - PanOffset.Y) / ZoomLevel;
            var transformedPos = new Point(transformedX, transformedY);

            string? newHovered = null;
            string? newHoveredCountry = null;

            if (_isDrillDownMode && _selectedContinent != null)
            {
                // Drill-down mode - check country icon hits
                foreach (var (countryCode, iconInfo) in _countryIcons)
                {
                    var dx = transformedPos.X - iconInfo.Center.X;
                    var dy = transformedPos.Y - iconInfo.Center.Y;
                    var distance = Math.Sqrt(dx * dx + dy * dy);

                    if (distance <= iconInfo.Radius)
                    {
                        newHoveredCountry = countryCode;
                        break;
                    }
                }
            }
            else
            {
                // World view - check continent hit
                // Update bounds first if needed
                var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
                var scaleX = bounds.Width / 800.0;
                var scaleY = bounds.Height / 400.0;
                var scale = Math.Min(scaleX, scaleY);
                var offsetX = (bounds.Width - 800 * scale) / 2;
                var offsetY = (bounds.Height - 400 * scale) / 2;

                UpdateContinentBounds(bounds, scale, offsetX, offsetY);

                foreach (var visual in _continentVisuals.Values)
                {
                    if (visual.Bounds.Contains(transformedPos))
                    {
                        newHovered = visual.Continent.Code;
                        break;
                    }
                }
            }

            // Update continent highlighting (world view)
            if (newHovered != HoveredCountry)
            {
                foreach (var visual in _continentVisuals.Values)
                {
                    visual.IsHighlighted = visual.Continent.Code == newHovered;
                }

                HoveredCountry = newHovered;
                InvalidateVisual();
            }

            // Update country hover state (continent view)
            if (newHoveredCountry != _hoveredCountryCode)
            {
                _hoveredCountryCode = newHoveredCountry;
                InvalidateVisual(); // Redraw to show/hide tooltip and glow
            }
        }

        /// <summary>
        /// Disable zoom functionality - map should be fixed size
        /// </summary>
        protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
        {
            // Don't call base - disable zoom
            // base.OnPointerWheelChanged(e);
            e.Handled = true;
        }

        /// <summary>
        /// Disable pan functionality - map should be fixed position
        /// </summary>
        protected override void OnPointerMoved(PointerEventArgs e)
        {
            // Call base ONLY for hover detection, not for panning
            var currentPos = e.GetPosition(this);
            UpdateHoveredCountry(currentPos);

            // Don't store mouse position or enable panning
            // base.OnPointerMoved(e);
        }

        /// <summary>
        /// Disable pan release
        /// </summary>
        protected override void OnPointerReleased(PointerReleasedEventArgs e)
        {
            // Don't call base - no panning to release
            // base.OnPointerReleased(e);
        }

        #endregion

        #region Property Change Handlers

        private static void OnTrafficDataChanged(ContinentMapControlV2 control, AvaloniaPropertyChangedEventArgs e)
        {
            control.InvalidateVisual();
        }

        private static void OnTrafficFlowsChanged(ContinentMapControlV2 control, AvaloniaPropertyChangedEventArgs e)
        {
            control._trafficFlows.Clear();

            var flows = e.NewValue as List<GeographicTrafficFlow>;
            if (flows != null)
            {
                foreach (var flow in flows.Take(20)) // Limit for performance
                {
                    control._trafficFlows.Add(new TrafficFlowAnimation
                    {
                        Flow = flow,
                        Progress = 0,
                        IsActive = flow.IsActive
                    });
                }
            }

            control.InvalidateVisual();
        }

        private static void OnFocusContinentChanged(ContinentMapControlV2 control, AvaloniaPropertyChangedEventArgs e)
        {
            var continentCode = e.NewValue as string;

            if (string.IsNullOrEmpty(continentCode) || continentCode == "World")
            {
                control._selectedContinent = null;
                control._isDrillDownMode = false;
            }
            else if (ContinentData.Continents.TryGetValue(continentCode, out var continent))
            {
                control._selectedContinent = continent;
                control._isDrillDownMode = true;
            }

            control.InvalidateVisual();
        }

        #endregion

        #region Helper Methods

        private double GetContinentTrafficValue(string continentCode)
        {
            if (TrafficData == null) return 0;

            var continentTraffic = TrafficData
                .Where(kvp => GetContinentForCountry(kvp.Key) == continentCode)
                .Sum(kvp => kvp.Value.TotalBytes);

            // Handle empty data to prevent "Sequence contains no elements" exception
            if (!TrafficData.Values.Any())
                return 0;

            var maxTraffic = TrafficData.Values.Max(c => c.TotalBytes);
            return maxTraffic > 0 ? continentTraffic / (double)maxTraffic : 0;
        }

        /// <summary>
        /// Calculates continent's percentage of TOTAL global traffic (aggregates all countries)
        /// Used for border heat map colors in legend
        /// </summary>
        private double GetContinentGlobalPercentage(string continentCode)
        {
            if (TrafficData == null || !TrafficData.Values.Any())
                return 0;

            // Sum ALL traffic from countries in this continent
            var continentTraffic = TrafficData
                .Where(kvp => GetContinentForCountry(kvp.Key) == continentCode)
                .Sum(kvp => kvp.Value.TotalBytes);

            // Sum TOTAL traffic from ALL countries worldwide
            var globalTraffic = TrafficData.Values.Sum(c => c.TotalBytes);

            return globalTraffic > 0 ? continentTraffic / (double)globalTraffic : 0;
        }

        private string? GetContinentForCountry(string countryCode)
        {
            return CountryGeographicData.GetContinentForCountry(countryCode);
        }

        private Color GetContinentColor(string continentCode, double trafficValue)
        {
            if (ContinentData.Continents.TryGetValue(continentCode, out var continent))
            {
                var baseColor = Color.Parse(continent.PrimaryColor);

                if (trafficValue > 0)
                {
                    // Brighten based on traffic
                    var brightness = 0.5 + trafficValue * 0.5;
                    return AdjustBrightness(baseColor, brightness);
                }

                return AdjustBrightness(baseColor, 0.3);
            }

            return Color.FromArgb(255, 28, 33, 40);
        }

        private Color GetHeatMapColor(double value)
        {
            // Heat map: blue -> green -> yellow -> red
            if (value < 0.25)
            {
                var t = value / 0.25;
                return Color.FromRgb(0, (byte)(128 + 127 * t), (byte)(255 * (1 - t)));
            }
            else if (value < 0.5)
            {
                var t = (value - 0.25) / 0.25;
                return Color.FromRgb((byte)(255 * t), 255, 0);
            }
            else if (value < 0.75)
            {
                var t = (value - 0.5) / 0.25;
                return Color.FromRgb(255, (byte)(255 * (1 - t)), 0);
            }
            else
            {
                return Colors.Red;
            }
        }

        private Color AdjustBrightness(Color color, double factor)
        {
            return Color.FromRgb(
                (byte)Math.Min(255, color.R * factor),
                (byte)Math.Min(255, color.G * factor),
                (byte)Math.Min(255, color.B * factor));
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double size = bytes;
            int order = 0;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:F1} {sizes[order]}";
        }

        private void DrawContinentShape(DrawingContext context, Rect bounds, string continentCode)
        {
            // Draw continent silhouette using cached geometries from world map
            var shapeColor = Color.FromArgb(40, 255, 255, 255); // Semi-transparent white
            var shapeBrush = new SolidColorBrush(shapeColor);

            // Get the cached geometry for the continent
            StreamGeometry? geometry = continentCode switch
            {
                "NA" => GetNorthAmericaGeometry(),
                "SA" => GetSouthAmericaGeometry(),
                "EU" => GetEuropeGeometry(),
                "AF" => GetAfricaGeometry(),
                "AS" => GetAsiaGeometry(),
                "OC" => GetOceaniaGeometry(),
                _ => null
            };

            if (geometry == null)
                return;

            // Transform geometry from 800x400 coordinate space to fit bounds
            // Calculate scale to fit geometry within bounds while maintaining aspect ratio
            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);

            // Center the geometry within bounds
            var scaledWidth = 800 * scale;
            var scaledHeight = 400 * scale;
            var offsetX = bounds.Left + (bounds.Width - scaledWidth) / 2;
            var offsetY = bounds.Top + (bounds.Height - scaledHeight) / 2;

            // Apply transformation and render
            using (context.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(offsetX, offsetY)))
            {
                context.DrawGeometry(shapeBrush, null, geometry);
            }
        }

        #endregion

        #region Continent Geometries

        /// <summary>
        /// Returns cached StreamGeometry for North America (Canada, USA, Mexico)
        /// Simplified angular design with 17 points - wide Canadian top narrowing to Central America
        /// Coordinates in 800x400 canvas space
        /// </summary>
        private StreamGeometry? GetNorthAmericaGeometry()
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
        private StreamGeometry? GetSouthAmericaGeometry()
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
        private StreamGeometry? GetEuropeGeometry()
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
        private StreamGeometry? GetAfricaGeometry()
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
        private StreamGeometry? GetAsiaGeometry()
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
        private StreamGeometry? GetOceaniaGeometry()
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

        #endregion

        #region Helper Classes

        private class ContinentVisual
        {
            public Continent Continent { get; set; } = new();
            public Rect Bounds { get; set; }
            public bool IsHighlighted { get; set; }
        }

        private class TrafficFlowAnimation
        {
            public GeographicTrafficFlow Flow { get; set; } = new();
            public double Progress { get; set; }
            public bool IsActive { get; set; }
        }

        /// <summary>
        /// Stores information about rendered country icons for hit testing and tooltips
        /// </summary>
        private class CountryIconInfo
        {
            public string CountryCode { get; set; } = string.Empty;
            public Point Center { get; set; }
            public double Radius { get; set; }
            public CountryTrafficStatistics Stats { get; set; } = new();
            public double PacketPercentage { get; set; }
            public double BytePercentage { get; set; }
        }

        #endregion
    }
}
