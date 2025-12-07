using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Data;
using PCAPAnalyzer.UI.Controls.Maps.Data;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Controls.Maps.Interaction;

namespace PCAPAnalyzer.UI.Controls.Maps.Rendering
{
    /// <summary>
    /// Handles rendering of continent map visuals including continent shapes, labels, and special regions.
    /// </summary>
    public class ContinentMapRenderer
    {
        private readonly Dictionary<string, ContinentVisual> _continentVisuals = [];
        private readonly CountryIconManager _iconManager = new();

        public IReadOnlyDictionary<string, ContinentVisual> ContinentVisuals => _continentVisuals;
        public CountryIconManager IconManager => _iconManager;

        public void InitializeContinents()
        {
            foreach (var continent in ContinentData.Continents.Values)
            {
                _continentVisuals[continent.Code] = new ContinentVisual
                {
                    Continent = continent,
                    Bounds = new Rect(0, 0, 100, 100),
                    IsHighlighted = false
                };
            }
        }

        /// <summary>
        /// Renders ocean background with subtle gradient for depth effect
        /// </summary>
        private void RenderOceanBackground(DrawingContext context, Rect bounds, double scale, double offsetX, double offsetY)
        {
            // Calculate the map area
            var mapRect = new Rect(offsetX, offsetY, 800 * scale, 400 * scale);

            // Create ocean gradient - dark blue with subtle depth variation
            var oceanGradient = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops = new GradientStops
                {
                    new GradientStop(Color.FromRgb(15, 23, 42), 0),      // Slate-900
                    new GradientStop(Color.FromRgb(23, 37, 58), 0.3),    // Darker blue
                    new GradientStop(Color.FromRgb(30, 41, 59), 0.7),    // Slate-800
                    new GradientStop(Color.FromRgb(15, 23, 42), 1)       // Back to dark
                }
            };

            // Draw ocean background with rounded corners
            context.DrawRectangle(oceanGradient, null, mapRect, 12, 12);

            // Add subtle grid lines for depth (latitude/longitude effect)
            var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(25, 100, 120, 140)), 0.5);

            // Horizontal lines (latitude)
            for (int i = 1; i < 4; i++)
            {
                var y = offsetY + (100 * i * scale);
                context.DrawLine(gridPen, new Point(offsetX, y), new Point(offsetX + 800 * scale, y));
            }

            // Vertical lines (longitude)
            for (int i = 1; i < 8; i++)
            {
                var x = offsetX + (100 * i * scale);
                context.DrawLine(gridPen, new Point(x, offsetY), new Point(x, offsetY + 400 * scale));
            }
        }

        /// <summary>
        /// Renders continents with recognizable geographic silhouettes
        /// </summary>
        public void RenderContinentShapes(DrawingContext context, Rect bounds,
            Dictionary<string, CountryTrafficStatistics>? trafficData,
            HashSet<string> excludedCountries, bool showCountryLabels, bool showAnimations, double animationPhase)
        {
            // Calculate scale to fit map within bounds
            var mapWidth = bounds.Width;
            var mapHeight = bounds.Height;
            var scaleX = mapWidth / 800.0;
            var scaleY = mapHeight / 400.0;
            var scale = Math.Min(scaleX, scaleY);

            // Center the map
            var offsetX = (mapWidth - 800 * scale) / 2;
            var offsetY = (mapHeight - 400 * scale) / 2;

            // Render ocean background with subtle gradient
            RenderOceanBackground(context, bounds, scale, offsetX, offsetY);

            // Render each continent
            RenderContinent(context, "NA", ContinentGeometry.GetNorthAmericaGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);
            RenderContinent(context, "SA", ContinentGeometry.GetSouthAmericaGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);
            RenderContinent(context, "EU", ContinentGeometry.GetEuropeGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);
            RenderContinent(context, "AF", ContinentGeometry.GetAfricaGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);
            RenderContinent(context, "AS", ContinentGeometry.GetAsiaGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);
            RenderContinent(context, "OC", ContinentGeometry.GetOceaniaGeometry(), scale, offsetX, offsetY,
                trafficData, excludedCountries, showCountryLabels, showAnimations, animationPhase);

            // Render special regions (INT, IP6) as legend boxes
            RenderSpecialRegions(context, bounds, trafficData, excludedCountries);
        }

        /// <summary>
        /// Renders a single continent with traffic-based coloring
        /// </summary>
        private void RenderContinent(DrawingContext context, string continentCode, StreamGeometry? geometry,
            double scale, double offsetX, double offsetY, Dictionary<string, CountryTrafficStatistics>? trafficData,
            HashSet<string> excludedCountries, bool showCountryLabels, bool showAnimations, double animationPhase)
        {
            if (geometry is null || excludedCountries.Contains(continentCode))
                return;

            if (!_continentVisuals.TryGetValue(continentCode, out var visual))
                return;

            // Calculate traffic intensity (for fill color brightness)
            var trafficValue = GetContinentTrafficValue(continentCode, trafficData);

            // Calculate global traffic percentage (for border color heat map)
            var globalPercentage = GetContinentGlobalPercentage(continentCode, trafficData);

            // Get base color and apply traffic intensity
            var fillColor = GetTrafficIntensityColor(continentCode, trafficValue);

            // Apply pulse animation if enabled
            if (showAnimations && trafficValue > 0)
            {
                var pulse = Math.Sin(animationPhase);
                var brightness = 0.8 + (pulse + 1) / 2 * 0.2;
                fillColor = MapColorScheme.AdjustBrightness(fillColor, brightness);
            }

            // Create gradient fill for depth
            var gradientBrush = MapColorScheme.CreateContinentGradient(fillColor, trafficValue);

            // Border styling - use heat map colors based on continent's GLOBAL traffic percentage
            var borderColor = visual.IsHighlighted
                ? Color.FromRgb(255, 215, 0) // Gold highlight
                : MapColorScheme.GetTrafficBorderColor(globalPercentage);

            var borderThickness = visual.IsHighlighted ? 2.5 : 2.0;
            var pen = new Pen(new SolidColorBrush(borderColor), borderThickness);

            // Apply transform for positioning and scaling
            using (context.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(offsetX, offsetY)))
            {
                // Draw drop shadow for depth effect
                var shadowOffset = Matrix.CreateTranslation(3, 3);
                using (context.PushTransform(shadowOffset))
                {
                    var shadowBrush = new SolidColorBrush(Color.FromArgb(60, 0, 0, 0));
                    context.DrawGeometry(shadowBrush, null, geometry);
                }

                // Draw continent shape with gradient fill
                context.DrawGeometry(gradientBrush, pen, geometry);

                // Add inner highlight for 3D effect (top-left edge)
                var highlightPen = new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1);
                context.DrawGeometry(null, highlightPen, geometry);

                // Add glow effect for high traffic
                if (trafficValue > 0.5)
                {
                    var glowColor = Color.FromArgb((byte)(80 * trafficValue), fillColor.R, fillColor.G, fillColor.B);
                    var glowPen = new Pen(new SolidColorBrush(glowColor), 4);
                    context.DrawGeometry(null, glowPen, geometry);
                }
            }

            // Draw continent label if enabled
            if (showCountryLabels)
            {
                var labelPos = GetContinentLabelPosition(continentCode, scale, offsetX, offsetY);
                DrawContinentLabel(context, visual.Continent.DisplayName, labelPos, trafficValue);
            }
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

            return MapColorScheme.GetTrafficIntensityColor(baseColor, trafficValue);
        }

        /// <summary>
        /// Renders special regions (Internal, IPv6) as legend boxes
        /// </summary>
        private void RenderSpecialRegions(DrawingContext context, Rect bounds,
            Dictionary<string, CountryTrafficStatistics>? trafficData, HashSet<string> excludedCountries)
        {
            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);
            var offsetX = (bounds.Width - 800 * scale) / 2;
            var offsetY = (bounds.Height - 400 * scale) / 2;

            var boxWidth = 120 * scale;
            var boxHeight = 35 * scale;

            var internalX = offsetX + (480 * scale);
            var ipv6X = offsetX + (620 * scale);
            var bottomY = offsetY + (360 * scale);

            if (!excludedCountries.Contains("INT"))
            {
                RenderLegendBox(context, "INT", "Internal", internalX, bottomY, boxWidth, boxHeight, trafficData);
            }

            if (!excludedCountries.Contains("IP6"))
            {
                RenderLegendBox(context, "IP6", "IPv6 Space", ipv6X, bottomY, boxWidth, boxHeight, trafficData);
            }
        }

        /// <summary>
        /// Renders a legend box for special regions
        /// </summary>
        private void RenderLegendBox(DrawingContext context, string code, string label,
            double x, double y, double width, double height, Dictionary<string, CountryTrafficStatistics>? trafficData)
        {
            if (!_continentVisuals.TryGetValue(code, out var visual))
                return;

            var trafficValue = GetContinentTrafficValue(code, trafficData);
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
            var positions = new Dictionary<string, (double x, double y)>
            {
                ["NA"] = (150, 120),
                ["SA"] = (185, 240),
                ["EU"] = (440, 110),
                ["AF"] = (475, 210),
                ["AS"] = (600, 150),
                ["OC"] = (720, 310)
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

            var padding = 4;
            var bgRect = new Rect(
                position.X - text.Width / 2 - padding,
                position.Y - text.Height / 2 - padding,
                text.Width + padding * 2,
                text.Height + padding * 2);

            var bgOpacity = (byte)(180 + intensity * 75);
            var bgBrush = new SolidColorBrush(Color.FromArgb(bgOpacity, 0, 0, 0));
            context.DrawRectangle(bgBrush, null, bgRect, 4, 4);

            var textPos = new Point(position.X - text.Width / 2, position.Y - text.Height / 2);
            context.DrawText(text, textPos);
        }

        /// <summary>
        /// Draws continent shape silhouette for drill-down view
        /// </summary>
        public void DrawContinentShape(DrawingContext context, Rect bounds, string continentCode)
        {
            var shapeColor = Color.FromArgb(40, 255, 255, 255);
            var shapeBrush = new SolidColorBrush(shapeColor);

            var geometry = ContinentGeometry.GetGeometry(continentCode);
            if (geometry is null)
                return;

            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);

            var scaledWidth = 800 * scale;
            var scaledHeight = 400 * scale;
            var offsetX = bounds.Left + (bounds.Width - scaledWidth) / 2;
            var offsetY = bounds.Top + (bounds.Height - scaledHeight) / 2;

            using (context.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(offsetX, offsetY)))
            {
                context.DrawGeometry(shapeBrush, null, geometry);
            }
        }

        /// <summary>
        /// Updates hit testing bounds for continents
        /// </summary>
        public void UpdateContinentBounds(Rect bounds, double scale, double offsetX, double offsetY)
        {
            var continentBounds = new Dictionary<string, Rect>
            {
                ["NA"] = new Rect(20, 40, 180, 160),
                ["SA"] = new Rect(140, 200, 120, 180),
                ["EU"] = new Rect(390, 50, 140, 110),
                ["AF"] = new Rect(400, 160, 140, 180),
                ["AS"] = new Rect(530, 60, 230, 180),
                ["OC"] = new Rect(640, 240, 140, 120)
            };

            foreach (var (code, localBounds) in continentBounds)
            {
                if (_continentVisuals.TryGetValue(code, out var visual))
                {
                    visual.Bounds = new Rect(
                        localBounds.X * scale + offsetX,
                        localBounds.Y * scale + offsetY,
                        localBounds.Width * scale,
                        localBounds.Height * scale);
                }
            }
        }

        private double GetContinentTrafficValue(string continentCode, Dictionary<string, CountryTrafficStatistics>? trafficData)
        {
            if (trafficData is null) return 0;

            var continentTraffic = trafficData
                .Where(kvp => CountryGeographicData.GetContinentForCountry(kvp.Key) == continentCode)
                .Sum(kvp => kvp.Value.TotalBytes);

            if (!trafficData.Values.Any())
                return 0;

            var maxTraffic = trafficData.Values.Max(c => c.TotalBytes);
            return maxTraffic > 0 ? continentTraffic / (double)maxTraffic : 0;
        }

        private double GetContinentGlobalPercentage(string continentCode, Dictionary<string, CountryTrafficStatistics>? trafficData)
        {
            if (trafficData is null || !trafficData.Values.Any())
                return 0;

            var continentTraffic = trafficData
                .Where(kvp => CountryGeographicData.GetContinentForCountry(kvp.Key) == continentCode)
                .Sum(kvp => kvp.Value.TotalBytes);

            var globalTraffic = trafficData.Values.Sum(c => c.TotalBytes);

            return globalTraffic > 0 ? continentTraffic / (double)globalTraffic : 0;
        }
    }

    public class ContinentVisual
    {
        public Continent Continent { get; set; } = new();
        public Rect Bounds { get; set; }
        public bool IsHighlighted { get; set; }
    }
}
