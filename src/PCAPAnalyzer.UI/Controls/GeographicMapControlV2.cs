using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Controls.Base;
using System.Globalization;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Modern geographic map control with real coordinates extending UnifiedMapControl.
    /// Supports heat maps, traffic flows, and protocol-based visualization.
    /// Replaces legacy GeographicWorldMapControl with cleaner architecture.
    /// </summary>
    public class GeographicMapControlV2 : UnifiedMapControl
    {
        #region Fields

        private readonly Dictionary<string, CountryGeoData> _countryGeoData = new();
        private readonly Dictionary<Protocol, Color> _protocolColors = new();
        private readonly List<TrafficFlowAnimation> _trafficFlows = new();
        private readonly Dictionary<string, HeatMapPoint> _heatMapPoints = new();

        #endregion

        #region Styled Properties

        public static readonly new StyledProperty<Dictionary<string, CountryTrafficStatistics>?> CountryDataProperty =
            AvaloniaProperty.Register<GeographicMapControlV2, Dictionary<string, CountryTrafficStatistics>?>(
                "CountryData");

        public static readonly StyledProperty<Dictionary<Protocol, List<PacketInfo>>?> ProtocolDataProperty =
            AvaloniaProperty.Register<GeographicMapControlV2, Dictionary<Protocol, List<PacketInfo>>?>(
                nameof(ProtocolData));

        public static readonly StyledProperty<bool> ShowHeatMapProperty =
            AvaloniaProperty.Register<GeographicMapControlV2, bool>(nameof(ShowHeatMap), true);

        public static readonly StyledProperty<bool> ShowProtocolColorCodingProperty =
            AvaloniaProperty.Register<GeographicMapControlV2, bool>(nameof(ShowProtocolColorCoding), true);

        #endregion

        #region Properties

        public new Dictionary<string, CountryTrafficStatistics>? CountryData
        {
            get => GetValue(CountryDataProperty);
            set => SetValue(CountryDataProperty, value);
        }

        public Dictionary<Protocol, List<PacketInfo>>? ProtocolData
        {
            get => GetValue(ProtocolDataProperty);
            set => SetValue(ProtocolDataProperty, value);
        }

        public bool ShowHeatMap
        {
            get => GetValue(ShowHeatMapProperty);
            set => SetValue(ShowHeatMapProperty, value);
        }

        public bool ShowProtocolColorCoding
        {
            get => GetValue(ShowProtocolColorCodingProperty);
            set => SetValue(ShowProtocolColorCodingProperty, value);
        }

        #endregion

        #region Constructor

        static GeographicMapControlV2()
        {
            ProtocolDataProperty.Changed.AddClassHandler<GeographicMapControlV2>(OnProtocolDataChanged);
        }

        public GeographicMapControlV2()
        {
            InitializeGeoData();
            InitializeProtocolColors();
        }

        #endregion

        #region Initialization

        private void InitializeGeoData()
        {
            // Approximate geographic centers for countries
            _countryGeoData["US"] = new CountryGeoData { Latitude = 39.0, Longitude = -98.0, Name = "United States" };
            _countryGeoData["CN"] = new CountryGeoData { Latitude = 35.0, Longitude = 105.0, Name = "China" };
            _countryGeoData["RU"] = new CountryGeoData { Latitude = 60.0, Longitude = 100.0, Name = "Russia" };
            _countryGeoData["DE"] = new CountryGeoData { Latitude = 51.0, Longitude = 10.0, Name = "Germany" };
            _countryGeoData["GB"] = new CountryGeoData { Latitude = 54.0, Longitude = -2.0, Name = "United Kingdom" };
            _countryGeoData["FR"] = new CountryGeoData { Latitude = 46.0, Longitude = 2.0, Name = "France" };
            _countryGeoData["JP"] = new CountryGeoData { Latitude = 36.0, Longitude = 138.0, Name = "Japan" };
            _countryGeoData["IN"] = new CountryGeoData { Latitude = 20.0, Longitude = 77.0, Name = "India" };
            _countryGeoData["BR"] = new CountryGeoData { Latitude = -10.0, Longitude = -55.0, Name = "Brazil" };
            _countryGeoData["CA"] = new CountryGeoData { Latitude = 56.0, Longitude = -106.0, Name = "Canada" };
            _countryGeoData["AU"] = new CountryGeoData { Latitude = -27.0, Longitude = 133.0, Name = "Australia" };
        }

        private void InitializeProtocolColors()
        {
            _protocolColors[Protocol.TCP] = Color.FromRgb(52, 152, 219);      // Blue
            _protocolColors[Protocol.UDP] = Color.FromRgb(46, 204, 113);      // Green
            _protocolColors[Protocol.ICMP] = Color.FromRgb(243, 156, 18);     // Orange
            _protocolColors[Protocol.DNS] = Color.FromRgb(155, 89, 182);      // Purple
            _protocolColors[Protocol.HTTP] = Color.FromRgb(231, 76, 60);      // Red
        }

        #endregion

        #region Property Changed Handlers

        private static void OnProtocolDataChanged(GeographicMapControlV2 control, AvaloniaPropertyChangedEventArgs e)
        {
            control.UpdateTrafficFlows();
            control.InvalidateVisual();
        }

        #endregion

        #region Rendering

        protected override void RenderMap(DrawingContext context, Rect bounds)
        {
            // Render world outline
            RenderWorldOutline(context, bounds);

            // Render heat map if enabled
            if (ShowHeatMap && _heatMapPoints.Any())
            {
                RenderHeatMap(context, bounds);
            }

            // Render country markers
            RenderCountryMarkers(context, bounds);

            // Render traffic flows if enabled
            if (ShowTrafficFlows && _trafficFlows.Any())
            {
                RenderTrafficFlows(context, bounds);
            }

            // Render labels if enabled
            if (ShowCountryLabels)
            {
                RenderCountryLabels(context, bounds);
            }
        }

        private void RenderWorldOutline(DrawingContext context, Rect bounds)
        {
            var outlinePen = new Pen(new SolidColorBrush(Color.FromRgb(48, 54, 61)), 1.5);
            var continentBrush = new SolidColorBrush(Color.FromRgb(28, 33, 40));

            // Simple world map representation (simplified continents)
            var mapWidth = bounds.Width;
            var mapHeight = bounds.Height;

            // Draw simplified continent shapes
            DrawSimplifiedContinent(context, bounds, continentBrush, outlinePen);
        }

        private void DrawSimplifiedContinent(DrawingContext context, Rect bounds, IBrush fill, IPen pen)
        {
            // Draw a simplified world map using rectangles for continents
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                // North America
                var naRect = new Rect(bounds.Width * 0.1, bounds.Height * 0.2, bounds.Width * 0.25, bounds.Height * 0.3);
                ctx.BeginFigure(naRect.TopLeft, true);
                ctx.LineTo(naRect.TopRight);
                ctx.LineTo(naRect.BottomRight);
                ctx.LineTo(naRect.BottomLeft);
                ctx.EndFigure(true);

                // Europe
                var euRect = new Rect(bounds.Width * 0.45, bounds.Height * 0.15, bounds.Width * 0.15, bounds.Height * 0.2);
                ctx.BeginFigure(euRect.TopLeft, true);
                ctx.LineTo(euRect.TopRight);
                ctx.LineTo(euRect.BottomRight);
                ctx.LineTo(euRect.BottomLeft);
                ctx.EndFigure(true);

                // Asia
                var asRect = new Rect(bounds.Width * 0.6, bounds.Height * 0.2, bounds.Width * 0.3, bounds.Height * 0.35);
                ctx.BeginFigure(asRect.TopLeft, true);
                ctx.LineTo(asRect.TopRight);
                ctx.LineTo(asRect.BottomRight);
                ctx.LineTo(asRect.BottomLeft);
                ctx.EndFigure(true);
            }

            context.DrawGeometry(fill, pen, geometry);
        }

        private void RenderHeatMap(DrawingContext context, Rect bounds)
        {
            foreach (var heatPoint in _heatMapPoints.Values)
            {
                var screenPos = GeoToScreen(heatPoint.Latitude, heatPoint.Longitude, bounds);
                var intensity = Math.Min(1.0, heatPoint.Intensity);
                var color = Color.FromArgb(
                    (byte)(intensity * 180),
                    (byte)(255 - intensity * 100),
                    (byte)(100 + intensity * 100),
                    (byte)(intensity * 155)
                );

                var brush = new RadialGradientBrush
                {
                    GradientStops = new GradientStops
                    {
                        new GradientStop(color, 0.0),
                        new GradientStop(Colors.Transparent, 1.0)
                    }
                };

                var radius = 15 + intensity * 20;
                context.DrawEllipse(brush, null, screenPos, radius, radius);
            }
        }

        private void RenderCountryMarkers(DrawingContext context, Rect bounds)
        {
            if (CountryData == null) return;

            foreach (var kvp in CountryData)
            {
                if (!_countryGeoData.TryGetValue(kvp.Key, out var geoData)) continue;
                if (ExcludedCountries?.Contains(kvp.Key) == true) continue;

                var screenPos = GeoToScreen(geoData.Latitude, geoData.Longitude, bounds);
                var stats = kvp.Value;
                var intensity = CalculateIntensity(stats);

                // Draw country marker
                var markerColor = ShowProtocolColorCoding ? GetProtocolColor(stats) : GetIntensityColor(intensity);
                var brush = new SolidColorBrush(markerColor);
                var radius = 3 + intensity * 8;

                context.DrawEllipse(brush, new Pen(Brushes.White, 1), screenPos, radius, radius);
            }
        }

        private void RenderTrafficFlows(DrawingContext context, Rect bounds)
        {
            foreach (var flow in _trafficFlows.Where(f => f.IsActive))
            {
                var color = _protocolColors.GetValueOrDefault(flow.Protocol, Colors.Gray);
                var brush = new SolidColorBrush(Color.FromArgb((byte)(flow.Opacity * 255), color.R, color.G, color.B));
                var pen = new Pen(brush, 1.5);

                // Draw bezier curve for traffic flow
                var geometry = new StreamGeometry();
                using (var ctx = geometry.Open())
                {
                    ctx.BeginFigure(flow.StartPoint, false);
                    var controlPoint = new Point(
                        (flow.StartPoint.X + flow.EndPoint.X) / 2,
                        Math.Min(flow.StartPoint.Y, flow.EndPoint.Y) - 30
                    );
                    ctx.CubicBezierTo(controlPoint, controlPoint, flow.EndPoint);
                }

                context.DrawGeometry(null, pen, geometry);
            }
        }

        private void RenderCountryLabels(DrawingContext context, Rect bounds)
        {
            if (CountryData == null || !ShowCountryLabels) return;

            var typeface = new Typeface("Segoe UI");

            foreach (var kvp in CountryData.Take(10))
            {
                if (!_countryGeoData.TryGetValue(kvp.Key, out var geoData)) continue;
                if (ExcludedCountries?.Contains(kvp.Key) == true) continue;

                var screenPos = GeoToScreen(geoData.Latitude, geoData.Longitude, bounds);
                var text = new FormattedText(
                    geoData.Name,
                    System.Globalization.CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    10,
                    Brushes.White
                );

                context.DrawText(text, new Point(screenPos.X - text.Width / 2, screenPos.Y - 20));
            }
        }

        #endregion

        #region Update Methods

        protected override void UpdateAnimations()
        {
            // Update traffic flow animations
            foreach (var flow in _trafficFlows)
            {
                flow.Progress += 0.02;
                if (flow.Progress >= 1.0)
                {
                    flow.Progress = 0;
                    flow.IsActive = false;
                }
            }

            // Remove inactive flows
            _trafficFlows.RemoveAll(f => !f.IsActive && f.Progress >= 1.0);
        }

        private void UpdateTrafficFlows()
        {
            _trafficFlows.Clear();

            if (ProtocolData == null) return;

            foreach (var protocolPackets in ProtocolData)
            {
                var protocol = protocolPackets.Key;
                var packets = protocolPackets.Value.Take(20); // Limit for performance

                foreach (var packet in packets)
                {
                    // Create traffic flow visualization
                    // This is a simplified version - in production you'd get real geo coordinates
                    _trafficFlows.Add(new TrafficFlowAnimation
                    {
                        Protocol = protocol,
                        StartPoint = new Point(100, 100),
                        EndPoint = new Point(200, 200),
                        IsActive = true,
                        Opacity = 0.6,
                        Progress = 0
                    });
                }
            }
        }

        #endregion

        #region Helper Methods

        protected override void OnCountryClicked(string countryCode)
        {
            // Can be overridden by derived classes or handled via event
            DebugLogger.Log($"Country clicked: {countryCode}");
        }

        private Point GeoToScreen(double latitude, double longitude, Rect bounds)
        {
            // Mercator projection
            var x = (longitude + 180) * (bounds.Width / 360);
            var latRad = latitude * Math.PI / 180;
            var mercN = Math.Log(Math.Tan(Math.PI / 4 + latRad / 2));
            var y = (bounds.Height / 2) - (bounds.Width * mercN / (2 * Math.PI));

            return new Point(x, y);
        }

        private double CalculateIntensity(CountryTrafficStatistics stats)
        {
            if (CountryData == null) return 0;
            var maxPackets = CountryData.Values.Max(s => s.TotalPackets);
            if (maxPackets == 0) return 0;
            return Math.Min(1.0, stats.TotalPackets / (double)maxPackets);
        }

        private Color GetProtocolColor(CountryTrafficStatistics stats)
        {
            // Get dominant protocol
            if (stats.ProtocolBreakdown.Any())
            {
                var dominant = stats.ProtocolBreakdown.OrderByDescending(p => p.Value).First().Key;
                if (Enum.TryParse<Protocol>(dominant, out var protocol))
                {
                    return _protocolColors.GetValueOrDefault(protocol, Colors.Gray);
                }
            }
            return Colors.Gray;
        }

        private Color GetIntensityColor(double intensity)
        {
            if (intensity < 0.2) return Color.FromRgb(107, 114, 128);
            if (intensity < 0.5) return Color.FromRgb(59, 130, 246);
            if (intensity < 0.8) return Color.FromRgb(16, 185, 129);
            return Color.FromRgb(239, 68, 68);
        }

        #endregion

        #region Supporting Classes

        private class CountryGeoData
        {
            public double Latitude { get; set; }
            public double Longitude { get; set; }
            public string Name { get; set; } = string.Empty;
        }

        private class HeatMapPoint
        {
            public double Latitude { get; set; }
            public double Longitude { get; set; }
            public double Intensity { get; set; }
        }

        private class TrafficFlowAnimation
        {
            public Protocol Protocol { get; set; }
            public Point StartPoint { get; set; }
            public Point EndPoint { get; set; }
            public double Progress { get; set; }
            public double Opacity { get; set; }
            public bool IsActive { get; set; }
        }

        #endregion
    }
}
