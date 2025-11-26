using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Rendering.SceneGraph;
using Avalonia.Skia;
using Avalonia.Threading;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using SkiaSharp;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Enhanced world map control with real-time IP traffic visualization
    /// Features: SVG world map, real-time traffic flows, geolocation markers, heatmap overlay
    /// </summary>
    public class EnhancedWorldMapControl : UserControl
    {
        private DispatcherTimer _animationTimer = null!;
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI animation pulse phase initialization, not security
        private readonly Random _random = new();
#pragma warning restore CA5394
        private readonly List<TrafficFlow> _activeFlows = new();
        private readonly List<PulseMarker> _pulseMarkers = new();
        private readonly Dictionary<string, CountryTrafficInfo> _countryTraffic = new();
        
        // Map interaction state
        private double _zoomLevel = 1.0;
        private Point _panOffset = new(0, 0);
        private Point? _lastPointerPosition;
        private bool _isPanning;

        // Animation state
        private double _animationPhase;
        private readonly Dictionary<string, double> _countryPulsePhase = new();
        
        // SVG Map coordinates mapping
        private readonly Dictionary<string, CountryCoordinates> _countryCoordinates = new()
        {
            ["US"] = new CountryCoordinates { Latitude = 39.0, Longitude = -98.0 },
            ["CN"] = new CountryCoordinates { Latitude = 35.0, Longitude = 105.0 },
            ["RU"] = new CountryCoordinates { Latitude = 60.0, Longitude = 100.0 },
            ["BR"] = new CountryCoordinates { Latitude = -10.0, Longitude = -55.0 },
            ["IN"] = new CountryCoordinates { Latitude = 20.0, Longitude = 77.0 },
            ["DE"] = new CountryCoordinates { Latitude = 51.0, Longitude = 10.0 },
            ["GB"] = new CountryCoordinates { Latitude = 54.0, Longitude = -2.0 },
            ["FR"] = new CountryCoordinates { Latitude = 46.0, Longitude = 2.0 },
            ["JP"] = new CountryCoordinates { Latitude = 36.0, Longitude = 138.0 },
            ["AU"] = new CountryCoordinates { Latitude = -27.0, Longitude = 133.0 },
            ["CA"] = new CountryCoordinates { Latitude = 56.0, Longitude = -106.0 },
            ["ZA"] = new CountryCoordinates { Latitude = -29.0, Longitude = 24.0 },
            ["MX"] = new CountryCoordinates { Latitude = 23.0, Longitude = -102.0 },
            ["AR"] = new CountryCoordinates { Latitude = -38.0, Longitude = -64.0 },
            ["EG"] = new CountryCoordinates { Latitude = 26.0, Longitude = 30.0 },
            ["SA"] = new CountryCoordinates { Latitude = 24.0, Longitude = 45.0 },
            ["KR"] = new CountryCoordinates { Latitude = 36.0, Longitude = 128.0 },
            ["ES"] = new CountryCoordinates { Latitude = 40.0, Longitude = -4.0 },
            ["IT"] = new CountryCoordinates { Latitude = 42.0, Longitude = 13.0 },
            ["PL"] = new CountryCoordinates { Latitude = 52.0, Longitude = 20.0 },
            ["NL"] = new CountryCoordinates { Latitude = 52.0, Longitude = 5.0 },
            ["SE"] = new CountryCoordinates { Latitude = 62.0, Longitude = 15.0 },
            ["NO"] = new CountryCoordinates { Latitude = 62.0, Longitude = 10.0 },
            ["FI"] = new CountryCoordinates { Latitude = 62.0, Longitude = 26.0 },
            ["DK"] = new CountryCoordinates { Latitude = 56.0, Longitude = 10.0 },
            ["UA"] = new CountryCoordinates { Latitude = 49.0, Longitude = 32.0 },
            ["TR"] = new CountryCoordinates { Latitude = 39.0, Longitude = 35.0 },
            ["GR"] = new CountryCoordinates { Latitude = 39.0, Longitude = 22.0 },
            ["TH"] = new CountryCoordinates { Latitude = 15.0, Longitude = 100.0 },
            ["VN"] = new CountryCoordinates { Latitude = 16.0, Longitude = 108.0 },
            ["ID"] = new CountryCoordinates { Latitude = -5.0, Longitude = 120.0 },
            ["PH"] = new CountryCoordinates { Latitude = 12.0, Longitude = 122.0 },
            ["MY"] = new CountryCoordinates { Latitude = 4.0, Longitude = 102.0 },
            ["SG"] = new CountryCoordinates { Latitude = 1.3, Longitude = 103.8 },
            ["NZ"] = new CountryCoordinates { Latitude = -41.0, Longitude = 174.0 },
            ["CL"] = new CountryCoordinates { Latitude = -30.0, Longitude = -71.0 },
            ["PE"] = new CountryCoordinates { Latitude = -10.0, Longitude = -76.0 },
            ["CO"] = new CountryCoordinates { Latitude = 4.0, Longitude = -72.0 },
            ["VE"] = new CountryCoordinates { Latitude = 7.0, Longitude = -66.0 },
            ["NG"] = new CountryCoordinates { Latitude = 10.0, Longitude = 8.0 },
            ["KE"] = new CountryCoordinates { Latitude = 1.0, Longitude = 38.0 },
            ["ET"] = new CountryCoordinates { Latitude = 9.0, Longitude = 40.0 },
            ["MA"] = new CountryCoordinates { Latitude = 32.0, Longitude = -6.0 },
            ["DZ"] = new CountryCoordinates { Latitude = 28.0, Longitude = 3.0 },
            ["IL"] = new CountryCoordinates { Latitude = 31.0, Longitude = 35.0 },
            ["AE"] = new CountryCoordinates { Latitude = 24.0, Longitude = 54.0 },
            ["IR"] = new CountryCoordinates { Latitude = 32.0, Longitude = 53.0 },
            ["PK"] = new CountryCoordinates { Latitude = 30.0, Longitude = 70.0 },
            ["BD"] = new CountryCoordinates { Latitude = 24.0, Longitude = 90.0 },
            ["LK"] = new CountryCoordinates { Latitude = 7.0, Longitude = 81.0 }
        };

        // Styled Properties
        public static readonly StyledProperty<ObservableCollection<IPTrafficData>> TrafficDataProperty =
            AvaloniaProperty.Register<EnhancedWorldMapControl, ObservableCollection<IPTrafficData>>(
                nameof(TrafficData), new ObservableCollection<IPTrafficData>());

        public static readonly StyledProperty<bool> ShowHeatmapProperty =
            AvaloniaProperty.Register<EnhancedWorldMapControl, bool>(nameof(ShowHeatmap), true);

        public static readonly StyledProperty<bool> ShowTrafficFlowsProperty =
            AvaloniaProperty.Register<EnhancedWorldMapControl, bool>(nameof(ShowTrafficFlows), true);

        public static readonly StyledProperty<bool> ShowCountryLabelsProperty =
            AvaloniaProperty.Register<EnhancedWorldMapControl, bool>(nameof(ShowCountryLabels), true);

        public static readonly StyledProperty<WorldMapTheme> MapThemeProperty =
            AvaloniaProperty.Register<EnhancedWorldMapControl, WorldMapTheme>(nameof(MapTheme), WorldMapTheme.Dark);

        public ObservableCollection<IPTrafficData> TrafficData
        {
            get => GetValue(TrafficDataProperty);
            set => SetValue(TrafficDataProperty, value);
        }

        public bool ShowHeatmap
        {
            get => GetValue(ShowHeatmapProperty);
            set => SetValue(ShowHeatmapProperty, value);
        }

        public bool ShowTrafficFlows
        {
            get => GetValue(ShowTrafficFlowsProperty);
            set => SetValue(ShowTrafficFlowsProperty, value);
        }

        public bool ShowCountryLabels
        {
            get => GetValue(ShowCountryLabelsProperty);
            set => SetValue(ShowCountryLabelsProperty, value);
        }

        public WorldMapTheme MapTheme
        {
            get => GetValue(MapThemeProperty);
            set => SetValue(MapThemeProperty, value);
        }

        public EnhancedWorldMapControl()
        {
            InitializeComponent();
            SetupAnimationTimer();
            SetupEventHandlers();
        }

        private void InitializeComponent()
        {
            Background = new SolidColorBrush(Color.FromRgb(15, 23, 42));
            ClipToBounds = true;
        }

        private void SetupAnimationTimer()
        {
            _animationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(33) // ~30 FPS for smooth animations
            };
            _animationTimer.Tick += OnAnimationTick;
            _animationTimer.Start();
        }

        private void SetupEventHandlers()
        {
            PointerPressed += OnPointerPressed;
            PointerMoved += OnPointerMoved;
            PointerReleased += OnPointerReleased;
            PointerWheelChanged += OnPointerWheelChanged;
            DoubleTapped += OnDoubleTapped;
        }

        private void OnAnimationTick(object? sender, EventArgs e)
        {
            _animationPhase += 0.05;

            // Update traffic flows
            foreach (var flow in _activeFlows.ToList())
            {
                flow.Progress += 0.02;
                if (flow.Progress >= 1.0)
                {
                    _activeFlows.Remove(flow);
                }
            }

            // Update pulse markers
            foreach (var marker in _pulseMarkers.ToList())
            {
                marker.Radius += 1.5;
                marker.Opacity -= 0.02;
                if (marker.Opacity <= 0)
                {
                    _pulseMarkers.Remove(marker);
                }
            }

            // Update country pulse phases
            foreach (var country in _countryPulsePhase.Keys.ToList())
            {
                _countryPulsePhase[country] += 0.05;
                if (_countryPulsePhase[country] > Math.PI * 2)
                {
                    _countryPulsePhase[country] = 0;
                }
            }

            InvalidateVisual();
        }

        public override void Render(DrawingContext context)
        {
            var bounds = Bounds;
            
            // Draw background
            DrawBackground(context, bounds);
            
            // Apply zoom and pan transform
            using (context.PushTransform(Matrix.CreateTranslation(_panOffset.X, _panOffset.Y) * 
                                        Matrix.CreateScale(_zoomLevel, _zoomLevel)))
            {
                // Draw world map outline
                DrawWorldMapOutline(context, bounds);
                
                // Draw heatmap layer
                if (ShowHeatmap)
                {
                    DrawHeatmapLayer(context, bounds);
                }
                
                // Draw country markers
                DrawCountryMarkers(context, bounds);
                
                // Draw traffic flows
                if (ShowTrafficFlows)
                {
                    DrawTrafficFlows(context, bounds);
                }
                
                // Draw pulse effects
                DrawPulseEffects(context);
                
                // Draw country labels
                if (ShowCountryLabels)
                {
                    DrawCountryLabels(context, bounds);
                }
            }
            
            // Draw UI overlays (not affected by zoom/pan)
            DrawStatisticsPanel(context, bounds);
            DrawMiniMap(context, bounds);
            DrawControlsHint(context, bounds);
        }

        private void DrawBackground(DrawingContext context, Rect bounds)
        {
            var gradient = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.FromRgb(15, 23, 42), 0),
                    new GradientStop(Color.FromRgb(30, 41, 59), 1)
                }
            };
            context.FillRectangle(gradient, bounds);
            
            // Draw grid
            DrawGrid(context, bounds);
        }

        private void DrawGrid(DrawingContext context, Rect bounds)
        {
            var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(20, 100, 116, 139)), 1);
            var spacing = 50;
            
            for (var x = 0.0; x < bounds.Width; x += spacing)
            {
                context.DrawLine(gridPen, new Point(x, 0), new Point(x, bounds.Height));
            }
            
            for (var y = 0.0; y < bounds.Height; y += spacing)
            {
                context.DrawLine(gridPen, new Point(0, y), new Point(bounds.Width, y));
            }
        }

        private void DrawWorldMapOutline(DrawingContext context, Rect bounds)
        {
            // Draw simplified world map using Mercator projection
            var mapPen = new Pen(new SolidColorBrush(Color.FromArgb(100, 94, 234, 212)), 1.5);
            
            // Draw continent outlines (simplified)
            DrawContinentOutline(context, bounds, mapPen, "NorthAmerica");
            DrawContinentOutline(context, bounds, mapPen, "SouthAmerica");
            DrawContinentOutline(context, bounds, mapPen, "Europe");
            DrawContinentOutline(context, bounds, mapPen, "Africa");
            DrawContinentOutline(context, bounds, mapPen, "Asia");
            DrawContinentOutline(context, bounds, mapPen, "Australia");
        }

        private void DrawContinentOutline(DrawingContext context, Rect bounds, Pen pen, string continent)
        {
            // Simplified continent shapes using bezier curves
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                switch (continent)
                {
                    case "NorthAmerica":
                        DrawNorthAmericaOutline(ctx, bounds);
                        break;
                    case "SouthAmerica":
                        DrawSouthAmericaOutline(ctx, bounds);
                        break;
                    case "Europe":
                        DrawEuropeOutline(ctx, bounds);
                        break;
                    case "Africa":
                        DrawAfricaOutline(ctx, bounds);
                        break;
                    case "Asia":
                        DrawAsiaOutline(ctx, bounds);
                        break;
                    case "Australia":
                        DrawAustraliaOutline(ctx, bounds);
                        break;
                }
            }
            context.DrawGeometry(null, pen, geometry);
        }

        private void DrawNorthAmericaOutline(StreamGeometryContext ctx, Rect bounds)
        {
            var scale = bounds.Width / 360.0;
            var offsetX = bounds.Width / 2;
            var offsetY = bounds.Height / 2;
            
            ctx.BeginFigure(LatLonToPoint(70, -170, bounds), false);
            ctx.LineTo(LatLonToPoint(70, -50, bounds));
            ctx.LineTo(LatLonToPoint(45, -65, bounds));
            ctx.LineTo(LatLonToPoint(25, -80, bounds));
            ctx.LineTo(LatLonToPoint(20, -97, bounds));
            ctx.LineTo(LatLonToPoint(30, -115, bounds));
            ctx.LineTo(LatLonToPoint(49, -125, bounds));
            ctx.LineTo(LatLonToPoint(60, -140, bounds));
            ctx.LineTo(LatLonToPoint(70, -170, bounds));
        }

        private void DrawSouthAmericaOutline(StreamGeometryContext ctx, Rect bounds)
        {
            ctx.BeginFigure(LatLonToPoint(12, -80, bounds), false);
            ctx.LineTo(LatLonToPoint(0, -50, bounds));
            ctx.LineTo(LatLonToPoint(-20, -40, bounds));
            ctx.LineTo(LatLonToPoint(-55, -70, bounds));
            ctx.LineTo(LatLonToPoint(-20, -70, bounds));
            ctx.LineTo(LatLonToPoint(0, -80, bounds));
            ctx.LineTo(LatLonToPoint(12, -80, bounds));
        }

        private void DrawEuropeOutline(StreamGeometryContext ctx, Rect bounds)
        {
            ctx.BeginFigure(LatLonToPoint(70, -10, bounds), false);
            ctx.LineTo(LatLonToPoint(70, 40, bounds));
            ctx.LineTo(LatLonToPoint(45, 40, bounds));
            ctx.LineTo(LatLonToPoint(36, 28, bounds));
            ctx.LineTo(LatLonToPoint(36, -6, bounds));
            ctx.LineTo(LatLonToPoint(50, -10, bounds));
            ctx.LineTo(LatLonToPoint(70, -10, bounds));
        }

        private void DrawAfricaOutline(StreamGeometryContext ctx, Rect bounds)
        {
            ctx.BeginFigure(LatLonToPoint(37, -10, bounds), false);
            ctx.LineTo(LatLonToPoint(37, 50, bounds));
            ctx.LineTo(LatLonToPoint(10, 50, bounds));
            ctx.LineTo(LatLonToPoint(-35, 20, bounds));
            ctx.LineTo(LatLonToPoint(-35, 18, bounds));
            ctx.LineTo(LatLonToPoint(0, -17, bounds));
            ctx.LineTo(LatLonToPoint(37, -10, bounds));
        }

        private void DrawAsiaOutline(StreamGeometryContext ctx, Rect bounds)
        {
            ctx.BeginFigure(LatLonToPoint(70, 40, bounds), false);
            ctx.LineTo(LatLonToPoint(70, 180, bounds));
            ctx.LineTo(LatLonToPoint(30, 150, bounds));
            ctx.LineTo(LatLonToPoint(0, 100, bounds));
            ctx.LineTo(LatLonToPoint(10, 50, bounds));
            ctx.LineTo(LatLonToPoint(45, 40, bounds));
            ctx.LineTo(LatLonToPoint(70, 40, bounds));
        }

        private void DrawAustraliaOutline(StreamGeometryContext ctx, Rect bounds)
        {
            ctx.BeginFigure(LatLonToPoint(-10, 115, bounds), false);
            ctx.LineTo(LatLonToPoint(-10, 154, bounds));
            ctx.LineTo(LatLonToPoint(-39, 146, bounds));
            ctx.LineTo(LatLonToPoint(-35, 115, bounds));
            ctx.LineTo(LatLonToPoint(-10, 115, bounds));
        }

        private Point LatLonToPoint(double latitude, double longitude, Rect bounds)
        {
            // Simple Mercator projection
            var x = (longitude + 180) * (bounds.Width / 360);
            var latRad = latitude * Math.PI / 180;
            var mercN = Math.Log(Math.Tan((Math.PI / 4) + (latRad / 2)));
            var y = (bounds.Height / 2) - (bounds.Width * mercN / (2 * Math.PI));
            
            return new Point(x, y);
        }

        private void DrawHeatmapLayer(DrawingContext context, Rect bounds)
        {
            // Create heatmap based on traffic intensity
            foreach (var country in _countryTraffic.Values)
            {
                if (_countryCoordinates.TryGetValue(country.CountryCode, out var coords))
                {
                    var point = LatLonToPoint(coords.Latitude, coords.Longitude, bounds);
                    var intensity = Math.Min(1.0, country.TrafficVolume / 1000.0);
                    var radius = 30 + intensity * 50;
                    
                    var heatBrush = new RadialGradientBrush
                    {
                        Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                        GradientStops =
                        {
                            new GradientStop(Color.FromArgb((byte)(intensity * 100), 255, 69, 0), 0),
                            new GradientStop(Color.FromArgb((byte)(intensity * 50), 255, 140, 0), 0.5),
                            new GradientStop(Color.FromArgb(0, 255, 140, 0), 1)
                        }
                    };
                    
                    context.DrawEllipse(heatBrush, null, point, radius, radius);
                }
            }
        }

        private void DrawCountryMarkers(DrawingContext context, Rect bounds)
        {
            foreach (var country in _countryTraffic.Values)
            {
                if (_countryCoordinates.TryGetValue(country.CountryCode, out var coords))
                {
                    var point = LatLonToPoint(coords.Latitude, coords.Longitude, bounds);
                    var intensity = Math.Min(1.0, country.TrafficVolume / 1000.0);
                    
                    // Get pulse animation
                    if (!_countryPulsePhase.ContainsKey(country.CountryCode))
                    {
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI pulse animation phase offset, not security
                        _countryPulsePhase[country.CountryCode] = _random.NextDouble() * Math.PI * 2;
#pragma warning restore CA5394
                    }
                    
                    var pulse = Math.Sin(_countryPulsePhase[country.CountryCode]) * 0.2 + 1.0;
                    var markerSize = (10 + intensity * 15) * pulse;
                    
                    // Draw marker
                    var color = GetTrafficColor(intensity);
                    var brush = new SolidColorBrush(color);
                    var pen = new Pen(brush, 2);
                    
                    // Outer glow
                    var glowBrush = new RadialGradientBrush
                    {
                        Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                        GradientStops =
                        {
                            new GradientStop(Color.FromArgb(100, color.R, color.G, color.B), 0),
                            new GradientStop(Color.FromArgb(0, color.R, color.G, color.B), 1)
                        }
                    };
                    context.DrawEllipse(glowBrush, null, point, markerSize * 2, markerSize * 2);
                    
                    // Main marker
                    context.DrawEllipse(brush, pen, point, markerSize, markerSize);
                    
                    // Inner dot
                    context.DrawEllipse(Brushes.White, null, point, 3, 3);
                }
            }
        }

        private void DrawTrafficFlows(DrawingContext context, Rect bounds)
        {
            foreach (var flow in _activeFlows)
            {
                if (_countryCoordinates.TryGetValue(flow.SourceCountry, out var sourceCoords) &&
                    _countryCoordinates.TryGetValue(flow.DestCountry, out var destCoords))
                {
                    var sourcePoint = LatLonToPoint(sourceCoords.Latitude, sourceCoords.Longitude, bounds);
                    var destPoint = LatLonToPoint(destCoords.Latitude, destCoords.Longitude, bounds);
                    
                    // Calculate bezier curve control point for arc
                    var midPoint = new Point((sourcePoint.X + destPoint.X) / 2, (sourcePoint.Y + destPoint.Y) / 2);
                    var distance = Math.Sqrt(Math.Pow(destPoint.X - sourcePoint.X, 2) + Math.Pow(destPoint.Y - sourcePoint.Y, 2));
                    var arcHeight = Math.Min(distance * 0.3, 100);
                    var controlPoint = new Point(midPoint.X, midPoint.Y - arcHeight);
                    
                    // Draw flow arc
                    var geometry = new StreamGeometry();
                    using (var ctx = geometry.Open())
                    {
                        ctx.BeginFigure(sourcePoint, false);
                        ctx.QuadraticBezierTo(controlPoint, destPoint);
                    }
                    
                    var flowColor = GetFlowColor(flow.Volume);
                    var opacity = (byte)(200 * (1 - flow.Progress * 0.5));
                    var pen = new Pen(new SolidColorBrush(Color.FromArgb(opacity, flowColor.R, flowColor.G, flowColor.B)), 2);
                    context.DrawGeometry(null, pen, geometry);
                    
                    // Draw moving packet
                    var t = flow.Progress;
                    var packetX = Math.Pow(1 - t, 2) * sourcePoint.X + 2 * (1 - t) * t * controlPoint.X + Math.Pow(t, 2) * destPoint.X;
                    var packetY = Math.Pow(1 - t, 2) * sourcePoint.Y + 2 * (1 - t) * t * controlPoint.Y + Math.Pow(t, 2) * destPoint.Y;
                    var packetPoint = new Point(packetX, packetY);
                    
                    var packetBrush = new SolidColorBrush(flowColor);
                    context.DrawEllipse(packetBrush, null, packetPoint, 4, 4);
                    
                    // Packet glow
                    var glowBrush = new RadialGradientBrush
                    {
                        Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                        GradientStops =
                        {
                            new GradientStop(Color.FromArgb(150, flowColor.R, flowColor.G, flowColor.B), 0),
                            new GradientStop(Color.FromArgb(0, flowColor.R, flowColor.G, flowColor.B), 1)
                        }
                    };
                    context.DrawEllipse(glowBrush, null, packetPoint, 12, 12);
                }
            }
        }

        private void DrawPulseEffects(DrawingContext context)
        {
            foreach (var marker in _pulseMarkers)
            {
                var opacity = (byte)(marker.Opacity * 255);
                var pen = new Pen(new SolidColorBrush(Color.FromArgb(opacity, 94, 234, 212)), 2);
                context.DrawEllipse(null, pen, marker.Center, marker.Radius, marker.Radius);
            }
        }

        private void DrawCountryLabels(DrawingContext context, Rect bounds)
        {
            var typeface = new Typeface("Segoe UI", FontStyle.Normal, FontWeight.SemiBold);
            var textBrush = new SolidColorBrush(Color.FromArgb(200, 226, 232, 240));
            
            foreach (var country in _countryTraffic.Values.OrderByDescending(c => c.TrafficVolume).Take(10))
            {
                if (_countryCoordinates.TryGetValue(country.CountryCode, out var coords))
                {
                    var point = LatLonToPoint(coords.Latitude, coords.Longitude, bounds);
                    var text = $"{country.CountryCode}: {country.TrafficVolume:F0} GB/s";
                    
                    var formattedText = new FormattedText(
                        text,
                        CultureInfo.CurrentCulture,
                        FlowDirection.LeftToRight,
                        typeface,
                        10,
                        textBrush);
                    
                    // Draw background
                    var bgRect = new Rect(point.X - formattedText.Width / 2 - 4, point.Y + 15, formattedText.Width + 8, formattedText.Height + 4);
                    context.FillRectangle(new SolidColorBrush(Color.FromArgb(180, 15, 23, 42)), bgRect);
                    
                    // Draw text
                    context.DrawText(formattedText, new Point(point.X - formattedText.Width / 2, point.Y + 17));
                }
            }
        }

        private void DrawStatisticsPanel(DrawingContext context, Rect bounds)
        {
            var panelRect = new Rect(10, 10, 250, 180);
            var bgBrush = new SolidColorBrush(Color.FromArgb(230, 15, 23, 42));
            context.FillRectangle(bgBrush, panelRect);
            
            var borderPen = new Pen(new SolidColorBrush(Color.FromArgb(255, 94, 234, 212)), 1);
            context.DrawRectangle(borderPen, panelRect);
            
            var typeface = new Typeface("Consolas", FontStyle.Normal, FontWeight.Normal);
            var titleBrush = new SolidColorBrush(Color.FromArgb(255, 94, 234, 212));
            var textBrush = new SolidColorBrush(Color.FromArgb(200, 226, 232, 240));
            
            DrawPanelText(context, "NETWORK TRAFFIC ANALYSIS", 20, 25, 12, titleBrush, typeface, FontWeight.Bold);
            
            var totalCountries = _countryTraffic.Count;
            var totalTraffic = _countryTraffic.Values.Sum(c => c.TrafficVolume);
            var avgTraffic = totalCountries > 0 ? totalTraffic / totalCountries : 0;
            var peakCountry = _countryTraffic.Values.OrderByDescending(c => c.TrafficVolume).FirstOrDefault();
            
            DrawPanelText(context, $"Active Countries: {totalCountries}", 20, 50, 10, textBrush, typeface);
            DrawPanelText(context, $"Total Traffic: {totalTraffic:F1} GB/s", 20, 70, 10, textBrush, typeface);
            DrawPanelText(context, $"Average Traffic: {avgTraffic:F2} GB/s", 20, 90, 10, textBrush, typeface);
            DrawPanelText(context, $"Active Flows: {_activeFlows.Count}", 20, 110, 10, textBrush, typeface);
            
            if (peakCountry != null)
            {
                DrawPanelText(context, $"Peak: {peakCountry.CountryCode} ({peakCountry.TrafficVolume:F1} GB/s)", 20, 130, 10, textBrush, typeface);
            }
            
            var statusColor = totalTraffic > 500 ? Colors.Red : Colors.Lime;
            DrawPanelText(context, "● LIVE", 20, 155, 10, new SolidColorBrush(statusColor), typeface, FontWeight.Bold);
        }

        private void DrawMiniMap(DrawingContext context, Rect bounds)
        {
            var miniMapRect = new Rect(bounds.Width - 160, 10, 150, 75);
            var bgBrush = new SolidColorBrush(Color.FromArgb(200, 15, 23, 42));
            context.FillRectangle(bgBrush, miniMapRect);
            
            var borderPen = new Pen(new SolidColorBrush(Color.FromArgb(255, 94, 234, 212)), 1);
            context.DrawRectangle(borderPen, miniMapRect);
            
            // Draw mini world representation
            foreach (var country in _countryTraffic.Values)
            {
                if (_countryCoordinates.TryGetValue(country.CountryCode, out var coords))
                {
                    var x = miniMapRect.X + (coords.Longitude + 180) * (miniMapRect.Width / 360);
                    var y = miniMapRect.Y + (90 - coords.Latitude) * (miniMapRect.Height / 180);
                    
                    var intensity = Math.Min(1.0, country.TrafficVolume / 1000.0);
                    var color = GetTrafficColor(intensity);
                    context.FillRectangle(new SolidColorBrush(color), new Rect(x - 1, y - 1, 2, 2));
                }
            }
            
            // Draw viewport indicator
            var viewportRect = new Rect(
                miniMapRect.X + (_panOffset.X / bounds.Width) * miniMapRect.Width,
                miniMapRect.Y + (_panOffset.Y / bounds.Height) * miniMapRect.Height,
                miniMapRect.Width / _zoomLevel,
                miniMapRect.Height / _zoomLevel
            );
            var viewportPen = new Pen(new SolidColorBrush(Colors.Yellow), 1);
            context.DrawRectangle(viewportPen, viewportRect);
        }

        private void DrawControlsHint(DrawingContext context, Rect bounds)
        {
            var hintRect = new Rect(bounds.Width - 160, bounds.Height - 80, 150, 70);
            var bgBrush = new SolidColorBrush(Color.FromArgb(180, 15, 23, 42));
            context.FillRectangle(bgBrush, hintRect);
            
            var typeface = new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal);
            var textBrush = new SolidColorBrush(Color.FromArgb(200, 148, 163, 184));
            
            DrawPanelText(context, "CONTROLS", hintRect.X + 5, hintRect.Y + 5, 10, textBrush, typeface, FontWeight.Bold);
            DrawPanelText(context, "Scroll: Zoom", hintRect.X + 5, hintRect.Y + 20, 9, textBrush, typeface);
            DrawPanelText(context, "Drag: Pan", hintRect.X + 5, hintRect.Y + 35, 9, textBrush, typeface);
            DrawPanelText(context, "Double-click: Reset", hintRect.X + 5, hintRect.Y + 50, 9, textBrush, typeface);
        }

        private void DrawPanelText(DrawingContext context, string text, double x, double y, double size,
            IBrush brush, Typeface typeface, FontWeight weight = FontWeight.Normal)
        {
            var formattedText = new FormattedText(
                text,
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface(typeface.FontFamily, typeface.Style, weight),
                size,
                brush);
            
            context.DrawText(formattedText, new Point(x, y));
        }

        private Color GetTrafficColor(double intensity)
        {
            if (intensity < 0.25)
                return Color.FromRgb(52, 211, 153);  // Green
            else if (intensity < 0.5)
                return Color.FromRgb(59, 130, 246);  // Blue
            else if (intensity < 0.75)
                return Color.FromRgb(251, 146, 60);  // Orange
            else
                return Color.FromRgb(239, 68, 68);   // Red
        }

        private Color GetFlowColor(double volume)
        {
            var intensity = Math.Min(1.0, volume / 100.0);
            return GetTrafficColor(intensity);
        }

        // Event handlers
        private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            var point = e.GetCurrentPoint(this);
            if (point.Properties.IsLeftButtonPressed)
            {
                _isPanning = true;
                _lastPointerPosition = point.Position;
                e.Handled = true;
            }
        }

        private void OnPointerMoved(object? sender, PointerEventArgs e)
        {
            var point = e.GetCurrentPoint(this);
            
            if (_isPanning && _lastPointerPosition.HasValue)
            {
                var delta = point.Position - _lastPointerPosition.Value;
                _panOffset = new Point(_panOffset.X + delta.X, _panOffset.Y + delta.Y);
                _lastPointerPosition = point.Position;
                InvalidateVisual();
            }
        }

        private void OnPointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            _isPanning = false;
            _lastPointerPosition = null;
        }

        private void OnPointerWheelChanged(object? sender, PointerWheelEventArgs e)
        {
            var delta = e.Delta.Y > 0 ? 1.1 : 0.9;
            _zoomLevel = Math.Max(0.5, Math.Min(5.0, _zoomLevel * delta));
            InvalidateVisual();
        }

        private void OnDoubleTapped(object? sender, TappedEventArgs e)
        {
            // Reset zoom and pan
            _zoomLevel = 1.0;
            _panOffset = new Point(0, 0);
            InvalidateVisual();
        }

        // Public methods for updating traffic data
        public void UpdateTrafficData(string sourceIP, string destIP, double volume, string sourceCountry, string destCountry)
        {
            // Update country traffic
            if (!string.IsNullOrEmpty(sourceCountry))
            {
                if (!_countryTraffic.ContainsKey(sourceCountry))
                {
                    _countryTraffic[sourceCountry] = new CountryTrafficInfo { CountryCode = sourceCountry };
                }
                _countryTraffic[sourceCountry].TrafficVolume += volume;
            }
            
            if (!string.IsNullOrEmpty(destCountry))
            {
                if (!_countryTraffic.ContainsKey(destCountry))
                {
                    _countryTraffic[destCountry] = new CountryTrafficInfo { CountryCode = destCountry };
                }
                _countryTraffic[destCountry].TrafficVolume += volume;
            }
            
            // Add traffic flow
            if (!string.IsNullOrEmpty(sourceCountry) && !string.IsNullOrEmpty(destCountry) && sourceCountry != destCountry)
            {
                _activeFlows.Add(new TrafficFlow
                {
                    SourceCountry = sourceCountry,
                    DestCountry = destCountry,
                    Volume = volume,
                    Progress = 0
                });
                
                // Add pulse marker at source
                if (_countryCoordinates.TryGetValue(sourceCountry, out var coords))
                {
                    var point = LatLonToPoint(coords.Latitude, coords.Longitude, Bounds);
                    _pulseMarkers.Add(new PulseMarker
                    {
                        Center = point,
                        Radius = 10,
                        Opacity = 1.0
                    });
                }
            }
            
            InvalidateVisual();
        }

        public void ClearTrafficData()
        {
            _countryTraffic.Clear();
            _activeFlows.Clear();
            _pulseMarkers.Clear();
            InvalidateVisual();
        }

        // Helper classes
        private class CountryCoordinates
        {
            public double Latitude { get; set; }
            public double Longitude { get; set; }
        }

        private class CountryTrafficInfo
        {
            public string CountryCode { get; set; } = string.Empty;
            public double TrafficVolume { get; set; }
            public int ConnectionCount { get; set; }
        }

        private class TrafficFlow
        {
            public string SourceCountry { get; set; } = string.Empty;
            public string DestCountry { get; set; } = string.Empty;
            public double Volume { get; set; }
            public double Progress { get; set; }
        }

        private class PulseMarker
        {
            public Point Center { get; set; }
            public double Radius { get; set; }
            public double Opacity { get; set; }
        }

        [SuppressMessage("Design", "CA1034:Nested types should not be visible",
            Justification = "IPTrafficData is a public data structure for traffic visualization data binding")]
        public class IPTrafficData
        {
            public string SourceIP { get; set; } = string.Empty;
            public string DestIP { get; set; } = string.Empty;
            public string SourceCountry { get; set; } = string.Empty;
            public string DestCountry { get; set; } = string.Empty;
            public double Volume { get; set; }
            public DateTime Timestamp { get; set; }
        }

        public enum WorldMapTheme
        {
            Dark,
            Light,
            Satellite,
            Cyber
        }
    }
}