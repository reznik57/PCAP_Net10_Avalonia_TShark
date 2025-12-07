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
using PCAPAnalyzer.UI.Controls.Maps.Rendering;
using PCAPAnalyzer.UI.Controls.Maps.Interaction;
using PCAPAnalyzer.UI.Controls.Maps.Data;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Modern continent map control extending UnifiedMapControl.
    /// Supports drill-down from world view to continent view.
    /// Replaces legacy ContinentMapControl with cleaner architecture.
    /// </summary>
    public class ContinentMapControl : UnifiedMapControl
    {
        #region Fields

        private readonly ContinentMapRenderer _renderer = new();
        private readonly List<TrafficFlowAnimation> _trafficFlows = [];
        private Continent? _selectedContinent;
        private bool _isDrillDownMode;
        private string? _hoveredCountryCode;

        #endregion

        #region Styled Properties

        public static readonly StyledProperty<Dictionary<string, CountryTrafficStatistics>?> TrafficDataProperty =
            AvaloniaProperty.Register<ContinentMapControl, Dictionary<string, CountryTrafficStatistics>?>(
                nameof(TrafficData));

        public static readonly StyledProperty<List<GeographicTrafficFlow>?> TrafficFlowsProperty =
            AvaloniaProperty.Register<ContinentMapControl, List<GeographicTrafficFlow>?>(
                nameof(TrafficFlows));

        public static readonly StyledProperty<string?> FocusContinentProperty =
            AvaloniaProperty.Register<ContinentMapControl, string?>(nameof(FocusContinent));

        public static readonly StyledProperty<MapVisualizationStyle?> VisualizationStyleProperty =
            AvaloniaProperty.Register<ContinentMapControl, MapVisualizationStyle?>(
                nameof(VisualizationStyle), new MapVisualizationStyle());

        public static readonly StyledProperty<Action<string>?> ContinentClickedProperty =
            AvaloniaProperty.Register<ContinentMapControl, Action<string>?>(nameof(ContinentClicked));

        public static readonly StyledProperty<Action<string>?> CountryClickedProperty =
            AvaloniaProperty.Register<ContinentMapControl, Action<string>?>(nameof(CountryClicked));

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

        /// <summary>
        /// Callback invoked when a country icon is clicked in continent drill-down view.
        /// Parameter is the country code (e.g., "US", "DE", "JP").
        /// </summary>
        public Action<string>? CountryClicked
        {
            get => GetValue(CountryClickedProperty);
            set => SetValue(CountryClickedProperty, value);
        }

        #endregion

        #region Constructor

        static ContinentMapControl()
        {
            TrafficDataProperty.Changed.AddClassHandler<ContinentMapControl>(OnTrafficDataChanged);
            TrafficFlowsProperty.Changed.AddClassHandler<ContinentMapControl>(OnTrafficFlowsChanged);
            FocusContinentProperty.Changed.AddClassHandler<ContinentMapControl>(OnFocusContinentChanged);
        }

        public ContinentMapControl()
        {
            _renderer.InitializeContinents();
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
            _renderer.RenderContinentShapes(context, bounds, TrafficData,
                new HashSet<string>(ExcludedCountries), ShowCountryLabels, ShowAnimations, AnimationPhase);

            // Render traffic flows if enabled
            if (ShowTrafficFlows && VisualizationStyle?.ShowTrafficFlows == true)
            {
                RenderTrafficFlows(context);
            }
        }


        private void RenderContinentView(DrawingContext context, Rect bounds, Continent continent)
        {
            // Fill background with continent color
            var bgColor = Color.Parse(continent.PrimaryColor);
            bgColor = Color.FromArgb(64, bgColor.R, bgColor.G, bgColor.B);
            context.FillRectangle(new SolidColorBrush(bgColor), bounds);

            // Draw continent shape silhouette
            var mapBounds = new Rect(20, 60, bounds.Width - 40, bounds.Height - 80);
            _renderer.DrawContinentShape(context, mapBounds, continent.Code);

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
            _renderer.IconManager.Clear();

            // Render countries geographically with flag icons and collision detection
            if (TrafficData != null)
            {
                var continentCountries = TrafficData
                    .Where(kvp => GetContinentForCountry(kvp.Key) == continent.Code)
                    .OrderByDescending(kvp => kvp.Value.TotalBytes)
                    .ToList();

                // Calculate initial positions
                var countryPositions = new List<(string code, Point initial, CountryTrafficStatistics stats)>();
                foreach (var (countryCode, stats) in continentCountries)
                {
                    var position = CountryGeographicData.GetCountryPosition(countryCode, continent.Code);
                    if (!position.HasValue)
                        continue;

                    var x = mapBounds.X + position.Value.x * mapBounds.Width;
                    var y = mapBounds.Y + position.Value.y * mapBounds.Height;
                    countryPositions.Add((countryCode, new Point(x, y), stats));
                }

                // Apply collision detection to resolve overlaps
                var resolvedPositions = _renderer.IconManager.ResolveIconCollisions(countryPositions, mapBounds);

                // Calculate totals for PUBLIC traffic only (exclude INT/IP6)
                var publicTrafficData = TrafficData.Where(kvp => kvp.Key != "INT" && kvp.Key != "IP6").ToList();
                var totalBytes = publicTrafficData.Sum(c => c.Value.TotalBytes);
                var totalPackets = publicTrafficData.Sum(c => c.Value.TotalPackets);

                foreach (var (countryCode, center) in resolvedPositions)
                {
                    var stats = continentCountries.First(c => c.Key == countryCode).Value;
                    _renderer.IconManager.DrawCountryIconWithInfo(context, countryCode, center, stats,
                        totalPackets, totalBytes, TrafficData, ShowAnimations, AnimationPhase, _hoveredCountryCode);
                }
            }

            // Render tooltip if hovering over a country
            _renderer.IconManager.RenderCountryTooltip(context, bounds, _hoveredCountryCode);
        }


        private void RenderTrafficFlows(DrawingContext context)
        {
            foreach (var flow in _trafficFlows.Where(f => f.IsActive))
            {
                var sourceContinentCode = GetContinentForCountry(flow.Flow.SourceCountryCode);
                var destContinentCode = GetContinentForCountry(flow.Flow.DestinationCountryCode);

                if (sourceContinentCode == null || destContinentCode == null)
                    continue;

                if (!_renderer.ContinentVisuals.TryGetValue(sourceContinentCode, out var sourceVisual) ||
                    !_renderer.ContinentVisuals.TryGetValue(destContinentCode, out var destVisual))
                    continue;

                var startPoint = sourceVisual.Bounds.Center;
                var endPoint = destVisual.Bounds.Center;

                var intensity = Math.Min(1.0, flow.Flow.Intensity);
                var color = Color.FromArgb((byte)(intensity * 200), 100, 200, 255);
                var pen = new Pen(new SolidColorBrush(color), 2);

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
                                new QuadraticBezierSegment { Point1 = controlPoint, Point2 = endPoint }
                            }
                        }
                    }
                };

                context.DrawGeometry(null, pen, geometry);
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

            // In drill-down mode, check for country icon clicks first
            if (_isDrillDownMode && _selectedContinent != null)
            {
                var clickedCountry = _renderer.IconManager.HitTestCountryIcon(transformedPos);
                if (!string.IsNullOrEmpty(clickedCountry))
                {
                    DebugLogger.Log($"[ContinentMapControl] Country clicked: {clickedCountry}");

                    // Invoke country clicked callback
                    if (CountryClicked != null)
                    {
                        DebugLogger.Log($"[ContinentMapControl] Invoking CountryClicked with code: {clickedCountry}");
                        CountryClicked.Invoke(clickedCountry);
                    }

                    // Brief visual feedback - flash the country
                    _hoveredCountryCode = clickedCountry;
                    InvalidateVisual();

                    e.Handled = true;
                    return;
                }
            }

            // Hit test continents (world view)
            var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
            var scaleX = bounds.Width / 800.0;
            var scaleY = bounds.Height / 400.0;
            var scale = Math.Min(scaleX, scaleY);
            var offsetX = (bounds.Width - 800 * scale) / 2;
            var offsetY = (bounds.Height - 400 * scale) / 2;

            _renderer.UpdateContinentBounds(bounds, scale, offsetX, offsetY);

            foreach (var visual in _renderer.ContinentVisuals.Values)
            {
                if (visual.Bounds.Contains(transformedPos))
                {
                    DebugLogger.Log($"[ContinentMapControl] Continent clicked: {visual.Continent.Code} ('{visual.Continent.DisplayName}')");
                    DebugLogger.Log($"[ContinentMapControl] ContinentClicked delegate is {(ContinentClicked == null ? "NULL" : "ASSIGNED")}");

                    if (ContinentClicked != null)
                    {
                        DebugLogger.Log($"[ContinentMapControl] Invoking ContinentClicked with code: {visual.Continent.Code}");
                        ContinentClicked.Invoke(visual.Continent.Code);
                    }
                    else
                    {
                        DebugLogger.Log("[ContinentMapControl] WARNING: ContinentClicked delegate is null - navigation will not work!");
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
                newHoveredCountry = _renderer.IconManager.HitTestCountryIcon(transformedPos);
            }
            else
            {
                // World view - check continent hit
                var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
                var scaleX = bounds.Width / 800.0;
                var scaleY = bounds.Height / 400.0;
                var scale = Math.Min(scaleX, scaleY);
                var offsetX = (bounds.Width - 800 * scale) / 2;
                var offsetY = (bounds.Height - 400 * scale) / 2;

                _renderer.UpdateContinentBounds(bounds, scale, offsetX, offsetY);

                foreach (var visual in _renderer.ContinentVisuals.Values)
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
                foreach (var visual in _renderer.ContinentVisuals.Values)
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

        private static void OnTrafficDataChanged(ContinentMapControl control, AvaloniaPropertyChangedEventArgs e)
        {
            control.InvalidateVisual();
        }

        private static void OnTrafficFlowsChanged(ContinentMapControl control, AvaloniaPropertyChangedEventArgs e)
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

        private static void OnFocusContinentChanged(ContinentMapControl control, AvaloniaPropertyChangedEventArgs e)
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

        private string? GetContinentForCountry(string countryCode)
        {
            return CountryGeographicData.GetContinentForCountry(countryCode);
        }

        #endregion

        #region Helper Classes

        private class TrafficFlowAnimation
        {
            public GeographicTrafficFlow Flow { get; set; } = new();
            public double Progress { get; set; }
            public bool IsActive { get; set; }
        }

        #endregion
    }
}
