using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using PCAPAnalyzer.UI.Controls.Base;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Simple world map implementation using UnifiedMapControl.
    /// Demonstrates the base class pattern with minimal custom code.
    /// Renders countries as colored rectangles in a grid layout.
    /// </summary>
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI particle effects and pulse animation, not security
    public class SimpleWorldMapControl : UnifiedMapControl
    {
        private readonly Dictionary<string, CountrySquare> _countrySquares = new();
        private readonly Dictionary<string, double> _pulsePhases = new();

        #region Country Grid Layout

        // Simple grid-based country layout (ISO 2-letter codes)
        private static readonly Dictionary<string, (int row, int col)> CountryPositions = new()
        {
            // North America
            ["US"] = (2, 2), ["CA"] = (1, 2), ["MX"] = (3, 2),

            // South America
            ["BR"] = (5, 3), ["AR"] = (6, 3), ["CL"] = (6, 2), ["CO"] = (4, 3),

            // Europe
            ["GB"] = (2, 5), ["FR"] = (3, 5), ["DE"] = (2, 6), ["IT"] = (3, 6),
            ["ES"] = (4, 5), ["PL"] = (2, 7), ["RU"] = (1, 8),

            // Africa
            ["ZA"] = (6, 6), ["EG"] = (3, 7), ["NG"] = (4, 6), ["KE"] = (5, 7),

            // Asia
            ["CN"] = (3, 9), ["JP"] = (2, 10), ["IN"] = (4, 8), ["KR"] = (2, 9),
            ["SG"] = (5, 9), ["AU"] = (6, 10), ["TH"] = (4, 9),

            // Middle East
            ["SA"] = (4, 7), ["AE"] = (4, 8), ["IL"] = (3, 7),
        };

        #endregion

        public SimpleWorldMapControl()
        {
            InitializeCountrySquares();
        }

        private void InitializeCountrySquares()
        {
            foreach (var (countryCode, position) in CountryPositions)
            {
                _countrySquares[countryCode] = new CountrySquare
                {
                    CountryCode = countryCode,
                    Row = position.row,
                    Column = position.col,
                    Color = Colors.DarkSlateGray
                };

                _pulsePhases[countryCode] = Random.NextDouble() * Math.PI * 2;
            }
        }

        protected override void RenderMap(DrawingContext context, Rect bounds)
        {
            const int GRID_COLS = 12;
            const int GRID_ROWS = 8;

            double cellWidth = bounds.Width / GRID_COLS;
            double cellHeight = bounds.Height / GRID_ROWS;

            foreach (var square in _countrySquares.Values)
            {
                // Skip excluded countries
                if (ExcludedCountries.Contains(square.CountryCode))
                    continue;

                // Get traffic data for this country
                double trafficValue = 0;
                CountryData?.TryGetValue(square.CountryCode, out trafficValue);

                // Calculate position
                double x = square.Column * cellWidth;
                double y = square.Row * cellHeight;

                // Calculate color based on traffic
                var color = GetCountryColor(trafficValue);

                // Add pulse effect if enabled
                if (ShowAnimations && trafficValue > 0)
                {
                    var pulse = Math.Sin(_pulsePhases[square.CountryCode] + AnimationPhase);
                    var pulseBrightness = (pulse + 1) / 2; // 0 to 1
                    color = AdjustBrightness(color, 0.7 + pulseBrightness * 0.3);
                }

                // Draw country square
                var rect = new Rect(x + 2, y + 2, cellWidth - 4, cellHeight - 4);
                var brush = new SolidColorBrush(color);
                var pen = HoveredCountry == square.CountryCode
                    ? new Pen(Brushes.Yellow, 2)
                    : new Pen(new SolidColorBrush(Color.FromArgb(64, 255, 255, 255)), 1);

                context.DrawRectangle(brush, pen, rect);

                // Draw country label if enabled
                if (ShowCountryLabels)
                {
                    var text = new FormattedText(
                        square.CountryCode,
                        System.Globalization.CultureInfo.CurrentCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Arial"),
                        10,
                        Brushes.White);

                    var textX = x + (cellWidth - text.Width) / 2;
                    var textY = y + (cellHeight - text.Height) / 2;

                    context.DrawText(text, new Point(textX, textY));
                }

                // Spawn particles for high traffic countries
                if (ShowParticles && trafficValue > 0.5 && Random.NextDouble() < 0.1)
                {
                    SpawnParticle(
                        x + cellWidth / 2,
                        y + cellHeight / 2,
                        color,
                        (Random.NextDouble() - 0.5) * 2,
                        -Random.NextDouble() * 2
                    );
                }
            }
        }

        protected override void UpdateAnimations()
        {
            // Update pulse phases for each country
            foreach (var countryCode in _pulsePhases.Keys.ToList())
            {
                _pulsePhases[countryCode] = (_pulsePhases[countryCode] + 0.05) % (Math.PI * 2);
            }
        }

        protected override void OnCountryClicked(string countryCode)
        {
            DebugLogger.Log($"[SimpleWorldMapControl] Country clicked: {countryCode}");
            // Can be extended with events or commands
        }

        protected override void UpdateHoveredCountry(Point mousePosition)
        {
            const int GRID_COLS = 12;
            const int GRID_ROWS = 8;

            if (Bounds.Width <= 0 || Bounds.Height <= 0)
                return;

            double cellWidth = Bounds.Width / GRID_COLS;
            double cellHeight = Bounds.Height / GRID_ROWS;

            // Transform mouse position by current zoom/pan
            var transformedX = (mousePosition.X - PanOffset.X) / ZoomLevel;
            var transformedY = (mousePosition.Y - PanOffset.Y) / ZoomLevel;

            int col = (int)(transformedX / cellWidth);
            int row = (int)(transformedY / cellHeight);

            // Find country at this position
            string? newHoveredCountry = null;
            foreach (var square in _countrySquares.Values)
            {
                if (square.Row == row && square.Column == col)
                {
                    newHoveredCountry = square.CountryCode;
                    break;
                }
            }

            if (newHoveredCountry != HoveredCountry)
            {
                HoveredCountry = newHoveredCountry;
                InvalidateVisual();
            }
        }

        #region Helper Methods

        private Color GetCountryColor(double trafficValue)
        {
            if (trafficValue <= 0)
                return Color.FromArgb(255, 28, 33, 40); // Dark background

            // Heat map: blue -> green -> yellow -> red
            if (trafficValue < 0.25)
            {
                // Blue to Green
                var t = trafficValue / 0.25;
                return Color.FromRgb(
                    (byte)(0 * (1 - t) + 0 * t),
                    (byte)(128 * (1 - t) + 255 * t),
                    (byte)(255 * (1 - t) + 0 * t)
                );
            }
            else if (trafficValue < 0.5)
            {
                // Green to Yellow
                var t = (trafficValue - 0.25) / 0.25;
                return Color.FromRgb(
                    (byte)(0 * (1 - t) + 255 * t),
                    (byte)(255),
                    (byte)(0)
                );
            }
            else if (trafficValue < 0.75)
            {
                // Yellow to Orange
                var t = (trafficValue - 0.5) / 0.25;
                return Color.FromRgb(
                    (byte)(255),
                    (byte)(255 * (1 - t) + 165 * t),
                    (byte)(0)
                );
            }
            else
            {
                // Orange to Red
                var t = (trafficValue - 0.75) / 0.25;
                return Color.FromRgb(
                    (byte)(255),
                    (byte)(165 * (1 - t) + 0 * t),
                    (byte)(0)
                );
            }
        }

        private Color AdjustBrightness(Color color, double factor)
        {
            return Color.FromRgb(
                (byte)Math.Min(255, color.R * factor),
                (byte)Math.Min(255, color.G * factor),
                (byte)Math.Min(255, color.B * factor)
            );
        }

        #endregion

        private class CountrySquare
        {
            public string CountryCode { get; set; } = "";
            public int Row { get; set; }
            public int Column { get; set; }
            public Color Color { get; set; }
        }
    }
#pragma warning restore CA5394
}
