using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Data;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Controls.Maps.Data;

namespace PCAPAnalyzer.UI.Controls.Maps.Interaction
{
    /// <summary>
    /// Manages country icon rendering with collision detection in continent drill-down view.
    /// Handles icon positioning, sizing, and tooltip data.
    /// </summary>
    public class CountryIconManager
    {
        private readonly Dictionary<string, CountryIconInfo> _countryIcons = new();

        /// <summary>
        /// Gets read-only dictionary of country icons for hit testing and tooltips
        /// </summary>
        public IReadOnlyDictionary<string, CountryIconInfo> CountryIcons => _countryIcons;

        /// <summary>
        /// Clears all icon data
        /// </summary>
        public void Clear()
        {
            _countryIcons.Clear();
        }

        /// <summary>
        /// Resolves icon collisions using force-directed layout with minimum spacing
        /// </summary>
        public List<(string code, Point position)> ResolveIconCollisions(
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

        /// <summary>
        /// Draws country icon with SPLIT colors (left=packets, right=bytes) and stores info for tooltips/hit testing
        /// </summary>
        public void DrawCountryIconWithInfo(DrawingContext context, string countryCode, Point center,
            CountryTrafficStatistics stats, long totalPackets, long totalBytes,
            Dictionary<string, CountryTrafficStatistics> trafficData, bool showAnimations, double animationPhase,
            string? hoveredCountryCode)
        {
            // Calculate percentages - percentages are relative to PUBLIC traffic only (exclude INT/IP6)
            var packetPercentage = totalPackets > 0 ? (double)stats.TotalPackets / totalPackets : 0;
            var bytePercentage = totalBytes > 0 ? (double)stats.TotalBytes / totalBytes : 0;

            // Adaptive icon sizing - use average of both percentages for sizing
            var continentCode = CountryGeographicData.GetContinentForCountry(countryCode);
            var countriesInContinent = trafficData.Keys.Count(k => CountryGeographicData.GetContinentForCountry(k) == continentCode);
            var baseSize = countriesInContinent > 15 ? 20 : 30;
            var maxSize = countriesInContinent > 15 ? 35 : 50;

            var avgPercentage = (packetPercentage + bytePercentage) / 2;
            var sizeMultiplier = 1 + Math.Min(avgPercentage * 2, 1.0);
            var iconSize = Math.Clamp(baseSize * sizeMultiplier, baseSize * 0.8, maxSize);
            var radius = iconSize / 2;

            // Apply pulse animation if enabled
            if (showAnimations && stats.TotalBytes > 0)
            {
                var pulse = Math.Sin(animationPhase);
                var pulseScale = 1 + (pulse + 1) / 2 * 0.15;
                radius *= pulseScale;
            }

            // Get heat map colors for BOTH metrics (packets and bytes)
            var packetColor = MapColorScheme.GetCountryHeatMapColor(packetPercentage);
            var byteColor = MapColorScheme.GetCountryHeatMapColor(bytePercentage);

            // Highlight if hovered
            var isHovered = hoveredCountryCode == countryCode;

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
        public void RenderCountryTooltip(DrawingContext context, Rect bounds, string? hoveredCountryCode)
        {
            if (string.IsNullOrEmpty(hoveredCountryCode) || !_countryIcons.TryGetValue(hoveredCountryCode, out var iconInfo))
                return;

            // Use country code with flag emoji and full name for display
            var countryFlag = CountryGeographicData.GetCountryFlag(hoveredCountryCode);
            var countryFullName = CountryNameHelper.GetDisplayName(hoveredCountryCode, hoveredCountryCode);
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

        /// <summary>
        /// Checks if a point hits any country icon
        /// </summary>
        public string? HitTestCountryIcon(Point position)
        {
            foreach (var (countryCode, iconInfo) in _countryIcons)
            {
                var dx = position.X - iconInfo.Center.X;
                var dy = position.Y - iconInfo.Center.Y;
                var distance = Math.Sqrt(dx * dx + dy * dy);

                if (distance <= iconInfo.Radius)
                {
                    return countryCode;
                }
            }
            return null;
        }

        private static string FormatBytes(long bytes)
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
    }

    /// <summary>
    /// Stores information about rendered country icons for hit testing and tooltips
    /// </summary>
    public class CountryIconInfo
    {
        public string CountryCode { get; set; } = string.Empty;
        public Point Center { get; set; }
        public double Radius { get; set; }
        public CountryTrafficStatistics Stats { get; set; } = new();
        public double PacketPercentage { get; set; }
        public double BytePercentage { get; set; }
    }
}
