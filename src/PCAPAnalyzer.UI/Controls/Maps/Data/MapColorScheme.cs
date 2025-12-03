using System;
using Avalonia;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Controls.Maps.Data
{
    /// <summary>
    /// Provides color scheme calculations for map visualization.
    /// Handles traffic intensity colors, heat maps, and border colors.
    /// </summary>
    public static class MapColorScheme
    {
        /// <summary>
        /// Gets traffic-intensity based color for continent
        /// </summary>
        public static Color GetTrafficIntensityColor(Color baseColor, double trafficValue)
        {
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
        public static Color GetTrafficBorderColor(double trafficValue)
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
        /// Returns heat map color for country traffic intensity
        /// Color scale: Grey (< 0.1%) -> Cyan (< 1%) -> Blue (< 3%) -> Green (< 5%) -> Yellow (< 10%) -> Red (>= 10%)
        /// </summary>
        public static Color GetCountryHeatMapColor(double percentage)
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
        /// Creates gradient fill for continent based on traffic intensity
        /// </summary>
        public static IBrush CreateContinentGradient(Color baseColor, double intensity)
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
        /// Adjusts color brightness by multiplying RGB values
        /// </summary>
        public static Color AdjustBrightness(Color color, double factor)
        {
            return Color.FromRgb(
                (byte)Math.Min(255, color.R * factor),
                (byte)Math.Min(255, color.G * factor),
                (byte)Math.Min(255, color.B * factor));
        }

        /// <summary>
        /// Gets heat map color with gradual blue to red gradient (legacy)
        /// </summary>
        public static Color GetHeatMapColor(double value)
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
    }
}
