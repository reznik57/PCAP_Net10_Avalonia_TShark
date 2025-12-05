using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Controls
{
    /// <summary>
    /// Specialized renderer for animated traffic flows between countries with protocol-based visualization
    /// </summary>
    public class TrafficFlowRenderer
    {
        private readonly List<AnimatedFlow> _flows = new();
        private readonly Dictionary<Protocol, FlowStyle> _protocolStyles = new();
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI animation natural variation, not security
        private readonly Random _random = new();
#pragma warning restore CA5394

        public TrafficFlowRenderer()
        {
            InitializeProtocolStyles();
        }

        private void InitializeProtocolStyles()
        {
            // HTTP - Blue for general web traffic
            _protocolStyles[Protocol.HTTP] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("ProtocolHTTP", "#3B82F6"),
                LineWidth = 2.0,
                AnimationSpeed = 0.02,
                ParticleSize = 3.0,
                DashPattern = null // Solid line
            };

            // HTTPS - Green for secure traffic
            _protocolStyles[Protocol.HTTPS] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("ColorSuccess", "#22C55E"),
                LineWidth = 2.5,
                AnimationSpeed = 0.025,
                ParticleSize = 3.5,
                DashPattern = null // Solid line for secure
            };

            // DNS - Orange/Yellow for name resolution
            _protocolStyles[Protocol.DNS] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("ProtocolDNS", "#FBBF24"),
                LineWidth = 1.5,
                AnimationSpeed = 0.03,
                ParticleSize = 2.5,
                DashPattern = new List<double> { 3, 2 } // Dashed for intermittent
            };

            // TCP - Purple for connection-oriented
            _protocolStyles[Protocol.TCP] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("AccentPurple", "#9333EA"),
                LineWidth = 2.0,
                AnimationSpeed = 0.02,
                ParticleSize = 3.0,
                DashPattern = null
            };

            // UDP - Red for connectionless
            _protocolStyles[Protocol.UDP] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("ProtocolUDP", "#EF4444"),
                LineWidth = 1.8,
                AnimationSpeed = 0.035,
                ParticleSize = 2.8,
                DashPattern = new List<double> { 5, 3 } // Dashed for connectionless
            };

            // ICMP - Light red for diagnostic
            _protocolStyles[Protocol.ICMP] = new FlowStyle
            {
                Color = ThemeColorHelper.GetColor("ProtocolICMP", "#F56565"),
                LineWidth = 1.0,
                AnimationSpeed = 0.05,
                ParticleSize = 2.0,
                DashPattern = new List<double> { 2, 2 } // Short dashes for diagnostic
            };
        }

        public void AddTrafficFlow(string sourceCountryCode, string destCountryCode, Protocol protocol, 
                                 Point sourcePos, Point destPos, long bytes, int packets)
        {
            if (!_protocolStyles.TryGetValue(protocol, out var style))
            {
                style = _protocolStyles[Protocol.TCP]; // Default style
            }

            // Calculate intensity based on traffic volume
            var intensity = Math.Min(1.0, bytes / (1024.0 * 1024.0)); // Scale by MB
            var adjustedStyle = new FlowStyle
            {
                Color = Color.FromArgb(
                    (byte)(100 + (155 * intensity)), 
                    style.Color.R, 
                    style.Color.G, 
                    style.Color.B),
                LineWidth = style.LineWidth * (0.5 + intensity),
                AnimationSpeed = style.AnimationSpeed * (0.8 + 0.4 * intensity),
                ParticleSize = style.ParticleSize * (0.7 + 0.6 * intensity),
                DashPattern = style.DashPattern
            };

            var flow = new AnimatedFlow
            {
                SourceCountry = sourceCountryCode,
                DestinationCountry = destCountryCode,
                Protocol = protocol,
                SourcePosition = sourcePos,
                DestinationPosition = destPos,
                Progress = 0.0,
                Style = adjustedStyle,
                Intensity = intensity,
                PacketCount = packets,
                ByteCount = bytes,
                CreatedAt = DateTime.UtcNow,
                DirectionArrows = GenerateDirectionArrows(sourcePos, destPos, 5)
            };

            // Calculate bezier control point for natural arc
            var midX = (sourcePos.X + destPos.X) / 2;
            var midY = (sourcePos.Y + destPos.Y) / 2;
            var distance = Math.Sqrt(Math.Pow(destPos.X - sourcePos.X, 2) + Math.Pow(destPos.Y - sourcePos.Y, 2));
            var arcHeight = Math.Min(distance * 0.25, 50);
            
            // Arc upward for better visibility
            flow.ControlPoint = new Point(midX, midY - arcHeight);

            _flows.Add(flow);
        }

        public void Update()
        {
            for (int i = _flows.Count - 1; i >= 0; i--)
            {
                var flow = _flows[i];
                flow.Progress += flow.Style.AnimationSpeed;

#pragma warning disable CA5394 // Random used only for UI animation natural variation, not security
                // Add slight randomness to make it look more natural
                flow.Progress += (_random.NextDouble() - 0.5) * 0.005;
#pragma warning restore CA5394

                if (flow.Progress >= 1.0)
                {
                    _flows.RemoveAt(i);
                }
            }
        }

        public void Render(DrawingContext context, Rect bounds)
        {
            foreach (var flow in _flows)
            {
                RenderFlow(context, flow);
            }
        }

        private void RenderFlow(DrawingContext context, AnimatedFlow flow)
        {
            // Create bezier path
            var pathGeometry = new StreamGeometry();
            using (var ctx = pathGeometry.Open())
            {
                ctx.BeginFigure(flow.SourcePosition, false);
                ctx.QuadraticBezierTo(flow.ControlPoint, flow.DestinationPosition);
            }

            // Render flow path with fade effect
            var opacity = (byte)(255 * (1 - flow.Progress) * flow.Intensity);
            var pathColor = Color.FromArgb(opacity, flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B);
            
            Pen? pathPen;
            if (flow.Style.DashPattern != null)
            {
                pathPen = new Pen(new SolidColorBrush(pathColor), flow.Style.LineWidth, 
                                new DashStyle(flow.Style.DashPattern, 0));
            }
            else
            {
                pathPen = new Pen(new SolidColorBrush(pathColor), flow.Style.LineWidth);
            }

            context.DrawGeometry(null, pathPen, pathGeometry);

            // Render moving particle along the path
            var packetPos = CalculateBezierPoint(flow.SourcePosition, flow.ControlPoint, 
                                                flow.DestinationPosition, flow.Progress);
            
            var packetBrush = new RadialGradientBrush
            {
                Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.FromArgb(200, flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B), 0),
                    new GradientStop(Color.FromArgb(100, flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B), 0.7),
                    new GradientStop(Color.FromArgb(0, flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B), 1)
                }
            };

            context.DrawEllipse(packetBrush, null, packetPos, 
                              flow.Style.ParticleSize * 2, flow.Style.ParticleSize * 2);

            // Render direction arrows along the path
            if (flow.Progress > 0.2) // Only show arrows after some progress
            {
                RenderDirectionArrows(context, flow);
            }

            // Render traffic volume indicator at destination
            if (flow.Progress > 0.8)
            {
                RenderVolumeIndicator(context, flow);
            }
        }

        private void RenderDirectionArrows(DrawingContext context, AnimatedFlow flow)
        {
            // Show 3 arrows along the path at different positions
            var arrowPositions = new[] { 0.3, 0.5, 0.7 };
            
            foreach (var pos in arrowPositions)
            {
                if (flow.Progress > pos)
                {
                    var arrowPos = CalculateBezierPoint(flow.SourcePosition, flow.ControlPoint, 
                                                       flow.DestinationPosition, pos);
                    
                    // Calculate direction vector
                    var tangentPos = CalculateBezierPoint(flow.SourcePosition, flow.ControlPoint, 
                                                         flow.DestinationPosition, pos + 0.01);
                    var direction = new Vector(tangentPos.X - arrowPos.X, tangentPos.Y - arrowPos.Y);
                    var angle = Math.Atan2(direction.Y, direction.X);

                    // Create arrow geometry
                    var arrowGeometry = CreateArrowGeometry(arrowPos, angle, 8);
                    var arrowOpacity = (byte)(150 * (1 - Math.Abs(flow.Progress - pos) * 2));
                    var arrowBrush = new SolidColorBrush(Color.FromArgb(arrowOpacity, 
                                                       flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B));
                    
                    context.DrawGeometry(arrowBrush, null, arrowGeometry);
                }
            }
        }

        private void RenderVolumeIndicator(DrawingContext context, AnimatedFlow flow)
        {
            // Show traffic volume as expanding circles at destination
            var radius = 5 + flow.Intensity * 10;
            var pulseEffect = Math.Sin((DateTime.UtcNow - flow.CreatedAt).TotalMilliseconds / 200) * 0.3 + 0.7;
            
            var volumeBrush = new SolidColorBrush(Color.FromArgb(
                (byte)(50 * pulseEffect), flow.Style.Color.R, flow.Style.Color.G, flow.Style.Color.B));
            
            context.DrawEllipse(volumeBrush, null, flow.DestinationPosition, 
                              radius * pulseEffect, radius * pulseEffect);

            // Show byte count label
            if (flow.ByteCount > 1024 * 1024) // Show for traffic > 1MB
            {
                var sizeText = PCAPAnalyzer.Core.Utilities.NumberFormatter.FormatBytes(flow.ByteCount);
                var typeface = new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Normal);
                var formattedText = new FormattedText(sizeText, 
                    System.Globalization.CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight, typeface, 8,
                    new SolidColorBrush(Colors.White));
                
                context.DrawText(formattedText, new Point(
                    flow.DestinationPosition.X - formattedText.Width / 2,
                    flow.DestinationPosition.Y + radius + 5));
            }
        }

        private Point CalculateBezierPoint(Point start, Point control, Point end, double t)
        {
            var x = (1 - t) * (1 - t) * start.X + 2 * (1 - t) * t * control.X + t * t * end.X;
            var y = (1 - t) * (1 - t) * start.Y + 2 * (1 - t) * t * control.Y + t * t * end.Y;
            return new Point(x, y);
        }

        private StreamGeometry CreateArrowGeometry(Point position, double angle, double size)
        {
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                var cos = Math.Cos(angle);
                var sin = Math.Sin(angle);
                
                // Arrow head points
                var tip = position;
                var left = new Point(position.X - size * cos - size * 0.5 * sin, 
                                   position.Y - size * sin + size * 0.5 * cos);
                var right = new Point(position.X - size * cos + size * 0.5 * sin,
                                    position.Y - size * sin - size * 0.5 * cos);

                ctx.BeginFigure(tip, true);
                ctx.LineTo(left);
                ctx.LineTo(right);
                ctx.EndFigure(true);
            }
            return geometry;
        }

        private List<Point> GenerateDirectionArrows(Point start, Point end, int count)
        {
            var arrows = new List<Point>();
            for (int i = 1; i <= count; i++)
            {
                var t = i / (double)(count + 1);
                arrows.Add(new Point(
                    start.X + t * (end.X - start.X),
                    start.Y + t * (end.Y - start.Y)
                ));
            }
            return arrows;
        }

        public void ClearFlows()
        {
            _flows.Clear();
        }

        public int GetActiveFlowCount() => _flows.Count;

        public Dictionary<Protocol, int> GetFlowsByProtocol()
        {
            return _flows.GroupBy(f => f.Protocol)
                        .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    public class AnimatedFlow
    {
        public string SourceCountry { get; set; } = string.Empty;
        public string DestinationCountry { get; set; } = string.Empty;
        public Protocol Protocol { get; set; }
        public Point SourcePosition { get; set; }
        public Point DestinationPosition { get; set; }
        public Point ControlPoint { get; set; }
        public double Progress { get; set; }
        public FlowStyle Style { get; set; } = new();
        public double Intensity { get; set; }
        public int PacketCount { get; set; }
        public long ByteCount { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<Point> DirectionArrows { get; set; } = new();
    }

    public class FlowStyle
    {
        public Color Color { get; set; }
        public double LineWidth { get; set; } = 2.0;
        public double AnimationSpeed { get; set; } = 0.02;
        public double ParticleSize { get; set; } = 3.0;
        public List<double>? DashPattern { get; set; }
    }

    public class HeatMapData
    {
        public double Temperature { get; set; }
        public DateTime LastUpdate { get; set; }
        public Dictionary<Protocol, long> ProtocolBytes { get; set; } = new();
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
    }

    public class ParticleEffect
    {
        public Point Position { get; set; }
        public Vector Velocity { get; set; }
        public Color Color { get; set; }
        public double Size { get; set; }
        public double Life { get; set; } = 1.0;
        public double Decay { get; set; } = 0.02;
        public Protocol Protocol { get; set; }
    }
}