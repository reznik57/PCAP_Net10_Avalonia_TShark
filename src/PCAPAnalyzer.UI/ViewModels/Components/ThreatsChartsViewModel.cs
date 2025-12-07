using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component ViewModel responsible for all threat visualization charts.
/// Extracted from ThreatsViewModel to follow Dashboard's composition pattern.
/// </summary>
public partial class ThreatsChartsViewModel : ObservableObject
{
    private readonly IInsecurePortDetector _insecurePortDetector;

    // Chart series collections
    [ObservableProperty] private ObservableCollection<ISeries> _threatSeveritySeries = [];
    [ObservableProperty] private ObservableCollection<ISeries> _threatTimelineSeries = [];
    [ObservableProperty] private ObservableCollection<ISeries> _portRiskSeries = [];
    [ObservableProperty] private ObservableCollection<ISeries> _threatCategorySeries = [];

    // Chart axes
    [ObservableProperty] private Axis[] _xAxes = new[] { new Axis() };
    [ObservableProperty] private Axis[] _yAxes = new[] { new Axis() };
    [ObservableProperty] private Axis[] _portRiskXAxes = new[] { new Axis() };
    [ObservableProperty] private Axis[] _threatCategoryYAxes = new[] { new Axis() };

    // Threat Port Activity Timeline (Dashboard pattern)
    [ObservableProperty] private ObservableCollection<ISeries> _threatPortActivitySeries = [];
    [ObservableProperty] private Axis[] _threatPortActivityXAxes = new[] { new Axis() };
    [ObservableProperty] private Axis[] _threatPortActivityYAxes = new[] { new Axis() };
    [ObservableProperty] private bool _showThreatPortActivityAsThroughput;
    [ObservableProperty] private bool _showTop10ThreatPortsTimeline;

    // Cached threat data for re-rendering when toggles change
    private List<EnhancedSecurityThreat> _cachedThreats = [];

    // Threat rates (calculated from timeline)
    [ObservableProperty] private double _peakThreatRate;
    [ObservableProperty] private double _averageThreatRate;

    // Severity colors - resolved at runtime for theme support via ThemeColorHelper
    private static Dictionary<string, SKColor>? _severityColorsCache;
    private static Dictionary<string, SKColor> SeverityColors => _severityColorsCache ??= new()
    {
        { "Critical", ThemeColorHelper.GetSKColor("ColorDanger", "#EF4444") },    // Red
        { "High", ThemeColorHelper.GetSKColor("ColorWarning", "#F59E0B") },        // Orange
        { "Medium", ThemeColorHelper.GetSKColor("AccentBlue", "#3B82F6") },        // Blue
        { "Low", ThemeColorHelper.GetSKColor("ColorSuccess", "#10B981") }          // Green
    };

    public ThreatsChartsViewModel() : this(new InsecurePortDetector())
    {
    }

    public ThreatsChartsViewModel(IInsecurePortDetector insecurePortDetector)
    {
        _insecurePortDetector = insecurePortDetector;
        InitializeCharts();
    }

    /// <summary>
    /// Updates all charts based on current threat data and metrics
    /// </summary>
    public void UpdateAllCharts(
        List<EnhancedSecurityThreat> allThreats,
        SecurityMetrics? metrics,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount)
    {
        _cachedThreats = allThreats;
        UpdateSeverityChart(criticalCount, highCount, mediumCount, lowCount);
        UpdateTimelineChart(allThreats);
        UpdatePortRiskChart(metrics);
        UpdateCategoryChart(metrics);
        UpdateThreatPortActivityChart(allThreats);
    }

    partial void OnShowThreatPortActivityAsThroughputChanged(bool value)
    {
        UpdateThreatPortActivityChart(_cachedThreats);
    }

    partial void OnShowTop10ThreatPortsTimelineChanged(bool value)
    {
        UpdateThreatPortActivityChart(_cachedThreats);
    }

    private void InitializeCharts()
    {
        XAxes = new[]
        {
            new Axis
            {
                Name = "Time",
                NamePaint = ThemeColorHelper.GrayPaint,
                LabelsPaint = ThemeColorHelper.GrayPaint
            }
        };

        YAxes = new[]
        {
            new Axis
            {
                Name = "Count",
                NamePaint = ThemeColorHelper.GrayPaint,
                LabelsPaint = ThemeColorHelper.GrayPaint
            }
        };
    }

    private void UpdateSeverityChart(int critical, int high, int medium, int low)
    {
        var severityData = new[]
        {
            new { Label = "Critical", Value = (double)critical, Color = SKColors.Red },
            new { Label = "High", Value = (double)high, Color = SKColors.OrangeRed },
            new { Label = "Medium", Value = (double)medium, Color = SKColors.Orange },
            new { Label = "Low", Value = (double)low, Color = SKColors.Blue },
        }.Where(x => x.Value > 0).ToArray();

        if (!severityData.Any())
        {
            ThreatSeveritySeries = new ObservableCollection<ISeries>();
            return;
        }

        var pieSeries = new PieSeries<double>[]
        {
            new()
            {
                Values = severityData.Select(x => x.Value).ToArray(),
                Name = "Threats by Severity",
                DataLabelsPaint = new SolidColorPaint(SKColors.White)
                {
                    SKTypeface = SKTypeface.FromFamilyName(null, SKFontStyleWeight.Bold, SKFontStyleWidth.Normal, SKFontStyleSlant.Upright)
                },
                DataLabelsSize = 12,
                DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                DataLabelsFormatter = point => $"{severityData[(int)point.Index].Label}\n{point.Coordinate.PrimaryValue:N0}"
            }
        };

        ThreatSeveritySeries = new ObservableCollection<ISeries>(pieSeries);
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Timeline chart requires aggregating threats by time period, grouping by severity, calculating time buckets")]
    private void UpdateTimelineChart(List<EnhancedSecurityThreat> allThreats)
    {
        if (!allThreats.Any())
        {
            ThreatTimelineSeries = new ObservableCollection<ISeries>();
            PeakThreatRate = 0;
            AverageThreatRate = 0;
            return;
        }

        // Group threats by severity
        var criticalThreats = allThreats.Where(t => t.Severity == ThreatSeverity.Critical).ToList();
        var highThreats = allThreats.Where(t => t.Severity == ThreatSeverity.High).ToList();
        var mediumThreats = allThreats.Where(t => t.Severity == ThreatSeverity.Medium).ToList();
        var lowThreats = allThreats.Where(t => t.Severity == ThreatSeverity.Low).ToList();

        // Use actual packet time range
        var minTime = allThreats.Min(t => t.FirstSeen);
        var maxTime = allThreats.Max(t => t.LastSeen);

        // Expand range for single-timestamp threats
        if ((maxTime - minTime).TotalMinutes < 1)
        {
            minTime = minTime.AddMinutes(-1);
            maxTime = maxTime.AddMinutes(1);
        }

        var series = new ObservableCollection<ISeries>();

        // Add series for each severity level
        AddTimelineSeries(series, criticalThreats, "Critical", minTime, maxTime);
        AddTimelineSeries(series, highThreats, "High", minTime, maxTime);
        AddTimelineSeries(series, mediumThreats, "Medium", minTime, maxTime);
        AddTimelineSeries(series, lowThreats, "Low", minTime, maxTime);

        // Calculate threat rates
        CalculateThreatRates(allThreats, minTime, maxTime);

        ThreatTimelineSeries = series;

        // Update axes
        UpdateTimelineAxes(minTime, maxTime);
    }

    private void AddTimelineSeries(
        ObservableCollection<ISeries> series,
        List<EnhancedSecurityThreat> threats,
        string severity,
        DateTime minTime,
        DateTime maxTime)
    {
        if (!threats.Any()) return;

        var timeRange = maxTime - minTime;
        var bucketSize = GetBucketSize(timeRange);

        // Create time buckets
        var timeBuckets = CreateTimeBuckets(minTime, maxTime, bucketSize);

        // Count threats per bucket
        foreach (var threat in threats)
        {
            var totalSeconds = (long)(threat.FirstSeen - minTime).TotalSeconds;
            var bucketSeconds = (long)bucketSize.TotalSeconds;
            var roundedSeconds = (totalSeconds / bucketSeconds) * bucketSeconds;
            var bucketTime = minTime.AddSeconds(roundedSeconds);

            var closestBucket = timeBuckets.Keys
                .OrderBy(k => Math.Abs((k - bucketTime).TotalSeconds))
                .FirstOrDefault();

            if (closestBucket != default && Math.Abs((closestBucket - bucketTime).TotalSeconds) < bucketSize.TotalSeconds)
            {
                timeBuckets[closestBucket]++;
            }
        }

        // Convert to chart points
        var points = timeBuckets
            .OrderBy(kvp => kvp.Key)
            .Select(kvp => new ObservablePoint(kvp.Key.Ticks, kvp.Value / 60.0))
            .ToArray();

        var color = SeverityColors[severity];
        series.Add(new LineSeries<ObservablePoint>
        {
            Values = points,
            Name = $"{severity} ({threats.Count})",
            GeometrySize = 3,
            GeometryStroke = new SolidColorPaint(color) { StrokeThickness = 2 },
            Stroke = new SolidColorPaint(color) { StrokeThickness = 2 },
            Fill = null,
            LineSmoothness = 0
        });
    }

    private static TimeSpan GetBucketSize(TimeSpan timeRange)
    {
        if (timeRange.TotalSeconds < 60) return TimeSpan.FromSeconds(1);
        if (timeRange.TotalMinutes < 5) return TimeSpan.FromSeconds(5);
        if (timeRange.TotalMinutes < 30) return TimeSpan.FromSeconds(30);
        if (timeRange.TotalHours < 1) return TimeSpan.FromMinutes(1);
        if (timeRange.TotalHours < 6) return TimeSpan.FromMinutes(5);
        return TimeSpan.FromMinutes(30);
    }

    private static Dictionary<DateTime, int> CreateTimeBuckets(DateTime minTime, DateTime maxTime, TimeSpan bucketSize)
    {
        var buckets = new Dictionary<DateTime, int>();
        var bucketSeconds = (int)bucketSize.TotalSeconds;
        var currentTime = new DateTime(
            minTime.Year, minTime.Month, minTime.Day,
            minTime.Hour, minTime.Minute, minTime.Second / bucketSeconds * bucketSeconds);
        var endTime = maxTime.AddSeconds(bucketSize.TotalSeconds);

        while (currentTime <= endTime)
        {
            buckets[currentTime] = 0;
            currentTime = currentTime.Add(bucketSize);
        }

        return buckets;
    }

    private void CalculateThreatRates(List<EnhancedSecurityThreat> allThreats, DateTime minTime, DateTime maxTime)
    {
        var totalDuration = (maxTime - minTime).TotalSeconds;

        if (totalDuration <= 0)
        {
            PeakThreatRate = 0;
            AverageThreatRate = 0;
            return;
        }

        AverageThreatRate = allThreats.Count / totalDuration;

        // Calculate peak from per-minute aggregation
        var allMinutes = new Dictionary<DateTime, int>();
        var currentMin = new DateTime(minTime.Year, minTime.Month, minTime.Day, minTime.Hour, minTime.Minute, 0);
        var endMin = new DateTime(maxTime.Year, maxTime.Month, maxTime.Day, maxTime.Hour, maxTime.Minute, 0);

        while (currentMin <= endMin)
        {
            allMinutes[currentMin] = 0;
            currentMin = currentMin.AddMinutes(1);
        }

        foreach (var threat in allThreats)
        {
            var minute = new DateTime(
                threat.FirstSeen.Year, threat.FirstSeen.Month, threat.FirstSeen.Day,
                threat.FirstSeen.Hour, threat.FirstSeen.Minute, 0);
            if (allMinutes.ContainsKey(minute))
                allMinutes[minute]++;
        }

        PeakThreatRate = allMinutes.Any() ? allMinutes.Max(kvp => kvp.Value / 60.0) : 0;
    }

    private void UpdateTimelineAxes(DateTime minTime, DateTime maxTime)
    {
        var timeRange = maxTime - minTime;
        var stepSize = timeRange.TotalHours > 1 ? TimeSpan.FromMinutes(30) :
                      timeRange.TotalMinutes > 30 ? TimeSpan.FromMinutes(5) :
                      TimeSpan.FromMinutes(1);

        XAxes = new[]
        {
            new Axis
            {
                Labeler = value =>
                {
                    try
                    {
                        var ticks = (long)value;
                        if (ticks <= 0 || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                            return "";
                        return new DateTime(ticks).ToString("HH:mm:ss");
                    }
                    catch
                    {
                        return "";
                    }
                },
                LabelsRotation = 45,
                UnitWidth = stepSize.Ticks,
                MinStep = stepSize.Ticks,
                MinLimit = minTime.Ticks,
                MaxLimit = maxTime.Ticks,
                TextSize = 10,
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E"),
                SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D")
            }
        };

        YAxes = new[]
        {
            new Axis
            {
                Name = "Threats/Second",
                Labeler = value => $"{value:F2}/s",
                TextSize = 10,
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E"),
                SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D"),
                MinLimit = 0
            }
        };
    }

    private void UpdatePortRiskChart(SecurityMetrics? metrics)
    {
        if (metrics is null || !metrics.ThreatsByPort.Any())
        {
            PortRiskSeries = new ObservableCollection<ISeries>();
            PortRiskXAxes = new[] { new Axis { Labels = [] } };
            return;
        }

        var topPorts = metrics.ThreatsByPort
            .OrderByDescending(kvp => kvp.Value)
            .Take(10)
            .Select(kvp => new
            {
                Port = kvp.Key,
                Count = kvp.Value,
                Profile = _insecurePortDetector.GetPortRiskProfile(kvp.Key, "TCP")
            })
            .ToArray();

        var columnSeries = new ColumnSeries<double>
        {
            Values = topPorts.Select(p => (double)p.Count).ToArray(),
            Name = "Threats by Port",
            Fill = new SolidColorPaint(SKColors.OrangeRed),
            DataLabelsPaint = ThemeColorHelper.WhitePaint,
            DataLabelsSize = 10,
            DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Middle,
            DataLabelsFormatter = point => topPorts[(int)point.Index].Count.ToString()
        };

        PortRiskSeries = new ObservableCollection<ISeries> { columnSeries };

        PortRiskXAxes = new[]
        {
            new Axis
            {
                Labels = topPorts.Select(p =>
                    $"{p.Port}\n{(p.Profile is not null ? p.Profile.ServiceName : "Unknown")}").ToArray(),
                LabelsRotation = -45,
                TextSize = 10,
                LabelsPaint = ThemeColorHelper.GrayPaint
            }
        };
    }

    private void UpdateCategoryChart(SecurityMetrics? metrics)
    {
        if (metrics is null || !metrics.ThreatsByCategory.Any())
        {
            ThreatCategorySeries = new ObservableCollection<ISeries>();
            ThreatCategoryYAxes = new[] { new Axis { Labels = [] } };
            return;
        }

        var categoryData = metrics.ThreatsByCategory
            .OrderByDescending(kvp => kvp.Value)
            .Select(kvp => new { Category = kvp.Key.ToString(), Count = (double)kvp.Value })
            .ToArray();

        var barSeries = new RowSeries<double>
        {
            Values = categoryData.Select(c => c.Count).ToArray(),
            Name = "Threats by Category",
            Fill = new SolidColorPaint(SKColors.Purple),
            DataLabelsPaint = ThemeColorHelper.WhitePaint,
            DataLabelsSize = 10,
            DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Middle,
            DataLabelsFormatter = point => categoryData[(int)point.Index].Count.ToString()
        };

        ThreatCategorySeries = new ObservableCollection<ISeries> { barSeries };

        ThreatCategoryYAxes = new[]
        {
            new Axis
            {
                Labels = categoryData.Select(c => c.Category).ToArray(),
                TextSize = 11,
                LabelsPaint = ThemeColorHelper.GrayPaint
            }
        };
    }

    /// <summary>
    /// Updates the Threat Port Activity Timeline chart (Dashboard pattern).
    /// Shows which ports had threats over time.
    /// </summary>
    private void UpdateThreatPortActivityChart(List<EnhancedSecurityThreat> allThreats)
    {
        if (allThreats is null || !allThreats.Any())
        {
            ThreatPortActivitySeries = new ObservableCollection<ISeries>();
            ThreatPortActivityXAxes = new[] { new Axis() };
            ThreatPortActivityYAxes = new[] { new Axis() };
            return;
        }

        // Group threats by port and count
        var portThreats = allThreats
            .Where(t => t.Port > 0)
            .GroupBy(t => t.Port)
            .Select(g => new
            {
                Port = g.Key,
                Threats = g.ToList(),
                Count = g.Count(),
                TotalOccurrences = g.Sum(t => t.OccurrenceCount)
            })
            .OrderByDescending(p => ShowThreatPortActivityAsThroughput ? p.TotalOccurrences : p.Count)
            .Take(ShowTop10ThreatPortsTimeline ? 10 : 5)
            .ToList();

        if (!portThreats.Any())
        {
            ThreatPortActivitySeries = new ObservableCollection<ISeries>();
            return;
        }

        // Time range from threats
        var minTime = allThreats.Min(t => t.FirstSeen);
        var maxTime = allThreats.Max(t => t.LastSeen);
        if ((maxTime - minTime).TotalMinutes < 1)
        {
            minTime = minTime.AddMinutes(-1);
            maxTime = maxTime.AddMinutes(1);
        }

        var timeRange = maxTime - minTime;
        var bucketSize = GetBucketSize(timeRange);
        var newSeries = new ObservableCollection<ISeries>();

        var colors = new[] {
            ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"),
            ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"),
            ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"),
            ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
            ThemeColorHelper.GetColorHex("AccentPurple", "#8B5CF6"),
            ThemeColorHelper.GetColorHex("AccentCyan", "#06B6D4"),
            ThemeColorHelper.GetColorHex("AccentPink", "#EC4899"),
            ThemeColorHelper.GetColorHex("ColorOrange", "#F97316"),
            ThemeColorHelper.GetColorHex("ColorLime", "#84CC16"),
            ThemeColorHelper.GetColorHex("AccentIndigo", "#6366F1")
        };

        for (int i = 0; i < portThreats.Count && i < colors.Length; i++)
        {
            var portData = portThreats[i];
            var color = ThemeColorHelper.ParseSKColor(colors[i]);

            // Create time buckets for this port
            var timeBuckets = CreateTimeBuckets(minTime, maxTime, bucketSize);

            // Aggregate threats into buckets
            foreach (var threat in portData.Threats)
            {
                var totalSeconds = (long)(threat.FirstSeen - minTime).TotalSeconds;
                var bucketSeconds = (long)bucketSize.TotalSeconds;
                if (bucketSeconds <= 0) bucketSeconds = 1;
                var roundedSeconds = (totalSeconds / bucketSeconds) * bucketSeconds;
                var bucketTime = minTime.AddSeconds(roundedSeconds);

                var closestBucket = timeBuckets.Keys
                    .OrderBy(k => Math.Abs((k - bucketTime).TotalSeconds))
                    .FirstOrDefault();

                if (closestBucket != default && Math.Abs((closestBucket - bucketTime).TotalSeconds) < bucketSize.TotalSeconds)
                {
                    if (ShowThreatPortActivityAsThroughput)
                        timeBuckets[closestBucket] += threat.OccurrenceCount;
                    else
                        timeBuckets[closestBucket]++;
                }
            }

            // Convert to chart points (rate per second)
            var points = timeBuckets
                .OrderBy(kvp => kvp.Key)
                .Select(kvp => new ObservablePoint(kvp.Key.Ticks, kvp.Value / 60.0))
                .ToArray();

            var serviceName = _insecurePortDetector.GetPortRiskProfile(portData.Port, "TCP")?.ServiceName ?? "Unknown";

            newSeries.Add(new LineSeries<ObservablePoint>
            {
                Values = points,
                Name = $"Port {portData.Port} ({serviceName})",
                GeometrySize = 3,
                GeometryStroke = new SolidColorPaint(color) { StrokeThickness = 2 },
                Stroke = new SolidColorPaint(color) { StrokeThickness = 2 },
                Fill = null,
                LineSmoothness = 0,
                IsVisibleAtLegend = (i < 3) // Limit legend entries
            });
        }

        ThreatPortActivitySeries = newSeries;

        // Update axes
        var stepSize = timeRange.TotalHours > 1 ? TimeSpan.FromMinutes(30) :
                      timeRange.TotalMinutes > 30 ? TimeSpan.FromMinutes(5) :
                      TimeSpan.FromMinutes(1);

        ThreatPortActivityXAxes = new[]
        {
            new Axis
            {
                Labeler = value =>
                {
                    try
                    {
                        var ticks = (long)value;
                        if (ticks <= 0 || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                            return "";
                        return new DateTime(ticks).ToString("HH:mm:ss");
                    }
                    catch
                    {
                        return "";
                    }
                },
                LabelsRotation = 45,
                UnitWidth = stepSize.Ticks,
                MinStep = stepSize.Ticks,
                MinLimit = minTime.Ticks,
                MaxLimit = maxTime.Ticks,
                TextSize = 10,
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E"),
                SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D")
            }
        };

        ThreatPortActivityYAxes = new[]
        {
            new Axis
            {
                Name = ShowThreatPortActivityAsThroughput ? "Occurrences/Second" : "Threats/Second",
                Labeler = value => $"{value:F2}/s",
                TextSize = 10,
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E"),
                SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D"),
                MinLimit = 0
            }
        };
    }

    private static string FormatBytesPerSecond(long bytesPerSecond)
        => Core.Utilities.NumberFormatter.FormatBytesPerSecond(bytesPerSecond);

    /// <summary>
    /// Generates SVG markup for the severity pie chart (for HTML reports)
    /// </summary>
    public string GenerateSeverityChartSvg(int critical, int high, int medium, int low, int width = 300, int height = 300)
    {
        var total = critical + high + medium + low;
        if (total == 0) return "<svg></svg>";

        var centerX = width / 2;
        var centerY = height / 2;
        var radius = Math.Min(centerX, centerY) - 20;

        var sb = new StringBuilder();
        sb.AppendLine($"<svg width=\"{width}\" height=\"{height}\" xmlns=\"http://www.w3.org/2000/svg\">");

        var data = new[]
        {
            (critical, "#EF4444", "Critical"),
            (high, "#F59E0B", "High"),
            (medium, "#3B82F6", "Medium"),
            (low, "#10B981", "Low")
        }.Where(d => d.Item1 > 0).ToArray();

        double startAngle = -90; // Start from top
        foreach (var (value, color, label) in data)
        {
            var percentage = (double)value / total;
            var angle = percentage * 360;
            var endAngle = startAngle + angle;

            // Calculate arc path
            var largeArc = angle > 180 ? 1 : 0;
            var x1 = centerX + radius * Math.Cos(startAngle * Math.PI / 180);
            var y1 = centerY + radius * Math.Sin(startAngle * Math.PI / 180);
            var x2 = centerX + radius * Math.Cos(endAngle * Math.PI / 180);
            var y2 = centerY + radius * Math.Sin(endAngle * Math.PI / 180);

            sb.AppendLine($"  <path d=\"M{centerX},{centerY} L{x1:F1},{y1:F1} A{radius},{radius} 0 {largeArc},1 {x2:F1},{y2:F1} Z\" fill=\"{color}\" />");

            // Add label at midpoint
            var midAngle = (startAngle + endAngle) / 2;
            var labelRadius = radius * 0.65;
            var labelX = centerX + labelRadius * Math.Cos(midAngle * Math.PI / 180);
            var labelY = centerY + labelRadius * Math.Sin(midAngle * Math.PI / 180);
            sb.AppendLine($"  <text x=\"{labelX:F1}\" y=\"{labelY:F1}\" text-anchor=\"middle\" fill=\"white\" font-size=\"12\" font-weight=\"bold\">{label}</text>");
            sb.AppendLine($"  <text x=\"{labelX:F1}\" y=\"{labelY + 14:F1}\" text-anchor=\"middle\" fill=\"white\" font-size=\"10\">{value}</text>");

            startAngle = endAngle;
        }

        sb.AppendLine("</svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Generates SVG markup for the timeline chart (for HTML reports)
    /// </summary>
    public string GenerateTimelineChartSvg(List<EnhancedSecurityThreat> threats, int width = 600, int height = 200)
    {
        if (!threats.Any()) return "<svg></svg>";

        var minTime = threats.Min(t => t.FirstSeen);
        var maxTime = threats.Max(t => t.LastSeen);
        var timeRange = (maxTime - minTime).TotalSeconds;
        if (timeRange < 60) timeRange = 120; // Minimum 2 minutes

        var margin = 40;
        var chartWidth = width - margin * 2;
        var chartHeight = height - margin * 2;

        var sb = new StringBuilder();
        sb.AppendLine($"<svg width=\"{width}\" height=\"{height}\" xmlns=\"http://www.w3.org/2000/svg\">");

        // Background
        sb.AppendLine($"  <rect width=\"{width}\" height=\"{height}\" fill=\"#161B22\" />");

        // Group threats by severity and time buckets
        var bucketCount = 20;
        var bucketSize = timeRange / bucketCount;
        var buckets = new Dictionary<int, Dictionary<string, int>>();

        for (int i = 0; i <= bucketCount; i++)
        {
            buckets[i] = new Dictionary<string, int>
            {
                { "Critical", 0 }, { "High", 0 }, { "Medium", 0 }, { "Low", 0 }
            };
        }

        var maxCount = 1;
        foreach (var threat in threats)
        {
            var seconds = (threat.FirstSeen - minTime).TotalSeconds;
            var bucket = Math.Min((int)(seconds / bucketSize), bucketCount);
            var severity = threat.Severity.ToString();
            if (buckets[bucket].ContainsKey(severity))
            {
                buckets[bucket][severity]++;
                maxCount = Math.Max(maxCount, buckets[bucket].Values.Sum());
            }
        }

        // Draw grid lines
        for (int i = 0; i <= 5; i++)
        {
            var y = margin + chartHeight - (chartHeight * i / 5);
            sb.AppendLine($"  <line x1=\"{margin}\" y1=\"{y}\" x2=\"{width - margin}\" y2=\"{y}\" stroke=\"#30363D\" stroke-width=\"1\" />");
        }

        // Draw lines for each severity
        var severities = new[] { ("Critical", "#EF4444"), ("High", "#F59E0B"), ("Medium", "#3B82F6"), ("Low", "#10B981") };

        foreach (var (severity, color) in severities)
        {
            var points = new List<string>();
            for (int i = 0; i <= bucketCount; i++)
            {
                var x = margin + (chartWidth * i / bucketCount);
                var y = margin + chartHeight - (chartHeight * buckets[i][severity] / maxCount);
                points.Add($"{x},{y}");
            }
            if (points.Any())
            {
                sb.AppendLine($"  <polyline points=\"{string.Join(" ", points)}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" />");
            }
        }

        // X axis labels
        sb.AppendLine($"  <text x=\"{margin}\" y=\"{height - 10}\" fill=\"#8B949E\" font-size=\"10\">{minTime:HH:mm:ss}</text>");
        sb.AppendLine($"  <text x=\"{width - margin - 50}\" y=\"{height - 10}\" fill=\"#8B949E\" font-size=\"10\">{maxTime:HH:mm:ss}</text>");

        sb.AppendLine("</svg>");
        return sb.ToString();
    }
}
