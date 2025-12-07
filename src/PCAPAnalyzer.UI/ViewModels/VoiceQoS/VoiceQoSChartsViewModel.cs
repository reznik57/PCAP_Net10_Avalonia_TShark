using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.VoiceQoS;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.VoiceQoS
{
    /// <summary>
    /// ViewModel for VoiceQoS timeline charts.
    /// Manages 11-series timeline chart with series visibility toggles.
    /// </summary>
    public partial class VoiceQoSChartsViewModel : ObservableObject
    {
        private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
            ?? throw new InvalidOperationException("IDispatcherService not registered");
        private IDispatcherService? _dispatcher;

        private List<VoiceQoSTimeSeriesPoint>? _cachedDataPoints;

        [ObservableProperty] private ObservableCollection<ISeries> _timelineSeries = [];
        [ObservableProperty] private Axis[] _xAxes = [];
        [ObservableProperty] private Axis[] _yAxes = [];

        // Series visibility toggles
        [ObservableProperty] private bool _showQoSPackets = true;
        [ObservableProperty] private bool _showLatencyAll = true;
        [ObservableProperty] private bool _showLatencyMin = true;
        [ObservableProperty] private bool _showLatencyAvg = true;
        [ObservableProperty] private bool _showLatencyMax = true;
        [ObservableProperty] private bool _showLatencyP5 = true;
        [ObservableProperty] private bool _showLatencyP95 = true;
        [ObservableProperty] private bool _showJitterAll = true;
        [ObservableProperty] private bool _showJitterMin = true;
        [ObservableProperty] private bool _showJitterAvg = true;
        [ObservableProperty] private bool _showJitterMax = true;
        [ObservableProperty] private bool _showJitterP5 = true;
        [ObservableProperty] private bool _showJitterP95 = true;

        // Chart statistics
        [ObservableProperty] private int _totalDataPoints;
        [ObservableProperty] private int _visibleSeriesCount;
        [ObservableProperty] private string _timeRange = "";

        // Percentile statistics for display below chart
        [ObservableProperty] private double _latencyP5;
        [ObservableProperty] private double _latencyP95;
        [ObservableProperty] private double _jitterP5;
        [ObservableProperty] private double _jitterP95;

        public VoiceQoSChartsViewModel()
        {
            InitializeAxes();
        }

        partial void OnShowLatencyAllChanged(bool value)
        {
            ShowLatencyMin = value;
            ShowLatencyP5 = value;
            ShowLatencyAvg = value;
            ShowLatencyP95 = value;
            ShowLatencyMax = value;
        }

        partial void OnShowJitterAllChanged(bool value)
        {
            ShowJitterMin = value;
            ShowJitterP5 = value;
            ShowJitterAvg = value;
            ShowJitterP95 = value;
            ShowJitterMax = value;
        }

        private void InitializeAxes()
        {
            XAxes = new[]
            {
                new Axis
                {
                    Labeler = value =>
                    {
                        var ticks = (long)value;
                        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                            return "Invalid";
                        return new DateTime(ticks).ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
                    },
                    LabelsRotation = 45,
                    TextSize = 10,
                    SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D", 50),
                    Name = "Time",
                    MinStep = TimeSpan.FromSeconds(1).Ticks
                }
            };

            YAxes = new[]
            {
                new Axis
                {
                    Name = "QoS Packets",
                    Position = LiveChartsCore.Measure.AxisPosition.Start,
                    Labeler = value => $"{value:N0}",
                    TextSize = 10,
                    SeparatorsPaint = ThemeColorHelper.GetSolidColorPaint("BorderSubtle", "#21262D", 50),
                    MinLimit = 0,
                    NamePaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#3FB950"),
                    LabelsPaint = ThemeColorHelper.GetSolidColorPaint("ColorSuccess", "#3FB950")
                },
                new Axis
                {
                    Name = "Latency/Jitter (ms)",
                    Position = LiveChartsCore.Measure.AxisPosition.End,
                    ShowSeparatorLines = false,
                    Labeler = value => $"{value:F1} ms",
                    TextSize = 10,
                    MinLimit = 0,
                    NamePaint = ThemeColorHelper.GetSolidColorPaint("AccentPurple", "#8B5CF6"),
                    LabelsPaint = ThemeColorHelper.GetSolidColorPaint("AccentPurple", "#8B5CF6")
                }
            };
        }

        /// <summary>
        /// Update timeline chart from pre-aggregated time-series data
        /// </summary>
        public void UpdateTimelineChartFromAggregated(VoiceQoSTimeSeriesData timeSeriesData)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.InvokeAsync(() => UpdateTimelineChartFromAggregated(timeSeriesData));
                return;
            }

            var startTime = DateTime.Now;

            if (!timeSeriesData.DataPoints.Any())
            {
                TimelineSeries = new ObservableCollection<ISeries>();
                TotalDataPoints = 0;
                TimeRange = "No data";
                return;
            }

            // Downsample if needed (max 100 points for performance)
            var dataPoints = timeSeriesData.DataPoints;
            TotalDataPoints = dataPoints.Count;

            const int MaxDataPoints = 100;
            if (dataPoints.Count > MaxDataPoints)
            {
                var step = Math.Max(1, (int)Math.Floor(dataPoints.Count / (double)MaxDataPoints));
                dataPoints = dataPoints.Where((x, i) => i % step == 0).Take(MaxDataPoints).ToList();
            }

            _cachedDataPoints = dataPoints;
            CalculatePercentileStatistics(dataPoints);

            // Update time range display
            if (timeSeriesData.StartTime >= DateTime.MinValue.AddDays(1) &&
                timeSeriesData.EndTime <= DateTime.MaxValue.AddDays(-1))
            {
                TimeRange = $"{timeSeriesData.StartTime:HH:mm:ss} - {timeSeriesData.EndTime:HH:mm:ss}";
            }
            else
            {
                TimeRange = "Invalid time range";
            }

            // Build series from data points
            TimelineSeries = BuildAllSeries(dataPoints, fullStyle: true);
            VisibleSeriesCount = TimelineSeries.Count;

            var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
            DebugLogger.Log($"[VoiceQoSCharts] Updated in {elapsed:F0}ms - {TimelineSeries.Count} series, {dataPoints.Count} points");
        }

        // Property change handlers trigger chart refresh
        partial void OnShowQoSPacketsChanged(bool value) => RefreshChart();
        partial void OnShowLatencyMinChanged(bool value) => RefreshChart();
        partial void OnShowLatencyAvgChanged(bool value) => RefreshChart();
        partial void OnShowLatencyMaxChanged(bool value) => RefreshChart();
        partial void OnShowLatencyP5Changed(bool value) => RefreshChart();
        partial void OnShowLatencyP95Changed(bool value) => RefreshChart();
        partial void OnShowJitterMinChanged(bool value) => RefreshChart();
        partial void OnShowJitterAvgChanged(bool value) => RefreshChart();
        partial void OnShowJitterMaxChanged(bool value) => RefreshChart();
        partial void OnShowJitterP5Changed(bool value) => RefreshChart();
        partial void OnShowJitterP95Changed(bool value) => RefreshChart();

        private void RefreshChart()
        {
            if (_cachedDataPoints == null || !_cachedDataPoints.Any())
                return;

            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.InvokeAsync(RefreshChart);
                return;
            }

            TimelineSeries = BuildAllSeries(_cachedDataPoints, fullStyle: false);
            VisibleSeriesCount = TimelineSeries.Count;
        }

        /// <summary>
        /// Build all series from data points based on current visibility settings
        /// </summary>
        private ObservableCollection<ISeries> BuildAllSeries(List<VoiceQoSTimeSeriesPoint> dataPoints, bool fullStyle)
        {
            var series = new ObservableCollection<ISeries>();

            // QoS Packets (Y-axis 0)
            if (ShowQoSPackets)
                AddSeries(series, dataPoints, "QoS Packets", p => p.QoSPacketCount, ThemeColorHelper.GetColorHex("ColorSuccess", "#3FB950"), 0, 4, 2.5f, fullStyle);

            // Latency series (Y-axis 1) - blue spectrum
            if (ShowLatencyMin)
                AddSeries(series, dataPoints, "Latency Min", p => p.LatencyMin, ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF"), 1, 3, 2f, fullStyle);
            if (ShowLatencyAvg)
                AddSeries(series, dataPoints, "Latency Avg", p => p.LatencyAvg, ThemeColorHelper.GetColorHex("AccentIndigo", "#1F6FEB"), 1, 4, 2.5f, fullStyle);
            if (ShowLatencyMax)
                AddSeries(series, dataPoints, "Latency Max", p => p.LatencyMax, ThemeColorHelper.GetColorHex("AccentNavy", "#003366"), 1, 3, 2f, fullStyle);
            if (ShowLatencyP5)
                AddSeries(series, dataPoints, "Latency P5", p => p.LatencyP5, ThemeColorHelper.GetColorHex("AccentCyan", "#87CEEB"), 1, 2, 1.5f, fullStyle);
            if (ShowLatencyP95)
                AddSeries(series, dataPoints, "Latency P95", p => p.LatencyP95, ThemeColorHelper.GetColorHex("AccentSteelBlue", "#4682B4"), 1, 2, 1.5f, fullStyle);

            // Jitter series (Y-axis 1) - warm spectrum
            if (ShowJitterMin)
                AddSeries(series, dataPoints, "Jitter Min", p => p.JitterMin, ThemeColorHelper.GetColorHex("ColorWarning", "#FFD700"), 1, 3, 2f, fullStyle);
            if (ShowJitterAvg)
                AddSeries(series, dataPoints, "Jitter Avg", p => p.JitterAvg, ThemeColorHelper.GetColorHex("ColorOrange", "#FF8C00"), 1, 4, 2.5f, fullStyle);
            if (ShowJitterMax)
                AddSeries(series, dataPoints, "Jitter Max", p => p.JitterMax, ThemeColorHelper.GetColorHex("ColorDanger", "#DC143C"), 1, 3, 2f, fullStyle);
            if (ShowJitterP5)
                AddSeries(series, dataPoints, "Jitter P5", p => p.JitterP5, ThemeColorHelper.GetColorHex("AccentLemon", "#FFFACD"), 1, 2, 1.5f, fullStyle);
            if (ShowJitterP95)
                AddSeries(series, dataPoints, "Jitter P95", p => p.JitterP95, ThemeColorHelper.GetColorHex("AccentTomato", "#FF6347"), 1, 2, 1.5f, fullStyle);

            return series;
        }

        /// <summary>
        /// Add a single series to the collection
        /// </summary>
        private static void AddSeries(
            ObservableCollection<ISeries> series,
            List<VoiceQoSTimeSeriesPoint> dataPoints,
            string name,
            Func<VoiceQoSTimeSeriesPoint, double> valueSelector,
            string color,
            int yAxisIndex,
            float geometrySize,
            float strokeThickness,
            bool fullStyle)
        {
            var filterThreshold = name == "QoS Packets" ? double.MinValue : 0;
            var data = dataPoints
                .Where(p => valueSelector(p) > filterThreshold &&
                           p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                .Select(p => new DateTimePoint(p.Timestamp, valueSelector(p)))
                .ToArray();

            if (!data.Any())
                return;

            var skColor = ThemeColorHelper.ParseSKColor(color);
            var lineSeries = new LineSeries<DateTimePoint>
            {
                Values = data,
                Name = name,
                GeometrySize = geometrySize,
                LineSmoothness = 0,
                Stroke = new SolidColorPaint(skColor) { StrokeThickness = strokeThickness },
                ScalesYAt = yAxisIndex,
                DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
            };

            if (fullStyle)
            {
                lineSeries.GeometryStroke = new SolidColorPaint(skColor) { StrokeThickness = strokeThickness * 0.6f };
                lineSeries.GeometryFill = new SolidColorPaint(skColor);

                // Only QoS Packets gets a fill
                if (name == "QoS Packets")
                    lineSeries.Fill = new SolidColorPaint(skColor.WithAlpha(15));
            }

            series.Add(lineSeries);
        }

        public void ClearChart()
        {
            TimelineSeries = new ObservableCollection<ISeries>();
            _cachedDataPoints = null;
            TotalDataPoints = 0;
            VisibleSeriesCount = 0;
            TimeRange = "";
            LatencyP5 = 0;
            LatencyP95 = 0;
            JitterP5 = 0;
            JitterP95 = 0;
        }

        private void CalculatePercentileStatistics(List<VoiceQoSTimeSeriesPoint> dataPoints)
        {
            if (dataPoints == null || !dataPoints.Any())
            {
                LatencyP5 = LatencyP95 = JitterP5 = JitterP95 = 0;
                return;
            }

            LatencyP5 = dataPoints.Where(p => p.LatencyP5 > 0).Select(p => p.LatencyP5).DefaultIfEmpty(0).Average();
            LatencyP95 = dataPoints.Where(p => p.LatencyP95 > 0).Select(p => p.LatencyP95).DefaultIfEmpty(0).Average();
            JitterP5 = dataPoints.Where(p => p.JitterP5 > 0).Select(p => p.JitterP5).DefaultIfEmpty(0).Average();
            JitterP95 = dataPoints.Where(p => p.JitterP95 > 0).Select(p => p.JitterP95).DefaultIfEmpty(0).Average();
        }
    }
}
