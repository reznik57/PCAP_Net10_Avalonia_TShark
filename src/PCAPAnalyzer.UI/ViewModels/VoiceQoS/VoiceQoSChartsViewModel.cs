using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.VoiceQoS;
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
    /// Manages 7-series timeline chart with series visibility toggles.
    /// </summary>
    public partial class VoiceQoSChartsViewModel : ObservableObject
    {
        private readonly VoiceQoSTimeSeriesGenerator _timeSeriesGenerator;
        private List<PacketInfo>? _cachedQoSPackets;
        private List<PacketInfo>? _cachedLatencyPackets;
        private List<PacketInfo>? _cachedJitterPackets;
        private List<VoiceQoSTimeSeriesPoint>? _cachedDataPoints; // Cache processed data points

        [ObservableProperty] private ObservableCollection<ISeries> _timelineSeries = new();
        [ObservableProperty] private Axis[] _xAxes = Array.Empty<Axis>();
        [ObservableProperty] private Axis[] _yAxes = Array.Empty<Axis>();

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
            _timeSeriesGenerator = new VoiceQoSTimeSeriesGenerator();
            InitializeAxes();
        }

        /// <summary>
        /// Toggle all latency series visibility
        /// </summary>
        partial void OnShowLatencyAllChanged(bool value)
        {
            ShowLatencyMin = value;
            ShowLatencyP5 = value;
            ShowLatencyAvg = value;
            ShowLatencyP95 = value;
            ShowLatencyMax = value;
        }

        /// <summary>
        /// Toggle all jitter series visibility
        /// </summary>
        partial void OnShowJitterAllChanged(bool value)
        {
            ShowJitterMin = value;
            ShowJitterP5 = value;
            ShowJitterAvg = value;
            ShowJitterP95 = value;
            ShowJitterMax = value;
        }

        /// <summary>
        /// Initialize chart axes with DateTime X-axis and dual Y-axes
        /// </summary>
        private void InitializeAxes()
        {
            XAxes = new[]
            {
                new Axis
                {
                    Labeler = value =>
                    {
                        try
                        {
                            // Validate ticks are within valid DateTime range
                            var ticks = (long)value;
                            if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
                            {
                                return "Invalid";
                            }
                            return new DateTime(ticks).ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
                        }
                        catch
                        {
                            return "Invalid";
                        }
                    },
                    LabelsRotation = 45,
                    TextSize = 10,
                    SeparatorsPaint = new SolidColorPaint(SKColors.LightGray.WithAlpha(50)),
                    Name = "Time",
                    MinStep = TimeSpan.FromSeconds(1).Ticks
                }
            };

            YAxes = new[]
            {
                // Left Y-axis: Packet count (Green)
                new Axis
                {
                    Name = "QoS Packets",
                    Position = LiveChartsCore.Measure.AxisPosition.Start,
                    Labeler = value => $"{value:N0}",
                    TextSize = 10,
                    SeparatorsPaint = new SolidColorPaint(SKColors.LightGray.WithAlpha(50)),
                    MinLimit = 0,  // Start at 0 baseline
                    NamePaint = new SolidColorPaint(SKColor.Parse("#3FB950")),  // Green to match QoS Packets series
                    LabelsPaint = new SolidColorPaint(SKColor.Parse("#3FB950"))
                },
                // Right Y-axis: Latency/Jitter (ms) - Multi-colored (Blue for Latency, Orange/Yellow for Jitter)
                new Axis
                {
                    Name = "Latency/Jitter (ms)",
                    Position = LiveChartsCore.Measure.AxisPosition.End,
                    ShowSeparatorLines = false,
                    Labeler = value => $"{value:F1} ms",
                    TextSize = 10,
                    MinLimit = 0,  // Start at 0 baseline
                    NamePaint = new SolidColorPaint(SKColor.Parse("#8B5CF6")),  // Purple (neutral color for mixed metric)
                    LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B5CF6"))
                }
            };
        }

        /// <summary>
        /// Update timeline chart from PRE-AGGREGATED time-series data (FAST - 1000x faster than packet processing)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "7 series creation requires branching; cohesive, well-documented, defensive code")]
        public void UpdateTimelineChartFromAggregated(PCAPAnalyzer.Core.Models.VoiceQoSTimeSeriesData timeSeriesData)
        {
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.InvokeAsync(() => UpdateTimelineChartFromAggregated(timeSeriesData));
                return;
            }

            var startTime = DateTime.Now;
            var timestamp = startTime.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{timestamp}] [VoiceQoSCharts] UpdateTimelineChartFromAggregated - BEGIN");

            try
            {
                var newSeries = new ObservableCollection<ISeries>();
                const int MaxDataPoints = 100;

                if (!timeSeriesData.DataPoints.Any())
                {
                    TimelineSeries = newSeries;
                    TotalDataPoints = 0;
                    TimeRange = "No data";
                    DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [VoiceQoSCharts] No data points");
                    return;
                }

                // Data is ALREADY aggregated by time-series generator
                var dataPoints = timeSeriesData.DataPoints;
                TotalDataPoints = dataPoints.Count;

                // Downsample if needed (data already aggregated, this is just final reduction)
                if (dataPoints.Count > MaxDataPoints)
                {
                    var step = Math.Max(1, (int)Math.Floor(dataPoints.Count / (double)MaxDataPoints));
                    dataPoints = dataPoints.Where((x, i) => i % step == 0).Take(MaxDataPoints).ToList();
                }

                // Cache the processed data points for fast toggle refresh
                _cachedDataPoints = dataPoints;

                // Calculate percentile statistics for display
                CalculatePercentileStatistics(dataPoints);

                // Update time range display (validate timestamps first)
                if (timeSeriesData.StartTime >= DateTime.MinValue.AddDays(1) &&
                    timeSeriesData.EndTime <= DateTime.MaxValue.AddDays(-1))
                {
                    TimeRange = $"{timeSeriesData.StartTime:HH:mm:ss} - {timeSeriesData.EndTime:HH:mm:ss}";
                }
                else
                {
                    TimeRange = "Invalid time range";
                }

                // Series 1: QoS Packet Count
                if (ShowQoSPackets)
                {
                    var qosData = dataPoints
                        .Where(p => p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.QoSPacketCount))
                        .ToArray();

                    newSeries.Add(new LineSeries<DateTimePoint>
                    {
                        Values = qosData,
                        Name = "QoS Packets",
                        GeometrySize = 4,
                        GeometryStroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 1.5f },
                        GeometryFill = new SolidColorPaint(SKColor.Parse("#3FB950")),
                        LineSmoothness = 0, // Performance: disabled Bezier curves
                        Stroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 2.5f },
                        Fill = new SolidColorPaint(SKColor.Parse("#3FB950").WithAlpha(15)),
                        ScalesYAt = 0, // Left Y-axis
                        DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                    });
                }

                // Series 2: Latency Min
                if (ShowLatencyMin)
                {
                    var latencyMinData = dataPoints
                        .Where(p => p.LatencyMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMin))
                        .ToArray();

                    if (latencyMinData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyMinData,
                            Name = "Latency Min",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#58A6FF")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 3: Latency Avg
                if (ShowLatencyAvg)
                {
                    var latencyAvgData = dataPoints
                        .Where(p => p.LatencyAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyAvg))
                        .ToArray();

                    if (latencyAvgData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyAvgData,
                            Name = "Latency Avg",
                            GeometrySize = 5,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#1F6FEB")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#1F6FEB")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#1F6FEB")) { StrokeThickness = 3.5f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 4: Latency Max
                if (ShowLatencyMax)
                {
                    var latencyMaxData = dataPoints
                        .Where(p => p.LatencyMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMax))
                        .ToArray();

                    if (latencyMaxData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyMaxData,
                            Name = "Latency Max",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#003366")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#003366")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#003366")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 5: Jitter Min
                if (ShowJitterMin)
                {
                    var jitterMinData = dataPoints
                        .Where(p => p.JitterMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMin))
                        .ToArray();

                    if (jitterMinData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterMinData,
                            Name = "Jitter Min",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FFD700")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 6: Jitter Avg
                if (ShowJitterAvg)
                {
                    var jitterAvgData = dataPoints
                        .Where(p => p.JitterAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterAvg))
                        .ToArray();

                    if (jitterAvgData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterAvgData,
                            Name = "Jitter Avg",
                            GeometrySize = 5,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FF8C00")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FF8C00")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FF8C00")) { StrokeThickness = 3.5f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 7: Jitter Max
                if (ShowJitterMax)
                {
                    var jitterMaxData = dataPoints
                        .Where(p => p.JitterMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMax))
                        .ToArray();

                    if (jitterMaxData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterMaxData,
                            Name = "Jitter Max",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#DC143C")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#DC143C")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#DC143C")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 8: Latency P5
                if (ShowLatencyP5)
                {
                    var latencyP5Data = dataPoints
                        .Where(p => p.LatencyP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP5))
                        .ToArray();

                    if (latencyP5Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyP5Data,
                            Name = "Latency P5",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#87CEEB")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#87CEEB")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#87CEEB")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 9: Latency P95
                if (ShowLatencyP95)
                {
                    var latencyP95Data = dataPoints
                        .Where(p => p.LatencyP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP95))
                        .ToArray();

                    if (latencyP95Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyP95Data,
                            Name = "Latency P95",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#4682B4")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#4682B4")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#4682B4")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 10: Jitter P5
                if (ShowJitterP5)
                {
                    var jitterP5Data = dataPoints
                        .Where(p => p.JitterP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP5))
                        .ToArray();

                    if (jitterP5Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterP5Data,
                            Name = "Jitter P5",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FFFACD")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FFFACD")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFFACD")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 11: Jitter P95
                if (ShowJitterP95)
                {
                    var jitterP95Data = dataPoints
                        .Where(p => p.JitterP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP95))
                        .ToArray();

                    if (jitterP95Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterP95Data,
                            Name = "Jitter P95",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FF6347")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FF6347")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FF6347")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                TimelineSeries = newSeries;
                VisibleSeriesCount = newSeries.Count;

                var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [VoiceQoSCharts] Updated from aggregated data in {elapsed:F0}ms - {newSeries.Count} visible series, {dataPoints.Count} data points");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[VoiceQoSCharts] Error updating from aggregated data: {ex.Message}");
                TimelineSeries = new ObservableCollection<ISeries>();
            }
        }

        /// <summary>
        /// Update timeline chart with new packet data (LEGACY - will be removed, use UpdateTimelineChartFromAggregated)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "7 series creation requires branching; cohesive, well-documented, defensive code")]
        public void UpdateTimelineChart(
            List<PacketInfo> qosPackets,
            List<PacketInfo> latencyPackets,
            List<PacketInfo> jitterPackets)
        {
            // Cache packets for visibility toggle refresh
            _cachedQoSPackets = qosPackets;
            _cachedLatencyPackets = latencyPackets;
            _cachedJitterPackets = jitterPackets;

            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.InvokeAsync(() => UpdateTimelineChart(qosPackets, latencyPackets, jitterPackets));
                return;
            }

            try
            {
                var newSeries = new ObservableCollection<ISeries>();
                const int MaxDataPoints = 100;

                // Generate time-series data
                var timeSeriesData = _timeSeriesGenerator.GenerateTimeSeries(
                    qosPackets,
                    latencyPackets,
                    jitterPackets,
                    TimeSpan.FromSeconds(1));

                if (!timeSeriesData.DataPoints.Any())
                {
                    TimelineSeries = newSeries;
                    TotalDataPoints = 0;
                    TimeRange = "No data";
                    DebugLogger.Log("[VoiceQoSCharts] No data points generated");
                    return;
                }

                // Downsample if needed
                var dataPoints = timeSeriesData.DataPoints;
                TotalDataPoints = dataPoints.Count;

                if (dataPoints.Count > MaxDataPoints)
                {
                    var step = Math.Max(1, (int)Math.Floor(dataPoints.Count / (double)MaxDataPoints));
                    dataPoints = dataPoints.Where((x, i) => i % step == 0).Take(MaxDataPoints).ToList();
                }

                // Cache the processed data points for fast toggle refresh
                _cachedDataPoints = dataPoints;

                // Calculate percentile statistics for display
                CalculatePercentileStatistics(dataPoints);

                // Update time range display (validate timestamps first)
                if (timeSeriesData.StartTime >= DateTime.MinValue.AddDays(1) &&
                    timeSeriesData.EndTime <= DateTime.MaxValue.AddDays(-1))
                {
                    TimeRange = $"{timeSeriesData.StartTime:HH:mm:ss} - {timeSeriesData.EndTime:HH:mm:ss}";
                }
                else
                {
                    TimeRange = "Invalid time range";
                }

                // Series 1: QoS Packet Count
                if (ShowQoSPackets)
                {
                    var qosData = dataPoints
                        .Where(p => p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.QoSPacketCount))
                        .ToArray();

                    newSeries.Add(new LineSeries<DateTimePoint>
                    {
                        Values = qosData,
                        Name = "QoS Packets",
                        GeometrySize = 4,
                        GeometryStroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 1.5f },
                        GeometryFill = new SolidColorPaint(SKColor.Parse("#3FB950")),
                        LineSmoothness = 0, // Performance: disabled Bezier curves
                        Stroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 2.5f },
                        Fill = new SolidColorPaint(SKColor.Parse("#3FB950").WithAlpha(15)),
                        ScalesYAt = 0, // Left Y-axis
                        DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                    });
                }

                // Series 2: Latency Min
                if (ShowLatencyMin)
                {
                    var latencyMinData = dataPoints
                        .Where(p => p.LatencyMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMin))
                        .ToArray();

                    if (latencyMinData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyMinData,
                            Name = "Latency Min",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#58A6FF")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 3: Latency Avg
                if (ShowLatencyAvg)
                {
                    var latencyAvgData = dataPoints
                        .Where(p => p.LatencyAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyAvg))
                        .ToArray();

                    if (latencyAvgData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyAvgData,
                            Name = "Latency Avg",
                            GeometrySize = 5,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#1F6FEB")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#1F6FEB")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#1F6FEB")) { StrokeThickness = 3.5f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 4: Latency Max
                if (ShowLatencyMax)
                {
                    var latencyMaxData = dataPoints
                        .Where(p => p.LatencyMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMax))
                        .ToArray();

                    if (latencyMaxData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyMaxData,
                            Name = "Latency Max",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#003366")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#003366")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#003366")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 5: Jitter Min
                if (ShowJitterMin)
                {
                    var jitterMinData = dataPoints
                        .Where(p => p.JitterMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMin))
                        .ToArray();

                    if (jitterMinData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterMinData,
                            Name = "Jitter Min",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FFD700")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 6: Jitter Avg
                if (ShowJitterAvg)
                {
                    var jitterAvgData = dataPoints
                        .Where(p => p.JitterAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterAvg))
                        .ToArray();

                    if (jitterAvgData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterAvgData,
                            Name = "Jitter Avg",
                            GeometrySize = 5,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FF8C00")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FF8C00")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FF8C00")) { StrokeThickness = 3.5f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 7: Jitter Max
                if (ShowJitterMax)
                {
                    var jitterMaxData = dataPoints
                        .Where(p => p.JitterMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMax))
                        .ToArray();

                    if (jitterMaxData.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterMaxData,
                            Name = "Jitter Max",
                            GeometrySize = 4,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#DC143C")) { StrokeThickness = 2f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#DC143C")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#DC143C")) { StrokeThickness = 3f },
                            Fill = null,
                            ScalesYAt = 1, // Right Y-axis
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 8: Latency P5
                if (ShowLatencyP5)
                {
                    var latencyP5Data = dataPoints
                        .Where(p => p.LatencyP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP5))
                        .ToArray();

                    if (latencyP5Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyP5Data,
                            Name = "Latency P5",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#87CEEB")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#87CEEB")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#87CEEB")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 9: Latency P95
                if (ShowLatencyP95)
                {
                    var latencyP95Data = dataPoints
                        .Where(p => p.LatencyP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP95))
                        .ToArray();

                    if (latencyP95Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = latencyP95Data,
                            Name = "Latency P95",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#4682B4")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#4682B4")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#4682B4")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 10: Jitter P5
                if (ShowJitterP5)
                {
                    var jitterP5Data = dataPoints
                        .Where(p => p.JitterP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP5))
                        .ToArray();

                    if (jitterP5Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterP5Data,
                            Name = "Jitter P5",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FFFACD")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FFFACD")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FFFACD")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                // Series 11: Jitter P95
                if (ShowJitterP95)
                {
                    var jitterP95Data = dataPoints
                        .Where(p => p.JitterP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP95))
                        .ToArray();

                    if (jitterP95Data.Any())
                    {
                        newSeries.Add(new LineSeries<DateTimePoint>
                        {
                            Values = jitterP95Data,
                            Name = "Jitter P95",
                            GeometrySize = 3,
                            GeometryStroke = new SolidColorPaint(SKColor.Parse("#FF6347")) { StrokeThickness = 1.5f },
                            GeometryFill = new SolidColorPaint(SKColor.Parse("#FF6347")),
                            LineSmoothness = 0, // Performance: disabled Bezier curves
                            Stroke = new SolidColorPaint(SKColor.Parse("#FF6347")) { StrokeThickness = 2f },
                            Fill = null,
                            ScalesYAt = 1,
                            DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                        });
                    }
                }

                TimelineSeries = newSeries;
                VisibleSeriesCount = newSeries.Count;

                DebugLogger.Log($"[VoiceQoSCharts] Timeline updated: {newSeries.Count} visible series, {dataPoints.Count} data points, Time: {TimeRange}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[VoiceQoSCharts] Error updating timeline: {ex.Message}");
                TimelineSeries = new ObservableCollection<ISeries>();
            }
        }

        // Property change handlers to update chart when toggles change
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

        /// <summary>
        /// Refresh chart with cached data points when visibility toggles change (FAST - no regeneration)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "7 series creation with defensive validation; performance-critical code")]
        private void RefreshChart()
        {
            if (_cachedDataPoints == null || !_cachedDataPoints.Any())
                return;

            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.InvokeAsync(RefreshChart);
                return;
            }

            try
            {
                var newSeries = new ObservableCollection<ISeries>();
                var dataPoints = _cachedDataPoints; // Use cached processed data

                // Series 1: QoS Packet Count
                if (ShowQoSPackets)
                {
                    var qosData = dataPoints
                        .Where(p => p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.QoSPacketCount))
                        .ToArray();

                    newSeries.Add(new LineSeries<DateTimePoint>
                    {
                        Values = qosData,
                        Name = "QoS Packets",
                        GeometrySize = 4,
                        GeometryStroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 1.5f },
                        GeometryFill = new SolidColorPaint(SKColor.Parse("#3FB950")),
                        LineSmoothness = 0, // Performance: disabled Bezier curves
                        Stroke = new SolidColorPaint(SKColor.Parse("#3FB950")) { StrokeThickness = 2.5f },
                        ScalesYAt = 0,
                        DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                    });
                }

                // Series 2-7: Same pattern for latency/jitter (copy from UpdateTimelineChart)
                if (ShowLatencyMin)
                {
                    var data = dataPoints.Where(p => p.LatencyMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMin)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Latency Min", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 2f }, ScalesYAt = 1 });
                }

                if (ShowLatencyAvg)
                {
                    var data = dataPoints.Where(p => p.LatencyAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyAvg)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Latency Avg", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#1F6FEB")) { StrokeThickness = 2.5f }, ScalesYAt = 1 });
                }

                if (ShowLatencyMax)
                {
                    var data = dataPoints.Where(p => p.LatencyMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyMax)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Latency Max", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#003366")) { StrokeThickness = 2f }, ScalesYAt = 1 });
                }

                if (ShowLatencyP5)
                {
                    var data = dataPoints.Where(p => p.LatencyP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP5)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Latency P5", GeometrySize = 2, Stroke = new SolidColorPaint(SKColor.Parse("#87CEEB")) { StrokeThickness = 1.5f }, ScalesYAt = 1 });
                }

                if (ShowLatencyP95)
                {
                    var data = dataPoints.Where(p => p.LatencyP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.LatencyP95)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Latency P95", GeometrySize = 2, Stroke = new SolidColorPaint(SKColor.Parse("#4682B4")) { StrokeThickness = 1.5f }, ScalesYAt = 1 });
                }

                if (ShowJitterMin)
                {
                    var data = dataPoints.Where(p => p.JitterMin > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMin)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Jitter Min", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#FFD700")) { StrokeThickness = 2f }, ScalesYAt = 1 });
                }

                if (ShowJitterAvg)
                {
                    var data = dataPoints.Where(p => p.JitterAvg > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterAvg)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Jitter Avg", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#FF8C00")) { StrokeThickness = 2.5f }, ScalesYAt = 1 });
                }

                if (ShowJitterMax)
                {
                    var data = dataPoints.Where(p => p.JitterMax > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterMax)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Jitter Max", GeometrySize = 3, Stroke = new SolidColorPaint(SKColor.Parse("#DC143C")) { StrokeThickness = 2f }, ScalesYAt = 1 });
                }

                if (ShowJitterP5)
                {
                    var data = dataPoints.Where(p => p.JitterP5 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP5)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Jitter P5", GeometrySize = 2, Stroke = new SolidColorPaint(SKColor.Parse("#FFFACD")) { StrokeThickness = 1.5f }, ScalesYAt = 1 });
                }

                if (ShowJitterP95)
                {
                    var data = dataPoints.Where(p => p.JitterP95 > 0 && p.Timestamp >= DateTime.MinValue && p.Timestamp <= DateTime.MaxValue)
                        .Select(p => new DateTimePoint(p.Timestamp, p.JitterP95)).ToArray();
                    if (data.Any())
                        newSeries.Add(new LineSeries<DateTimePoint> { Values = data, Name = "Jitter P95", GeometrySize = 2, Stroke = new SolidColorPaint(SKColor.Parse("#FF6347")) { StrokeThickness = 1.5f }, ScalesYAt = 1 });
                }

                TimelineSeries = newSeries;
                VisibleSeriesCount = newSeries.Count;
                DebugLogger.Log($"[VoiceQoSCharts] Fast refresh: {newSeries.Count} visible series");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[VoiceQoSCharts] Error in fast refresh: {ex.Message}");
            }
        }

        /// <summary>
        /// Clear chart data and reset state
        /// </summary>
        public void ClearChart()
        {
            TimelineSeries = new ObservableCollection<ISeries>();
            _cachedQoSPackets = null;
            _cachedLatencyPackets = null;
            _cachedJitterPackets = null;
            _cachedDataPoints = null; // Clear cached data points
            TotalDataPoints = 0;
            VisibleSeriesCount = 0;
            TimeRange = "";
            LatencyP5 = 0;
            LatencyP95 = 0;
            JitterP5 = 0;
            JitterP95 = 0;
        }

        /// <summary>
        /// Calculate P5/P95 percentile statistics from cached data points for display below chart
        /// </summary>
        private void CalculatePercentileStatistics(List<VoiceQoSTimeSeriesPoint> dataPoints)
        {
            if (dataPoints == null || !dataPoints.Any())
            {
                LatencyP5 = 0;
                LatencyP95 = 0;
                JitterP5 = 0;
                JitterP95 = 0;
                return;
            }

            // Extract all P5/P95 values from the time series data points
            var latencyP5Values = dataPoints.Where(p => p.LatencyP5 > 0).Select(p => p.LatencyP5).ToList();
            var latencyP95Values = dataPoints.Where(p => p.LatencyP95 > 0).Select(p => p.LatencyP95).ToList();
            var jitterP5Values = dataPoints.Where(p => p.JitterP5 > 0).Select(p => p.JitterP5).ToList();
            var jitterP95Values = dataPoints.Where(p => p.JitterP95 > 0).Select(p => p.JitterP95).ToList();

            // Calculate average of percentiles across all time windows (represents overall percentile)
            LatencyP5 = latencyP5Values.Any() ? latencyP5Values.Average() : 0;
            LatencyP95 = latencyP95Values.Any() ? latencyP95Values.Average() : 0;
            JitterP5 = jitterP5Values.Any() ? jitterP5Values.Average() : 0;
            JitterP95 = jitterP95Values.Any() ? jitterP95Values.Average() : 0;
        }
    }
}
