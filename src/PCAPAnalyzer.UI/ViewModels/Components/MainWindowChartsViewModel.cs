using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages chart data and visualization for the main window.
/// Handles protocol distribution, traffic charts, and Packets Over Time chart for Packet Analysis tab.
/// </summary>
public partial class MainWindowChartsViewModel : ObservableObject
{
    public ObservableCollection<ISeries> ProtocolSeries { get; }
    public ObservableCollection<ISeries> TrafficSeries { get; }

    // ==================== PACKETS OVER TIME CHART ====================

    /// <summary>
    /// Series for Packets Over Time chart (filtered packets only)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<ISeries> _packetsOverTimeSeries = new();

    /// <summary>
    /// X-Axis configuration for Packets Over Time chart
    /// </summary>
    [ObservableProperty]
    private Axis[] _packetsOverTimeXAxes = Array.Empty<Axis>();

    /// <summary>
    /// Y-Axis configuration for Packets Over Time chart
    /// </summary>
    [ObservableProperty]
    private Axis[] _packetsOverTimeYAxes = Array.Empty<Axis>();

    /// <summary>
    /// Tooltip text for Packets Over Time chart hover
    /// </summary>
    [ObservableProperty]
    private string _packetsOverTimeTooltip = "";

    /// <summary>
    /// Indicates if packet data is available for the chart
    /// </summary>
    [ObservableProperty]
    private bool _hasPacketData;

    /// <summary>
    /// Total filtered packet count displayed above the chart
    /// </summary>
    [ObservableProperty]
    private int _filteredPacketCount;

    // Zoom properties
    [ObservableProperty]
    private double _packetsTimelineZoomLevel = 100;
    private const double MinZoom = 50;
    private const double MaxZoom = 200;
    private const double ZoomStep = 5;
    private double _originalMinLimit;
    private double _originalMaxLimit;
    private bool _zoomInitialized;

    // Cache for tooltip lookup
    private Dictionary<long, (DateTime Time, int Count)> _timelineDataCache = new();

    public MainWindowChartsViewModel()
    {
        ProtocolSeries = new ObservableCollection<ISeries>();
        TrafficSeries = new ObservableCollection<ISeries>();

        InitializeCharts();
        InitializePacketsOverTimeAxes();
    }

    /// <summary>
    /// Initializes charts with empty data
    /// </summary>
    private void InitializeCharts()
    {
        ProtocolSeries.Clear();
        ProtocolSeries.Add(new PieSeries<double>
        {
            Values = new[] { 1.0 },
            Name = "No Data",
            Fill = new SolidColorPaint(SKColors.Gray)
        });
    }

    /// <summary>
    /// Updates all charts with current statistics
    /// </summary>
    public void UpdateCharts(PacketStatistics stats)
    {
        try
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                try
                {
                    UpdateProtocolChart(stats);
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[MainWindowChartsViewModel] UpdateProtocolChart failed: {ex.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdateCharts failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Updates protocol distribution chart
    /// </summary>
    private void UpdateProtocolChart(PacketStatistics stats)
    {
        try
        {
            ProtocolSeries.Clear();

            if (stats.ProtocolCounts.Any())
            {
                foreach (var kvp in stats.ProtocolCounts.OrderByDescending(x => x.Value).Take(6))
                {
                    ProtocolSeries.Add(new PieSeries<double>
                    {
                        Values = new[] { (double)kvp.Value },
                        Name = kvp.Key.ToString(),
                        Fill = new SolidColorPaint(GetColorForProtocol(kvp.Key))
                    });
                }
            }
            else
            {
                InitializeCharts();
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdateProtocolChart failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets color for protocol
    /// </summary>
    private SKColor GetColorForProtocol(Protocol protocol)
    {
        return protocol switch
        {
            Protocol.TCP => SKColors.Blue,
            Protocol.UDP => SKColors.Green,
            Protocol.HTTP => SKColors.Orange,
            Protocol.HTTPS => SKColors.DarkOrange,
            Protocol.DNS => SKColors.Purple,
            Protocol.ICMP => SKColors.Cyan,
            Protocol.ARP => SKColors.Yellow,
            Protocol.DHCP => SKColors.Magenta,
            _ => SKColors.Gray
        };
    }

    /// <summary>
    /// Resets all charts to initial state
    /// </summary>
    public void ResetCharts()
    {
        InitializeCharts();
        TrafficSeries.Clear();
        PacketsOverTimeSeries.Clear();
        HasPacketData = false;
        FilteredPacketCount = 0;
        _timelineDataCache.Clear();
    }

    // ==================== PACKETS OVER TIME CHART METHODS ====================

    /// <summary>
    /// Initializes the Packets Over Time chart axes
    /// </summary>
    private void InitializePacketsOverTimeAxes()
    {
        PacketsOverTimeXAxes = new[]
        {
            new Axis
            {
                Labeler = value =>
                {
                    try
                    {
                        return new DateTime((long)value).ToString("HH:mm:ss");
                    }
                    catch
                    {
                        return "";
                    }
                },
                LabelsRotation = 45,
                TextSize = 10,
                SeparatorsPaint = new SolidColorPaint(SKColors.LightGray.WithAlpha(50)),
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#8B949E"))
            }
        };

        PacketsOverTimeYAxes = new[]
        {
            new Axis
            {
                Name = "Packets",
                Position = LiveChartsCore.Measure.AxisPosition.Start,
                Labeler = value => value >= 1000 ? $"{value / 1000:F1}K" : $"{value:F0}",
                TextSize = 10,
                SeparatorsPaint = new SolidColorPaint(SKColors.LightGray.WithAlpha(50)),
                MinLimit = 0,
                NamePaint = new SolidColorPaint(SKColor.Parse("#58A6FF")),
                LabelsPaint = new SolidColorPaint(SKColor.Parse("#58A6FF"))
            }
        };
    }

    /// <summary>
    /// Updates the Packets Over Time chart with filtered packets.
    /// Groups packets into time buckets and displays packet count over time.
    /// </summary>
    /// <param name="filteredPackets">The filtered packets from Packet Analysis table</param>
    public void UpdatePacketsOverTimeChart(IReadOnlyList<PacketInfo> filteredPackets)
    {
        try
        {
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.InvokeAsync(() => UpdatePacketsOverTimeChart(filteredPackets));
                return;
            }

            if (filteredPackets == null || filteredPackets.Count == 0)
            {
                PacketsOverTimeSeries.Clear();
                HasPacketData = false;
                FilteredPacketCount = 0;
                _timelineDataCache.Clear();
                return;
            }

            FilteredPacketCount = filteredPackets.Count;
            HasPacketData = true;

            // Group packets by time buckets (auto-adjust bucket size based on time range)
            var orderedPackets = filteredPackets
                .Where(p => p.Timestamp != default && p.Timestamp != DateTime.MinValue)
                .OrderBy(p => p.Timestamp)
                .ToList();

            if (orderedPackets.Count == 0)
            {
                PacketsOverTimeSeries.Clear();
                HasPacketData = false;
                return;
            }

            var minTime = orderedPackets.First().Timestamp;
            var maxTime = orderedPackets.Last().Timestamp;
            var timeRange = maxTime - minTime;

            // Calculate bucket size based on time range
            TimeSpan bucketSize = CalculateBucketSize(timeRange, orderedPackets.Count);

            // Group packets into time buckets
            var buckets = new Dictionary<DateTime, int>();
            foreach (var packet in orderedPackets)
            {
                var bucketTime = RoundToNearestBucket(packet.Timestamp, bucketSize, minTime);
                if (!buckets.TryGetValue(bucketTime, out int count))
                {
                    buckets[bucketTime] = 1;
                }
                else
                {
                    buckets[bucketTime] = count + 1;
                }
            }

            // Build cache for tooltip lookup
            _timelineDataCache.Clear();
            foreach (var kvp in buckets)
            {
                _timelineDataCache[kvp.Key.Ticks] = (kvp.Key, kvp.Value);
            }

            // Create data points for the chart
            var dataPoints = buckets
                .OrderBy(b => b.Key)
                .Select(b => new LiveChartsCore.Defaults.DateTimePoint(b.Key, b.Value))
                .ToArray();

            // Build series
            var newSeries = new ObservableCollection<ISeries>
            {
                new LineSeries<LiveChartsCore.Defaults.DateTimePoint>
                {
                    Values = dataPoints,
                    Name = "Packets",
                    GeometrySize = 4,
                    GeometryStroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 1.5f },
                    GeometryFill = new SolidColorPaint(SKColor.Parse("#58A6FF")),
                    LineSmoothness = 0.65,
                    Stroke = new SolidColorPaint(SKColor.Parse("#58A6FF")) { StrokeThickness = 2.5f },
                    Fill = new SolidColorPaint(SKColor.Parse("#58A6FF").WithAlpha(60)),
                    DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0)
                }
            };

            PacketsOverTimeSeries = newSeries;

            // Set axis limits
            if (dataPoints.Length > 0)
            {
                var xMin = dataPoints.Min(p => p.DateTime.Ticks);
                var xMax = dataPoints.Max(p => p.DateTime.Ticks);
                var yMax = dataPoints.Max(p => p.Value ?? 0);

                // Store original limits for zoom
                _originalMinLimit = xMin;
                _originalMaxLimit = xMax;
                _zoomInitialized = true;

                if (PacketsOverTimeXAxes.Length > 0)
                {
                    PacketsOverTimeXAxes[0].MinLimit = xMin;
                    PacketsOverTimeXAxes[0].MaxLimit = xMax;
                }
                if (PacketsOverTimeYAxes.Length > 0)
                {
                    PacketsOverTimeYAxes[0].MaxLimit = yMax * 1.1; // 10% padding
                }
            }

            DebugLogger.Log($"[MainWindowChartsViewModel] PacketsOverTime chart updated: {filteredPackets.Count:N0} packets, {buckets.Count} time buckets");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdatePacketsOverTimeChart failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Calculates appropriate bucket size based on time range and packet count.
    /// </summary>
    private TimeSpan CalculateBucketSize(TimeSpan timeRange, int packetCount)
    {
        // Target ~50-100 buckets for good visualization
        const int targetBuckets = 75;

        if (timeRange.TotalSeconds < 60)
        {
            // Less than 1 minute: 1 second buckets
            return TimeSpan.FromSeconds(1);
        }
        else if (timeRange.TotalMinutes < 10)
        {
            // Less than 10 minutes: 5 second buckets
            return TimeSpan.FromSeconds(5);
        }
        else if (timeRange.TotalMinutes < 60)
        {
            // Less than 1 hour: 30 second buckets
            return TimeSpan.FromSeconds(30);
        }
        else if (timeRange.TotalHours < 6)
        {
            // Less than 6 hours: 1 minute buckets
            return TimeSpan.FromMinutes(1);
        }
        else if (timeRange.TotalHours < 24)
        {
            // Less than 1 day: 5 minute buckets
            return TimeSpan.FromMinutes(5);
        }
        else
        {
            // More than 1 day: calculate based on target buckets
            var secondsPerBucket = timeRange.TotalSeconds / targetBuckets;
            return TimeSpan.FromSeconds(Math.Max(60, secondsPerBucket));
        }
    }

    /// <summary>
    /// Rounds a timestamp to the nearest bucket boundary.
    /// </summary>
    private DateTime RoundToNearestBucket(DateTime time, TimeSpan bucketSize, DateTime minTime)
    {
        var ticksSinceMin = time.Ticks - minTime.Ticks;
        var bucketTicks = bucketSize.Ticks;
        var bucketIndex = ticksSinceMin / bucketTicks;
        return new DateTime(minTime.Ticks + (bucketIndex * bucketTicks));
    }

    /// <summary>
    /// Gets tooltip data for a given X position (DateTime ticks).
    /// </summary>
    public (DateTime Time, int PacketCount)? GetTooltipDataAtPosition(double xTicks)
    {
        if (_timelineDataCache.Count == 0)
            return null;

        // Find closest bucket
        var targetTicks = (long)xTicks;
        var closest = _timelineDataCache.Keys
            .OrderBy(k => Math.Abs(k - targetTicks))
            .FirstOrDefault();

        if (closest != 0 && _timelineDataCache.TryGetValue(closest, out var data))
        {
            return data;
        }

        return null;
    }

    // ==================== ZOOM COMMANDS ====================

    [RelayCommand]
    private void ZoomInPacketsTimeline()
    {
        if (PacketsTimelineZoomLevel < MaxZoom)
        {
            PacketsTimelineZoomLevel = Math.Min(PacketsTimelineZoomLevel + ZoomStep, MaxZoom);
            ApplyPacketsZoomToChart();
        }
    }

    [RelayCommand]
    private void ZoomOutPacketsTimeline()
    {
        if (PacketsTimelineZoomLevel > MinZoom)
        {
            PacketsTimelineZoomLevel = Math.Max(PacketsTimelineZoomLevel - ZoomStep, MinZoom);
            ApplyPacketsZoomToChart();
        }
    }

    [RelayCommand]
    private void ResetPacketsTimelineZoom()
    {
        PacketsTimelineZoomLevel = 100;
        ApplyPacketsZoomToChart();
    }

    private void ApplyPacketsZoomToChart()
    {
        if (PacketsOverTimeXAxes == null || PacketsOverTimeXAxes.Length == 0 ||
            PacketsOverTimeSeries == null || PacketsOverTimeSeries.Count == 0 ||
            !_zoomInitialized)
            return;

        var axis = PacketsOverTimeXAxes[0];
        if (axis == null) return;

        // Calculate zoom
        var zoomFactor = 100.0 / PacketsTimelineZoomLevel;
        var originalRange = _originalMaxLimit - _originalMinLimit;
        var newRange = originalRange * zoomFactor;

        // Get current center or use original center
        var currentCenter = axis.MinLimit.HasValue && axis.MaxLimit.HasValue
            ? (axis.MinLimit.Value + axis.MaxLimit.Value) / 2
            : (_originalMinLimit + _originalMaxLimit) / 2;

        // Apply new limits
        var newMin = currentCenter - newRange / 2;
        var newMax = currentCenter + newRange / 2;

        // Constrain to original bounds
        if (newMin < _originalMinLimit)
        {
            newMin = _originalMinLimit;
            newMax = newMin + newRange;
        }
        if (newMax > _originalMaxLimit)
        {
            newMax = _originalMaxLimit;
            newMin = newMax - newRange;
        }

        axis.MinLimit = newMin;
        axis.MaxLimit = newMax;
    }
}
