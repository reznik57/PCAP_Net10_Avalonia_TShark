using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Defaults;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages chart data and visualization for the main window.
/// Handles protocol distribution, traffic charts, and Packets Over Time chart for Packet Analysis tab.
/// </summary>
public partial class MainWindowChartsViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    public ObservableCollection<ISeries> ProtocolSeries { get; }
    public ObservableCollection<ISeries> TrafficSeries { get; }

    // ==================== PACKETS OVER TIME CHART ====================

    /// <summary>
    /// Series for Packets Over Time chart (filtered packets only)
    /// Now supports Total line + Top 5 streams
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<ISeries> _packetsOverTimeSeries = [];

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

    // ==================== STREAM POPUP ====================

    /// <summary>
    /// View model for the stream chart popup
    /// </summary>
    [ObservableProperty]
    private StreamChartPopupViewModel? _streamPopupViewModel;

    /// <summary>
    /// Controls visibility of the stream popup
    /// </summary>
    [ObservableProperty]
    private bool _isStreamPopupOpen;

    /// <summary>
    /// DrillDown popup ViewModel for detailed time slice analysis (matches Dashboard style)
    /// </summary>
    [ObservableProperty]
    private DrillDownPopupViewModel? _drillDown;

    // ==================== INTERACTIVE LEGEND ====================

    /// <summary>
    /// Legend items for interactive series toggling
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<SeriesLegendItem> _legendItems = [];

    // ==================== TOP STREAMS TABLES ====================

    /// <summary>
    /// Top streams sorted by packet count (for table display)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<TopStreamTableItem> _topStreamsByPackets = [];

    /// <summary>
    /// Top streams sorted by byte count (for table display)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<TopStreamTableItem> _topStreamsByBytes = [];

    // ==================== CHART TOGGLE OPTIONS ====================

    /// <summary>
    /// When true, shows throughput (bytes/s) instead of packets/s
    /// </summary>
    [ObservableProperty]
    private bool _showStreamActivityAsThroughput;

    /// <summary>
    /// When true, shows top 10 streams instead of top 5
    /// </summary>
    [ObservableProperty]
    private bool _showTop10Streams;

    /// <summary>
    /// Number of streams to display in chart (5 or 10)
    /// </summary>
    [ObservableProperty]
    private int _streamTimelineDisplayCount = 5;

    partial void OnShowStreamActivityAsThroughputChanged(bool value)
    {
        // Rebuild chart with throughput or packet data (force update - display mode changed)
        if (_lastFilteredPackets != null)
        {
            UpdatePacketsOverTimeChart(_lastFilteredPackets, forceUpdate: true);
        }
    }

    partial void OnShowTop10StreamsChanged(bool value)
    {
        StreamTimelineDisplayCount = value ? 10 : 5;
        // Rebuild chart with new stream count (force update - display mode changed)
        if (_lastFilteredPackets != null)
        {
            UpdatePacketsOverTimeChart(_lastFilteredPackets, forceUpdate: true);
        }
    }

    // Cache last filtered packets for toggle rebuilds
    private IReadOnlyList<PacketInfo>? _lastFilteredPackets;

    // Dedupe guard: skip redundant chart updates with same data
    private int _lastChartPacketCount;
    private long _lastChartDataHash;

    // Cache for tooltip lookup - now includes stream data
    private Dictionary<long, PacketsTimelineDataPoint> _timelineDataCache = [];

    // Cache for Y-axis range (for highlight vertical line)
    private double _cachedMinY;
    private double _cachedMaxY;

    // Top 5 streams for the current filter
    private List<StreamInfo> _topStreams = [];

    // Stream colors - delegate to centralized ThemeColorHelper
    private static string[] StreamColors => ThemeColorHelper.StreamColors;

    /// <summary>
    /// Gets the top streams for external access (used by click handler)
    /// </summary>
    public IReadOnlyList<StreamInfo> TopStreams => _topStreams;

    /// <summary>
    /// Gets cached Y-axis range for highlight line
    /// </summary>
    public (double Min, double Max) CachedYRange => (_cachedMinY, _cachedMaxY);

    /// <summary>
    /// Gets the timeline data cache for tooltip/click handling
    /// </summary>
    public IReadOnlyDictionary<long, PacketsTimelineDataPoint> TimelineDataCache => _timelineDataCache;

    public MainWindowChartsViewModel()
    {
        ProtocolSeries = new ObservableCollection<ISeries>();
        TrafficSeries = new ObservableCollection<ISeries>();

        InitializeCharts();
        InitializePacketsOverTimeAxes();
        InitializeDrillDown();
    }

    /// <summary>
    /// Initializes the DrillDown popup ViewModel
    /// </summary>
    private void InitializeDrillDown()
    {
        DrillDown = new DrillDownPopupViewModel();
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
            Fill = ThemeColorHelper.GrayPaint
        });
    }

    /// <summary>
    /// Updates all charts with current statistics
    /// </summary>
    public void UpdateCharts(PacketStatistics stats)
    {
        try
        {
            Dispatcher.InvokeAsync(() =>
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
        _topStreams.Clear();
        _cachedMinY = 0;
        _cachedMaxY = 0;
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
                        var ticks = (long)value;
                        // Validate ticks are in valid DateTime range
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
                TextSize = 10,
                SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("TextMuted", "#8B949E")
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
                SeparatorsPaint = ThemeColorHelper.LightGrayAlpha50Paint,
                MinLimit = 0,
                NamePaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF"),
                LabelsPaint = ThemeColorHelper.GetSolidColorPaint("AccentBlue", "#58A6FF")
            }
        };
    }

    /// <summary>
    /// Updates the Packets Over Time chart with filtered packets.
    /// Groups packets into time buckets and displays:
    /// - Total packets line (primary, with fill)
    /// - Top 5 streams by packet count (secondary lines)
    /// </summary>
    /// <param name="filteredPackets">The filtered packets from Packet Analysis table</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Chart update method performs cohesive stream analysis and series building operations")]
    public void UpdatePacketsOverTimeChart(IReadOnlyList<PacketInfo> filteredPackets, bool forceUpdate = false)
    {
        try
        {
            // Cache for toggle rebuilds
            _lastFilteredPackets = filteredPackets;

            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.InvokeAsync(() => UpdatePacketsOverTimeChart(filteredPackets, forceUpdate));
                return;
            }

            if (filteredPackets == null || filteredPackets.Count == 0)
            {
                PacketsOverTimeSeries.Clear();
                HasPacketData = false;
                FilteredPacketCount = 0;
                _timelineDataCache.Clear();
                _topStreams.Clear();
                _lastChartPacketCount = 0;
                _lastChartDataHash = 0;
                return;
            }

            // Dedupe guard: skip redundant updates with same data (unless toggling display options)
            var dataHash = ComputePacketDataHash(filteredPackets);
            if (!forceUpdate && filteredPackets.Count == _lastChartPacketCount && dataHash == _lastChartDataHash)
            {
                DebugLogger.Log($"[MainWindowChartsViewModel] ⏭️ Skipping redundant chart update ({filteredPackets.Count:N0} packets, same data)");
                return;
            }
            _lastChartPacketCount = filteredPackets.Count;
            _lastChartDataHash = dataHash;

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

            // Step 1: Build IP:Port stream stats (full granularity for Packet Analysis)
            var streamStats = new Dictionary<string, (int Count, long Bytes, string SourceIP, int SourcePort, string DestIP, int DestPort)>();
            foreach (var packet in orderedPackets)
            {
                // Create sorted stream key with ports for consistent identification
                var srcEndpoint = $"{packet.SourceIP ?? ""}:{packet.SourcePort}";
                var dstEndpoint = $"{packet.DestinationIP ?? ""}:{packet.DestinationPort}";
                var endpoints = new[] { srcEndpoint, dstEndpoint }.OrderBy(x => x).ToArray();
                var streamKey = $"{endpoints[0]}↔{endpoints[1]}";

                // Determine canonical source/dest based on sort order
                var isReversed = srcEndpoint != endpoints[0];
                var canonicalSrcIP = isReversed ? (packet.DestinationIP ?? "") : (packet.SourceIP ?? "");
                var canonicalSrcPort = isReversed ? packet.DestinationPort : packet.SourcePort;
                var canonicalDstIP = isReversed ? (packet.SourceIP ?? "") : (packet.DestinationIP ?? "");
                var canonicalDstPort = isReversed ? packet.SourcePort : packet.DestinationPort;

                if (streamStats.TryGetValue(streamKey, out var stats))
                    streamStats[streamKey] = (stats.Count + 1, stats.Bytes + packet.Length, stats.SourceIP, stats.SourcePort, stats.DestIP, stats.DestPort);
                else
                    streamStats[streamKey] = (1, packet.Length, canonicalSrcIP, canonicalSrcPort, canonicalDstIP, canonicalDstPort);
            }

            // Use StreamTimelineDisplayCount (5 or 10 based on toggle) for chart
            var displayCount = StreamTimelineDisplayCount;
            _topStreams = streamStats
                .OrderByDescending(s => ShowStreamActivityAsThroughput ? s.Value.Bytes : s.Value.Count)
                .Take(displayCount)
                .Select(s => new StreamInfo
                {
                    SourceIP = s.Value.SourceIP,
                    SourcePort = s.Value.SourcePort,
                    DestIP = s.Value.DestIP,
                    DestPort = s.Value.DestPort,
                    StreamKey = s.Key,
                    TotalPackets = s.Value.Count,
                    TotalBytes = s.Value.Bytes
                })
                .ToList();

            var topStreamKeys = _topStreams.Select(s => s.StreamKey).ToHashSet();

            // Build Top Streams tables (top 30 for each) - IP:Port based for detailed analysis
            var totalPackets = streamStats.Sum(s => s.Value.Count);
            var totalBytes = streamStats.Sum(s => s.Value.Bytes);

            var topByPackets = streamStats
                .OrderByDescending(s => s.Value.Count)
                .Take(30)
                .Select((s, index) => new TopStreamTableItem
                {
                    Rank = index + 1,
                    SourceIP = s.Value.SourceIP,
                    SourcePort = s.Value.SourcePort,
                    DestinationIP = s.Value.DestIP,
                    DestPort = s.Value.DestPort,
                    StreamKey = s.Key,
                    PacketCount = s.Value.Count,
                    ByteCount = s.Value.Bytes,
                    Percentage = totalPackets > 0 ? (s.Value.Count * 100.0) / totalPackets : 0
                })
                .ToList();

            var topByBytes = streamStats
                .OrderByDescending(s => s.Value.Bytes)
                .Take(30)
                .Select((s, index) => new TopStreamTableItem
                {
                    Rank = index + 1,
                    SourceIP = s.Value.SourceIP,
                    SourcePort = s.Value.SourcePort,
                    DestinationIP = s.Value.DestIP,
                    DestPort = s.Value.DestPort,
                    StreamKey = s.Key,
                    PacketCount = s.Value.Count,
                    ByteCount = s.Value.Bytes,
                    Percentage = totalBytes > 0 ? (s.Value.Bytes * 100.0) / totalBytes : 0
                })
                .ToList();

            TopStreamsByPackets = new ObservableCollection<TopStreamTableItem>(topByPackets);
            TopStreamsByBytes = new ObservableCollection<TopStreamTableItem>(topByBytes);

            // Step 2: Group packets into time buckets with stream breakdown
            var buckets = new Dictionary<DateTime, PacketsTimelineDataPoint>();
            foreach (var packet in orderedPackets)
            {
                var bucketTime = RoundToNearestBucket(packet.Timestamp, bucketSize, minTime);

                if (!buckets.TryGetValue(bucketTime, out var dataPoint))
                {
                    dataPoint = new PacketsTimelineDataPoint { Time = bucketTime };
                    buckets[bucketTime] = dataPoint;
                }

                dataPoint.TotalCount++;
                dataPoint.TotalBytes += packet.Length;

                // Track per-stream counts (using IP:Port format)
                var srcEndpoint = $"{packet.SourceIP ?? ""}:{packet.SourcePort}";
                var dstEndpoint = $"{packet.DestinationIP ?? ""}:{packet.DestinationPort}";
                var sortedEndpoints = new[] { srcEndpoint, dstEndpoint }.OrderBy(x => x).ToArray();
                var streamKey = $"{sortedEndpoints[0]}↔{sortedEndpoints[1]}";

                if (topStreamKeys.Contains(streamKey))
                {
                    if (dataPoint.StreamCounts.TryGetValue(streamKey, out var count))
                    {
                        dataPoint.StreamCounts[streamKey] = count + 1;
                        dataPoint.StreamBytes[streamKey] = dataPoint.StreamBytes[streamKey] + packet.Length;
                    }
                    else
                    {
                        dataPoint.StreamCounts[streamKey] = 1;
                        dataPoint.StreamBytes[streamKey] = packet.Length;
                    }
                }
            }

            // Build cache for tooltip lookup
            _timelineDataCache.Clear();
            foreach (var kvp in buckets)
            {
                _timelineDataCache[kvp.Key.Ticks] = kvp.Value;
            }

            // Create data points for the Total line (packets or bytes based on toggle)
            var orderedBuckets = buckets.OrderBy(b => b.Key).ToList();
            var totalDataPoints = orderedBuckets
                .Select(b => new ObservablePoint(b.Key.Ticks,
                    ShowStreamActivityAsThroughput ? b.Value.TotalBytes : b.Value.TotalCount))
                .ToArray();

            // Build series collection and legend items
            var newSeries = new ObservableCollection<ISeries>();
            var newLegendItems = new ObservableCollection<SeriesLegendItem>();

            // Primary series: Total packets (with fill area)
            var totalColor = ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF");
            newSeries.Add(new LineSeries<ObservablePoint>
            {
                Values = totalDataPoints,
                Name = "Total",
                GeometrySize = 4,
                GeometryStroke = ThemeColorHelper.ParseSolidColorPaint(totalColor, 1.5f),
                GeometryFill = ThemeColorHelper.ParseSolidColorPaint(totalColor),
                LineSmoothness = 0,
                Stroke = ThemeColorHelper.ParseSolidColorPaint(totalColor, 2.5f),
                Fill = ThemeColorHelper.ParseSolidColorPaint(totalColor, 40),
                DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                IsVisibleAtLegend = false, // Use custom legend
                ZIndex = 0
            });

            newLegendItems.Add(new SeriesLegendItem
            {
                Name = "Total",
                Color = totalColor,
                IsVisible = true,
                SeriesIndex = 0,
                SourceIP = null,  // Not a stream - single line display
                DestIP = null,
                OnToggle = ToggleSeriesVisibility
            });

            // Secondary series: Top 5 streams (lines only, no fill)
            for (int i = 0; i < _topStreams.Count && i < StreamColors.Length; i++)
            {
                var stream = _topStreams[i];
                var colorHex = StreamColors[i];
                var color = ThemeColorHelper.ParseSKColor(colorHex);

                var streamDataPoints = orderedBuckets
                    .Select(b =>
                    {
                        if (ShowStreamActivityAsThroughput)
                        {
                            b.Value.StreamBytes.TryGetValue(stream.StreamKey, out var bytes);
                            return new ObservablePoint(b.Key.Ticks, bytes);
                        }
                        else
                        {
                            b.Value.StreamCounts.TryGetValue(stream.StreamKey, out var count);
                            return new ObservablePoint(b.Key.Ticks, count);
                        }
                    })
                    .ToArray();

                newSeries.Add(new LineSeries<ObservablePoint>
                {
                    Values = streamDataPoints,
                    Name = TruncateStreamName(stream.DisplayName, 25),
                    GeometrySize = 3,
                    GeometryStroke = new SolidColorPaint(color) { StrokeThickness = 1.5f },
                    GeometryFill = new SolidColorPaint(color),
                    LineSmoothness = 0,
                    Stroke = new SolidColorPaint(color) { StrokeThickness = 2f },
                    Fill = null, // No fill for stream lines
                    DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                    IsVisibleAtLegend = false, // Use custom legend
                    ZIndex = i + 1
                });

                newLegendItems.Add(new SeriesLegendItem
                {
                    Name = stream.DisplayName,  // Full name for tooltip
                    Color = colorHex,
                    IsVisible = true,
                    SeriesIndex = i + 1,
                    SourceIP = stream.SourceIP,   // For two-line display
                    DestIP = stream.DestIP,
                    OnToggle = ToggleSeriesVisibility
                });
            }

            PacketsOverTimeSeries = newSeries;
            LegendItems = newLegendItems;

            // Set axis limits and cache Y range
            if (totalDataPoints.Length > 0)
            {
                var xMin = totalDataPoints.Min(p => p.X ?? 0);
                var xMax = totalDataPoints.Max(p => p.X ?? 0);
                var yMax = totalDataPoints.Max(p => p.Y ?? 0);

                // Store original limits for zoom
                _originalMinLimit = xMin;
                _originalMaxLimit = xMax;
                _zoomInitialized = true;

                // Cache Y range for highlight line
                _cachedMinY = 0;
                _cachedMaxY = yMax * 1.1;

                if (PacketsOverTimeXAxes.Length > 0)
                {
                    PacketsOverTimeXAxes[0].MinLimit = xMin;
                    PacketsOverTimeXAxes[0].MaxLimit = xMax;
                }
                if (PacketsOverTimeYAxes.Length > 0)
                {
                    // Update Y-axis based on throughput mode
                    var yAxis = PacketsOverTimeYAxes[0];
                    yAxis.MaxLimit = _cachedMaxY;
                    yAxis.Name = ShowStreamActivityAsThroughput ? "Throughput" : "Packets";
                    yAxis.Labeler = ShowStreamActivityAsThroughput
                        ? (value => FormatBytes((long)value))
                        : (value => value >= 1000 ? $"{value / 1000:F1}K" : $"{value:F0}");
                    var axisColor = ShowStreamActivityAsThroughput ? ("ColorSuccess", "#10B981") : ("AccentBlue", "#58A6FF");
                    yAxis.NamePaint = ThemeColorHelper.GetSolidColorPaint(axisColor.Item1, axisColor.Item2);
                    yAxis.LabelsPaint = ThemeColorHelper.GetSolidColorPaint(axisColor.Item1, axisColor.Item2);
                }
            }

            DebugLogger.Log($"[MainWindowChartsViewModel] PacketsOverTime chart updated: {filteredPackets.Count:N0} packets, {buckets.Count} time buckets, {_topStreams.Count} streams");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdatePacketsOverTimeChart failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Truncates a stream name for display in legend
    /// </summary>
    private static string TruncateStreamName(string name, int maxLength)
    {
        if (string.IsNullOrEmpty(name) || name.Length <= maxLength)
            return name;
        return name[..(maxLength - 3)] + "...";
    }

    /// <summary>
    /// Formats bytes into human-readable format for Y-axis labels
    /// </summary>
    private static string FormatBytes(long bytes)
        => Core.Utilities.NumberFormatter.FormatBytes(bytes);

    /// <summary>
    /// Calculates appropriate bucket size based on time range and packet count.
    /// Uses 1-second buckets for short captures (under 5 minutes) for precise visualization.
    /// </summary>
    private TimeSpan CalculateBucketSize(TimeSpan timeRange, int packetCount)
    {
        // Target ~100-150 buckets for good visualization
        const int targetBuckets = 120;

        if (timeRange.TotalMinutes < 5)
        {
            // Less than 5 minutes: 1 second buckets (user requested precise timestamps)
            return TimeSpan.FromSeconds(1);
        }
        else if (timeRange.TotalMinutes < 15)
        {
            // Less than 15 minutes: 5 second buckets
            return TimeSpan.FromSeconds(5);
        }
        else if (timeRange.TotalMinutes < 60)
        {
            // Less than 1 hour: 15 second buckets
            return TimeSpan.FromSeconds(15);
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
    /// Returns the full PacketsTimelineDataPoint including stream breakdown.
    /// </summary>
    public PacketsTimelineDataPoint? GetTooltipDataAtPosition(double xTicks)
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

    /// <summary>
    /// Gets the data index for a relative X position (0-1 range)
    /// </summary>
    public int GetDataIndexForRelativeX(double relativeX)
    {
        if (_timelineDataCache.Count == 0)
            return -1;

        var sortedKeys = _timelineDataCache.Keys.OrderBy(k => k).ToList();
        var index = (int)(relativeX * (sortedKeys.Count - 1));
        return Math.Max(0, Math.Min(sortedKeys.Count - 1, index));
    }

    /// <summary>
    /// Gets the data point at a specific index
    /// </summary>
    public PacketsTimelineDataPoint? GetDataPointAtIndex(int index)
    {
        if (_timelineDataCache.Count == 0 || index < 0)
            return null;

        var sortedKeys = _timelineDataCache.Keys.OrderBy(k => k).ToList();
        if (index >= sortedKeys.Count)
            return null;

        return _timelineDataCache[sortedKeys[index]];
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

    // ==================== LEGEND TOGGLE ====================

    /// <summary>
    /// Toggles visibility of a series by index and recalculates Y-axis
    /// </summary>
    private void ToggleSeriesVisibility(int seriesIndex, bool isVisible)
    {
        try
        {
            if (PacketsOverTimeSeries == null || seriesIndex < 0 || seriesIndex >= PacketsOverTimeSeries.Count)
                return;

            PacketsOverTimeSeries[seriesIndex].IsVisible = isVisible;
            DebugLogger.Log($"[MainWindowChartsViewModel] Series {seriesIndex} visibility: {isVisible}");

            // Recalculate Y-axis max based on visible series
            RecalculateYAxisForVisibleSeries();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] ToggleSeriesVisibility error: {ex.Message}");
        }
    }

    /// <summary>
    /// Recalculates Y-axis max based on currently visible series
    /// </summary>
    private void RecalculateYAxisForVisibleSeries()
    {
        try
        {
            if (PacketsOverTimeSeries == null || PacketsOverTimeSeries.Count == 0)
                return;

            double maxY = 0;

            for (int i = 0; i < PacketsOverTimeSeries.Count; i++)
            {
                var series = PacketsOverTimeSeries[i];
                if (!series.IsVisible)
                    continue;

                // Skip highlight series (scatter and line)
                if (series.Name == "Highlight" || series.Name == "VerticalLine")
                    continue;

                if (series is LineSeries<ObservablePoint> lineSeries && lineSeries.Values != null)
                {
                    foreach (var point in lineSeries.Values)
                    {
                        if (point.Y.HasValue && point.Y.Value > maxY)
                            maxY = point.Y.Value;
                    }
                }
            }

            // Apply padding (10% above max)
            maxY = maxY > 0 ? maxY * 1.1 : 100;

            // Update Y-axis
            if (PacketsOverTimeYAxes != null && PacketsOverTimeYAxes.Length > 0)
            {
                PacketsOverTimeYAxes[0].MaxLimit = maxY;
                _cachedMaxY = maxY;
                DebugLogger.Log($"[MainWindowChartsViewModel] Y-axis recalculated: max={maxY:F0}");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] RecalculateYAxisForVisibleSeries error: {ex.Message}");
        }
    }

    /// <summary>
    /// Compute a fast hash of packet data for deduplication.
    /// Uses first/last timestamps and total bytes to detect changes.
    /// </summary>
    private static long ComputePacketDataHash(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0) return 0;

        // Sample first, middle, and last packets for a fast hash
        var first = packets[0];
        var last = packets[packets.Count - 1];
        var mid = packets[packets.Count / 2];

        // Combine key properties into a hash
        unchecked
        {
            long hash = 17;
            hash = hash * 31 + first.Timestamp.Ticks;
            hash = hash * 31 + last.Timestamp.Ticks;
            hash = hash * 31 + mid.FrameNumber;
            hash = hash * 31 + first.Length + last.Length;
            return hash;
        }
    }

    // ==================== STREAM POPUP METHODS ====================

    /// <summary>
    /// Shows the stream popup with data for a specific time point (stream-focused, matches chart context)
    /// </summary>
    public void ShowStreamPopup(PacketsTimelineDataPoint dataPoint)
    {
        if (dataPoint == null)
            return;

        var streams = new ObservableCollection<StreamPopupItem>();

        // Add top streams with their data at this time point (matches chart legend)
        for (int i = 0; i < _topStreams.Count && i < StreamColors.Length; i++)
        {
            var stream = _topStreams[i];
            dataPoint.StreamCounts.TryGetValue(stream.StreamKey, out var packetCount);
            dataPoint.StreamBytes.TryGetValue(stream.StreamKey, out var byteCount);

            streams.Add(new StreamPopupItem
            {
                SourceIP = stream.SourceIP,
                DestIP = stream.DestIP,
                StreamKey = stream.StreamKey,
                PacketCount = packetCount,
                ByteCount = byteCount,
                Percentage = dataPoint.TotalCount > 0 ? (packetCount * 100.0) / dataPoint.TotalCount : 0,
                Color = StreamColors[i],
                Protocol = "TCP" // Default, could be enhanced
            });
        }

        StreamPopupViewModel = new StreamChartPopupViewModel
        {
            Timestamp = dataPoint.Time,
            TotalPackets = dataPoint.TotalCount,
            TotalBytes = dataPoint.TotalBytes,
            Streams = streams
        };

        StreamPopupViewModel.CloseCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
        {
            IsStreamPopupOpen = false;
            StreamPopupViewModel = null;
        });

        StreamPopupViewModel.CopyCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(async () =>
        {
            try
            {
                var clipboardText = StreamPopupViewModel?.GetClipboardText() ?? "";
                if (!string.IsNullOrEmpty(clipboardText))
                {
                    var clipboard = Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                        ? desktop.MainWindow?.Clipboard
                        : null;

                    if (clipboard != null)
                    {
                        await clipboard.SetTextAsync(clipboardText);
                        DebugLogger.Log("[MainWindowChartsViewModel] Stream data copied to clipboard");
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MainWindowChartsViewModel] Copy to clipboard error: {ex.Message}");
            }
        });

        IsStreamPopupOpen = true;
        DebugLogger.Log($"[MainWindowChartsViewModel] Stream popup opened at {dataPoint.Time:HH:mm:ss} - Total: {dataPoint.TotalCount:N0}");
    }

    /// <summary>
    /// Closes the stream popup
    /// </summary>
    [RelayCommand]
    private void CloseStreamPopup()
    {
        IsStreamPopupOpen = false;
        StreamPopupViewModel = null;
    }

    /// <summary>
    /// Shows details for a stream from the Top Streams table (IP-pair based).
    /// Uses DrillDownPopupViewModel for consistent Dashboard-style popup.
    /// </summary>
    [RelayCommand]
    private void ShowStreamDetails(TopStreamTableItem? item)
    {
        if (item == null || _lastFilteredPackets == null || DrillDown == null) return;

        DebugLogger.Log($"[Charts] ShowStreamDetails: {item.SourceIP} ↔ {item.DestinationIP}");

        // Ensure on UI thread
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.InvokeAsync(() => ShowStreamDetails(item));
            return;
        }

        // Use DrillDownPopupViewModel for consistent Dashboard-style popup
        DrillDown.ShowForStream(
            item.SourceIP,
            item.SourcePort,
            item.DestinationIP,
            item.DestPort,
            _lastFilteredPackets,
            item.PacketCount,
            item.ByteCount
        );

        DebugLogger.Log($"[Charts] DrillDown popup opened for stream: {item.SourceIP}:{item.SourcePort} ↔ {item.DestinationIP}:{item.DestPort}");
    }
}
