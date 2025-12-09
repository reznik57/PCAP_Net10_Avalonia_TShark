using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Defaults;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Charts;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages chart data and visualization for the main window.
/// Handles protocol distribution, traffic charts, and Packets Over Time chart for Packet Analysis tab.
/// Uses extracted utilities: ChartAxisBuilder, StreamAnalyzer, ChartZoomController.
/// </summary>
public partial class MainWindowChartsViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly ChartZoomController _zoomController = new();

    public ObservableCollection<ISeries> ProtocolSeries { get; }
    public ObservableCollection<ISeries> TrafficSeries { get; }

    // ==================== PACKETS OVER TIME CHART ====================

    [ObservableProperty] private ObservableCollection<ISeries> _packetsOverTimeSeries = [];
    [ObservableProperty] private Axis[] _packetsOverTimeXAxes = [];
    [ObservableProperty] private Axis[] _packetsOverTimeYAxes = [];
    [ObservableProperty] private string _packetsOverTimeTooltip = "";
    [ObservableProperty] private bool _hasPacketData;
    [ObservableProperty] private int _filteredPacketCount;
    [ObservableProperty] private double _packetsTimelineZoomLevel = 100;

    // ==================== STREAM POPUP ====================

    [ObservableProperty] private StreamChartPopupViewModel? _streamPopupViewModel;
    [ObservableProperty] private bool _isStreamPopupOpen;
    [ObservableProperty] private DrillDownPopupViewModel? _drillDown;

    // ==================== INTERACTIVE LEGEND ====================

    [ObservableProperty] private ObservableCollection<SeriesLegendItem> _legendItems = [];

    // ==================== TOP STREAMS TABLES ====================

    [ObservableProperty] private ObservableCollection<TopStreamTableItem> _topStreamsByPackets = [];
    [ObservableProperty] private ObservableCollection<TopStreamTableItem> _topStreamsByBytes = [];

    // ==================== CHART TOGGLE OPTIONS ====================

    [ObservableProperty] private bool _showStreamActivityAsThroughput;
    [ObservableProperty] private bool _showTop10Streams;
    [ObservableProperty] private int _streamTimelineDisplayCount = 5;

    // Cache and state
    private IReadOnlyList<PacketInfo>? _lastFilteredPackets;
    private int _lastChartPacketCount;
    private long _lastChartDataHash;
    private Dictionary<long, PacketsTimelineDataPoint> _timelineDataCache = [];
    private double _cachedMinY;
    private double _cachedMaxY;
    private List<StreamInfo> _topStreams = [];

    private static string[] StreamColors => ThemeColorHelper.StreamColors;

    public IReadOnlyList<StreamInfo> TopStreams => _topStreams;
    public (double Min, double Max) CachedYRange => (_cachedMinY, _cachedMaxY);
    public IReadOnlyDictionary<long, PacketsTimelineDataPoint> TimelineDataCache => _timelineDataCache;

    public MainWindowChartsViewModel()
    {
        ProtocolSeries = new ObservableCollection<ISeries>();
        TrafficSeries = new ObservableCollection<ISeries>();

        InitializeCharts();
        InitializePacketsOverTimeAxes();
        InitializeDrillDown();
    }

    partial void OnShowStreamActivityAsThroughputChanged(bool value)
    {
        if (_lastFilteredPackets is not null)
            UpdatePacketsOverTimeChart(_lastFilteredPackets, forceUpdate: true);
    }

    partial void OnShowTop10StreamsChanged(bool value)
    {
        StreamTimelineDisplayCount = value ? 10 : 5;
        if (_lastFilteredPackets is not null)
            UpdatePacketsOverTimeChart(_lastFilteredPackets, forceUpdate: true);
    }

    private void InitializeDrillDown() => DrillDown = new();

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

    private void InitializePacketsOverTimeAxes()
    {
        PacketsOverTimeXAxes = [ChartAxisBuilder.CreateTimelineXAxis()];
        PacketsOverTimeYAxes = [ChartAxisBuilder.CreatePacketCountYAxis()];
    }

    public void UpdateCharts(PacketStatistics stats)
    {
        try
        {
            Dispatcher.InvokeAsync(() =>
            {
                try { UpdateProtocolChart(stats); }
                catch (Exception ex) { DebugLogger.Log($"[MainWindowChartsViewModel] UpdateProtocolChart failed: {ex.Message}"); }
            });
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdateCharts failed: {ex.Message}");
        }
    }

    private void UpdateProtocolChart(PacketStatistics stats)
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

    private static SKColor GetColorForProtocol(Protocol protocol) => protocol switch
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
        _zoomController.Reset();
    }

    // ==================== PACKETS OVER TIME CHART METHODS ====================

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Chart update method performs cohesive stream analysis and series building")]
    public void UpdatePacketsOverTimeChart(IReadOnlyList<PacketInfo> filteredPackets, bool forceUpdate = false)
    {
        try
        {
            _lastFilteredPackets = filteredPackets;

            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.InvokeAsync(() => UpdatePacketsOverTimeChart(filteredPackets, forceUpdate));
                return;
            }

            if (filteredPackets is null || filteredPackets.Count == 0)
            {
                ClearChartState();
                return;
            }

            // Dedupe guard
            var dataHash = ComputePacketDataHash(filteredPackets);
            if (!forceUpdate && filteredPackets.Count == _lastChartPacketCount && dataHash == _lastChartDataHash)
            {
                DebugLogger.Log($"[MainWindowChartsViewModel] Skipping redundant chart update");
                return;
            }
            _lastChartPacketCount = filteredPackets.Count;
            _lastChartDataHash = dataHash;

            FilteredPacketCount = filteredPackets.Count;
            HasPacketData = true;

            // Use StreamAnalyzer for analysis
            var analyzer = new StreamAnalyzer(StreamTimelineDisplayCount, ShowStreamActivityAsThroughput);
            var result = analyzer.Analyze(filteredPackets);

            if (result.Buckets.Count == 0)
            {
                PacketsOverTimeSeries.Clear();
                HasPacketData = false;
                return;
            }

            _topStreams = result.TopStreams;
            TopStreamsByPackets = new ObservableCollection<TopStreamTableItem>(result.TopByPackets);
            TopStreamsByBytes = new ObservableCollection<TopStreamTableItem>(result.TopByBytes);

            // Build cache
            _timelineDataCache.Clear();
            foreach (var kvp in result.Buckets)
                _timelineDataCache[kvp.Key.Ticks] = kvp.Value;

            // Build series
            var orderedBuckets = result.Buckets.OrderBy(b => b.Key).ToList();
            var (newSeries, newLegendItems) = BuildChartSeries(orderedBuckets, _topStreams);

            PacketsOverTimeSeries = newSeries;
            LegendItems = newLegendItems;

            // Configure axes
            ConfigureAxes(orderedBuckets);

            DebugLogger.Log($"[MainWindowChartsViewModel] Chart updated: {filteredPackets.Count:N0} packets, {result.Buckets.Count} buckets, {_topStreams.Count} streams");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] UpdatePacketsOverTimeChart failed: {ex.Message}");
        }
    }

    private void ClearChartState()
    {
        PacketsOverTimeSeries.Clear();
        HasPacketData = false;
        FilteredPacketCount = 0;
        _timelineDataCache.Clear();
        _topStreams.Clear();
        _lastChartPacketCount = 0;
        _lastChartDataHash = 0;
    }

    private (ObservableCollection<ISeries>, ObservableCollection<SeriesLegendItem>) BuildChartSeries(
        List<KeyValuePair<DateTime, PacketsTimelineDataPoint>> orderedBuckets,
        List<StreamInfo> topStreams)
    {
        var newSeries = new ObservableCollection<ISeries>();
        var newLegendItems = new ObservableCollection<SeriesLegendItem>();

        // Total line data
        var totalDataPoints = orderedBuckets
            .Select(b => new ObservablePoint(b.Key.Ticks,
                ShowStreamActivityAsThroughput ? b.Value.TotalBytes : b.Value.TotalCount))
            .ToArray();

        // Primary series: Total
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
            IsVisibleAtLegend = false,
            ZIndex = 0
        });

        newLegendItems.Add(new SeriesLegendItem
        {
            Name = "Total",
            Color = totalColor,
            IsVisible = true,
            SeriesIndex = 0,
            OnToggle = ToggleSeriesVisibility
        });

        // Stream lines
        for (int i = 0; i < topStreams.Count && i < StreamColors.Length; i++)
        {
            var stream = topStreams[i];
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
                    b.Value.StreamCounts.TryGetValue(stream.StreamKey, out var count);
                    return new ObservablePoint(b.Key.Ticks, count);
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
                Fill = null,
                DataPadding = new LiveChartsCore.Drawing.LvcPoint(0, 0),
                IsVisibleAtLegend = false,
                ZIndex = i + 1
            });

            newLegendItems.Add(new SeriesLegendItem
            {
                Name = stream.DisplayName,
                Color = colorHex,
                IsVisible = true,
                SeriesIndex = i + 1,
                SourceIP = stream.SourceIP,
                DestIP = stream.DestIP,
                OnToggle = ToggleSeriesVisibility
            });
        }

        return (newSeries, newLegendItems);
    }

    private void ConfigureAxes(List<KeyValuePair<DateTime, PacketsTimelineDataPoint>> orderedBuckets)
    {
        if (orderedBuckets.Count == 0) return;

        var totalDataPoints = orderedBuckets
            .Select(b => new ObservablePoint(b.Key.Ticks,
                ShowStreamActivityAsThroughput ? b.Value.TotalBytes : b.Value.TotalCount))
            .ToArray();

        var xMin = totalDataPoints.Min(p => p.X ?? 0);
        var xMax = totalDataPoints.Max(p => p.X ?? 0);
        var yMax = totalDataPoints.Max(p => p.Y ?? 0);

        _zoomController.Initialize(xMin, xMax);
        PacketsTimelineZoomLevel = _zoomController.ZoomLevel;

        _cachedMinY = 0;
        _cachedMaxY = yMax * 1.1;

        if (PacketsOverTimeXAxes.Length > 0)
        {
            PacketsOverTimeXAxes[0].MinLimit = xMin;
            PacketsOverTimeXAxes[0].MaxLimit = xMax;
        }

        if (PacketsOverTimeYAxes.Length > 0)
        {
            var yAxis = PacketsOverTimeYAxes[0];
            yAxis.MaxLimit = _cachedMaxY;
            ChartAxisBuilder.ConfigureYAxisMode(yAxis, ShowStreamActivityAsThroughput);
        }
    }

    private static string TruncateStreamName(string name, int maxLength)
    {
        if (string.IsNullOrEmpty(name) || name.Length <= maxLength)
            return name;
        return name[..(maxLength - 3)] + "...";
    }

    public PacketsTimelineDataPoint? GetTooltipDataAtPosition(double xTicks)
    {
        if (_timelineDataCache.Count == 0) return null;

        var targetTicks = (long)xTicks;
        var closest = _timelineDataCache.Keys.OrderBy(k => Math.Abs(k - targetTicks)).FirstOrDefault();

        return closest != 0 && _timelineDataCache.TryGetValue(closest, out var data) ? data : null;
    }

    public int GetDataIndexForRelativeX(double relativeX)
    {
        if (_timelineDataCache.Count == 0) return -1;
        var sortedKeys = _timelineDataCache.Keys.OrderBy(k => k).ToList();
        var index = (int)(relativeX * (sortedKeys.Count - 1));
        return Math.Max(0, Math.Min(sortedKeys.Count - 1, index));
    }

    public PacketsTimelineDataPoint? GetDataPointAtIndex(int index)
    {
        if (_timelineDataCache.Count == 0 || index < 0) return null;
        var sortedKeys = _timelineDataCache.Keys.OrderBy(k => k).ToList();
        return index < sortedKeys.Count ? _timelineDataCache[sortedKeys[index]] : null;
    }

    // ==================== ZOOM COMMANDS ====================

    [RelayCommand]
    private void ZoomInPacketsTimeline()
    {
        if (_zoomController.ZoomIn())
        {
            PacketsTimelineZoomLevel = _zoomController.ZoomLevel;
            ApplyZoom();
        }
    }

    [RelayCommand]
    private void ZoomOutPacketsTimeline()
    {
        if (_zoomController.ZoomOut())
        {
            PacketsTimelineZoomLevel = _zoomController.ZoomLevel;
            ApplyZoom();
        }
    }

    [RelayCommand]
    private void ResetPacketsTimelineZoom()
    {
        _zoomController.ResetZoom();
        PacketsTimelineZoomLevel = _zoomController.ZoomLevel;
        ApplyZoom();
    }

    private void ApplyZoom()
    {
        if (PacketsOverTimeXAxes is null || PacketsOverTimeXAxes.Length == 0 || !_zoomController.IsInitialized)
            return;
        _zoomController.ApplyToAxis(PacketsOverTimeXAxes[0]);
    }

    // ==================== LEGEND TOGGLE ====================

    private void ToggleSeriesVisibility(int seriesIndex, bool isVisible)
    {
        try
        {
            if (PacketsOverTimeSeries is null || seriesIndex < 0 || seriesIndex >= PacketsOverTimeSeries.Count)
                return;

            PacketsOverTimeSeries[seriesIndex].IsVisible = isVisible;
            RecalculateYAxisForVisibleSeries();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowChartsViewModel] ToggleSeriesVisibility error: {ex.Message}");
        }
    }

    private void RecalculateYAxisForVisibleSeries()
    {
        if (PacketsOverTimeSeries is null || PacketsOverTimeSeries.Count == 0) return;

        double maxY = 0;
        foreach (var series in PacketsOverTimeSeries)
        {
            if (!series.IsVisible || series.Name == "Highlight" || series.Name == "VerticalLine")
                continue;

            if (series is LineSeries<ObservablePoint> lineSeries && lineSeries.Values is not null)
            {
                foreach (var point in lineSeries.Values)
                {
                    if (point.Y.HasValue && point.Y.Value > maxY)
                        maxY = point.Y.Value;
                }
            }
        }

        maxY = maxY > 0 ? maxY * 1.1 : 100;

        if (PacketsOverTimeYAxes is not null && PacketsOverTimeYAxes.Length > 0)
        {
            PacketsOverTimeYAxes[0].MaxLimit = maxY;
            _cachedMaxY = maxY;
        }
    }

    private static long ComputePacketDataHash(IReadOnlyList<PacketInfo> packets)
    {
        if (packets.Count == 0) return 0;

        var first = packets[0];
        var last = packets[packets.Count - 1];
        var mid = packets[packets.Count / 2];

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

    public void ShowStreamPopup(PacketsTimelineDataPoint dataPoint)
    {
        if (dataPoint is null) return;

        var streams = new ObservableCollection<StreamPopupItem>();

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
                Protocol = "TCP"
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

                    if (clipboard is not null)
                        await clipboard.SetTextAsync(clipboardText);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MainWindowChartsViewModel] Copy error: {ex.Message}");
            }
        });

        IsStreamPopupOpen = true;
    }

    [RelayCommand]
    private void CloseStreamPopup()
    {
        IsStreamPopupOpen = false;
        StreamPopupViewModel = null;
    }

    [RelayCommand]
    private void ShowStreamDetails(TopStreamTableItem? item)
    {
        if (item is null || _lastFilteredPackets is null || DrillDown is null) return;

        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.InvokeAsync(() => ShowStreamDetails(item));
            return;
        }

        DrillDown.ShowForStream(
            item.SourceIP,
            item.SourcePort,
            item.DestinationIP,
            item.DestPort,
            _lastFilteredPackets,
            item.PacketCount,
            item.ByteCount
        );
    }
}
