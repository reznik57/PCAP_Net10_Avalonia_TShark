using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using Avalonia.Threading; // Required for DispatcherTimer only
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Performance;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;
using SkiaSharp;

namespace PCAPAnalyzer.UI.ViewModels.Capture;

/// <summary>
/// ViewModel for live capture statistics panel with real-time charts and UI performance monitoring
/// Updates statistics at throttled intervals to maintain UI performance
/// Tracks UI FPS and latency for performance validation
/// </summary>
public partial class LiveStatisticsViewModel : ViewModelBase, IDisposable
{
    private readonly DispatcherTimer _updateTimer;
    private readonly object _statsLock = new();
    private DateTime _sessionStart = DateTime.UtcNow;
    private readonly Dictionary<string, long> _protocolCounts = new();
    private readonly ObservableCollection<DateTimePoint> _packetRateData = new();
    private readonly Stopwatch _uiUpdateStopwatch = Stopwatch.StartNew();
    private int _uiUpdateCount;
    private bool _disposed;

    /// <summary>
    /// Total packets captured in this session
    /// </summary>
    [ObservableProperty]
    private long _totalPackets;

    /// <summary>
    /// Total bytes captured
    /// </summary>
    [ObservableProperty]
    private long _totalBytes;

    /// <summary>
    /// Current packet rate (packets per second)
    /// </summary>
    [ObservableProperty]
    private double _packetsPerSecond;

    /// <summary>
    /// Current bandwidth (megabytes per second)
    /// </summary>
    [ObservableProperty]
    private double _megabytesPerSecond;

    /// <summary>
    /// Packets dropped by kernel
    /// </summary>
    [ObservableProperty]
    private long _packetsDropped;

    /// <summary>
    /// Drop percentage
    /// </summary>
    [ObservableProperty]
    private double _dropPercentage;

    /// <summary>
    /// Session duration formatted
    /// </summary>
    [ObservableProperty]
    private string _sessionDuration = "00:00:00";

    /// <summary>
    /// Formatted total packets
    /// </summary>
    [ObservableProperty]
    private string _totalPacketsFormatted = "0";

    /// <summary>
    /// Formatted total bytes
    /// </summary>
    [ObservableProperty]
    private string _totalBytesFormatted = "0 B";

    /// <summary>
    /// Formatted packet rate
    /// </summary>
    [ObservableProperty]
    private string _packetRateFormatted = "0 pps";

    /// <summary>
    /// Formatted bandwidth
    /// </summary>
    [ObservableProperty]
    private string _bandwidthFormatted = "0.00 MB/s";

    /// <summary>
    /// UI updates per second (frames per second)
    /// </summary>
    [ObservableProperty]
    private double _uiFps;

    /// <summary>
    /// Average UI update latency in milliseconds
    /// </summary>
    [ObservableProperty]
    private double _avgUpdateLatency;

    /// <summary>
    /// Formatted UI FPS
    /// </summary>
    [ObservableProperty]
    private string _uiFpsFormatted = "0 FPS";

    /// <summary>
    /// Protocol distribution for pie chart
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<ProtocolStatistic> _protocolDistribution = new();

    /// <summary>
    /// Top talkers list
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<TalkerStatistic> _topTalkers = new();

    /// <summary>
    /// Packet rate chart series
    /// </summary>
    public ISeries[] PacketRateSeries { get; set; }

    /// <summary>
    /// Protocol distribution pie chart series
    /// </summary>
    public ISeries[] ProtocolPieSeries { get; set; }

    public LiveStatisticsViewModel()
    {
        // Initialize packet rate chart
        PacketRateSeries = new ISeries[]
        {
            new LineSeries<DateTimePoint>
            {
                Values = _packetRateData,
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0,
                Stroke = new SolidColorPaint(SKColors.CornflowerBlue) { StrokeThickness = 2 },
                Name = "Packet Rate (pps)"
            }
        };

        // Initialize protocol pie chart (will be updated dynamically)
        ProtocolPieSeries = Array.Empty<ISeries>();

        // Update statistics every 500ms
        _updateTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _updateTimer.Tick += UpdateStatistics;
        _updateTimer.Start();
    }

    /// <summary>
    /// Updates statistics from CaptureSessionStats
    /// </summary>
    public void UpdateFromSessionStats(CaptureSessionStats stats)
    {
        if (_disposed) return;

        lock (_statsLock)
        {
            TotalPackets = stats.TotalPackets;
            TotalBytes = stats.TotalBytes;
            PacketsPerSecond = stats.CurrentPacketsPerSecond;
            MegabytesPerSecond = stats.CurrentBytesPerSecond / (1024.0 * 1024.0);
            PacketsDropped = stats.PacketsDropped;
            DropPercentage = stats.DropPercentage;
        }
    }

    /// <summary>
    /// Records a packet for protocol distribution tracking
    /// </summary>
    public void RecordPacket(string protocol, int length)
    {
        if (_disposed) return;

        lock (_statsLock)
        {
            if (!_protocolCounts.ContainsKey(protocol))
            {
                _protocolCounts[protocol] = 0;
            }
            _protocolCounts[protocol]++;
        }
    }

    /// <summary>
    /// Periodic statistics update (throttled to 2Hz)
    /// Includes UI performance monitoring (FPS tracking)
    /// </summary>
    private void UpdateStatistics(object? sender, EventArgs e)
    {
        if (_disposed) return;

        RunOnUIThread(() =>
        {
            _uiUpdateCount++;

            // Calculate UI FPS every second
            if (_uiUpdateStopwatch.ElapsedMilliseconds >= 1000)
            {
                UiFps = _uiUpdateCount;
                AvgUpdateLatency = _uiUpdateCount > 0 ? 1000.0 / _uiUpdateCount : 0;
                UiFpsFormatted = $"{UiFps:F0} FPS";

                // Record performance metrics
                PerformanceMonitor.Instance.RecordMetric("UI_FPS", UiFps, "fps");
                PerformanceMonitor.Instance.RecordMetric("UI_Latency", AvgUpdateLatency, "ms");

                _uiUpdateCount = 0;
                _uiUpdateStopwatch.Restart();
            }

            // Update formatted strings
            TotalPacketsFormatted = TotalPackets.ToString("N0");
            TotalBytesFormatted = Core.Utilities.NumberFormatter.FormatBytes(TotalBytes);
            PacketRateFormatted = $"{PacketsPerSecond:F0} pps";
            BandwidthFormatted = $"{MegabytesPerSecond:F2} MB/s";

            // Update session duration
            var duration = DateTime.UtcNow - _sessionStart;
            SessionDuration = $"{(int)duration.TotalHours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}";

            // Update packet rate chart (keep last 60 data points = 30 seconds)
            _packetRateData.Add(new DateTimePoint(DateTime.Now, PacketsPerSecond));
            if (_packetRateData.Count > 60)
            {
                _packetRateData.RemoveAt(0);
            }

            // Update protocol distribution (every 5 updates = 2.5 seconds)
            if (_updateTimer.Tag is int count && count % 5 == 0)
            {
                UpdateProtocolDistribution();
            }
            _updateTimer.Tag = ((int?)_updateTimer.Tag ?? 0) + 1;
        });
    }

    /// <summary>
    /// Updates protocol distribution pie chart
    /// </summary>
    private void UpdateProtocolDistribution()
    {
        lock (_statsLock)
        {
            var topProtocols = _protocolCounts
                .OrderByDescending(kvp => kvp.Value)
                .Take(5)
                .ToList();

            ProtocolDistribution.Clear();
            foreach (var kvp in topProtocols)
            {
                var percentage = TotalPackets > 0 ? (double)kvp.Value / TotalPackets * 100 : 0;
                ProtocolDistribution.Add(new ProtocolStatistic
                {
                    Protocol = kvp.Key,
                    Count = kvp.Value,
                    Percentage = percentage
                });
            }

            // Update pie chart series
            ProtocolPieSeries = ProtocolDistribution.Select(p => new PieSeries<double>
            {
                Values = new double[] { (double)p.Count },
                Name = p.Protocol,
                DataLabelsPaint = ThemeColorHelper.WhitePaint,
                DataLabelsSize = 12,
                DataLabelsFormatter = point => $"{p.Protocol}\n{p.Percentage:F1}%"
            }).ToArray();

            OnPropertyChanged(nameof(ProtocolPieSeries));
        }
    }

    /// <summary>
    /// Resets all statistics
    /// </summary>
    public void Reset()
    {
        lock (_statsLock)
        {
            TotalPackets = 0;
            TotalBytes = 0;
            PacketsPerSecond = 0;
            MegabytesPerSecond = 0;
            PacketsDropped = 0;
            DropPercentage = 0;
            _sessionStart = DateTime.UtcNow;
            _protocolCounts.Clear();
            _packetRateData.Clear();
            ProtocolDistribution.Clear();
            TopTalkers.Clear();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _updateTimer?.Stop();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Protocol statistics for pie chart
/// </summary>
public class ProtocolStatistic
{
    public string Protocol { get; set; } = string.Empty;
    public long Count { get; set; }
    public double Percentage { get; set; }
}

/// <summary>
/// Top talker statistics
/// </summary>
public class TalkerStatistic
{
    public string IpAddress { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public string BytesFormatted { get; set; } = string.Empty;
}
