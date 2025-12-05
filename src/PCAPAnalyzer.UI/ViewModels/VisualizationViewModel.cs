using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Services.Visualization;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    /// <summary>
    /// ViewModel for advanced visualization features
    /// Manages interactive dashboards, real-time charts, and advanced visualizations
    /// </summary>
    public partial class VisualizationViewModel : ObservableObject, IDisposable
    {
        private readonly IChartDataService _chartDataService;
        private readonly IChartExportService _exportService;

        private List<PacketInfo>? _currentPackets;
        private NetworkStatistics? _currentStatistics;
        private Timer? _updateTimer;
        private bool _isRealTimeEnabled;

        // Chart Collections
        [ObservableProperty] private ObservableCollection<ISeries> _timeSeriesSeries = new();
        [ObservableProperty] private ObservableCollection<ISeries> _heatmapSeries = new();
        [ObservableProperty] private ObservableCollection<ISeries> _histogramSeries = new();
        [ObservableProperty] private ObservableCollection<ISeries> _boxPlotSeries = new();

        // Axes
        [ObservableProperty] private ObservableCollection<Axis> _timeSeriesXAxes = new();
        [ObservableProperty] private ObservableCollection<Axis> _timeSeriesYAxes = new();

        // Heatmap Data
        [ObservableProperty] private ObservableCollection<HeatmapCellViewModel> _heatmapCells = new();
        [ObservableProperty] private ObservableCollection<string> _xLabels = new();
        [ObservableProperty] private ObservableCollection<string> _yLabels = new();
        [ObservableProperty] private int _rowCount;
        [ObservableProperty] private int _columnCount;

        // Network Graph Data
        [ObservableProperty] private ObservableCollection<NetworkNodeViewModel> _nodes = new();
        [ObservableProperty] private ObservableCollection<NetworkEdgeViewModel> _edges = new();
        [ObservableProperty] private int _nodeCount;
        [ObservableProperty] private int _edgeCount;

        // UI State
        [ObservableProperty] private string _title = "Advanced Visualizations";
        [ObservableProperty] private string _statusMessage = "Ready";
        [ObservableProperty] private int _dataPointCount;
        [ObservableProperty] private string _timeRange = "All Time";
        [ObservableProperty] private DateTime _lastUpdate = DateTime.Now;
        [ObservableProperty] private bool _isLoading;
        [ObservableProperty] private string? _selectedNode;

        // Real-time Configuration
        [ObservableProperty] private int _updateInterval = 1000; // milliseconds
        [ObservableProperty] private bool _autoScroll = true;
        [ObservableProperty] private bool _isPanMode;

        public VisualizationViewModel(
            IChartDataService? chartDataService = null,
            IChartExportService? exportService = null)
        {
            _chartDataService = chartDataService ?? new ChartDataService();
            _exportService = exportService ?? new ChartExportService();

            InitializeAxes();
        }

        private void InitializeAxes()
        {
            TimeSeriesXAxes = new ObservableCollection<Axis>
            {
                new DateTimeAxis(TimeSpan.FromSeconds(1), date => date.ToString("HH:mm:ss"))
                {
                    Name = "Time",
                    NamePaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextPrimary", "#E6EDF3"))),
                    LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E")))
                }
            };

            TimeSeriesYAxes = new ObservableCollection<Axis>
            {
                new Axis
                {
                    Name = "Value",
                    NamePaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextPrimary", "#E6EDF3"))),
                    LabelsPaint = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("TextMuted", "#8B949E")))
                }
            };
        }

        /// <summary>
        /// Updates all visualizations with new packet data
        /// </summary>
        public async Task UpdateVisualizationsAsync(List<PacketInfo> packets, NetworkStatistics statistics)
        {
            try
            {
                IsLoading = true;
                StatusMessage = "Updating visualizations...";

                _currentPackets = packets;
                _currentStatistics = statistics;

                await Task.WhenAll(
                    UpdateTimeSeriesAsync(),
                    UpdateHeatmapAsync(),
                    UpdateHistogramAsync(),
                    UpdateNetworkGraphAsync()
                );

                LastUpdate = DateTime.Now;
                DataPointCount = packets.Count;
                StatusMessage = $"Updated {packets.Count:N0} data points";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
                DebugLogger.Log($"[VisualizationViewModel] Update error: {ex.Message}");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private async Task UpdateTimeSeriesAsync()
        {
            if (_currentStatistics?.ThroughputTimeSeries == null || !_currentStatistics.ThroughputTimeSeries.Any())
                return;

            await Task.Run(() =>
            {
                var cacheKey = "timeseries_throughput";
                var cached = _chartDataService.GetCachedData<List<TimeSeriesDataPoint>>(cacheKey);

                var data = cached ?? _currentStatistics.ThroughputTimeSeries;

                if (data.Count > 1000)
                {
                    data = _chartDataService.AggregateTimeSeries(data, TimeSpan.FromSeconds(1));
                    _chartDataService.CacheChartData(cacheKey, data);
                }

                var series = new LineSeries<TimeSeriesDataPoint>
                {
                    Values = data,
                    Mapping = (point, index) =>
                    {
                        return new LiveChartsCore.Kernel.Coordinate(index, point.Value);
                    },
                    Fill = null,
                    Stroke = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6")), 2),
                    GeometrySize = 0,
                    LineSmoothness = 0,
                    Name = "Throughput"
                };

                TimeSeriesSeries = new ObservableCollection<ISeries> { series };
            });
        }

        private async Task UpdateHeatmapAsync()
        {
            if (_currentPackets == null || !_currentPackets.Any())
                return;

            await Task.Run(() =>
            {
                var heatmapData = _chartDataService.CreateHeatmap(_currentPackets, "hour", "protocol");

                XLabels = new ObservableCollection<string>(heatmapData.XLabels);
                YLabels = new ObservableCollection<string>(heatmapData.YLabels);
                ColumnCount = heatmapData.XLabels.Count;
                RowCount = heatmapData.YLabels.Count;

                var cells = new ObservableCollection<HeatmapCellViewModel>();

                foreach (var cell in heatmapData.Cells)
                {
                    var intensity = (double)cell.Intensity / heatmapData.MaxIntensity;
                    cells.Add(new HeatmapCellViewModel
                    {
                        XValue = cell.XValue,
                        YValue = cell.YValue,
                        Intensity = cell.Intensity,
                        IntensityText = cell.Intensity > 10 ? cell.Intensity.ToString() : "",
                        CellColor = GetHeatColor(intensity),
                        TextColor = intensity > 0.5 ? ThemeColorHelper.GetColorHex("TextPrimary", "#FFFFFF") : ThemeColorHelper.GetColorHex("BackgroundPrimary", "#0D1117"),
                        Tooltip = $"{cell.YValue} at {cell.XValue}: {cell.Intensity:N0} packets"
                    });
                }

                HeatmapCells = cells;
            });
        }

        private async Task UpdateHistogramAsync()
        {
            if (_currentPackets == null || !_currentPackets.Any())
                return;

            await Task.Run(() =>
            {
                var histogram = _chartDataService.CreateHistogram(
                    _currentPackets,
                    p => p.Length,
                    20
                );

                var values = histogram.Select(kvp => new HistogramBar
                {
                    Category = kvp.Key,
                    Count = kvp.Value
                }).ToList();

                var series = new ColumnSeries<HistogramBar>
                {
                    Values = values,
                    Mapping = (bar, index) =>
                    {
                        return new LiveChartsCore.Kernel.Coordinate(index, bar.Count);
                    },
                    Fill = new SolidColorPaint(SKColor.Parse(ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"))),
                    Name = "Packet Size Distribution"
                };

                HistogramSeries = new ObservableCollection<ISeries> { series };
            });
        }

        private async Task UpdateNetworkGraphAsync()
        {
            if (_currentStatistics?.TopConversations == null || !_currentStatistics.TopConversations.Any())
                return;

            await Task.Run(() =>
            {
                var graphData = _chartDataService.CreateNetworkGraph(_currentStatistics.TopConversations, 50);

                // Simple circular layout
                var nodes = new ObservableCollection<NetworkNodeViewModel>();
                var radius = 200.0;
                var centerX = 300.0;
                var centerY = 300.0;
                var angleStep = 2 * Math.PI / graphData.Nodes.Count;

                for (int i = 0; i < graphData.Nodes.Count; i++)
                {
                    var node = graphData.Nodes[i];
                    var angle = i * angleStep;
                    var x = centerX + radius * Math.Cos(angle);
                    var y = centerY + radius * Math.Sin(angle);

                    nodes.Add(new NetworkNodeViewModel
                    {
                        Id = node.Id,
                        Label = node.Label.Length > 15 ? string.Concat(node.Label.AsSpan(0, 12), "...") : node.Label,
                        X = x,
                        Y = y,
                        NodeSize = Math.Max(20, Math.Min(60, node.Size / 100)),
                        NodeRadius = "50%",
                        NodeColor = node.Type == "source" ? ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6") : ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
                        Tooltip = $"{node.Label}\nPackets: {node.Size:N0}"
                    });
                }

                var edges = new ObservableCollection<NetworkEdgeViewModel>();
                foreach (var edge in graphData.Edges)
                {
                    var sourceNode = nodes.FirstOrDefault(n => n.Id == edge.Source);
                    var targetNode = nodes.FirstOrDefault(n => n.Id == edge.Target);

                    if (sourceNode != null && targetNode != null)
                    {
                        edges.Add(new NetworkEdgeViewModel
                        {
                            StartPoint = new Avalonia.Point(sourceNode.X, sourceNode.Y),
                            EndPoint = new Avalonia.Point(targetNode.X, targetNode.Y),
                            Thickness = Math.Max(1, Math.Min(5, edge.Weight / 1000)),
                            EdgeColor = ThemeColorHelper.GetColorHex("TextMuted", "#718096")
                        });
                    }
                }

                Nodes = nodes;
                Edges = edges;
                NodeCount = nodes.Count;
                EdgeCount = edges.Count;
            });
        }

        private string GetHeatColor(double intensity)
        {
            // Heat color scheme: blue (cold) -> red (hot)
            if (intensity < 0.2) return ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
            if (intensity < 0.4) return ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
            if (intensity < 0.6) return ThemeColorHelper.GetColorHex("AccentYellow", "#FCD34D");
            if (intensity < 0.8) return ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B");
            return ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
        }

        [RelayCommand]
        public void ResetZoom()
        {
            // Reset zoom on time series
            StatusMessage = "Zoom reset";
        }

        [RelayCommand]
        public void TogglePanMode()
        {
            IsPanMode = !IsPanMode;
            StatusMessage = IsPanMode ? "Pan mode enabled" : "Pan mode disabled";
        }

        [RelayCommand]
        public void EnableRealTime()
        {
            if (_isRealTimeEnabled)
            {
                StopRealTimeUpdates();
            }
            else
            {
                StartRealTimeUpdates();
            }
        }

        private void StartRealTimeUpdates()
        {
            _isRealTimeEnabled = true;
            _updateTimer = new Timer(
                async _ => await RefreshDataAsync(),
                null,
                TimeSpan.Zero,
                TimeSpan.FromMilliseconds(UpdateInterval)
            );
            StatusMessage = "Real-time updates enabled";
        }

        private void StopRealTimeUpdates()
        {
            _isRealTimeEnabled = false;
            _updateTimer?.Dispose();
            _updateTimer = null;
            StatusMessage = "Real-time updates disabled";
        }

        private async Task RefreshDataAsync()
        {
            if (_currentPackets != null && _currentStatistics != null)
            {
                await UpdateVisualizationsAsync(_currentPackets, _currentStatistics);
            }
        }

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _updateTimer = null;
        }
    }

    // Helper ViewModels
    public class HeatmapCellViewModel
    {
        public string XValue { get; set; } = string.Empty;
        public string YValue { get; set; } = string.Empty;
        public long Intensity { get; set; }
        public string IntensityText { get; set; } = string.Empty;
        public string CellColor { get; set; } = ThemeColorHelper.GetColorHex("TextMuted", "#808080");
        public string TextColor { get; set; } = ThemeColorHelper.GetColorHex("TextPrimary", "#FFFFFF");
        public string Tooltip { get; set; } = string.Empty;
    }

    public class NetworkNodeViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public double X { get; set; }
        public double Y { get; set; }
        public double NodeSize { get; set; } = 30;
        public string NodeRadius { get; set; } = "50%";
        public string NodeColor { get; set; } = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
        public string Tooltip { get; set; } = string.Empty;
    }

    public class NetworkEdgeViewModel
    {
        public Avalonia.Point StartPoint { get; set; }
        public Avalonia.Point EndPoint { get; set; }
        public double Thickness { get; set; } = 1;
        public string EdgeColor { get; set; } = ThemeColorHelper.GetColorHex("TextMuted", "#718096");
    }

    public class HistogramBar
    {
        public string Category { get; set; } = string.Empty;
        public int Count { get; set; }
    }

    public class LegendItemViewModel
    {
        public string Color { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
    }
}
