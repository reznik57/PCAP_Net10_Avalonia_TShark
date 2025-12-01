using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using LiveChartsCore;
using LiveChartsCore.Kernel;
using LiveChartsCore.Kernel.Events;
using LiveChartsCore.SkiaSharpView.Avalonia;
using LiveChartsCore.SkiaSharpView.Drawing;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using ObservablePoint = LiveChartsCore.Defaults.ObservablePoint;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// DashboardView - Main partial class for initialization and lifecycle management
    /// </summary>
    /// <remarks>
    /// This is the core partial class that handles:
    /// - Component initialization
    /// - DataContext setup
    /// - Lifecycle events (OnLoaded)
    /// - Basic chart configuration
    ///
    /// Chart interactions are in DashboardView.ChartHandlers.cs
    /// Tooltip logic is in DashboardView.TooltipManager.cs
    /// Zoom controls are in DashboardView.ZoomControls.cs
    /// </remarks>
    public partial class DashboardView : UserControl
    {
        // Cached data for efficient tooltip rendering
        private Dictionary<string, List<DateTimePoint>> _cachedTrafficData = new();
        private Dictionary<string, List<object>> _cachedPortData = new();
        // Separate min/max for each Y-axis to prevent cross-contamination
        private double _cachedThroughputMinY;
        private double _cachedThroughputMaxY;
        private double _cachedPacketsMinY;
        private double _cachedPacketsMaxY;
        private double _cachedAnomaliesMinY;
        private double _cachedAnomaliesMaxY;
        private double _cachedPortMinY;
        private double _cachedPortMaxY;

        // Highlight series for visual feedback
        private ScatterSeries<DateTimePoint>? _trafficHighlightScatter;
        private LineSeries<DateTimePoint>? _trafficHighlightLine;
        private ScatterSeries<DateTimePoint>? _portHighlightScatter;
        private LineSeries<DateTimePoint>? _portHighlightLine;
        private int _lastHighlightedIndex = -1;

        /// <summary>
        /// Initializes the DashboardView component
        /// </summary>
        public DashboardView()
        {
            try
            {
                DebugLogger.Log("[DashboardView] Constructor started");
                InitializeComponent();
                DebugLogger.Log("[DashboardView] InitializeComponent completed");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] Constructor failed: {ex.Message}");
                DebugLogger.Log($"[DashboardView] Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    DebugLogger.Log($"[DashboardView] Inner exception: {ex.InnerException.Message}");
                    DebugLogger.Log($"[DashboardView] Inner stack trace: {ex.InnerException.StackTrace}");
                }
                throw;
            }
        }

        /// <summary>
        /// Called when the view is fully loaded
        /// Sets up DataContext, caches initial data, and subscribes to ViewModel events
        /// </summary>
        protected override void OnLoaded(RoutedEventArgs e)
        {
            try
            {
                DebugLogger.Log("[DashboardView] OnLoaded started");
                base.OnLoaded(e);

                if (DataContext == null)
                {
                    DebugLogger.Log("[DashboardView] WARNING: DataContext is null in OnLoaded");
                }
                else
                {
                    DebugLogger.Log($"[DashboardView] DataContext type: {DataContext.GetType().Name}");

                    if (DataContext is DashboardViewModel vm)
                    {
                        DebugLogger.Log("[DashboardView] DataContext is DashboardViewModel");

                        // Subscribe to property changes to cache data for tooltip performance
                        vm.PropertyChanged += (s, args) =>
                        {
                            if (args.PropertyName == nameof(vm.TimelineSeries))
                            {
                                DebugLogger.Log("[DashboardView] TimelineSeries changed - caching data");
                                CacheTrafficData(vm.TimelineSeries);
                            }
                            else if (args.PropertyName == nameof(vm.PortActivitySeries))
                            {
                                DebugLogger.Log("[DashboardView] PortActivitySeries changed - caching data");
                                CachePortData(vm.PortActivitySeries);
                            }
                        };

                        // Cache initial data if available
                        if (vm.TimelineSeries != null && vm.TimelineSeries.Count > 0)
                        {
                            CacheTrafficData(vm.TimelineSeries);
                        }
                        if (vm.PortActivitySeries != null && vm.PortActivitySeries.Count > 0)
                        {
                            CachePortData(vm.PortActivitySeries);
                        }
                    }
                }

                // Set up chart event handlers
                SetupChartEventHandlers();

                // Wire up UnifiedFilterPanelControl's Apply button
                WireUpFilterPanelEvents();

                DebugLogger.Log("[DashboardView] OnLoaded completed");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnLoaded failed: {ex.Message}");
                DebugLogger.Log($"[DashboardView] Stack trace: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Wires up UnifiedFilterPanelControl's ApplyFiltersRequested event
        /// </summary>
        private void WireUpFilterPanelEvents()
        {
            try
            {
                var filterPanel = this.FindControl<Controls.UnifiedFilterPanelControl>("UnifiedFilterPanel");
                if (filterPanel?.DataContext is ViewModels.Components.UnifiedFilterPanelViewModel filterPanelVm)
                {
                    filterPanelVm.ApplyFiltersRequested += OnFilterPanelApplyRequested;
                    DebugLogger.Log("[DashboardView] Successfully subscribed to UnifiedFilterPanel.ApplyFiltersRequested");
                }
                else
                {
                    DebugLogger.Log("[DashboardView] WARNING: Could not find UnifiedFilterPanelControl or its ViewModel");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] Failed to wire filter panel events: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles UnifiedFilterPanel Apply button click
        /// </summary>
        private void OnFilterPanelApplyRequested()
        {
            try
            {
                DebugLogger.Log("[DashboardView] Filter panel Apply button clicked");

                if (DataContext is DashboardViewModel vm)
                {
                    vm.ApplyGlobalFilters();
                }
                else
                {
                    DebugLogger.Log("[DashboardView] DataContext is not DashboardViewModel");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnFilterPanelApplyRequested failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Cache traffic data for efficient tooltip rendering
        /// Stores DateTimePoint data and calculates min/max Y values PER AXIS for vertical lines
        /// </summary>
        private void CacheTrafficData(ObservableCollection<ISeries> series)
        {
            try
            {
                _cachedTrafficData.Clear();

                // Initialize min/max per axis
                double throughputMin = double.MaxValue, throughputMax = double.MinValue;
                double packetsMin = double.MaxValue, packetsMax = double.MinValue;
                double anomaliesMin = double.MaxValue, anomaliesMax = double.MinValue;

                foreach (var s in series)
                {
                    if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values != null)
                    {
                        var name = dateTimeSeries.Name ?? "Unknown";
                        if (name == "Highlight" || name == "VerticalLine")
                            continue;

                        var values = dateTimeSeries.Values.Cast<DateTimePoint>().ToList();
                        _cachedTrafficData[name] = values;
                        DebugLogger.Log($"[DashboardView] Cached {values.Count} points for traffic series: {name}");

                        // Determine which axis this series belongs to
                        int scalesYAt = dateTimeSeries.ScalesYAt;

                        foreach (var point in values)
                        {
                            if (point != null && point.Value.HasValue)
                            {
                                var val = point.Value.Value;

                                // Update appropriate axis min/max
                                if (scalesYAt == 0) // Throughput axis
                                {
                                    if (val < throughputMin) throughputMin = val;
                                    if (val > throughputMax) throughputMax = val;
                                }
                                else if (scalesYAt == 1) // Packets axis
                                {
                                    if (val < packetsMin) packetsMin = val;
                                    if (val > packetsMax) packetsMax = val;
                                }
                                else if (scalesYAt == 2) // Anomalies axis
                                {
                                    if (val < anomaliesMin) anomaliesMin = val;
                                    if (val > anomaliesMax) anomaliesMax = val;
                                }
                            }
                        }
                    }
                }

                // Set cached values with defaults if no data
                _cachedThroughputMinY = throughputMin == double.MaxValue ? 0 : Math.Min(0, throughputMin);
                _cachedThroughputMaxY = throughputMax == double.MinValue ? 0 : throughputMax;
                _cachedPacketsMinY = packetsMin == double.MaxValue ? 0 : Math.Min(0, packetsMin);
                _cachedPacketsMaxY = packetsMax == double.MinValue ? 0 : packetsMax;
                _cachedAnomaliesMinY = anomaliesMin == double.MaxValue ? 0 : Math.Min(0, anomaliesMin);
                _cachedAnomaliesMaxY = anomaliesMax == double.MinValue ? 0 : anomaliesMax;

                DebugLogger.Log($"[DashboardView] Cached Y ranges - Throughput: [{_cachedThroughputMinY:F2}, {_cachedThroughputMaxY:F2}], Packets: [{_cachedPacketsMinY:F0}, {_cachedPacketsMaxY:F0}], Anomalies: [{_cachedAnomaliesMinY:F0}, {_cachedAnomaliesMaxY:F0}]");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] CacheTrafficData error: {ex.Message}");
            }
        }

        /// <summary>
        /// Cache port activity data for efficient tooltip rendering
        /// Handles both DateTimePoint and ObservablePoint data types
        /// </summary>
        private void CachePortData(ObservableCollection<ISeries> series)
        {
            try
            {
                _cachedPortData.Clear();

                if (series == null || series.Count == 0)
                {
                    DebugLogger.Log("[DashboardView] PortActivitySeries is null or empty");
                    return;
                }

                double min = double.MaxValue;
                double max = double.MinValue;

                foreach (var s in series)
                {
                    var name = s.Name ?? "Unknown";
                    DebugLogger.Log($"[DashboardView] Processing port series: {name}, Type: {s.GetType().Name}");
                    if (name == "Highlight" || name == "VerticalLine")
                        continue;

                    if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values != null)
                    {
                        var values = dateTimeSeries.Values.Cast<object>().ToList();
                        _cachedPortData[name] = values;
                        DebugLogger.Log($"[DashboardView] Cached {values.Count} DateTimePoints for port series: {name}");

                        foreach (var obj in values)
                        {
                            if (obj is DateTimePoint dt && dt.Value.HasValue)
                            {
                                var val = dt.Value.Value;
                                if (val < min) min = val;
                                if (val > max) max = val;
                            }
                        }
                    }
                    else if (s is LineSeries<LiveChartsCore.Defaults.ObservablePoint> observableSeries && observableSeries.Values != null)
                    {
                        var values = observableSeries.Values.Cast<object>().ToList();
                        _cachedPortData[name] = values;
                        DebugLogger.Log($"[DashboardView] Cached {values.Count} ObservablePoints for port series: {name}");

                        foreach (var obj in values)
                        {
                            if (obj is ObservablePoint op && op.Y.HasValue)
                            {
                                var val = op.Y.Value;
                                if (val < min) min = val;
                                if (val > max) max = val;
                            }
                        }
                    }
                    else if (s.Values != null)
                    {
                        try
                        {
                            var values = s.Values.Cast<object>().ToList();
                            _cachedPortData[name] = values;
                            DebugLogger.Log($"[DashboardView] Cached {values.Count} generic points for port series: {name}");
                        }
                        catch (Exception innerEx)
                        {
                            DebugLogger.Log($"[DashboardView] Failed to cache generic series {name}: {innerEx.Message}");
                        }
                    }
                    else
                    {
                        DebugLogger.Log($"[DashboardView] Series {name} has no values or unsupported type");
                    }
                }

                if (min == double.MaxValue || max == double.MinValue)
                {
                    _cachedPortMinY = 0;
                    _cachedPortMaxY = 0;
                }
                else
                {
                    _cachedPortMinY = Math.Min(0, min);
                    _cachedPortMaxY = max;
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] CachePortData error: {ex.Message}");
                DebugLogger.Log($"[DashboardView] Stack: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Handles the drop event for PCAP files
        /// </summary>
        private void OnPcapDrop(object? sender, DragEventArgs e)
        {
            try
            {
                DebugLogger.Log("[DashboardView] OnPcapDrop started");

                var files = e.DataTransfer.TryGetFiles()?.ToList();
                if (files == null || !files.Any())
                {
                    DebugLogger.Log("[DashboardView] No files in drop data");
                    return;
                }

                var pcapFile = files.FirstOrDefault(f =>
                    f.Name.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) ||
                    f.Name.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase) ||
                    f.Name.EndsWith(".cap", StringComparison.OrdinalIgnoreCase));

                if (pcapFile == null)
                {
                    DebugLogger.Log("[DashboardView] No PCAP file found in dropped files");
                    return;
                }

                DebugLogger.Log($"[DashboardView] Processing dropped PCAP file: {pcapFile.Path}");

                // File loading is handled via MainWindow.LoadPcapFileAsync
                // Dashboard receives data through MainWindowViewModel after analysis completes
                DebugLogger.Log($"[DashboardView] File drop detected - use File Manager tab to load: {pcapFile.Path.LocalPath}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnPcapDrop failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles chart pointer pressed events for both Network Traffic and Port Activity charts
        /// </summary>
        private void OnChartPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            try
            {
                DebugLogger.Log("[DashboardView] OnChartPointerPressed triggered");

                if (sender is not CartesianChart chart)
                {
                    DebugLogger.Log("[DashboardView] Sender is not a CartesianChart");
                    return;
                }

                if (DataContext is not DashboardViewModel viewModel)
                {
                    DebugLogger.Log("[DashboardView] DataContext is not DashboardViewModel");
                    return;
                }

                // Find nearest data point from cached data
                var clickPos = e.GetPosition(chart);
                DateTime? nearestTimestamp = FindNearestTimestamp(chart, clickPos);

                if (nearestTimestamp.HasValue && viewModel.DrillDown != null)
                {
                    DebugLogger.Log($"[DashboardView] Found nearest timestamp: {nearestTimestamp.Value:HH:mm:ss}");
                    viewModel.DrillDown.ShowForTimeSlice(
                        nearestTimestamp.Value,
                        TimeSpan.FromSeconds(1),  // ±1 second window
                        viewModel.CurrentPackets);
                }
                else
                {
                    DebugLogger.Log("[DashboardView] No timestamp found or DrillDown is null");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnChartPointerPressed failed: {ex.Message}");
                DebugLogger.Log($"[DashboardView] Stack trace: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Finds the nearest timestamp from cached traffic data based on click position
        /// </summary>
        private DateTime? FindNearestTimestamp(CartesianChart chart, Avalonia.Point clickPos)
        {
            if (_cachedTrafficData.Count == 0)
                return null;

            // Get all timestamps from the first series
            var firstSeries = _cachedTrafficData.Values.FirstOrDefault();
            if (firstSeries == null || firstSeries.Count == 0)
                return null;

            // Map click X position to data index (approximate)
            // Chart coordinate system: 0,0 is top-left
            var chartWidth = chart.Bounds.Width;
            if (chartWidth <= 0) return null;

            // Normalize X position (0 to 1)
            var normalizedX = Math.Clamp(clickPos.X / chartWidth, 0, 1);

            // Map to data index
            var dataIndex = (int)(normalizedX * (firstSeries.Count - 1));
            dataIndex = Math.Clamp(dataIndex, 0, firstSeries.Count - 1);

            var nearestPoint = firstSeries[dataIndex];
            return nearestPoint?.DateTime;
        }

        /// <summary>
        /// Sets up chart event handlers
        /// Note: Events are primarily attached in XAML
        /// </summary>
        private void SetupChartEventHandlers()
        {
            try
            {
                DebugLogger.Log("[DashboardView] SetupChartEventHandlers called");
                // No longer needed - events are now attached directly in XAML
                // This method is kept for logging purposes
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] SetupChartEventHandlers failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles click on popup background to close drill-down popup
        /// </summary>
        private void OnPopupBackgroundPressed(object? sender, PointerPressedEventArgs e)
        {
            // Close popup when clicking outside
            if (DataContext is DashboardViewModel vm && vm.DrillDown != null)
            {
                vm.DrillDown.CloseCommand.Execute(null);
            }
        }

        /// <summary>
        /// Handles filter copy button click - copies CommonFilters to selected destination tab
        /// </summary>
        private void OnFilterCopyClick(object? sender, RoutedEventArgs e)
        {
            try
            {
                var filterCopyService = App.Services?.GetService<FilterCopyService>();
                if (filterCopyService == null)
                {
                    DebugLogger.Log("[DashboardView] FilterCopyService not available");
                    return;
                }

                var comboBox = this.FindControl<ComboBox>("FilterCopyDestination");
                if (comboBox?.SelectedItem is ComboBoxItem selectedItem)
                {
                    var destinationTabName = selectedItem.Content?.ToString();
                    if (string.IsNullOrEmpty(destinationTabName))
                    {
                        DebugLogger.Log("[DashboardView] No destination tab selected");
                        return;
                    }

                    var success = filterCopyService.CopyFilters(TabNames.Dashboard, destinationTabName);

                    if (success)
                    {
                        DebugLogger.Log($"[DashboardView] Successfully copied filters to {destinationTabName}");
                    }
                    else
                    {
                        DebugLogger.Log($"[DashboardView] Failed to copy filters to {destinationTabName}");
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[DashboardView] OnFilterCopyClick error: {ex.Message}");
            }
        }
    }
}
