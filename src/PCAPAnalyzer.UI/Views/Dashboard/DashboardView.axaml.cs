using System;
using System.ComponentModel;
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
using Microsoft.Extensions.DependencyInjection;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.Defaults;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// DashboardView - Main partial class for initialization and lifecycle management.
///
/// Partial class structure:
/// - DashboardView.axaml.cs (this file): Lifecycle, caching, event wiring
/// - DashboardView.ChartHandlers.cs: Pointer events, tooltip rendering
/// - DashboardView.TooltipManager.cs: Highlight series management
/// - DashboardView.ZoomControls.cs: Chart zoom functionality
/// </summary>
public partial class DashboardView : UserControl
{
    #region Fields

    // Cached data for efficient tooltip rendering
    private readonly Dictionary<string, List<DateTimePoint>> _cachedTrafficData = [];
    private readonly Dictionary<string, List<object>> _cachedPortData = [];

    // Cached ViewModel references for cleanup
    private DashboardViewModel? _dashboardVm;
    private ViewModels.Components.UnifiedFilterPanelViewModel? _filterPanelVm;

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

    #endregion

    #region Constructor

    public DashboardView()
    {
        InitializeComponent();
    }

    #endregion

    #region Lifecycle

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);

        if (DataContext is DashboardViewModel vm)
        {
            _dashboardVm = vm;
            vm.PropertyChanged += OnDashboardViewModelDataPropertyChanged;

            // Cache initial data if available
            if (vm.TimelineSeries?.Count > 0)
                CacheTrafficData(vm.TimelineSeries);
            if (vm.PortActivitySeries?.Count > 0)
                CachePortData(vm.PortActivitySeries);
        }

        WireUpFilterPanelEvents();
    }

    protected override void OnUnloaded(RoutedEventArgs e)
    {
        base.OnUnloaded(e);

        // Unsubscribe from filter panel events
        if (_filterPanelVm is not null)
        {
            _filterPanelVm.ApplyFiltersRequested -= OnFilterPanelApplyRequested;
            _filterPanelVm.IsApplyingFilter = false;
            _filterPanelVm = null;
        }

        // Unsubscribe from DashboardViewModel property changes
        if (_dashboardVm is not null)
        {
            _dashboardVm.PropertyChanged -= OnDashboardViewModelDataPropertyChanged;
            _dashboardVm.PropertyChanged -= OnDashboardViewModelFilterProgressChanged;
            _dashboardVm = null;
        }
    }

    #endregion

    #region Filter Panel Integration

    private void WireUpFilterPanelEvents()
    {
        var filterPanel = this.FindControl<Controls.UnifiedFilterPanelControl>("UnifiedFilterPanel");
        if (filterPanel?.DataContext is ViewModels.Components.UnifiedFilterPanelViewModel filterPanelVm)
        {
            _filterPanelVm = filterPanelVm;
            filterPanelVm.ApplyFiltersRequested += OnFilterPanelApplyRequested;

            if (_dashboardVm is not null)
                _dashboardVm.PropertyChanged += OnDashboardViewModelFilterProgressChanged;
        }
    }

    private void OnFilterPanelApplyRequested()
    {
        _dashboardVm?.ApplyGlobalFilters();
    }

    /// <summary>
    /// Mirrors filter progress state to the filter panel for UI feedback.
    /// </summary>
    private void OnDashboardViewModelFilterProgressChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_filterPanelVm is null || sender is not DashboardViewModel dashVm)
            return;

        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            switch (e.PropertyName)
            {
                case nameof(DashboardViewModel.IsFilteringInProgress):
                    _filterPanelVm.IsApplyingFilter = dashVm.IsFilteringInProgress;
                    break;
                case nameof(DashboardViewModel.FilterProgress):
                    _filterPanelVm.FilterProgress = dashVm.FilterProgress;
                    break;
            }
        });
    }

    #endregion

    #region Data Caching

    /// <summary>
    /// Handles data property changes for cache invalidation.
    /// </summary>
    private void OnDashboardViewModelDataPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not DashboardViewModel vm)
            return;

        switch (e.PropertyName)
        {
            case nameof(DashboardViewModel.TimelineSeries):
                CacheTrafficData(vm.TimelineSeries);
                break;
            case nameof(DashboardViewModel.PortActivitySeries):
                CachePortData(vm.PortActivitySeries);
                break;
        }
    }

    /// <summary>
    /// Caches traffic data and calculates min/max Y values per axis for vertical line rendering.
    /// </summary>
    private void CacheTrafficData(ObservableCollection<ISeries>? series)
    {
        _cachedTrafficData.Clear();

        if (series is null || series.Count == 0)
            return;

        double throughputMin = double.MaxValue, throughputMax = double.MinValue;
        double packetsMin = double.MaxValue, packetsMax = double.MinValue;
        double anomaliesMin = double.MaxValue, anomaliesMax = double.MinValue;

        foreach (var s in series)
        {
            if (s is not LineSeries<DateTimePoint> dateTimeSeries || dateTimeSeries.Values is null)
                continue;

            var name = dateTimeSeries.Name ?? "Unknown";
            if (name is "Highlight" or "VerticalLine")
                continue;

            var values = dateTimeSeries.Values.Cast<DateTimePoint>().ToList();
            _cachedTrafficData[name] = values;

            int scalesYAt = dateTimeSeries.ScalesYAt;
            foreach (var point in values.Where(p => p?.Value.HasValue == true))
            {
                var val = point.Value!.Value;
                switch (scalesYAt)
                {
                    case 0: // Throughput
                        throughputMin = Math.Min(throughputMin, val);
                        throughputMax = Math.Max(throughputMax, val);
                        break;
                    case 1: // Packets
                        packetsMin = Math.Min(packetsMin, val);
                        packetsMax = Math.Max(packetsMax, val);
                        break;
                    case 2: // Anomalies
                        anomaliesMin = Math.Min(anomaliesMin, val);
                        anomaliesMax = Math.Max(anomaliesMax, val);
                        break;
                }
            }
        }

        // Apply cached values with defaults
        _cachedThroughputMinY = throughputMin == double.MaxValue ? 0 : Math.Min(0, throughputMin);
        _cachedThroughputMaxY = throughputMax == double.MinValue ? 0 : throughputMax;
        _cachedPacketsMinY = packetsMin == double.MaxValue ? 0 : Math.Min(0, packetsMin);
        _cachedPacketsMaxY = packetsMax == double.MinValue ? 0 : packetsMax;
        _cachedAnomaliesMinY = anomaliesMin == double.MaxValue ? 0 : Math.Min(0, anomaliesMin);
        _cachedAnomaliesMaxY = anomaliesMax == double.MinValue ? 0 : anomaliesMax;
    }

    /// <summary>
    /// Caches port activity data. Handles both DateTimePoint and ObservablePoint types.
    /// </summary>
    private void CachePortData(ObservableCollection<ISeries>? series)
    {
        _cachedPortData.Clear();

        if (series is null || series.Count == 0)
            return;

        double min = double.MaxValue;
        double max = double.MinValue;

        foreach (var s in series)
        {
            var name = s.Name ?? "Unknown";
            if (name is "Highlight" or "VerticalLine")
                continue;

            if (s is LineSeries<DateTimePoint> dateTimeSeries && dateTimeSeries.Values is not null)
            {
                var values = dateTimeSeries.Values.Cast<object>().ToList();
                _cachedPortData[name] = values;

                foreach (var dt in values.OfType<DateTimePoint>().Where(p => p.Value.HasValue))
                {
                    min = Math.Min(min, dt.Value!.Value);
                    max = Math.Max(max, dt.Value!.Value);
                }
            }
            else if (s is LineSeries<ObservablePoint> observableSeries && observableSeries.Values is not null)
            {
                var values = observableSeries.Values.Cast<object>().ToList();
                _cachedPortData[name] = values;

                foreach (var op in values.OfType<ObservablePoint>().Where(p => p.Y.HasValue))
                {
                    min = Math.Min(min, op.Y!.Value);
                    max = Math.Max(max, op.Y!.Value);
                }
            }
        }

        _cachedPortMinY = min == double.MaxValue ? 0 : Math.Min(0, min);
        _cachedPortMaxY = max == double.MinValue ? 0 : max;
    }

    #endregion

    #region Chart Interactions

    /// <summary>
    /// Handles chart click for drill-down functionality.
    /// </summary>
    private void OnChartPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (sender is not LiveChartsCore.SkiaSharpView.Avalonia.CartesianChart chart)
            return;
        if (_dashboardVm?.DrillDown is null)
            return;

        var clickPos = e.GetPosition(chart);
        var timestamp = FindNearestTimestamp(chart, clickPos);

        if (timestamp.HasValue)
        {
            _dashboardVm.DrillDown.ShowForTimeSlice(
                timestamp.Value,
                ChartConstants.DrillDownTimeWindow,
                _dashboardVm.CurrentPackets);
        }
    }

    private DateTime? FindNearestTimestamp(LiveChartsCore.SkiaSharpView.Avalonia.CartesianChart chart, Avalonia.Point clickPos)
    {
        var firstSeries = _cachedTrafficData.Values.FirstOrDefault();
        if (firstSeries is null || firstSeries.Count == 0)
            return null;

        var chartWidth = chart.Bounds.Width;
        if (chartWidth <= 0)
            return null;

        var normalizedX = Math.Clamp(clickPos.X / chartWidth, 0, 1);
        var dataIndex = Math.Clamp((int)(normalizedX * (firstSeries.Count - 1)), 0, firstSeries.Count - 1);

        return firstSeries[dataIndex]?.DateTime;
    }

    /// <summary>
    /// Closes drill-down popup when clicking outside.
    /// </summary>
    private void OnPopupBackgroundPressed(object? sender, PointerPressedEventArgs e)
    {
        _dashboardVm?.DrillDown?.CloseCommand.Execute(null);
    }

    #endregion

    #region Filter Copy

    /// <summary>
    /// Handles filter copy button click.
    /// </summary>
    private void OnFilterCopyClick(object? sender, RoutedEventArgs e)
    {
        var filterCopyService = App.Services?.GetService<FilterCopyService>();
        if (filterCopyService is null)
            return;

        var comboBox = this.FindControl<ComboBox>("FilterCopyDestination");
        if (comboBox?.SelectedItem is ComboBoxItem { Content: string destinationTabName })
        {
            filterCopyService.CopyFilters(TabNames.Dashboard, destinationTabName);
        }
    }

    #endregion
}
