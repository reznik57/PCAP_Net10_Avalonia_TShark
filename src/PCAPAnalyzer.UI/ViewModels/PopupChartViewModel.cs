using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class PopupChartViewModel : ObservableObject
    {
        [ObservableProperty] private ObservableCollection<ISeries> _chartSeries = new();
        [ObservableProperty] private ObservableCollection<ISeries> _pieSeries = new();
        [ObservableProperty] private ObservableCollection<ISeries> _cartesianSeries = new();
        [ObservableProperty] private Axis[]? _chartXAxes;
        [ObservableProperty] private Axis[]? _chartYAxes;
        [ObservableProperty] private bool _isTimelineChart;
        [ObservableProperty] private bool _isProtocolChart;
        [ObservableProperty] private bool _isPortsChart;
        [ObservableProperty] private string _chartType = "";

        public PopupChartViewModel(string chartType, ObservableCollection<ISeries>? series, Axis[]? xAxes = null, Axis[]? yAxes = null)
        {
            try
            {
                ChartType = chartType ?? "";
                var inputSeries = series ?? new ObservableCollection<ISeries>();
                
                // Reset all visibility flags and series first
                IsTimelineChart = false;
                IsProtocolChart = false;
                IsPortsChart = false;
                ChartSeries = new ObservableCollection<ISeries>();
                PieSeries = new ObservableCollection<ISeries>();
                CartesianSeries = new ObservableCollection<ISeries>();
                
                // Set axes only for cartesian charts
                bool needsAxes = false;

                // Set visibility flags and appropriate series based on chart type
                switch (chartType?.ToLower())
                {
                    case "timeline":
                        IsTimelineChart = true;
                        needsAxes = true;
                        CartesianSeries = inputSeries;
                        ChartSeries = inputSeries; // For backward compatibility
                        System.Diagnostics.Debug.WriteLine($"[PopupChartViewModel] Setting up timeline chart with {inputSeries?.Count ?? 0} series");
                        break;
                    case "protocol":
                        IsProtocolChart = true;
                        needsAxes = false; // Pie chart doesn't need axes
                        PieSeries = inputSeries;
                        ChartSeries = inputSeries; // For backward compatibility
                        System.Diagnostics.Debug.WriteLine($"[PopupChartViewModel] Setting up protocol chart with {inputSeries?.Count ?? 0} series");
                        break;
                    case "ports":
                        IsPortsChart = true;
                        needsAxes = true;
                        CartesianSeries = inputSeries;
                        ChartSeries = inputSeries; // For backward compatibility
                        System.Diagnostics.Debug.WriteLine($"[PopupChartViewModel] Setting up ports chart with {inputSeries?.Count ?? 0} series");
                        break;
                    default:
                        // Default to protocol chart if type is unknown
                        IsProtocolChart = true;
                        needsAxes = false;
                        PieSeries = inputSeries;
                        ChartSeries = inputSeries; // For backward compatibility
                        System.Diagnostics.Debug.WriteLine($"[PopupChartViewModel] Unknown chart type '{chartType}', defaulting to protocol");
                        break;
                }
                
                // Only set axes if needed
                if (needsAxes)
                {
                    ChartXAxes = xAxes;
                    ChartYAxes = yAxes;
                }
                else
                {
                    // Explicitly null out axes for non-cartesian charts
                    ChartXAxes = null;
                    ChartYAxes = null;
                }
                
                // Log the final state
                System.Diagnostics.Debug.WriteLine($"[PopupChartViewModel] Chart initialized - Type: {ChartType}, Timeline: {IsTimelineChart}, Protocol: {IsProtocolChart}, Ports: {IsPortsChart}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error initializing PopupChartViewModel: {ex.Message}");
                // Ensure we have at least empty collections
                ChartSeries = new ObservableCollection<ISeries>();
                ChartType = chartType ?? "";
                IsProtocolChart = true; // Default to protocol
                IsTimelineChart = false;
                IsPortsChart = false;
                ChartXAxes = null;
                ChartYAxes = null;
            }
        }
    }
}