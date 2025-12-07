using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages time-slice and source/target drill-down state.
/// </summary>
public partial class AnomaliesDrillDownViewModel : ObservableObject
{
    // Time slice popup
    [ObservableProperty] private bool _isTimeSlicePopupOpen;
    [ObservableProperty] private AnomalyTimeSliceSummary? _timeSliceSummary;

    // Source/Target detail popup
    [ObservableProperty] private bool _isDetailPopupOpen;
    [ObservableProperty] private string _detailPopupTitle = string.Empty;
    [ObservableProperty] private string _detailPopupSubtitle = string.Empty;
    [ObservableProperty] private int _detailTotalAnomalies;
    [ObservableProperty] private int _detailCriticalCount;
    [ObservableProperty] private int _detailHighCount;
    [ObservableProperty] private int _detailMediumCount;
    [ObservableProperty] private int _detailLowCount;

    // Time-point details popup (click on chart)
    [ObservableProperty] private bool _isTimePointPopupOpen;
    [ObservableProperty] private DateTime _timePointTimestamp;
    [ObservableProperty] private int _timePointTotalAnomalies;
    [ObservableProperty] private string _timePointTopSource = string.Empty;
    [ObservableProperty] private int _timePointTopSourceCount;
    [ObservableProperty] private string _timePointTopDestination = string.Empty;
    [ObservableProperty] private int _timePointTopDestinationCount;
    [ObservableProperty] private string _timePointTopPort = string.Empty;
    [ObservableProperty] private int _timePointTopPortCount;
    public ObservableCollection<AnomalyCategoryViewModel> TimePointCategories { get; } = [];
    public ObservableCollection<NetworkAnomaly> TimePointTopAnomalies { get; } = [];

    // Anomaly list in detail popup
    public ObservableCollection<NetworkAnomaly> DetailAnomalies { get; } = [];
    public ObservableCollection<AnomalyCategoryViewModel> DetailCategoryBreakdown { get; } = [];

    // Pagination
    [ObservableProperty] private int _detailCurrentPage = 1;
    [ObservableProperty] private int _detailTotalPages = 1;
    [ObservableProperty] private int _detailPageSize = 10;

    private List<NetworkAnomaly> _allDetailAnomalies = [];

    public void ShowTimeSliceDrillDown(
        DateTime timestamp,
        TimeSpan windowSize,
        IEnumerable<NetworkAnomaly> allAnomalies)
    {
        var windowStart = timestamp - TimeSpan.FromTicks(windowSize.Ticks / 2);
        var windowEnd = timestamp + TimeSpan.FromTicks(windowSize.Ticks / 2);

        var windowAnomalies = allAnomalies
            .Where(a => a.DetectedAt >= windowStart && a.DetectedAt <= windowEnd)
            .ToList();

        TimeSliceSummary = new AnomalyTimeSliceSummary
        {
            WindowStart = windowStart,
            WindowEnd = windowEnd,
            TotalAnomalies = windowAnomalies.Count,
            CriticalCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = windowAnomalies.Count(a => a.Severity == AnomalySeverity.Low),
            CategoryBreakdown = windowAnomalies
                .GroupBy(a => a.Category)
                .ToDictionary(g => g.Key, g => g.Count()),
            TopAnomalies = windowAnomalies
                .OrderByDescending(a => a.Severity)
                .ThenByDescending(a => a.DetectedAt)
                .Take(10)
                .ToList()
        };

        IsTimeSlicePopupOpen = true;
    }

    public void ShowSourceDetail(string ipAddress, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Source Analysis: {ipAddress}", "Anomalies originating from this IP", anomalies);
    }

    public void ShowTargetDetail(string ipAddress, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Target Analysis: {ipAddress}", "Anomalies targeting this IP", anomalies);
    }

    public void ShowPortDetail(string portName, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Port Analysis: {portName}", "Anomalies on this port", anomalies);
    }

    public void ShowCategoryDetail(string categoryName, IEnumerable<NetworkAnomaly> anomalies)
    {
        ShowDetailPopup($"Category Analysis: {categoryName}", "Anomalies in this category", anomalies);
    }

    /// <summary>
    /// Shows time-point details popup with top sources, destinations, ports, and category breakdown
    /// </summary>
    public void ShowTimePointDetails(DateTime timestamp, TimeSpan windowSize, IEnumerable<NetworkAnomaly> allAnomalies)
    {
        var windowStart = timestamp - TimeSpan.FromTicks(windowSize.Ticks / 2);
        var windowEnd = timestamp + TimeSpan.FromTicks(windowSize.Ticks / 2);

        var windowAnomalies = allAnomalies
            .Where(a => a.DetectedAt >= windowStart && a.DetectedAt <= windowEnd)
            .ToList();

        if (windowAnomalies.Count == 0)
            return;

        TimePointTimestamp = timestamp;
        TimePointTotalAnomalies = windowAnomalies.Count;

        // Top source
        var topSource = windowAnomalies
            .Where(a => !string.IsNullOrEmpty(a.SourceIP))
            .GroupBy(a => a.SourceIP)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        TimePointTopSource = topSource?.Key ?? "N/A";
        TimePointTopSourceCount = topSource?.Count() ?? 0;

        // Top destination
        var topDest = windowAnomalies
            .Where(a => !string.IsNullOrEmpty(a.DestinationIP))
            .GroupBy(a => a.DestinationIP)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        TimePointTopDestination = topDest?.Key ?? "N/A";
        TimePointTopDestinationCount = topDest?.Count() ?? 0;

        // Top port
        var topPort = windowAnomalies
            .Where(a => a.DestinationPort > 0)
            .GroupBy(a => a.DestinationPort)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        TimePointTopPort = topPort is not null ? $"Port {topPort.Key}" : "N/A";
        TimePointTopPortCount = topPort?.Count() ?? 0;

        // Category breakdown
        TimePointCategories.Clear();
        var categories = windowAnomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / windowAnomalies.Count * 100
            })
            .OrderByDescending(c => c.Count);
        foreach (var cat in categories)
            TimePointCategories.Add(cat);

        // Top anomalies (first 5)
        TimePointTopAnomalies.Clear();
        var topAnomalies = windowAnomalies
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.DetectedAt)
            .Take(5);
        foreach (var anomaly in topAnomalies)
            TimePointTopAnomalies.Add(anomaly);

        IsTimePointPopupOpen = true;
    }

    private void ShowDetailPopup(string title, string subtitle, IEnumerable<NetworkAnomaly> anomalies)
    {
        _allDetailAnomalies = anomalies
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.DetectedAt)
            .ToList();

        DetailPopupTitle = title;
        DetailPopupSubtitle = subtitle;
        DetailTotalAnomalies = _allDetailAnomalies.Count;
        DetailCriticalCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Critical);
        DetailHighCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.High);
        DetailMediumCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Medium);
        DetailLowCount = _allDetailAnomalies.Count(a => a.Severity == AnomalySeverity.Low);

        // Category breakdown
        DetailCategoryBreakdown.Clear();
        var categories = _allDetailAnomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / _allDetailAnomalies.Count * 100
            })
            .OrderByDescending(c => c.Count);

        foreach (var cat in categories)
            DetailCategoryBreakdown.Add(cat);

        // Pagination
        DetailCurrentPage = 1;
        DetailTotalPages = (int)Math.Ceiling((double)_allDetailAnomalies.Count / DetailPageSize);
        UpdateDetailPage();

        IsDetailPopupOpen = true;
    }

    private void UpdateDetailPage()
    {
        DetailAnomalies.Clear();
        var pageItems = _allDetailAnomalies
            .Skip((DetailCurrentPage - 1) * DetailPageSize)
            .Take(DetailPageSize);

        foreach (var anomaly in pageItems)
            DetailAnomalies.Add(anomaly);
    }

    [RelayCommand]
    private void NextDetailPage()
    {
        if (DetailCurrentPage < DetailTotalPages)
        {
            DetailCurrentPage++;
            UpdateDetailPage();
        }
    }

    [RelayCommand]
    private void PreviousDetailPage()
    {
        if (DetailCurrentPage > 1)
        {
            DetailCurrentPage--;
            UpdateDetailPage();
        }
    }

    [RelayCommand]
    private void CloseTimeSlicePopup()
    {
        IsTimeSlicePopupOpen = false;
        TimeSliceSummary = null;
    }

    [RelayCommand]
    private void CloseDetailPopup()
    {
        IsDetailPopupOpen = false;
        DetailAnomalies.Clear();
        DetailCategoryBreakdown.Clear();
        _allDetailAnomalies.Clear();
    }

    [RelayCommand]
    private void CloseTimePointPopup()
    {
        IsTimePointPopupOpen = false;
        TimePointCategories.Clear();
        TimePointTopAnomalies.Clear();
        TimePointTopSource = string.Empty;
        TimePointTopDestination = string.Empty;
        TimePointTopPort = string.Empty;
    }

    public void Clear()
    {
        CloseTimeSlicePopup();
        CloseDetailPopup();
        CloseTimePointPopup();
    }
}
