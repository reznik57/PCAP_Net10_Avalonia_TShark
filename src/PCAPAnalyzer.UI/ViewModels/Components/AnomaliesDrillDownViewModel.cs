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

    // Anomaly list in detail popup
    public ObservableCollection<NetworkAnomaly> DetailAnomalies { get; } = new();
    public ObservableCollection<AnomalyCategoryViewModel> DetailCategoryBreakdown { get; } = new();

    // Pagination
    [ObservableProperty] private int _detailCurrentPage = 1;
    [ObservableProperty] private int _detailTotalPages = 1;
    [ObservableProperty] private int _detailPageSize = 10;

    private List<NetworkAnomaly> _allDetailAnomalies = new();

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

    public void Clear()
    {
        CloseTimeSlicePopup();
        CloseDetailPopup();
    }
}
