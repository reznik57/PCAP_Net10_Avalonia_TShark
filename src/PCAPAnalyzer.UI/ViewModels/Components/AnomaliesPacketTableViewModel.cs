using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Filter types for the anomaly packet table
/// </summary>
public enum AnomalyPacketFilterType
{
    None,
    Source,
    Target,
    Category,
    Port,
    TimeWindow,
    Severity
}

/// <summary>
/// Manages the Anomaly Packet Table: filtering, pagination, and selection.
/// </summary>
public partial class AnomaliesPacketTableViewModel : ObservableObject
{
    private const int DefaultPageSize = 30;

    // All anomalous packets (unfiltered)
    private List<AnomalyPacketViewModel> _allPackets = new();

    // Current filtered list
    private List<AnomalyPacketViewModel> _filteredPackets = new();

    // Displayed packets (current page)
    public ObservableCollection<AnomalyPacketViewModel> Packets { get; } = new();

    // Pagination
    [ObservableProperty] private int _currentPage = 1;
    [ObservableProperty] private int _totalPages = 1;
    [ObservableProperty] private int _pageSize = DefaultPageSize;
    [ObservableProperty] private int _totalPackets;
    [ObservableProperty] private int _filteredPacketCount;

    // Filter state
    [ObservableProperty] private bool _isFilterActive;
    [ObservableProperty] private string _filterDescription = string.Empty;
    [ObservableProperty] private AnomalyPacketFilterType _activeFilterType = AnomalyPacketFilterType.None;
    private string? _filterValue;
    private DateTime? _filterTimeStart;
    private DateTime? _filterTimeEnd;

    // Selection
    [ObservableProperty] private AnomalyPacketViewModel? _selectedPacket;

    // First packet timestamp for delta calculation
    [ObservableProperty] private DateTime? _firstPacketTimestamp;

    // Events
    public event EventHandler<AnomalyPacketViewModel>? PacketSelected;

    /// <summary>
    /// Builds the anomaly packet list from packets and anomalies
    /// </summary>
    public void LoadPackets(IEnumerable<PacketInfo> allPackets, IEnumerable<NetworkAnomaly> anomalies)
    {
        try
        {
            // Build frame number → anomalies index
            var frameToAnomalies = new Dictionary<long, List<NetworkAnomaly>>();
            foreach (var anomaly in anomalies)
            {
                foreach (var frameNumber in anomaly.AffectedFrames)
                {
                    if (!frameToAnomalies.TryGetValue(frameNumber, out var list))
                    {
                        list = new List<NetworkAnomaly>();
                        frameToAnomalies[frameNumber] = list;
                    }
                    list.Add(anomaly);
                }
            }

            if (frameToAnomalies.Count == 0)
            {
                DebugLogger.Log("[AnomaliesPacketTable] No frame-to-anomaly mappings found");
                Clear();
                return;
            }

            // Join packets with anomalies
            var packetList = allPackets.ToList();
            _allPackets = packetList
                .Where(p => frameToAnomalies.ContainsKey(p.FrameNumber))
                .Select(p => new AnomalyPacketViewModel(p, frameToAnomalies[p.FrameNumber]))
                .OrderBy(p => p.FrameNumber)
                .ToList();

            TotalPackets = _allPackets.Count;
            DebugLogger.Log($"[AnomaliesPacketTable] Loaded {TotalPackets:N0} anomalous packets from {frameToAnomalies.Count:N0} frame mappings");

            // Apply current filter (or show all)
            ApplyFilter();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomaliesPacketTable] LoadPackets error: {ex.Message}");
            Clear();
        }
    }

    /// <summary>
    /// Filters to show only packets from a specific source IP
    /// </summary>
    public void FilterBySource(string sourceIP)
    {
        ActiveFilterType = AnomalyPacketFilterType.Source;
        _filterValue = sourceIP;
        FilterDescription = $"Source: {sourceIP}";
        IsFilterActive = true;
        ApplyFilter();
    }

    /// <summary>
    /// Filters to show only packets to a specific destination IP
    /// </summary>
    public void FilterByTarget(string targetIP)
    {
        ActiveFilterType = AnomalyPacketFilterType.Target;
        _filterValue = targetIP;
        FilterDescription = $"Target: {targetIP}";
        IsFilterActive = true;
        ApplyFilter();
    }

    /// <summary>
    /// Filters to show only packets of a specific anomaly category
    /// </summary>
    public void FilterByCategory(AnomalyCategory category)
    {
        ActiveFilterType = AnomalyPacketFilterType.Category;
        _filterValue = category.ToString();
        FilterDescription = $"Category: {category}";
        IsFilterActive = true;
        ApplyFilter();
    }

    /// <summary>
    /// Filters to show only packets on a specific port
    /// </summary>
    public void FilterByPort(int port)
    {
        ActiveFilterType = AnomalyPacketFilterType.Port;
        _filterValue = port.ToString();
        FilterDescription = $"Port: {port}";
        IsFilterActive = true;
        ApplyFilter();
    }

    /// <summary>
    /// Filters to show only packets within a time window
    /// </summary>
    public void FilterByTimeWindow(DateTime centerTime, TimeSpan window)
    {
        ActiveFilterType = AnomalyPacketFilterType.TimeWindow;
        _filterTimeStart = centerTime - TimeSpan.FromTicks(window.Ticks / 2);
        _filterTimeEnd = centerTime + TimeSpan.FromTicks(window.Ticks / 2);
        FilterDescription = $"Time: {centerTime:HH:mm:ss} ±{window.TotalSeconds:F0}s";
        IsFilterActive = true;
        ApplyFilter();
    }

    /// <summary>
    /// Filters to show only packets of a specific severity
    /// </summary>
    public void FilterBySeverity(AnomalySeverity severity)
    {
        ActiveFilterType = AnomalyPacketFilterType.Severity;
        _filterValue = severity.ToString();
        FilterDescription = $"Severity: {severity}";
        IsFilterActive = true;
        ApplyFilter();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        ActiveFilterType = AnomalyPacketFilterType.None;
        _filterValue = null;
        _filterTimeStart = null;
        _filterTimeEnd = null;
        FilterDescription = string.Empty;
        IsFilterActive = false;
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        _filteredPackets = ActiveFilterType switch
        {
            AnomalyPacketFilterType.Source =>
                _allPackets.Where(p => p.SourceIP == _filterValue).ToList(),

            AnomalyPacketFilterType.Target =>
                _allPackets.Where(p => p.DestinationIP == _filterValue).ToList(),

            AnomalyPacketFilterType.Category =>
                _allPackets.Where(p => p.Anomalies.Any(a => a.Category.ToString() == _filterValue)).ToList(),

            AnomalyPacketFilterType.Port =>
                _allPackets.Where(p =>
                    p.SourcePort.ToString() == _filterValue ||
                    p.DestinationPort.ToString() == _filterValue).ToList(),

            AnomalyPacketFilterType.TimeWindow =>
                _allPackets.Where(p =>
                    p.Timestamp >= _filterTimeStart && p.Timestamp <= _filterTimeEnd).ToList(),

            AnomalyPacketFilterType.Severity =>
                _allPackets.Where(p => p.Severity.ToString() == _filterValue).ToList(),

            _ => new List<AnomalyPacketViewModel>(_allPackets)
        };

        FilteredPacketCount = _filteredPackets.Count;
        FirstPacketTimestamp = _filteredPackets.Count > 0 ? _filteredPackets[0].Timestamp : null;

        // Reset to page 1 and update display
        CurrentPage = 1;
        UpdatePagination();
        UpdatePageDisplay();
    }

    private void UpdatePagination()
    {
        TotalPages = Math.Max(1, (int)Math.Ceiling((double)_filteredPackets.Count / PageSize));
        if (CurrentPage > TotalPages)
            CurrentPage = TotalPages;
    }

    private void UpdatePageDisplay()
    {
        Packets.Clear();

        if (_filteredPackets.Count == 0)
            return;

        var startIndex = (CurrentPage - 1) * PageSize;
        var endIndex = Math.Min(startIndex + PageSize, _filteredPackets.Count);

        for (int i = startIndex; i < endIndex; i++)
        {
            Packets.Add(_filteredPackets[i]);
        }
    }

    [RelayCommand]
    private void GoToFirstPage()
    {
        if (CurrentPage != 1)
        {
            CurrentPage = 1;
            UpdatePageDisplay();
        }
    }

    [RelayCommand]
    private void GoToPreviousPage()
    {
        if (CurrentPage > 1)
        {
            CurrentPage--;
            UpdatePageDisplay();
        }
    }

    [RelayCommand]
    private void GoToNextPage()
    {
        if (CurrentPage < TotalPages)
        {
            CurrentPage++;
            UpdatePageDisplay();
        }
    }

    [RelayCommand]
    private void GoToLastPage()
    {
        if (CurrentPage != TotalPages)
        {
            CurrentPage = TotalPages;
            UpdatePageDisplay();
        }
    }

    [RelayCommand]
    private void SelectPacket(AnomalyPacketViewModel? packet)
    {
        SelectedPacket = packet;
        if (packet != null)
        {
            PacketSelected?.Invoke(this, packet);
        }
    }

    public void Clear()
    {
        _allPackets.Clear();
        _filteredPackets.Clear();
        Packets.Clear();
        TotalPackets = 0;
        FilteredPacketCount = 0;
        CurrentPage = 1;
        TotalPages = 1;
        ClearFilter();
        SelectedPacket = null;
        FirstPacketTimestamp = null;
    }
}
