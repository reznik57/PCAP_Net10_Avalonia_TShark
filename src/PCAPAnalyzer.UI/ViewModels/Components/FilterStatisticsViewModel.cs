using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for filter statistics tracking and efficiency calculation.
/// Handles packet counts, filter descriptions, and analysis state.
/// </summary>
public partial class FilterStatisticsViewModel : ObservableObject
{
    // Packet statistics
    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _filteredPackets;
    [ObservableProperty] private string _filterEfficiency = "0%";

    // Filter state
    [ObservableProperty] private bool _isFilterActive;
    [ObservableProperty] private string _filterDescription = "No filter applied";
    [ObservableProperty] private string _combinedFiltersDescription = "";
    [ObservableProperty] private bool _hasCombinedFilters;

    // Analysis state
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private bool _canApplyFilters = true;

    /// <summary>
    /// Event raised when statistics are updated
    /// </summary>
    public event EventHandler? StatisticsUpdated;

    /// <summary>
    /// Updates packet counts and recalculates efficiency
    /// </summary>
    public void UpdatePacketCounts(long total, long filtered)
    {
        TotalPackets = total;
        FilteredPackets = filtered;
        CalculateFilterEfficiency();

        DebugLogger.Log($"[FilterStatisticsViewModel] Updated counts: {FilteredPackets:N0} / {TotalPackets:N0}");
        StatisticsUpdated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Calculates filter efficiency percentage
    /// </summary>
    private void CalculateFilterEfficiency()
    {
        if (TotalPackets == 0)
        {
            FilterEfficiency = "0%";
            return;
        }

        var efficiency = (FilteredPackets * 100.0) / TotalPackets;
        FilterEfficiency = $"{efficiency:F1}%";
    }

    /// <summary>
    /// Updates filter description from active filters
    /// </summary>
    public void UpdateFilterDescription(
        string basicFilters,
        string quickFilters,
        string protocolFilters,
        bool useAndMode)
    {
        var descriptions = new List<string>();

        if (!string.IsNullOrWhiteSpace(basicFilters))
            descriptions.Add(basicFilters);
        if (!string.IsNullOrWhiteSpace(quickFilters))
            descriptions.Add(quickFilters);
        if (!string.IsNullOrWhiteSpace(protocolFilters))
            descriptions.Add(protocolFilters);

        if (descriptions.Count == 0)
        {
            FilterDescription = "No filter applied";
            IsFilterActive = false;
            CombinedFiltersDescription = "";
            HasCombinedFilters = false;
            return;
        }

        var mode = useAndMode ? " AND " : " OR ";
        FilterDescription = string.Join(mode, descriptions);
        IsFilterActive = true;
        CombinedFiltersDescription = FilterDescription;
        HasCombinedFilters = descriptions.Count > 1;

        DebugLogger.Log($"[FilterStatisticsViewModel] Filter description updated: {FilterDescription}");
    }

    /// <summary>
    /// Sets the analysis state
    /// </summary>
    public void SetAnalyzing(bool analyzing)
    {
        IsAnalyzing = analyzing;
        CanApplyFilters = !analyzing;
        DebugLogger.Log($"[FilterStatisticsViewModel] Analysis state: {(analyzing ? "Running" : "Idle")}");
    }

    /// <summary>
    /// Resets all statistics
    /// </summary>
    public void Reset()
    {
        TotalPackets = 0;
        FilteredPackets = 0;
        FilterEfficiency = "0%";
        FilterDescription = "No filter applied";
        CombinedFiltersDescription = "";
        HasCombinedFilters = false;
        IsFilterActive = false;
        IsAnalyzing = false;
        CanApplyFilters = true;

        DebugLogger.Log("[FilterStatisticsViewModel] Reset all statistics");
        StatisticsUpdated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets summary of filter statistics
    /// </summary>
    public string GetSummary()
    {
        if (!IsFilterActive)
            return "No filters active";

        return $"{FilteredPackets:N0} / {TotalPackets:N0} packets ({FilterEfficiency})";
    }

    /// <summary>
    /// Gets whether any filter is currently active
    /// </summary>
    public bool HasActiveFilter => IsFilterActive;

    /// <summary>
    /// Gets the reduction percentage (inverse of efficiency)
    /// </summary>
    public string GetReductionPercentage()
    {
        if (TotalPackets == 0)
            return "0%";

        var reduction = ((TotalPackets - FilteredPackets) * 100.0) / TotalPackets;
        return $"{reduction:F1}%";
    }

    // Property change handlers
    partial void OnTotalPacketsChanged(long value)
    {
        CalculateFilterEfficiency();
    }

    partial void OnFilteredPacketsChanged(long value)
    {
        CalculateFilterEfficiency();
    }

    partial void OnIsAnalyzingChanged(bool value)
    {
        CanApplyFilters = !value;
    }
}
