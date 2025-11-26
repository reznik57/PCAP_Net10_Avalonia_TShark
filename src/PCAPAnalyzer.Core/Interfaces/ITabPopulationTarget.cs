using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Interface for tab ViewModels that can be populated from cached analysis results.
/// Enables AnalysisCoordinatorService to populate all tabs in parallel without coupling.
/// </summary>
public interface ITabPopulationTarget
{
    /// <summary>
    /// Tab name for logging and diagnostics
    /// </summary>
    string TabName { get; }

    /// <summary>
    /// Populate this tab's data from cached analysis result.
    /// Implementation should be thread-safe and update UI on dispatcher.
    /// </summary>
    /// <param name="result">Cached analysis result containing all data</param>
    Task PopulateFromCacheAsync(AnalysisResult result);
}

/// <summary>
/// Interface for tabs that support lazy loading (load data on-demand when tab selected).
/// Extends ITabPopulationTarget with loading state and on-demand data loading.
/// </summary>
public interface ILazyLoadableTab : ITabPopulationTarget
{
    /// <summary>
    /// Indicates whether data has been loaded for this tab.
    /// Used to prevent redundant loading on repeated tab selection.
    /// </summary>
    bool IsDataLoaded { get; }

    /// <summary>
    /// Indicates whether data is currently being loaded.
    /// Used to show loading spinner in UI.
    /// </summary>
    bool IsLoading { get; set; }

    /// <summary>
    /// Load data on-demand when user selects this tab.
    /// Called by AnalysisCoordinator when tab is selected and IsDataLoaded is false.
    /// </summary>
    /// <param name="packets">Current packet collection for analysis</param>
    Task LoadDataAsync(IReadOnlyList<PacketInfo> packets);
}
