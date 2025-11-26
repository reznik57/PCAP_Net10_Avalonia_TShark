using System;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Coordinates analysis orchestration and tab population.
/// Extracts orchestration logic from MainWindowViewModel for better testability.
/// </summary>
public interface IAnalysisCoordinator
{
    /// <summary>
    /// Run complete analysis: load packets → analyze → cache → populate tabs → notify
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file to analyze</param>
    /// <param name="progress">Optional progress reporter for UI updates</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Analysis result with all data</returns>
    Task<AnalysisResult> RunAnalysisAsync(
        string pcapPath,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>
    /// Populate all registered tab ViewModels from cached analysis result
    /// </summary>
    /// <param name="result">Cached analysis result</param>
    Task PopulateTabsAsync(AnalysisResult result);

    /// <summary>
    /// Register tab ViewModels for population (called at app startup)
    /// </summary>
    /// <param name="tabs">Array of tab population targets</param>
    void RegisterTabs(params ITabPopulationTarget[] tabs);

    /// <summary>
    /// Event raised when analysis completes (for UI notification)
    /// </summary>
    event EventHandler<CoordinatorCompletedEventArgs>? AnalysisCompleted;

    /// <summary>
    /// Event raised when analysis fails (for UI error handling)
    /// </summary>
    event EventHandler<CoordinatorFailedEventArgs>? AnalysisFailed;

    /// <summary>
    /// Handle lazy loading when user switches tabs.
    /// Loads data on-demand for tabs that weren't preloaded.
    /// </summary>
    /// <param name="tabIndex">Index of the selected tab</param>
    /// <param name="packets">Current packet collection for analysis</param>
    /// <returns>True if tab was loaded, false if already loaded or not a lazy-load tab</returns>
    Task<bool> HandleTabSelectionAsync(int tabIndex, IReadOnlyList<PacketInfo> packets);

    /// <summary>
    /// Check if a specific tab needs lazy loading.
    /// </summary>
    /// <param name="tabIndex">Index of the tab to check</param>
    /// <returns>True if tab requires lazy loading</returns>
    bool RequiresLazyLoading(int tabIndex);
}

/// <summary>
/// Event args for successful coordinator analysis completion.
/// Named "Coordinator*" to avoid collision with UI.Models.AnalysisCompletedEventArgs.
/// </summary>
public class CoordinatorCompletedEventArgs : EventArgs
{
    public AnalysisResult Result { get; }
    public TimeSpan Duration { get; }

    public CoordinatorCompletedEventArgs(AnalysisResult result, TimeSpan duration)
    {
        Result = result;
        Duration = duration;
    }
}

/// <summary>
/// Event args for coordinator analysis failure.
/// Named "Coordinator*" to avoid collision with UI event args.
/// </summary>
public class CoordinatorFailedEventArgs : EventArgs
{
    public string ErrorMessage { get; }
    public Exception? Exception { get; }

    public CoordinatorFailedEventArgs(string errorMessage, Exception? exception = null)
    {
        ErrorMessage = errorMessage;
        Exception = exception;
    }
}
