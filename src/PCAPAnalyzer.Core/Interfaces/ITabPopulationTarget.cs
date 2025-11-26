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
