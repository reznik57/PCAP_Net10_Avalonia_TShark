using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Service for collecting and reporting application dependencies
/// </summary>
public interface IDependencyService
{
    /// <summary>
    /// Collects all dependency information for the application
    /// </summary>
    Task<ApplicationDependencies> CollectDependenciesAsync(CancellationToken cancellationToken = default);
}
