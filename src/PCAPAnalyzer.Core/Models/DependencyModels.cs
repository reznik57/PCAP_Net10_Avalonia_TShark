namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Represents a dependency category for grouping related dependencies
/// </summary>
public enum DependencyCategory
{
    Framework,
    UIFramework,
    CoreLibrary,
    ExternalTool,
    DataFile
}

/// <summary>
/// Represents the status of a dependency
/// </summary>
public enum DependencyStatus
{
    Available,
    NotFound,
    Error,
    Unknown
}

/// <summary>
/// Information about a single dependency
/// </summary>
public sealed record DependencyInfo
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required DependencyCategory Category { get; init; }
    public DependencyStatus Status { get; init; } = DependencyStatus.Available;
    public string? Description { get; init; }
    public string? Path { get; init; }
    public string? License { get; init; }
    public string? ProjectUrl { get; init; }
}

/// <summary>
/// Complete dependency information for the application
/// </summary>
public sealed class ApplicationDependencies
{
    public required string ApplicationName { get; init; }
    public required string ApplicationVersion { get; init; }
    public required string RuntimeVersion { get; init; }
    public required string OSDescription { get; init; }
    public DateTime CollectedAt { get; init; } = DateTime.UtcNow;
    public List<DependencyInfo> Dependencies { get; init; } = [];

    public IEnumerable<DependencyInfo> GetByCategory(DependencyCategory category) =>
        Dependencies.Where(d => d.Category == category);
}
