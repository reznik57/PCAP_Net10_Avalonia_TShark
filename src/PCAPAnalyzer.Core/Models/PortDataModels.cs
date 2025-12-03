namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// JSON-serializable port data file structure
/// </summary>
public sealed record PortDataFile
{
    public required string Version { get; init; }
    public required string LastUpdated { get; init; }
    public required List<PortEntry> Ports { get; init; }
}

/// <summary>
/// Individual port entry from JSON
/// </summary>
public sealed record PortEntry
{
    public required int Port { get; init; }
    public required string Transport { get; init; } // "TCP", "UDP", "Both"
    public required string ServiceName { get; init; }
    public required string Description { get; init; }
    public required string Risk { get; init; } // "Low", "Medium", "High", "Critical"
    public string? Category { get; init; }
    public string? Recommendation { get; init; }
}
