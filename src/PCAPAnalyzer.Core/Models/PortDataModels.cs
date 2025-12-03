using System.Text.Json.Serialization;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// JSON-serializable port data file structure
/// </summary>
public sealed record PortDataFile
{
    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("lastUpdated")]
    public required string LastUpdated { get; init; }

    [JsonPropertyName("ports")]
    public required IReadOnlyList<PortEntry> Ports { get; init; }
}

/// <summary>
/// Individual port entry from JSON
/// </summary>
public sealed record PortEntry
{
    [JsonPropertyName("port")]
    public required int Port { get; init; }

    [JsonPropertyName("transport")]
    public required string Transport { get; init; } // "TCP", "UDP", "Both"

    [JsonPropertyName("serviceName")]
    public required string ServiceName { get; init; }

    [JsonPropertyName("description")]
    public required string Description { get; init; }

    [JsonPropertyName("risk")]
    public required string Risk { get; init; } // "Low", "Medium", "High", "Critical"

    [JsonPropertyName("category")]
    public string? Category { get; init; }

    [JsonPropertyName("recommendation")]
    public string? Recommendation { get; init; }
}
