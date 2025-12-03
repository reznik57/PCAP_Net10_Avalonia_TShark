using System.Text.Json.Serialization;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Root object for insecure ports JSON data file
/// </summary>
public sealed record InsecurePortDataFile
{
    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("lastUpdated")]
    public required string LastUpdated { get; init; }

    [JsonPropertyName("ports")]
    public required IReadOnlyList<InsecurePortEntry> Ports { get; init; }
}

/// <summary>
/// Represents a single insecure port entry from JSON
/// </summary>
public sealed record InsecurePortEntry
{
    [JsonPropertyName("port")]
    public required int Port { get; init; }

    [JsonPropertyName("protocol")]
    public required string Protocol { get; init; }

    [JsonPropertyName("serviceName")]
    public required string ServiceName { get; init; }

    [JsonPropertyName("riskLevel")]
    public required string RiskLevel { get; init; }

    [JsonPropertyName("isEncrypted")]
    public required bool IsEncrypted { get; init; }

    [JsonPropertyName("knownVulnerabilities")]
    public required IReadOnlyList<string> KnownVulnerabilities { get; init; }

    [JsonPropertyName("recommendedAlternative")]
    public required string RecommendedAlternative { get; init; }

    [JsonPropertyName("securityNotes")]
    public required string SecurityNotes { get; init; }

    [JsonPropertyName("requiresImmediateAction")]
    public required bool RequiresImmediateAction { get; init; }
}
