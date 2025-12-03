using System.Collections.Frozen;
using System.Text.Json;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Loads insecure port data from embedded JSON resource with lazy initialization.
/// Provides high-performance frozen dictionary for port risk lookups.
/// </summary>
public static class InsecurePortDataLoader
{
    private static readonly Lazy<FrozenDictionary<int, PortRiskProfile>> _database = new(LoadDatabase);

    /// <summary>
    /// Complete insecure port database keyed by port number
    /// </summary>
    public static FrozenDictionary<int, PortRiskProfile> Database => _database.Value;

    private static FrozenDictionary<int, PortRiskProfile> LoadDatabase()
    {
        var assembly = typeof(InsecurePortDataLoader).Assembly;
        using var stream = assembly.GetManifestResourceStream(
            "PCAPAnalyzer.Core.Resources.Data.insecure-ports.json")
            ?? throw new InvalidOperationException("insecure-ports.json not found as embedded resource");

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            AllowTrailingCommas = true
        };

        var data = JsonSerializer.Deserialize<InsecurePortDataFile>(stream, options)
            ?? throw new InvalidOperationException("Failed to deserialize insecure-ports.json");

        var dict = new Dictionary<int, PortRiskProfile>(data.Ports.Count);

        foreach (var entry in data.Ports)
        {
            var riskLevel = entry.RiskLevel switch
            {
                "Critical" => ThreatSeverity.Critical,
                "High" => ThreatSeverity.High,
                "Medium" => ThreatSeverity.Medium,
                "Low" => ThreatSeverity.Low,
                "Info" => ThreatSeverity.Info,
                _ => throw new InvalidOperationException($"Unknown risk level: {entry.RiskLevel}")
            };

            var profile = new PortRiskProfile
            {
                Port = entry.Port,
                Protocol = entry.Protocol,
                ServiceName = entry.ServiceName,
                RiskLevel = riskLevel,
                IsEncrypted = entry.IsEncrypted,
                KnownVulnerabilities = entry.KnownVulnerabilities.ToArray(),
                RecommendedAlternative = entry.RecommendedAlternative,
                SecurityNotes = entry.SecurityNotes,
                RequiresImmediateAction = entry.RequiresImmediateAction
            };

            dict.TryAdd(entry.Port, profile);
        }

        return dict.ToFrozenDictionary();
    }
}
