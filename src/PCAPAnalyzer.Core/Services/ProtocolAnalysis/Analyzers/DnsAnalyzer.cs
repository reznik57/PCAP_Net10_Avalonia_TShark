using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes DNS protocol for queries and responses.
/// Informational only - DNS does not contain credentials.
/// </summary>
public class DnsAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "DNS";
    public string[] Keywords => ["DNS"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("DNS", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "DNS",
            ContentType = "Query/Response",
            Severity = CleartextSeverity.Info,
            Description = "DNS query (informational - no credentials)"
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if ((fieldUpper.Contains("NAME", StringComparison.Ordinal) ||
                 fieldUpper.Contains("QUERY", StringComparison.Ordinal)) &&
                !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Query: {field.Value}");
            }
            else if (fieldUpper.Contains("ADDRESS", StringComparison.Ordinal) ||
                     fieldUpper.Contains("CNAME", StringComparison.Ordinal) ||
                     fieldUpper.Contains("MX", StringComparison.Ordinal))
            {
                rawParts.Add($"Answer: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        return rawParts.Count > 0 ? content : null;
    }
}
