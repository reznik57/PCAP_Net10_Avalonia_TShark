using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes Telnet protocol for cleartext session data.
/// Detects: Login sequences and session content.
/// </summary>
public class TelnetAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "Telnet";
    public string[] Keywords => ["TELNET"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("TELNET", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "Telnet",
            ContentType = "Session Data",
            Severity = CleartextSeverity.Warning,
            Description = "Telnet session data (all content transmitted in cleartext)"
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            if (!string.IsNullOrEmpty(field.Value) && field.Value.Length > 1)
            {
                // Telnet data is inherently cleartext
                rawParts.Add(field.Value);

                // Check for login patterns
                var valueUpper = field.Value.ToUpperInvariant();
                if (valueUpper.Contains("LOGIN", StringComparison.Ordinal) ||
                    valueUpper.Contains("USERNAME", StringComparison.Ordinal) ||
                    valueUpper.Contains("PASSWORD", StringComparison.Ordinal))
                {
                    content.Severity = CleartextSeverity.Critical;
                    content.Description = "Telnet login sequence detected - credentials may be present";
                }
            }
        }

        content.RawContent = string.Join("", rawParts);
        return rawParts.Count > 0 ? content : null;
    }
}
