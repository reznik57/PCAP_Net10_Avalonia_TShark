using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes MySQL protocol for cleartext credentials.
/// Detects: Username and database in authentication packets.
/// </summary>
public class MysqlAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "MySQL";
    public string[] Keywords => ["MYSQL"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("MYSQL", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "MySQL",
            ContentType = "Authentication",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if (fieldUpper.Contains("USER", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "MySQL",
                    CredentialType = "Login",
                    FieldName = "Username",
                    Value = field.Value,
                    SecurityWarning = "MySQL username in cleartext"
                });
                rawParts.Add($"User: {field.Value}");
            }
            else if (fieldUpper.Contains("DATABASE", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Database: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "MySQL authentication detected"
            : "MySQL protocol";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
