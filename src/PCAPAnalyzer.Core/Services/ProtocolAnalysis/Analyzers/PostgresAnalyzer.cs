using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes PostgreSQL protocol for cleartext credentials.
/// Detects: Username, database, and password messages.
/// </summary>
public class PostgresAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "PostgreSQL";
    public string[] Keywords => ["PGSQL", "POSTGRESQL"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("PGSQL", StringComparison.OrdinalIgnoreCase) ||
        layerName.Contains("POSTGRESQL", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "PostgreSQL",
            ContentType = "Authentication",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if (fieldUpper.Contains("USER", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "PostgreSQL",
                    CredentialType = "Startup",
                    FieldName = "Username",
                    Value = field.Value,
                    SecurityWarning = "PostgreSQL username in cleartext"
                });
                rawParts.Add($"User: {field.Value}");
            }
            else if (fieldUpper.Contains("DATABASE", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Database: {field.Value}");
            }
            else if (fieldUpper.Contains("PASSWORD", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "PostgreSQL",
                    CredentialType = "Password Message",
                    FieldName = "Password",
                    Value = ProtocolAnalysisHelpers.MaskPassword(field.Value),
                    IsPassword = true,
                    SecurityWarning = "PostgreSQL password in cleartext!"
                });
                rawParts.Add($"Password: {ProtocolAnalysisHelpers.MaskPassword(field.Value)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "PostgreSQL authentication detected"
            : "PostgreSQL protocol";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
