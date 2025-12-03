using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes Redis protocol for cleartext credentials.
/// Detects: AUTH commands.
/// </summary>
public class RedisAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "Redis";
    public string[] Keywords => ["REDIS"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("REDIS", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "Redis",
            ContentType = "Command",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var valueUpper = field.Value.ToUpperInvariant();

            // Redis AUTH command
            if (valueUpper.Contains("AUTH", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var authMatch = Regex.Match(field.Value, @"AUTH\s+(\S+)", RegexOptions.IgnoreCase);
                if (authMatch.Success)
                {
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "Redis",
                        CredentialType = "AUTH",
                        FieldName = "Password",
                        Value = ProtocolAnalysisHelpers.MaskPassword(authMatch.Groups[1].Value),
                        IsPassword = true,
                        SecurityWarning = "Redis AUTH password in cleartext!"
                    });
                }
                rawParts.Add($"AUTH {ProtocolAnalysisHelpers.MaskPassword(authMatch.Success ? authMatch.Groups[1].Value : "***")}");
            }
            else if (!string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add(field.Value);
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "Redis AUTH detected"
            : "Redis command";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
