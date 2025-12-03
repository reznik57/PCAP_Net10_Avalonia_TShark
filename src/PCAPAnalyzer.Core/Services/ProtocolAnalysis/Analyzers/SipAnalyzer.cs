using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes SIP protocol for cleartext credentials and signaling data.
/// Detects: Digest authentication, From/To headers.
/// </summary>
public class SipAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "SIP";
    public string[] Keywords => ["SIP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("SIP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "SIP",
            ContentType = "Signaling",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            // SIP Authorization/Proxy-Authorization
            if (fieldUpper.Contains("AUTHORIZATION", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var usernameMatch = Regex.Match(field.Value, @"username=""([^""]+)""", RegexOptions.IgnoreCase);
                if (usernameMatch.Success)
                {
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "SIP",
                        CredentialType = "Digest Auth",
                        FieldName = "Username",
                        Value = usernameMatch.Groups[1].Value,
                        SecurityWarning = "SIP authentication username exposed"
                    });
                }
                rawParts.Add($"Authorization: {ProtocolAnalysisHelpers.TruncateValue(field.Value, 100)}");
            }
            // From/To headers
            else if (fieldUpper.Contains("FROM", StringComparison.Ordinal) ||
                     fieldUpper.Contains("TO", StringComparison.Ordinal))
            {
                rawParts.Add($"{field.Name}: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "SIP authentication detected"
            : "SIP signaling";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
