using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes POP3 protocol for cleartext credentials.
/// Detects: USER and PASS commands.
/// </summary>
public class Pop3Analyzer : IProtocolAnalyzer
{
    public string Protocol => "POP3";
    public string[] Keywords => ["POP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("POP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "POP3",
            ContentType = "Command",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var valueUpper = field.Value.ToUpperInvariant();

            if (valueUpper.StartsWith("USER ", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var username = field.Value[5..].Trim();
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "POP3",
                    CredentialType = "Login",
                    FieldName = "Username",
                    Value = username,
                    SecurityWarning = "POP3 username transmitted in cleartext"
                });
                rawParts.Add(field.Value);
            }
            else if (valueUpper.StartsWith("PASS ", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var password = field.Value[5..].Trim();
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "POP3",
                    CredentialType = "Login",
                    FieldName = "Password",
                    Value = ProtocolAnalysisHelpers.MaskPassword(password),
                    IsPassword = true,
                    SecurityWarning = "POP3 password transmitted in cleartext!"
                });
                rawParts.Add($"PASS {ProtocolAnalysisHelpers.MaskPassword(password)}");
            }
            else if (!string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add(field.Value);
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "POP3 credentials detected"
            : "POP3 command";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
