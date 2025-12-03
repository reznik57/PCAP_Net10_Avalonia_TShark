using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes FTP protocol for cleartext credentials.
/// Detects: USER and PASS commands.
/// </summary>
public class FtpAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "FTP";
    public string[] Keywords => ["FTP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("FTP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "FTP",
            ContentType = "Command",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();
            var valueUpper = field.Value.ToUpperInvariant();

            // FTP USER command
            if (fieldUpper.Contains("REQUEST", StringComparison.Ordinal) || fieldUpper.Contains("COMMAND", StringComparison.Ordinal))
            {
                if (valueUpper.StartsWith("USER ", StringComparison.Ordinal))
                {
                    content.Severity = CleartextSeverity.Critical;
                    var username = field.Value[5..].Trim();
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "FTP",
                        CredentialType = "Login",
                        FieldName = "Username",
                        Value = username,
                        SecurityWarning = "FTP username transmitted in cleartext"
                    });
                    rawParts.Add($"USER {username}");
                }
                else if (valueUpper.StartsWith("PASS ", StringComparison.Ordinal))
                {
                    content.Severity = CleartextSeverity.Critical;
                    var password = field.Value[5..].Trim();
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "FTP",
                        CredentialType = "Login",
                        FieldName = "Password",
                        Value = ProtocolAnalysisHelpers.MaskPassword(password),
                        IsPassword = true,
                        SecurityWarning = "FTP password transmitted in cleartext!"
                    });
                    rawParts.Add($"PASS {ProtocolAnalysisHelpers.MaskPassword(password)}");
                }
                else if (!string.IsNullOrEmpty(field.Value))
                {
                    rawParts.Add(field.Value);
                }
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "FTP credentials detected in cleartext"
            : "FTP command";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
