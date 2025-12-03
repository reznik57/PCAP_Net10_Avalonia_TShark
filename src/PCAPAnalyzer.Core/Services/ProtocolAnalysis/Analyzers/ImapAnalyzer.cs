using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes IMAP protocol for cleartext credentials.
/// Detects: LOGIN command, AUTHENTICATE PLAIN.
/// </summary>
public class ImapAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "IMAP";
    public string[] Keywords => ["IMAP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("IMAP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "IMAP",
            ContentType = "Command",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var valueUpper = field.Value.ToUpperInvariant();

            // IMAP LOGIN command: a1 LOGIN username password
            if (valueUpper.Contains(" LOGIN ", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var loginMatch = Regex.Match(field.Value, @"LOGIN\s+(\S+)\s+(\S+)", RegexOptions.IgnoreCase);
                if (loginMatch.Success)
                {
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "IMAP",
                        CredentialType = "Login",
                        FieldName = "Username",
                        Value = loginMatch.Groups[1].Value.Trim('"'),
                        SecurityWarning = "IMAP username transmitted in cleartext"
                    });
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "IMAP",
                        CredentialType = "Login",
                        FieldName = "Password",
                        Value = ProtocolAnalysisHelpers.MaskPassword(loginMatch.Groups[2].Value.Trim('"')),
                        IsPassword = true,
                        SecurityWarning = "IMAP password transmitted in cleartext!"
                    });
                }
                rawParts.Add(field.Value);
            }
            // AUTHENTICATE PLAIN
            else if (valueUpper.Contains("AUTHENTICATE PLAIN", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Description = "IMAP AUTHENTICATE PLAIN detected - credentials follow";
                rawParts.Add(field.Value);
            }
            else if (!string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add(field.Value);
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "IMAP credentials detected"
            : "IMAP command";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
