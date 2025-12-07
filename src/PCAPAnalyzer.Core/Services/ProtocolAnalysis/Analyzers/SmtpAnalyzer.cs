using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes SMTP protocol for cleartext credentials and email content.
/// Detects: AUTH PLAIN, AUTH LOGIN, mail headers and data.
/// </summary>
public class SmtpAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "SMTP";
    public string[] Keywords => ["SMTP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("SMTP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "SMTP",
            ContentType = "Command/Message",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();
            var valueUpper = field.Value.ToUpperInvariant();

            // AUTH PLAIN (Base64 encoded credentials)
            if (valueUpper.Contains("AUTH PLAIN", StringComparison.Ordinal) ||
                valueUpper.Contains("AUTH LOGIN", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                rawParts.Add(field.Value);

                // Try to decode AUTH PLAIN
                var parts = field.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3)
                {
                    var decoded = ProtocolAnalysisHelpers.DecodeBase64Credentials(parts[2]);
                    if (decoded is not null)
                    {
                        // AUTH PLAIN format: \0username\0password
                        var authParts = decoded.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                        if (authParts.Length >= 1)
                        {
                            content.Credentials.Add(new CleartextCredential
                            {
                                Protocol = "SMTP",
                                CredentialType = "AUTH PLAIN",
                                FieldName = "Username",
                                Value = authParts[0],
                                SecurityWarning = "SMTP AUTH PLAIN credentials in cleartext"
                            });
                        }
                        if (authParts.Length >= 2)
                        {
                            content.Credentials.Add(new CleartextCredential
                            {
                                Protocol = "SMTP",
                                CredentialType = "AUTH PLAIN",
                                FieldName = "Password",
                                Value = ProtocolAnalysisHelpers.MaskPassword(authParts[1]),
                                IsPassword = true,
                                SecurityWarning = "SMTP password exposed in AUTH PLAIN"
                            });
                        }
                    }
                }
            }
            // Mail headers
            else if (fieldUpper.Contains("FROM", StringComparison.Ordinal) ||
                     fieldUpper.Contains("TO", StringComparison.Ordinal) ||
                     fieldUpper.Contains("SUBJECT", StringComparison.Ordinal))
            {
                rawParts.Add($"{field.Name}: {field.Value}");
            }
            // Mail data
            else if (fieldUpper.Contains("DATA", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Message: {ProtocolAnalysisHelpers.TruncateValue(field.Value, 200)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "SMTP authentication credentials detected"
            : "SMTP mail transaction";

        return rawParts.Count > 0 ? content : null;
    }
}
