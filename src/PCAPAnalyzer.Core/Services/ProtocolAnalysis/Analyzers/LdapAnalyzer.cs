using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes LDAP protocol for cleartext credentials.
/// Detects: Simple bind DN and passwords.
/// </summary>
public class LdapAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "LDAP";
    public string[] Keywords => ["LDAP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("LDAP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "LDAP",
            ContentType = "Bind Request",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            // Simple bind DN
            if (fieldUpper.Contains("BIND", StringComparison.Ordinal) &&
                fieldUpper.Contains("NAME", StringComparison.Ordinal))
            {
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "LDAP",
                    CredentialType = "Simple Bind",
                    FieldName = "Bind DN",
                    Value = field.Value,
                    SecurityWarning = "LDAP bind DN transmitted in cleartext"
                });
                rawParts.Add($"Bind DN: {field.Value}");
            }
            // Simple authentication (password)
            else if (fieldUpper.Contains("SIMPLE", StringComparison.Ordinal) ||
                     (fieldUpper.Contains("AUTH", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value)))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "LDAP",
                    CredentialType = "Simple Bind",
                    FieldName = "Password",
                    Value = ProtocolAnalysisHelpers.MaskPassword(field.Value),
                    IsPassword = true,
                    SecurityWarning = "LDAP simple bind password in cleartext!"
                });
                rawParts.Add($"Password: {ProtocolAnalysisHelpers.MaskPassword(field.Value)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "LDAP simple bind credentials detected"
            : "LDAP operation";

        return content.Credentials.Count > 0 ? content : null;
    }
}
