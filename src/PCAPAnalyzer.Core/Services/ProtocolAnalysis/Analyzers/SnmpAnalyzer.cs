using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes SNMP protocol for cleartext community strings.
/// Detects: SNMPv1/v2c community strings.
/// </summary>
public class SnmpAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "SNMP";
    public string[] Keywords => ["SNMP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("SNMP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "SNMP",
            ContentType = "Community String",
            Severity = CleartextSeverity.Warning
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            // SNMP v1/v2c community string
            if (fieldUpper.Contains("COMMUNITY", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "SNMP",
                    CredentialType = "Community String",
                    FieldName = "Community",
                    Value = field.Value,
                    SecurityWarning = "SNMP community string in cleartext - equivalent to password for v1/v2c"
                });
                rawParts.Add($"Community: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "SNMP community string detected"
            : "SNMP request";

        return content.Credentials.Count > 0 ? content : null;
    }
}
