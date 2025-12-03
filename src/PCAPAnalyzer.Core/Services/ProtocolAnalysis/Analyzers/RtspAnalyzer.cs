using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes RTSP protocol for cleartext credentials.
/// Detects: Basic authentication in streaming control.
/// </summary>
public class RtspAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "RTSP";
    public string[] Keywords => ["RTSP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("RTSP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "RTSP",
            ContentType = "Streaming Control",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            // RTSP Authorization (similar to HTTP)
            if (fieldUpper.Contains("AUTHORIZATION", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;

                if (field.Value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    var decoded = ProtocolAnalysisHelpers.DecodeBase64Credentials(field.Value[6..].Trim());
                    if (decoded != null)
                    {
                        var parts = decoded.Split(':', 2);
                        content.Credentials.Add(new CleartextCredential
                        {
                            Protocol = "RTSP",
                            CredentialType = "Basic Auth",
                            FieldName = "Username",
                            Value = parts[0],
                            SecurityWarning = "RTSP Basic Auth credentials in cleartext"
                        });
                        if (parts.Length > 1)
                        {
                            content.Credentials.Add(new CleartextCredential
                            {
                                Protocol = "RTSP",
                                CredentialType = "Basic Auth",
                                FieldName = "Password",
                                Value = ProtocolAnalysisHelpers.MaskPassword(parts[1]),
                                IsPassword = true,
                                SecurityWarning = "RTSP password exposed"
                            });
                        }
                    }
                }
                rawParts.Add($"Authorization: {ProtocolAnalysisHelpers.TruncateValue(field.Value, 80)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "RTSP authentication detected"
            : "RTSP control";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }
}
