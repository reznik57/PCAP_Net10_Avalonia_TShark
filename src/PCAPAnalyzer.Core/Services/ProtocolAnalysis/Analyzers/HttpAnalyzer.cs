using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

/// <summary>
/// Analyzes HTTP protocol for cleartext credentials and sensitive data.
/// Detects: Basic Auth, Digest Auth, Bearer tokens, session cookies, form credentials.
/// </summary>
public class HttpAnalyzer : IProtocolAnalyzer
{
    public string Protocol => "HTTP";
    public string[] Keywords => ["HTTP"];

    public bool CanAnalyze(string layerName) =>
        layerName.Contains("HTTP", StringComparison.OrdinalIgnoreCase);

    public CleartextContent? Analyze(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "HTTP",
            ContentType = "Request/Response",
            Severity = CleartextSeverity.Info
        };
        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldNameUpper = field.Name.ToUpperInvariant();
            ProcessHttpField(content, rawParts, field, fieldNameUpper);
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? $"HTTP traffic with {content.Credentials.Count} credential(s) detected"
            : "HTTP request/response";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }

    private static void ProcessHttpField(CleartextContent content, List<string> rawParts, ProtocolField field, string fieldNameUpper)
    {
        if (fieldNameUpper.Contains("AUTHORIZATION", StringComparison.Ordinal))
            ExtractHttpAuthorization(content, rawParts, field);
        else if (fieldNameUpper.Contains("COOKIE", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            ExtractHttpCookie(content, rawParts, field);
        else if (IsHttpBodyField(fieldNameUpper))
            ExtractHttpFormCredentials(content, rawParts, field);
        else if (fieldNameUpper.Contains("URI", StringComparison.Ordinal) || fieldNameUpper.Contains("REQUEST", StringComparison.Ordinal))
            rawParts.Add(field.Value);
    }

    private static bool IsHttpBodyField(string fieldNameUpper) =>
        fieldNameUpper.Contains("FILE DATA", StringComparison.Ordinal) ||
        fieldNameUpper.Contains("DATA", StringComparison.Ordinal) ||
        fieldNameUpper.Contains("BODY", StringComparison.Ordinal);

    private static void ExtractHttpAuthorization(CleartextContent content, List<string> rawParts, ProtocolField field)
    {
        content.Severity = CleartextSeverity.Critical;

        if (field.Value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            ExtractBasicAuth(content, rawParts, field.Value);
        else if (field.Value.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase))
            ExtractDigestAuth(content, rawParts, field.Value);
        else if (field.Value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            ExtractBearerToken(content, rawParts, field.Value);
    }

    private static void ExtractBasicAuth(CleartextContent content, List<string> rawParts, string value)
    {
        var decoded = ProtocolAnalysisHelpers.DecodeBase64Credentials(value[6..].Trim());
        if (decoded is null) return;

        var parts = decoded.Split(':', 2);
        content.Credentials.Add(new CleartextCredential
        {
            Protocol = "HTTP", CredentialType = "Basic Auth", FieldName = "Username",
            Value = parts[0], SecurityWarning = "HTTP Basic Auth transmits credentials in cleartext (Base64 encoded)"
        });
        if (parts.Length > 1)
        {
            content.Credentials.Add(new CleartextCredential
            {
                Protocol = "HTTP", CredentialType = "Basic Auth", FieldName = "Password",
                Value = ProtocolAnalysisHelpers.MaskPassword(parts[1]), IsPassword = true, SecurityWarning = "Password exposed in HTTP Basic Auth header"
            });
        }
        rawParts.Add($"Authorization: Basic {decoded}");
    }

    private static void ExtractDigestAuth(CleartextContent content, List<string> rawParts, string value)
    {
        var usernameMatch = Regex.Match(value, @"username=""([^""]+)""", RegexOptions.IgnoreCase);
        if (usernameMatch.Success)
        {
            content.Credentials.Add(new CleartextCredential
            {
                Protocol = "HTTP", CredentialType = "Digest Auth", FieldName = "Username",
                Value = usernameMatch.Groups[1].Value, SecurityWarning = "HTTP Digest Auth username exposed"
            });
        }
        rawParts.Add($"Authorization: {value}");
    }

    private static void ExtractBearerToken(CleartextContent content, List<string> rawParts, string value)
    {
        content.Credentials.Add(new CleartextCredential
        {
            Protocol = "HTTP", CredentialType = "Bearer Token", FieldName = "Token",
            Value = ProtocolAnalysisHelpers.MaskToken(value[7..].Trim()), IsPassword = true, SecurityWarning = "Bearer token transmitted in cleartext"
        });
        rawParts.Add("Authorization: Bearer [TOKEN]");
    }

    private static void ExtractHttpCookie(CleartextContent content, List<string> rawParts, ProtocolField field)
    {
        if (content.Severity < CleartextSeverity.Warning)
            content.Severity = CleartextSeverity.Warning;

        foreach (var pattern in ProtocolAnalysisHelpers.SessionCookiePatterns)
        {
            if (field.Value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "HTTP", CredentialType = "Session Cookie", FieldName = "Cookie",
                    Value = ProtocolAnalysisHelpers.TruncateValue(field.Value, 80), SecurityWarning = "Session identifier transmitted in cleartext"
                });
                break;
            }
        }
        rawParts.Add($"Cookie: {ProtocolAnalysisHelpers.TruncateValue(field.Value, 100)}");
    }

    private static void ExtractHttpFormCredentials(CleartextContent content, List<string> rawParts, ProtocolField field)
    {
        foreach (var (pattern, credType) in ProtocolAnalysisHelpers.FormCredentialPatterns)
        {
            var match = Regex.Match(field.Value, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                content.Severity = CleartextSeverity.Critical;
                var isPassword = credType is "Password" or "API Key" or "Token";
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "HTTP", CredentialType = $"Form {credType}", FieldName = credType,
                    Value = isPassword ? ProtocolAnalysisHelpers.MaskPassword(match.Groups[1].Value) : match.Groups[1].Value,
                    IsPassword = isPassword, SecurityWarning = $"{credType} submitted via HTTP form in cleartext"
                });
            }
        }
        if (!string.IsNullOrEmpty(field.Value))
            rawParts.Add($"Body: {ProtocolAnalysisHelpers.TruncateValue(field.Value, 200)}");
    }
}
