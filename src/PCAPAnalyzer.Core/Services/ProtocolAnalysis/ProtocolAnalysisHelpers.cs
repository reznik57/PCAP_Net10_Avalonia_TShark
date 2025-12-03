using System;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis;

/// <summary>
/// Shared utility methods for protocol analysis and credential extraction.
/// </summary>
public static class ProtocolAnalysisHelpers
{
    /// <summary>Session cookie patterns to detect</summary>
    public static readonly string[] SessionCookiePatterns =
        ["session", "sessid", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid", "asp.net_sessionid"];

    /// <summary>Form credential patterns: regex pattern -> credential type</summary>
    public static readonly (string Pattern, string CredType)[] FormCredentialPatterns =
    [
        (@"(?:user(?:name)?|login|email)=([^&\s]+)", "Username"),
        (@"(?:pass(?:word)?|pwd|passwd)=([^&\s]+)", "Password"),
        (@"(?:api[_-]?key|apikey)=([^&\s]+)", "API Key"),
        (@"(?:token|auth[_-]?token)=([^&\s]+)", "Token")
    ];

    /// <summary>
    /// Decodes Base64-encoded credentials.
    /// </summary>
    public static string? DecodeBase64Credentials(string base64)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Masks a password for display (shows first 2 chars + asterisks).
    /// </summary>
    public static string MaskPassword(string password)
    {
        if (string.IsNullOrEmpty(password)) return "***";
        if (password.Length <= 3) return new string('*', password.Length);
        return password[..2] + new string('*', Math.Min(password.Length - 2, 8));
    }

    /// <summary>
    /// Masks a token for display (shows first 8 and last 4 chars).
    /// </summary>
    public static string MaskToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return "***";
        if (token.Length <= 16) return new string('*', token.Length);
        return $"{token[..8]}...{token[^4..]}";
    }

    /// <summary>
    /// Truncates a value for display.
    /// </summary>
    public static string TruncateValue(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;
        return value[..(maxLength - 3)] + "...";
    }

    /// <summary>
    /// Scans raw output for credential patterns that might be missed by protocol-specific extraction.
    /// </summary>
    public static CleartextContent ScanForCredentialPatterns(string rawOutput)
    {
        var content = new CleartextContent
        {
            Protocol = "Generic",
            ContentType = "Pattern Match",
            Severity = CleartextSeverity.Info,
            Description = "Additional credentials detected via pattern matching"
        };

        // Patterns for common credential formats
        var patterns = new System.Collections.Generic.Dictionary<string, (string CredType, string FieldName, bool IsPassword)>
        {
            { @"password[=:]\s*['""]?([^'""&\s]{3,})['""]?", ("Generic", "Password", true) },
            { @"passwd[=:]\s*['""]?([^'""&\s]{3,})['""]?", ("Generic", "Password", true) },
            { @"api[_-]?key[=:]\s*['""]?([A-Za-z0-9_\-]{16,})['""]?", ("API", "API Key", true) },
            { @"secret[=:]\s*['""]?([^'""&\s]{8,})['""]?", ("Generic", "Secret", true) },
            { @"token[=:]\s*['""]?([A-Za-z0-9_\-\.]{20,})['""]?", ("Generic", "Token", true) },
            { @"aws[_-]?access[_-]?key[_-]?id[=:]\s*['""]?([A-Z0-9]{20})['""]?", ("AWS", "Access Key ID", false) },
            { @"aws[_-]?secret[_-]?access[_-]?key[=:]\s*['""]?([A-Za-z0-9/+=]{40})['""]?", ("AWS", "Secret Key", true) },
        };

        foreach (var (pattern, info) in patterns)
        {
            var matches = Regex.Matches(rawOutput, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            foreach (Match match in matches)
            {
                if (match.Success && match.Groups.Count > 1)
                {
                    content.Severity = CleartextSeverity.Critical;
                    var value = match.Groups[1].Value;
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = info.CredType,
                        CredentialType = "Pattern Match",
                        FieldName = info.FieldName,
                        Value = info.IsPassword ? MaskPassword(value) : value,
                        IsPassword = info.IsPassword,
                        SecurityWarning = $"{info.FieldName} detected via pattern matching"
                    });
                }
            }
        }

        return content;
    }
}
