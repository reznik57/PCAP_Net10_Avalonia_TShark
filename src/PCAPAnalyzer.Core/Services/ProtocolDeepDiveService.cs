using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service for extracting detailed protocol information from specific packets using TShark.
/// Uses on-demand extraction to avoid slowing down initial parsing.
/// </summary>
public class ProtocolDeepDiveService
{
    private readonly string _tsharkPath;

    public ProtocolDeepDiveService(string? tsharkPath = null)
    {
        // Auto-detect tshark path on Windows
        _tsharkPath = tsharkPath ?? DetectTSharkPath();
        DebugLogger.Log($"[ProtocolDeepDive] Using TShark: {_tsharkPath}");
    }

    /// <summary>
    /// Detects TShark path across Windows and Linux.
    /// </summary>
    private static string DetectTSharkPath()
    {
        // On Linux/Unix, tshark is typically in PATH
        if (!OperatingSystem.IsWindows())
            return "tshark";

        // On Windows, check standard Wireshark installation paths
        var paths = new[]
        {
            @"C:\Program Files\Wireshark\tshark.exe",
            @"C:\Program Files (x86)\Wireshark\tshark.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", "tshark.exe")
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
                return path;
        }

        // Fallback to PATH
        return "tshark";
    }

    /// <summary>
    /// Detects editcap path for fast single-frame extraction.
    /// </summary>
    private static string? GetEditcapPath()
    {
        if (!OperatingSystem.IsWindows())
            return "editcap"; // Assume in PATH on Linux

        var paths = new[]
        {
            @"C:\Program Files\Wireshark\editcap.exe",
            @"C:\Program Files (x86)\Wireshark\editcap.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "editcap.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", "editcap.exe")
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
                return path;
        }

        return null; // editcap not found, will fall back to slow method
    }

    /// <summary>
    /// Extracts detailed protocol dissection for a specific packet.
    /// Returns structured protocol layers with their fields.
    /// Uses editcap to extract single frame for FAST extraction on large files.
    /// </summary>
    public async Task<ProtocolDeepDiveResult> ExtractProtocolDetailsAsync(
        string pcapPath,
        uint frameNumber,
        CancellationToken cancellationToken = default)
    {
        var result = new ProtocolDeepDiveResult { FrameNumber = frameNumber };
        string? tempFile = null;

        try
        {
            // OPTIMIZATION: Extract single frame with editcap first (MUCH faster for large files)
            // editcap just copies raw bytes, no protocol decoding
            var editcapPath = GetEditcapPath();
            if (editcapPath != null)
            {
                tempFile = Path.Combine(Path.GetTempPath(), $"deepdive_{frameNumber}_{Guid.NewGuid():N}.pcap");

                // Extract single frame: editcap -r input.pcap output.pcap {frame_number}
                var editcapArgs = $"-r \"{pcapPath}\" \"{tempFile}\" {frameNumber}";
                DebugLogger.Log($"[DeepDive] Using editcap for fast extraction");

                using var editcapProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = editcapPath,
                        Arguments = editcapArgs,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                editcapProcess.Start();
                await editcapProcess.WaitForExitAsync(cancellationToken);

                if (editcapProcess.ExitCode == 0 && File.Exists(tempFile))
                {
                    // Now run tshark -V on the tiny single-packet file (instant!)
                    pcapPath = tempFile;
                }
                else
                {
                    DebugLogger.Log("[DeepDive] editcap failed, using full scan fallback");
                }
            }

            // Use tshark -V for verbose output (full protocol dissection)
            // If we extracted single frame, this is instant. Otherwise scans entire file.
            var args = tempFile != null
                ? $"-r \"{pcapPath}\" -V"  // Single packet file - no filter needed
                : $"-r \"{pcapPath}\" -Y \"frame.number=={frameNumber}\" -V";  // Full file - need filter

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = _tsharkPath,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (!string.IsNullOrEmpty(output))
            {
                result.Layers = ParseVerboseOutput(output);
                result.RawOutput = output;
                result.Success = true;

                // Extract cleartext content and credentials
                result.CleartextContent = ExtractCleartextContent(result);
                if (result.HasCleartextCredentials)
                {
                    DebugLogger.Log($"[ProtocolDeepDive] Detected {result.CleartextContent.Sum(c => c.Credentials.Count)} cleartext credential(s)");
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ProtocolDeepDive] Error: {ex.Message}");
            result.Error = ex.Message;
        }
        finally
        {
            // Cleanup temp file
            if (tempFile != null && File.Exists(tempFile))
            {
                try { File.Delete(tempFile); }
                catch { /* Ignore cleanup errors */ }
            }
        }

        return result;
    }

    /// <summary>
    /// Parses TShark verbose output into structured protocol layers.
    /// </summary>
    private List<ProtocolLayer> ParseVerboseOutput(string output)
    {
        var layers = new List<ProtocolLayer>();
        ProtocolLayer? currentLayer = null;
        var indent = 0;

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');

            // Skip empty lines
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Detect protocol layer headers (no leading spaces, ends with protocol name)
            if (!char.IsWhiteSpace(line[0]) && !line.StartsWith("Frame", StringComparison.Ordinal) && line.Contains(':', StringComparison.Ordinal))
            {
                // New protocol layer
                if (currentLayer != null)
                    layers.Add(currentLayer);

                var colonIdx = line.IndexOf(':', StringComparison.Ordinal);
                var name = colonIdx > 0 ? line[..colonIdx].Trim() : line;
                currentLayer = new ProtocolLayer { Name = name, Fields = new List<ProtocolField>() };
                indent = 0;
            }
            else if (line.StartsWith("Frame ", StringComparison.Ordinal))
            {
                // Frame info layer
                if (currentLayer != null)
                    layers.Add(currentLayer);

                currentLayer = new ProtocolLayer { Name = "Frame", Fields = new List<ProtocolField>() };
            }
            else if (currentLayer != null)
            {
                // Parse field line
                var field = ParseFieldLine(line, ref indent);
                if (field != null)
                    currentLayer.Fields.Add(field);
            }
        }

        // Don't forget the last layer
        if (currentLayer != null)
            layers.Add(currentLayer);

        return layers;
    }

    /// <summary>
    /// Parses a single field line from verbose output.
    /// </summary>
    private ProtocolField? ParseFieldLine(string line, ref int indent)
    {
        // Count leading spaces to determine indent level
        var leadingSpaces = line.TakeWhile(char.IsWhiteSpace).Count();
        var trimmed = line.Trim();

        if (string.IsNullOrEmpty(trimmed))
            return null;

        // Parse "Field Name: Value" format
        var colonIdx = trimmed.IndexOf(':', StringComparison.Ordinal);
        if (colonIdx > 0)
        {
            var name = trimmed[..colonIdx].Trim();
            var value = trimmed[(colonIdx + 1)..].Trim();

            return new ProtocolField
            {
                Name = name,
                Value = value,
                IndentLevel = leadingSpaces / 4,
                IsHighlighted = IsImportantField(name)
            };
        }

        // Field without value (section header or flags)
        return new ProtocolField
        {
            Name = trimmed,
            Value = "",
            IndentLevel = leadingSpaces / 4
        };
    }

    /// <summary>
    /// Determines if a field should be highlighted as important.
    /// </summary>
    private static bool IsImportantField(string fieldName)
    {
        var importantFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // DNS
            "Name", "Queries", "Answers", "Type", "Class", "Address", "CNAME", "MX", "NS", "TXT",
            // HTTP
            "Request URI", "Host", "User-Agent", "Content-Type", "Status Code", "Request Method",
            "Response Code", "Cookie", "Set-Cookie", "Authorization", "Location", "Referer",
            // TLS/SSL
            "Version", "Cipher Suite", "Server Name", "Certificate", "Handshake Type",
            "Content Type", "Issuer", "Subject", "Validity", "Serial Number",
            // SMTP/POP/IMAP
            "Command", "Response", "Subject", "From", "To", "Message-ID",
            // SIP
            "Method", "Status-Code", "Call-ID", "From", "To", "Via",
            // Generic
            "Source", "Destination", "Source Port", "Destination Port", "Length", "Checksum",
            "Sequence Number", "Acknowledgment Number", "Flags", "Window"
        };

        return importantFields.Any(f => fieldName.Contains(f, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Extracts protocol-specific summary for quick display.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Protocol detection requires checking multiple protocol types")]
    public static ProtocolSummary ExtractSummary(ProtocolDeepDiveResult result)
    {
        var summary = new ProtocolSummary();

        foreach (var layer in result.Layers)
        {
            var layerName = layer.Name.ToUpperInvariant();

            // DNS
            if (layerName.Contains("DNS", StringComparison.Ordinal))
            {
                summary.Protocol = "DNS";
                summary.Icon = "🔍";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Name", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(field.Value))
                        summary.KeyValues["Query"] = field.Value;
                    if (field.Name.Contains("Type", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Type"] = field.Value;
                    if (field.Name.Contains("Address", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(field.Value))
                        summary.KeyValues["Answer"] = field.Value;
                }
            }
            // HTTP
            else if (layerName.Contains("HTTP", StringComparison.Ordinal))
            {
                summary.Protocol = "HTTP";
                summary.Icon = "🌐";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Request URI", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["URI"] = field.Value;
                    if (field.Name.Contains("Host", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Host"] = field.Value;
                    if (field.Name.Contains("Request Method", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Method"] = field.Value;
                    if (field.Name.Contains("Status Code", StringComparison.OrdinalIgnoreCase) || field.Name.Contains("Response Code", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Status"] = field.Value;
                    if (field.Name.Contains("User-Agent", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["User-Agent"] = TruncateValue(field.Value, 60);
                    if (field.Name.Contains("Content-Type", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Content-Type"] = field.Value;
                }
            }
            // TLS
            else if (layerName.Contains("TLS", StringComparison.Ordinal) || layerName.Contains("SSL", StringComparison.Ordinal))
            {
                summary.Protocol = "TLS/SSL";
                summary.Icon = "🔒";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Version", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Version"] = field.Value;
                    if (field.Name.Contains("Cipher Suite", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Cipher"] = field.Value;
                    if (field.Name.Contains("Server Name", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["SNI"] = field.Value;
                    if (field.Name.Contains("Handshake Type", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Handshake"] = field.Value;
                }
            }
            // SMTP
            else if (layerName.Contains("SMTP", StringComparison.Ordinal))
            {
                summary.Protocol = "SMTP";
                summary.Icon = "📧";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Command", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Command"] = field.Value;
                    if (field.Name.Contains("Response", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Response"] = TruncateValue(field.Value, 50);
                }
            }
            // SIP
            else if (layerName.Contains("SIP", StringComparison.Ordinal))
            {
                summary.Protocol = "SIP";
                summary.Icon = "📞";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Method", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Method"] = field.Value;
                    if (field.Name.Contains("Status-Code", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Status"] = field.Value;
                    if (field.Name.Contains("Call-ID", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Call-ID"] = TruncateValue(field.Value, 30);
                }
            }
            // RTP
            else if (layerName.Contains("RTP", StringComparison.Ordinal))
            {
                summary.Protocol = "RTP";
                summary.Icon = "🎤";
                foreach (var field in layer.Fields)
                {
                    if (field.Name.Contains("Payload type", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Payload"] = field.Value;
                    if (field.Name.Contains("Sequence", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["Seq"] = field.Value;
                    if (field.Name.Contains("SSRC", StringComparison.OrdinalIgnoreCase))
                        summary.KeyValues["SSRC"] = field.Value;
                }
            }
        }

        // Default if no specific protocol detected
        if (string.IsNullOrEmpty(summary.Protocol))
        {
            summary.Protocol = result.Layers.LastOrDefault()?.Name ?? "Unknown";
            summary.Icon = "📦";
        }

        return summary;
    }

    private static string TruncateValue(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value;
        return value[..(maxLength - 3)] + "...";
    }

    /// <summary>
    /// Protocol extractors registry - maps protocol keywords to their extraction methods.
    /// </summary>
    private static readonly (string[] Keywords, Func<ProtocolLayer, CleartextContent?> Extractor)[] ProtocolExtractors =
    [
        (["HTTP"], ExtractHttpCleartext),
        (["FTP"], ExtractFtpCleartext),
        (["TELNET"], ExtractTelnetCleartext),
        (["SMTP"], ExtractSmtpCleartext),
        (["POP"], ExtractPop3Cleartext),
        (["IMAP"], ExtractImapCleartext),
        (["LDAP"], ExtractLdapCleartext),
        (["MYSQL"], ExtractMysqlCleartext),
        (["PGSQL", "POSTGRESQL"], ExtractPostgresCleartext),
        (["REDIS"], ExtractRedisCleartext),
        (["SNMP"], ExtractSnmpCleartext),
        (["SIP"], ExtractSipCleartext),
        (["RTSP"], ExtractRtspCleartext),
        (["DNS"], ExtractDnsCleartext),
    ];

    /// <summary>
    /// Extracts cleartext content and credentials from protocol layers.
    /// Supports: HTTP, FTP, Telnet, SMTP, POP3, IMAP, LDAP, MySQL, PostgreSQL, Redis, SNMP, SIP, RTSP
    /// </summary>
    public static List<CleartextContent> ExtractCleartextContent(ProtocolDeepDiveResult result)
    {
        var contents = new List<CleartextContent>();

        foreach (var layer in result.Layers)
        {
            var content = ExtractLayerContent(layer);
            if (content != null)
                contents.Add(content);
        }

        MergeAdditionalCredentials(contents, result.RawOutput);
        return contents;
    }

    /// <summary>
    /// Extracts content from a single protocol layer using registered extractors.
    /// </summary>
    private static CleartextContent? ExtractLayerContent(ProtocolLayer layer)
    {
        var layerName = layer.Name.ToUpperInvariant();

        foreach (var (keywords, extractor) in ProtocolExtractors)
        {
            foreach (var keyword in keywords)
            {
                if (layerName.Contains(keyword, StringComparison.Ordinal))
                    return extractor(layer);
            }
        }
        return null;
    }

    /// <summary>
    /// Merges additional credentials found in raw output with existing contents.
    /// </summary>
    private static void MergeAdditionalCredentials(List<CleartextContent> contents, string? rawOutput)
    {
        if (string.IsNullOrEmpty(rawOutput))
            return;

        var additionalCredentials = ScanForCredentialPatterns(rawOutput);
        if (additionalCredentials.Credentials.Count == 0)
            return;

        var existingCritical = contents.FirstOrDefault(c => c.Severity == CleartextSeverity.Critical);
        if (existingCritical != null)
        {
            foreach (var cred in additionalCredentials.Credentials)
            {
                if (!existingCritical.Credentials.Any(c => c.Value == cred.Value))
                    existingCritical.Credentials.Add(cred);
            }
        }
        else
        {
            contents.Add(additionalCredentials);
        }
    }

    #region Protocol-Specific Cleartext Extraction

    /// <summary>Session cookie patterns to detect</summary>
    private static readonly string[] SessionCookiePatterns =
        ["session", "sessid", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid", "asp.net_sessionid"];

    /// <summary>Form credential patterns: regex pattern -> credential type</summary>
    private static readonly (string Pattern, string CredType)[] FormCredentialPatterns =
    [
        (@"(?:user(?:name)?|login|email)=([^&\s]+)", "Username"),
        (@"(?:pass(?:word)?|pwd|passwd)=([^&\s]+)", "Password"),
        (@"(?:api[_-]?key|apikey)=([^&\s]+)", "API Key"),
        (@"(?:token|auth[_-]?token)=([^&\s]+)", "Token")
    ];

    private static CleartextContent? ExtractHttpCleartext(ProtocolLayer layer)
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

    /// <summary>Processes a single HTTP field and extracts credentials.</summary>
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

    /// <summary>Extracts credentials from HTTP Authorization header.</summary>
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
        var decoded = DecodeBase64Credentials(value[6..].Trim());
        if (decoded == null) return;

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
                Value = MaskPassword(parts[1]), IsPassword = true, SecurityWarning = "Password exposed in HTTP Basic Auth header"
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
            Value = MaskToken(value[7..].Trim()), IsPassword = true, SecurityWarning = "Bearer token transmitted in cleartext"
        });
        rawParts.Add("Authorization: Bearer [TOKEN]");
    }

    /// <summary>Extracts session identifiers from HTTP cookies.</summary>
    private static void ExtractHttpCookie(CleartextContent content, List<string> rawParts, ProtocolField field)
    {
        if (content.Severity < CleartextSeverity.Warning)
            content.Severity = CleartextSeverity.Warning;

        foreach (var pattern in SessionCookiePatterns)
        {
            if (field.Value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "HTTP", CredentialType = "Session Cookie", FieldName = "Cookie",
                    Value = TruncateValue(field.Value, 80), SecurityWarning = "Session identifier transmitted in cleartext"
                });
                break;
            }
        }
        rawParts.Add($"Cookie: {TruncateValue(field.Value, 100)}");
    }

    /// <summary>Extracts credentials from HTTP form data.</summary>
    private static void ExtractHttpFormCredentials(CleartextContent content, List<string> rawParts, ProtocolField field)
    {
        foreach (var (pattern, credType) in FormCredentialPatterns)
        {
            var match = Regex.Match(field.Value, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                content.Severity = CleartextSeverity.Critical;
                var isPassword = credType is "Password" or "API Key" or "Token";
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "HTTP", CredentialType = $"Form {credType}", FieldName = credType,
                    Value = isPassword ? MaskPassword(match.Groups[1].Value) : match.Groups[1].Value,
                    IsPassword = isPassword, SecurityWarning = $"{credType} submitted via HTTP form in cleartext"
                });
            }
        }
        if (!string.IsNullOrEmpty(field.Value))
            rawParts.Add($"Body: {TruncateValue(field.Value, 200)}");
    }

    private static CleartextContent? ExtractFtpCleartext(ProtocolLayer layer)
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
                        Value = MaskPassword(password),
                        IsPassword = true,
                        SecurityWarning = "FTP password transmitted in cleartext!"
                    });
                    rawParts.Add($"PASS {MaskPassword(password)}");
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

    private static CleartextContent? ExtractTelnetCleartext(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "Telnet",
            ContentType = "Session Data",
            Severity = CleartextSeverity.Warning,
            Description = "Telnet session data (all content transmitted in cleartext)"
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            if (!string.IsNullOrEmpty(field.Value) && field.Value.Length > 1)
            {
                // Telnet data is inherently cleartext
                rawParts.Add(field.Value);

                // Check for login patterns
                var valueUpper = field.Value.ToUpperInvariant();
                if (valueUpper.Contains("LOGIN", StringComparison.Ordinal) ||
                    valueUpper.Contains("USERNAME", StringComparison.Ordinal) ||
                    valueUpper.Contains("PASSWORD", StringComparison.Ordinal))
                {
                    content.Severity = CleartextSeverity.Critical;
                    content.Description = "Telnet login sequence detected - credentials may be present";
                }
            }
        }

        content.RawContent = string.Join("", rawParts);
        return rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractSmtpCleartext(ProtocolLayer layer)
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
                    var decoded = DecodeBase64Credentials(parts[2]);
                    if (decoded != null)
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
                                Value = MaskPassword(authParts[1]),
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
                rawParts.Add($"Message: {TruncateValue(field.Value, 200)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "SMTP authentication credentials detected"
            : "SMTP mail transaction";

        return rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractPop3Cleartext(ProtocolLayer layer)
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
                    Value = MaskPassword(password),
                    IsPassword = true,
                    SecurityWarning = "POP3 password transmitted in cleartext!"
                });
                rawParts.Add($"PASS {MaskPassword(password)}");
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

    private static CleartextContent? ExtractImapCleartext(ProtocolLayer layer)
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
                        Value = MaskPassword(loginMatch.Groups[2].Value.Trim('"')),
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

    private static CleartextContent? ExtractLdapCleartext(ProtocolLayer layer)
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
                    Value = MaskPassword(field.Value),
                    IsPassword = true,
                    SecurityWarning = "LDAP simple bind password in cleartext!"
                });
                rawParts.Add($"Password: {MaskPassword(field.Value)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "LDAP simple bind credentials detected"
            : "LDAP operation";

        return content.Credentials.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractMysqlCleartext(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "MySQL",
            ContentType = "Authentication",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if (fieldUpper.Contains("USER", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "MySQL",
                    CredentialType = "Login",
                    FieldName = "Username",
                    Value = field.Value,
                    SecurityWarning = "MySQL username in cleartext"
                });
                rawParts.Add($"User: {field.Value}");
            }
            else if (fieldUpper.Contains("DATABASE", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Database: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "MySQL authentication detected"
            : "MySQL protocol";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractPostgresCleartext(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "PostgreSQL",
            ContentType = "Authentication",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if (fieldUpper.Contains("USER", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "PostgreSQL",
                    CredentialType = "Startup",
                    FieldName = "Username",
                    Value = field.Value,
                    SecurityWarning = "PostgreSQL username in cleartext"
                });
                rawParts.Add($"User: {field.Value}");
            }
            else if (fieldUpper.Contains("DATABASE", StringComparison.Ordinal) && !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Database: {field.Value}");
            }
            else if (fieldUpper.Contains("PASSWORD", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                content.Credentials.Add(new CleartextCredential
                {
                    Protocol = "PostgreSQL",
                    CredentialType = "Password Message",
                    FieldName = "Password",
                    Value = MaskPassword(field.Value),
                    IsPassword = true,
                    SecurityWarning = "PostgreSQL password in cleartext!"
                });
                rawParts.Add($"Password: {MaskPassword(field.Value)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "PostgreSQL authentication detected"
            : "PostgreSQL protocol";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractRedisCleartext(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "Redis",
            ContentType = "Command",
            Severity = CleartextSeverity.Info
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var valueUpper = field.Value.ToUpperInvariant();

            // Redis AUTH command
            if (valueUpper.Contains("AUTH", StringComparison.Ordinal))
            {
                content.Severity = CleartextSeverity.Critical;
                var authMatch = Regex.Match(field.Value, @"AUTH\s+(\S+)", RegexOptions.IgnoreCase);
                if (authMatch.Success)
                {
                    content.Credentials.Add(new CleartextCredential
                    {
                        Protocol = "Redis",
                        CredentialType = "AUTH",
                        FieldName = "Password",
                        Value = MaskPassword(authMatch.Groups[1].Value),
                        IsPassword = true,
                        SecurityWarning = "Redis AUTH password in cleartext!"
                    });
                }
                rawParts.Add($"AUTH {MaskPassword(authMatch.Success ? authMatch.Groups[1].Value : "***")}");
            }
            else if (!string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add(field.Value);
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "Redis AUTH detected"
            : "Redis command";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractSnmpCleartext(ProtocolLayer layer)
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

    private static CleartextContent? ExtractSipCleartext(ProtocolLayer layer)
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
                rawParts.Add($"Authorization: {TruncateValue(field.Value, 100)}");
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

    private static CleartextContent? ExtractRtspCleartext(ProtocolLayer layer)
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
                    var decoded = DecodeBase64Credentials(field.Value[6..].Trim());
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
                                Value = MaskPassword(parts[1]),
                                IsPassword = true,
                                SecurityWarning = "RTSP password exposed"
                            });
                        }
                    }
                }
                rawParts.Add($"Authorization: {TruncateValue(field.Value, 80)}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        content.Description = content.Credentials.Count > 0
            ? "RTSP authentication detected"
            : "RTSP control";

        return content.Credentials.Count > 0 || rawParts.Count > 0 ? content : null;
    }

    private static CleartextContent? ExtractDnsCleartext(ProtocolLayer layer)
    {
        var content = new CleartextContent
        {
            Protocol = "DNS",
            ContentType = "Query/Response",
            Severity = CleartextSeverity.Info,
            Description = "DNS query (informational - no credentials)"
        };

        var rawParts = new List<string>();

        foreach (var field in layer.Fields)
        {
            var fieldUpper = field.Name.ToUpperInvariant();

            if ((fieldUpper.Contains("NAME", StringComparison.Ordinal) ||
                 fieldUpper.Contains("QUERY", StringComparison.Ordinal)) &&
                !string.IsNullOrEmpty(field.Value))
            {
                rawParts.Add($"Query: {field.Value}");
            }
            else if (fieldUpper.Contains("ADDRESS", StringComparison.Ordinal) ||
                     fieldUpper.Contains("CNAME", StringComparison.Ordinal) ||
                     fieldUpper.Contains("MX", StringComparison.Ordinal))
            {
                rawParts.Add($"Answer: {field.Value}");
            }
        }

        content.RawContent = string.Join("\n", rawParts);
        return rawParts.Count > 0 ? content : null;
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Scans raw output for credential patterns that might be missed by protocol-specific extraction.
    /// </summary>
    private static CleartextContent ScanForCredentialPatterns(string rawOutput)
    {
        var content = new CleartextContent
        {
            Protocol = "Generic",
            ContentType = "Pattern Match",
            Severity = CleartextSeverity.Info,
            Description = "Additional credentials detected via pattern matching"
        };

        // Patterns for common credential formats
        var patterns = new Dictionary<string, (string CredType, string FieldName, bool IsPassword)>
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

    /// <summary>
    /// Decodes Base64-encoded credentials.
    /// </summary>
    private static string? DecodeBase64Credentials(string base64)
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
    private static string MaskPassword(string password)
    {
        if (string.IsNullOrEmpty(password)) return "***";
        if (password.Length <= 3) return new string('*', password.Length);
        return password[..2] + new string('*', Math.Min(password.Length - 2, 8));
    }

    /// <summary>
    /// Masks a token for display (shows first 8 and last 4 chars).
    /// </summary>
    private static string MaskToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return "***";
        if (token.Length <= 16) return new string('*', token.Length);
        return $"{token[..8]}...{token[^4..]}";
    }

    #endregion
}

/// <summary>
/// Result of protocol deep dive extraction.
/// </summary>
public class ProtocolDeepDiveResult
{
    public uint FrameNumber { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
    public List<ProtocolLayer> Layers { get; set; } = new();
    public string? RawOutput { get; set; }

    /// <summary>
    /// Detected cleartext content including credentials, messages, and sensitive data.
    /// </summary>
    public List<CleartextContent> CleartextContent { get; set; } = new();

    /// <summary>
    /// Indicates if any cleartext credentials were detected.
    /// </summary>
    public bool HasCleartextCredentials => CleartextContent.Any(c => c.Credentials.Count > 0);

    /// <summary>
    /// Gets the highest severity level of detected cleartext content.
    /// </summary>
    public CleartextSeverity MaxSeverity => CleartextContent.Count > 0
        ? CleartextContent.Max(c => c.Severity)
        : CleartextSeverity.Info;
}

/// <summary>
/// Represents a protocol layer (e.g., Ethernet, IP, TCP, HTTP).
/// </summary>
public class ProtocolLayer
{
    public string Name { get; set; } = "";
    public List<ProtocolField> Fields { get; set; } = new();
}

/// <summary>
/// Represents a single field within a protocol layer.
/// </summary>
public class ProtocolField
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public int IndentLevel { get; set; }
    public bool IsHighlighted { get; set; }
}

/// <summary>
/// Quick summary of protocol-specific information.
/// </summary>
public class ProtocolSummary
{
    public string Protocol { get; set; } = "";
    public string Icon { get; set; } = "📦";
    public Dictionary<string, string> KeyValues { get; set; } = new();
}

/// <summary>
/// Represents detected cleartext content in a packet.
/// </summary>
public class CleartextContent
{
    public string Protocol { get; set; } = "";
    public string ContentType { get; set; } = "";  // "Credential", "Message", "Query", "Command"
    public string Description { get; set; } = "";
    public string RawContent { get; set; } = "";
    public CleartextSeverity Severity { get; set; } = CleartextSeverity.Info;
    public List<CleartextCredential> Credentials { get; set; } = new();
}

/// <summary>
/// Represents a detected cleartext credential.
/// </summary>
public class CleartextCredential
{
    public string Protocol { get; set; } = "";
    public string CredentialType { get; set; } = "";  // "Username", "Password", "API Key", "Token", "Community String"
    public string FieldName { get; set; } = "";
    public string Value { get; set; } = "";
    public bool IsPassword { get; set; }
    public string SecurityWarning { get; set; } = "";
}

/// <summary>
/// Severity level for cleartext content.
/// </summary>
public enum CleartextSeverity
{
    Info,       // General cleartext (DNS queries, HTTP paths)
    Warning,    // Sensitive but not credentials (cookies, session IDs)
    Critical    // Passwords, API keys, authentication tokens
}
