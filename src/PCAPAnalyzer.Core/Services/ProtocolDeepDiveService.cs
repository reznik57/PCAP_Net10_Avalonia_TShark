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
            else if (line.StartsWith("Frame "))
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
