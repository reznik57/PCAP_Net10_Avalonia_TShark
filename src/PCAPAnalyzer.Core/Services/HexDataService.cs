using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service for extracting raw packet hex data on-demand using TShark JSON output.
/// Optimized for single-packet extraction (avoids full file parsing overhead).
/// Uses TShark display filters to extract only the requested frame.
/// </summary>
public sealed class HexDataService
{
    private readonly ILogger<HexDataService> _logger;
    private readonly string? _tsharkPath;

    public HexDataService(ILogger<HexDataService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _tsharkPath = FindTSharkExecutable();
    }

    /// <summary>
    /// Extracts raw hex bytes for multiple packet frames in a single TShark call.
    /// Much more efficient than extracting one frame at a time for large files.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file</param>
    /// <param name="frameNumbers">Frame numbers to extract (1-based)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Dictionary mapping frame numbers to raw bytes</returns>
    public async Task<Dictionary<uint, byte[]>> ExtractHexDataBatchAsync(
        string pcapPath,
        IEnumerable<uint> frameNumbers,
        CancellationToken cancellationToken = default)
    {
        var result = new Dictionary<uint, byte[]>();
        var frameList = frameNumbers.ToList();

        if (frameList.Count == 0 || string.IsNullOrWhiteSpace(_tsharkPath) || string.IsNullOrWhiteSpace(pcapPath))
            return result;

        try
        {
            // Build frame filter: frame.number == 1 or frame.number == 2 or ...
            var frameFilter = string.Join(" or ", frameList.Select(f => $"frame.number == {f}"));
            var arguments = $"-r \"{pcapPath}\" -Y \"{frameFilter}\" -T fields -e frame.number -x";

            var sw = Stopwatch.StartNew();

            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
                return result;

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);

            var exitTask = process.WaitForExitAsync(cancellationToken);
            await Task.WhenAny(exitTask, Task.Delay(120000, cancellationToken));

            sw.Stop();
            _logger.LogDebug("Batch extraction of {Count} frames completed in {Ms}ms", frameList.Count, sw.ElapsedMilliseconds);

            // Parse output - each packet starts with frame number then hex dump
            result = ParseBatchHexOutput(output);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in batch hex extraction");
        }

        return result;
    }

    private Dictionary<uint, byte[]> ParseBatchHexOutput(string output)
    {
        var result = new Dictionary<uint, byte[]>();
        if (string.IsNullOrWhiteSpace(output))
            return result;

        // Output format: frame_number\nhex_dump_lines\n\nframe_number\nhex_dump_lines\n...
        var sections = output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var section in sections)
        {
            var lines = section.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0)
                continue;

            // First line should be frame number
            if (uint.TryParse(lines[0].Trim(), out var frameNum))
            {
                var hexLines = string.Join("\n", lines.Skip(1));
                var bytes = ParseHexFromTextDump(hexLines);
                if (bytes.Length > 0)
                {
                    result[frameNum] = bytes;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Extracts raw hex bytes for a specific packet frame using TShark JSON output with -x flag.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file</param>
    /// <param name="frameNumber">Frame number to extract (1-based)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Raw packet bytes or empty array if extraction fails</returns>
    public async Task<byte[]> ExtractHexDataAsync(string pcapPath, uint frameNumber, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_tsharkPath))
        {
            _logger.LogWarning("TShark not available - cannot extract hex data");
            return Array.Empty<byte>();
        }

        if (string.IsNullOrWhiteSpace(pcapPath))
        {
            _logger.LogError("Invalid PCAP path");
            return Array.Empty<byte>();
        }

        try
        {
            var sw = Stopwatch.StartNew();

            // APPROACH: Use rawshark with direct hex output for fastest extraction
            // rawshark reads pcap directly without full protocol dissection
            // Alternative: Use tshark -x with minimal dissection
            // -o "gui.column.format:" disables column output for speed
            // -Tfields with -e frame.protocols and -x for raw hex

            // Simplest fast approach: Just read first N bytes raw from packet
            // But TShark must still find the packet. Let's try minimal dissection:
            var arguments = $"-r \"{pcapPath}\" -Y \"frame.number == {frameNumber}\" -T fields -e frame.protocols -x -c 1";

            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                _logger.LogError("Failed to start TShark process");
                return Array.Empty<byte>();
            }

            // Read output - with -x it outputs hex dump in classic format
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);

            // 60 second timeout for large files
            var exitTask = process.WaitForExitAsync(cancellationToken);
            if (await Task.WhenAny(exitTask, Task.Delay(60000, cancellationToken)) != exitTask)
            {
                _logger.LogWarning("TShark timeout for frame {Frame} - killing process", frameNumber);
                try { process.Kill(); } catch { }
                return Array.Empty<byte>();
            }

            sw.Stop();
            _logger.LogDebug("TShark extraction for frame {Frame} completed in {Ms}ms", frameNumber, sw.ElapsedMilliseconds);

            if (process.ExitCode != 0)
            {
                var error = await process.StandardError.ReadToEndAsync(cancellationToken);
                _logger.LogWarning("TShark returned exit code {ExitCode}: {Error}", process.ExitCode, error);
            }

            // Parse hex dump from -x output format (classic hex dump)
            return ParseHexFromTextDump(output);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting hex data for frame {FrameNumber}", frameNumber);
            return Array.Empty<byte>();
        }
    }

    /// <summary>
    /// Parses TShark -x text hex dump output to extract raw bytes.
    /// Format: "0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00   ................"
    /// </summary>
    private byte[] ParseHexFromTextDump(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return Array.Empty<byte>();
        }

        var bytes = new System.Collections.Generic.List<byte>();
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            // Skip lines that don't start with hex offset (e.g., "0000", "0010")
            var trimmedLine = line.TrimStart();
            if (trimmedLine.Length < 4)
                continue;

            // Check if line starts with hex offset pattern
            if (!IsHexOffset(trimmedLine.AsSpan(0, 4)))
                continue;

            // Parse hex bytes from the line
            // Format: "0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00   ................"
            // Hex bytes are between offset and ASCII representation

            // Find start of hex data (after offset and spaces)
            var hexStart = 4;
            while (hexStart < trimmedLine.Length && (trimmedLine[hexStart] == ' ' || trimmedLine[hexStart] == '\t'))
                hexStart++;

            // Extract hex portion (stop at double space or end)
            var hexEnd = trimmedLine.IndexOf("  ", hexStart + 1, StringComparison.Ordinal);
            if (hexEnd < 0)
                hexEnd = trimmedLine.Length;

            var hexPart = trimmedLine.Substring(hexStart, hexEnd - hexStart);

            // Parse space-separated hex bytes
            var hexBytes = hexPart.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var hexByte in hexBytes)
            {
                if (hexByte.Length == 2 && IsHexString(hexByte))
                {
                    bytes.Add(Convert.ToByte(hexByte, 16));
                }
            }
        }

        return bytes.ToArray();
    }

    private static bool IsHexOffset(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    private static bool IsHexString(string s)
    {
        foreach (var c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Parses TShark JSON output to extract frame_raw hex string and convert to bytes.
    /// TShark JSON structure: [{ "_source": { "layers": { "frame_raw": ["hex", offset, len, ...] } } }]
    /// </summary>
    private byte[] ParseHexFromJson(string jsonOutput, uint frameNumber)
    {
        if (string.IsNullOrWhiteSpace(jsonOutput))
        {
            return Array.Empty<byte>();
        }

        try
        {
            using var document = JsonDocument.Parse(jsonOutput);
            var root = document.RootElement;

            // TShark JSON output is an array with single packet
            if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() == 0)
            {
                _logger.LogWarning("Invalid TShark JSON output for frame {FrameNumber}", frameNumber);
                return Array.Empty<byte>();
            }

            var packet = root[0];

            // Navigate to frame_raw: packet["_source"]["layers"]["frame_raw"][0]
            if (!packet.TryGetProperty("_source", out var source) ||
                !source.TryGetProperty("layers", out var layers) ||
                !layers.TryGetProperty("frame_raw", out var frameRaw))
            {
                _logger.LogWarning("frame_raw not found in JSON for frame {FrameNumber}", frameNumber);
                return Array.Empty<byte>();
            }

            // frame_raw is an array: ["hexstring", offset, length, ...]
            if (frameRaw.ValueKind != JsonValueKind.Array || frameRaw.GetArrayLength() == 0)
            {
                return Array.Empty<byte>();
            }

            var hexString = frameRaw[0].GetString();
            if (string.IsNullOrWhiteSpace(hexString))
            {
                return Array.Empty<byte>();
            }

            // Convert hex string to byte array
            return ConvertHexStringToBytes(hexString);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "JSON parsing error for frame {FrameNumber}", frameNumber);
            return Array.Empty<byte>();
        }
    }

    /// <summary>
    /// Converts hex string (e.g., "ffffffffffff001122334455...") to byte array.
    /// </summary>
    private byte[] ConvertHexStringToBytes(string hexString)
    {
        if (string.IsNullOrWhiteSpace(hexString))
        {
            return Array.Empty<byte>();
        }

        // Remove any whitespace or separators
        hexString = hexString.Replace(" ", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .Replace(":", "", StringComparison.Ordinal);

        if (hexString.Length % 2 != 0)
        {
            _logger.LogWarning("Invalid hex string length: {Length}", hexString.Length);
            return Array.Empty<byte>();
        }

        var bytes = new byte[hexString.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            var hex = hexString.Substring(i * 2, 2);
            bytes[i] = Convert.ToByte(hex, 16);
        }

        return bytes;
    }

    /// <summary>
    /// Finds TShark executable on the system.
    /// Checks common installation paths and PATH environment variable.
    /// </summary>
    private string? FindTSharkExecutable()
    {
        // Check environment variable first
        var envPath = Environment.GetEnvironmentVariable("TSHARK_PATH");
        if (!string.IsNullOrWhiteSpace(envPath) && System.IO.File.Exists(envPath))
        {
            return envPath;
        }

        // Check common Windows paths
        if (OperatingSystem.IsWindows())
        {
            var candidates = new[]
            {
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe"
            };

            foreach (var candidate in candidates)
            {
                if (System.IO.File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        // For Linux/WSL, assume tshark is in PATH
        return "tshark";
    }
}
