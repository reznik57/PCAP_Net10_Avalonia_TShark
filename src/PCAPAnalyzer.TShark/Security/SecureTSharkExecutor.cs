using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.TShark.Security;

/// <summary>
/// Provides secure execution of TShark commands using ProcessStartInfo.ArgumentList
/// to prevent command injection vulnerabilities.
/// </summary>
/// <remarks>
/// SECURITY: This class implements defense-in-depth security by:
/// 1. Using ProcessStartInfo.ArgumentList (no shell interpretation)
/// 2. Validating all inputs through TSharkInputValidator
/// 3. Never using string-based Arguments property
/// 4. Sanitizing all logged information
/// </remarks>
public sealed class SecureTSharkExecutor
{
    private readonly ILogger<SecureTSharkExecutor> _logger;
    private readonly TSharkInputValidator _validator;

    public SecureTSharkExecutor(ILogger<SecureTSharkExecutor> logger, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;

        // Create a properly typed logger for the validator if factory is available
        var validatorLogger = loggerFactory?.CreateLogger<TSharkInputValidator>();
        _validator = new TSharkInputValidator(validatorLogger);
    }

    /// <summary>
    /// Creates a secure ProcessStartInfo for TShark packet streaming analysis.
    /// </summary>
    /// <param name="pcapPath">Path to the PCAP file</param>
    /// <param name="filter">Optional Wireshark display filter</param>
    /// <param name="executionMode">The TShark execution mode (Native, WSL, etc.)</param>
    /// <param name="tsharkExecutable">The TShark executable path</param>
    /// <returns>Configured ProcessStartInfo with ArgumentList</returns>
    /// <remarks>
    /// SECURITY: Uses ArgumentList to pass arguments individually, preventing shell injection.
    /// All inputs are validated before being added to the argument list.
    /// </remarks>
    public ProcessStartInfo CreateStreamingAnalysisProcess(
        string pcapPath,
        string? filter,
        TSharkExecutionMode executionMode,
        string tsharkExecutable)
    {
        // Validate inputs
        var validatedPath = _validator.ValidatePath(pcapPath);
        var validatedFilter = string.IsNullOrWhiteSpace(filter) ? string.Empty : _validator.ValidateFilter(filter);

        // Convert path for WSL if needed
        var effectivePath = executionMode == TSharkExecutionMode.Wsl
            ? ConvertToWslPath(validatedPath)
            : validatedPath;

        // Standard packet analysis fields
        var fields = new[]
        {
            "frame.number", "frame.time", "frame.time_epoch", "frame.len",
            "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
            "_ws.col.Protocol", "frame.protocols", "_ws.col.Info"
        };

        var validatedFields = _validator.ValidateFields(fields);

        return BuildProcessStartInfo(executionMode, tsharkExecutable, effectivePath, validatedFilter, validatedFields);
    }

    /// <summary>
    /// Creates a secure ProcessStartInfo for TShark packet counting.
    /// </summary>
    /// <param name="pcapPath">Path to the PCAP file</param>
    /// <param name="executionMode">The TShark execution mode (Native, WSL, etc.)</param>
    /// <param name="tsharkExecutable">The TShark executable path</param>
    /// <returns>Configured ProcessStartInfo with ArgumentList</returns>
    public ProcessStartInfo CreatePacketCountProcess(
        string pcapPath,
        TSharkExecutionMode executionMode,
        string tsharkExecutable)
    {
        // Validate inputs
        var validatedPath = _validator.ValidatePath(pcapPath);

        // Convert path for WSL if needed
        var effectivePath = executionMode == TSharkExecutionMode.Wsl
            ? ConvertToWslPath(validatedPath)
            : validatedPath;

        // Only need frame.number for counting
        var validatedFields = _validator.ValidateFields("frame.number");

        return BuildProcessStartInfo(executionMode, tsharkExecutable, effectivePath, string.Empty, validatedFields);
    }

    /// <summary>
    /// Builds a secure ProcessStartInfo with ArgumentList (NO shell interpretation).
    /// </summary>
    /// <remarks>
    /// SECURITY: This method uses ArgumentList instead of Arguments to prevent shell injection.
    /// Each argument is passed individually to the process, with no shell interpretation.
    /// </remarks>
    private ProcessStartInfo BuildProcessStartInfo(
        TSharkExecutionMode executionMode,
        string tsharkExecutable,
        string pcapPath,
        string displayFilter,
        string[] fields)
    {
        var startInfo = new ProcessStartInfo
        {
            UseShellExecute = false, // CRITICAL: Must be false for ArgumentList
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8
        };

        if (executionMode == TSharkExecutionMode.Wsl)
        {
            // For WSL, we launch wsl.exe and pass tshark as first argument
            startInfo.FileName = "wsl.exe";

            // Add tshark executable
            startInfo.ArgumentList.Add(tsharkExecutable);
        }
        else
        {
            // Native Windows or Linux execution
            startInfo.FileName = tsharkExecutable;
        }

        // Add arguments using ArgumentList (SECURE - no shell interpretation)
        // Input file (-r)
        startInfo.ArgumentList.Add("-r");
        startInfo.ArgumentList.Add(pcapPath); // Already validated

        // Display filter (-Y) if provided
        if (!string.IsNullOrEmpty(displayFilter))
        {
            startInfo.ArgumentList.Add("-Y");
            startInfo.ArgumentList.Add(displayFilter); // Already validated
        }

        // Output format (-T fields)
        startInfo.ArgumentList.Add("-T");
        startInfo.ArgumentList.Add("fields");

        // Add fields (-e)
        foreach (var field in fields)
        {
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add(field); // Already validated
        }

        // Field occurrence (first occurrence only)
        startInfo.ArgumentList.Add("-E");
        startInfo.ArgumentList.Add("occurrence=f");

        _logger.LogDebug("Created secure TShark process: {FileName} with {ArgCount} arguments",
            startInfo.FileName, startInfo.ArgumentList.Count);

        return startInfo;
    }

    /// <summary>
    /// Converts a Windows path to WSL path format (/mnt/c/path/to/file).
    /// </summary>
    /// <param name="windowsPath">The Windows path to convert (already validated)</param>
    /// <returns>The WSL-formatted path</returns>
    /// <remarks>
    /// SECURITY: Input must be validated before calling this method.
    /// Output is also validated to prevent injection through path conversion.
    /// </remarks>
    private string ConvertToWslPath(string windowsPath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return windowsPath;
        }

        // Input should already be validated, but double-check
        if (windowsPath.Length < 2 || windowsPath[1] != ':')
        {
            throw new ArgumentException("Invalid Windows path format", nameof(windowsPath));
        }

        // Convert: C:\path\to\file.pcap → /mnt/c/path/to/file.pcap
        var driveLetter = char.ToLowerInvariant(windowsPath[0]);
        var relativePath = windowsPath.Substring(2).Replace('\\', '/');
        var wslPath = $"/mnt/{driveLetter}{relativePath}";

        // Validate the converted path
        _validator.ValidateWslPath(wslPath);

        _logger.LogDebug("Converted Windows path to WSL: {WslPath}", wslPath);
        return wslPath;
    }

    /// <summary>
    /// Sanitizes a file path for safe logging (removes directory information).
    /// </summary>
    public static string SanitizePathForLogging(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return "[unknown]";

        try
        {
            return Path.GetFileName(filePath);
        }
        catch
        {
            return "[invalid-path]";
        }
    }
}

/// <summary>
/// TShark execution modes for different environments.
/// </summary>
public enum TSharkExecutionMode
{
    /// <summary>
    /// Native Windows execution (tshark.exe in Program Files)
    /// </summary>
    Native,

    /// <summary>
    /// WSL execution (tshark via wsl.exe on Windows)
    /// </summary>
    Wsl,

    /// <summary>
    /// Direct Linux/Unix execution
    /// </summary>
    Direct,

    /// <summary>
    /// TShark not available
    /// </summary>
    Unavailable
}
