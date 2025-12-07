using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.TShark.Security;

/// <summary>
/// Provides comprehensive input validation for TShark command arguments to prevent command injection attacks.
/// Implements defense-in-depth security strategy with whitelisting and pattern validation.
/// </summary>
/// <remarks>
/// SECURITY: This class is critical for preventing shell command injection vulnerabilities.
/// All TShark inputs (file paths, filters, field names) MUST be validated through these methods
/// before being passed to ProcessStartInfo.ArgumentList.
/// </remarks>
public sealed class TSharkInputValidator
{
    private readonly ILogger<TSharkInputValidator>? _logger;

    // Shell metacharacters that could be exploited for command injection
    private static readonly char[] ShellMetacharacters = { ';', '&', '|', '<', '>', '`', '$', '(', ')', '{', '}', '[', ']', '\n', '\r' };

    // Whitelisted PCAP file extensions
    private static readonly string[] AllowedExtensions = { ".pcap", ".pcapng", ".cap", ".dmp" };

    // Maximum lengths to prevent DoS attacks
    private const int MaxPathLength = 4096;
    private const int MaxFilterLength = 2000;
    private const int MaxFieldNameLength = 100;

    // Regex patterns for validation (compiled for performance)
    private static readonly Regex FilterPattern = new(@"^[a-zA-Z0-9\.\s_\-\(\)\[\]<>=!&|:]+$", RegexOptions.Compiled);
    // Allow field names to start with underscore (e.g., _ws.col.Protocol) or lowercase letter
    // Allow uppercase in column names (e.g., _ws.col.Protocol has uppercase P)
    private static readonly Regex FieldNamePattern = new(@"^[a-z_][a-zA-Z0-9_\.]*$", RegexOptions.Compiled);

    public TSharkInputValidator(ILogger<TSharkInputValidator>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validates a file path for use with TShark, preventing command injection and path traversal attacks.
    /// </summary>
    /// <param name="filePath">The file path to validate</param>
    /// <returns>The validated, canonical file path</returns>
    /// <exception cref="ArgumentException">Thrown when the path is invalid or contains dangerous characters</exception>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist</exception>
    /// <remarks>
    /// SECURITY: This method performs the following validations:
    /// 1. Checks for null/empty input
    /// 2. Verifies file exists
    /// 3. Gets canonical path (prevents path traversal)
    /// 4. Validates file extension (whitelist approach)
    /// 5. Checks for shell metacharacters (defense in depth)
    /// 6. Enforces maximum path length (prevents DoS)
    /// </remarks>
#pragma warning disable CA1502 // Security validation requires multiple checks
    public string ValidatePath(string filePath)
#pragma warning restore CA1502
    {
        // Check for null or empty
        if (string.IsNullOrWhiteSpace(filePath))
        {
            _logger?.LogWarning("File path validation failed: Path is null or empty");
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
        }

        // Length check (prevent DoS)
        if (filePath.Length > MaxPathLength)
        {
            _logger?.LogWarning("File path validation failed: Path too long ({Length} > {Max})", filePath.Length, MaxPathLength);
            throw new ArgumentException($"File path too long (max {MaxPathLength} characters)", nameof(filePath));
        }

        // CRITICAL: Validate file extension BEFORE other checks
        // This ensures proper error message ordering for invalid file types
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        if (!AllowedExtensions.Contains(extension))
        {
            _logger?.LogWarning("File path validation failed: Invalid extension {Extension} for {Path}", extension, filePath);
            throw new ArgumentException($"Invalid file type. Must be .pcap, .pcapng, or .cap (Parameter '{nameof(filePath)}')");
        }

        // Check for shell metacharacters BEFORE quotes/backslashes
        // This ensures proper error message ordering for forbidden characters
        char[] forbiddenShellChars = { '|', '&', ';', '$', '`' };
        if (filePath.IndexOfAny(forbiddenShellChars) >= 0)
        {
            _logger?.LogError("SECURITY: Shell metacharacters detected in path: {Path}", filePath);
            throw new ArgumentException($"Path contains forbidden characters (Parameter '{nameof(filePath)}')");
        }

        // Check for tilde expansion attack
        if (filePath.Contains('~', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Tilde character detected in path: {Path}", filePath);
            throw new ArgumentException("Path contains tilde which could enable path expansion attacks", nameof(filePath));
        }

        // Check for path separators in filename (prevent directory traversal)
        string filename = Path.GetFileName(filePath);
        if (filename.Contains('/', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Forward slash in filename: {Path}", filePath);
            throw new ArgumentException("Filename cannot contain path separators", nameof(filePath));
        }

        // Check for dangerous path characters (quotes and backslashes) - AFTER extension and shell checks
        if (filePath.Contains('"', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Quote character detected in path: {Path}", filePath);
            throw new ArgumentException("Path contains dangerous characters (quotes or backslashes)", nameof(filePath));
        }

        // Get canonical path (resolves relative paths, symlinks, etc.)
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(filePath);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "File path validation failed: Cannot get full path for {Path}", filePath);
            throw new ArgumentException($"Invalid file path: {ex.Message}", nameof(filePath), ex);
        }

        // Verify file exists - do this LAST so proper error messages appear for validation failures
        if (!File.Exists(fullPath))
        {
            _logger?.LogWarning("File path validation failed: File not found at {Path}", fullPath);
            throw new FileNotFoundException("PCAP file not found", fullPath);
        }

        // Additional validation on the resolved full path
        // Check for shell metacharacters in resolved path (defense in depth)
        if (fullPath.IndexOfAny(ShellMetacharacters) >= 0)
        {
            _logger?.LogError("SECURITY: Shell metacharacters detected in resolved path: {Path}", fullPath);
            throw new ArgumentException("File path contains forbidden shell metacharacters", nameof(filePath));
        }

        // Check for dangerous path characters in resolved path (defense in depth)
        if (fullPath.Contains('"', StringComparison.Ordinal) || fullPath.Contains('\'', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Quote characters detected in resolved path: {Path}", fullPath);
            throw new ArgumentException("File path contains forbidden quote characters", nameof(filePath));
        }

        // Check for backslashes on non-Windows platforms (could indicate injection attempts)
        if (Path.DirectorySeparatorChar != '\\' && fullPath.Contains('\\', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Backslash detected in path on non-Windows platform: {Path}", fullPath);
            throw new ArgumentException("File path contains forbidden characters", nameof(filePath));
        }

        _logger?.LogDebug("File path validated successfully: {Path}", fullPath);
        return fullPath;
    }

    /// <summary>
    /// Validates a Wireshark display filter for use with TShark, preventing command injection.
    /// </summary>
    /// <param name="filter">The display filter to validate</param>
    /// <returns>The validated filter string (empty if input is null/whitespace)</returns>
    /// <exception cref="ArgumentException">Thrown when the filter contains invalid characters</exception>
    /// <remarks>
    /// SECURITY: This method performs the following validations:
    /// 1. Returns empty for null/whitespace input (safe default)
    /// 2. Enforces maximum length (prevents DoS)
    /// 3. Validates against whitelist pattern (Wireshark display filter syntax)
    /// 4. Checks for shell metacharacters (defense in depth)
    ///
    /// Wireshark display filters support: alphanumeric, dots, underscores, spaces,
    /// comparison operators (&lt;, &gt;, =, !), logical operators (&amp;&amp;, ||), parentheses, brackets.
    /// </remarks>
    public string ValidateFilter(string filter)
    {
        // Empty filter is valid
        if (string.IsNullOrWhiteSpace(filter))
        {
            return string.Empty;
        }

        // Length check (prevent DoS)
        if (filter.Length > MaxFilterLength)
        {
            _logger?.LogWarning("Filter validation failed: Filter too long ({Length} > {Max})", filter.Length, MaxFilterLength);
            throw new ArgumentException($"Filter too long (max {MaxFilterLength} characters)", nameof(filter));
        }

        // Whitelist validation (Wireshark display filter syntax)
        // Allows: alphanumeric, dots, spaces, underscores, hyphens, comparison/logical operators, parentheses, brackets
        if (!FilterPattern.IsMatch(filter))
        {
            _logger?.LogWarning("Filter validation failed: Invalid characters in filter: {Filter}", filter);
            throw new ArgumentException("Invalid display filter syntax: contains forbidden characters", nameof(filter));
        }

        // Check for shell metacharacters that could be exploited
        // Note: Some overlap with pattern check, but provides defense in depth
        var dangerousChars = new[] { ';', '`', '$', '\n', '\r', '"', '\'' };
        if (filter.IndexOfAny(dangerousChars) >= 0)
        {
            _logger?.LogError("SECURITY: Shell metacharacters detected in filter: {Filter}", filter);
            throw new ArgumentException("Filter contains forbidden shell metacharacters", nameof(filter));
        }

        _logger?.LogDebug("Filter validated successfully: {Filter}", filter);
        return filter;
    }

    /// <summary>
    /// Validates a TShark field name for use with the -e flag, preventing command injection.
    /// </summary>
    /// <param name="field">The field name to validate</param>
    /// <returns>The validated field name</returns>
    /// <exception cref="ArgumentException">Thrown when the field name is invalid</exception>
    /// <remarks>
    /// SECURITY: This method performs the following validations:
    /// 1. Checks for null/empty input
    /// 2. Enforces maximum length (prevents DoS)
    /// 3. Validates against strict whitelist pattern (Wireshark field naming convention)
    ///
    /// Wireshark field names must:
    /// - Start with a lowercase letter
    /// - Contain only lowercase letters, digits, underscores, and dots
    /// - Follow the pattern: protocol.subfield.attribute (e.g., "frame.number", "ip.src")
    /// </remarks>
    public string ValidateField(string field)
    {
        // Check for null or empty
        if (string.IsNullOrWhiteSpace(field))
        {
            _logger?.LogWarning("Field validation failed: Field name is null or empty");
            throw new ArgumentException("Field name cannot be null or empty", nameof(field));
        }

        // Length check (prevent DoS)
        if (field.Length > MaxFieldNameLength)
        {
            _logger?.LogWarning("Field validation failed: Field name too long ({Length} > {Max})", field.Length, MaxFieldNameLength);
            throw new ArgumentException($"Field name too long (max {MaxFieldNameLength} characters)", nameof(field));
        }

        // Strict whitelist validation (Wireshark field naming convention)
        // Must start with lowercase letter, followed by lowercase letters, digits, underscores, or dots
        if (!FieldNamePattern.IsMatch(field))
        {
            _logger?.LogWarning("Field validation failed: Invalid field name: {Field}", field);
            throw new ArgumentException($"Invalid field name: {field}. Must follow Wireshark naming convention (lowercase, alphanumeric, dots, underscores)", nameof(field));
        }

        _logger?.LogDebug("Field name validated successfully: {Field}", field);
        return field;
    }

    /// <summary>
    /// Validates multiple field names at once.
    /// Uses params ReadOnlySpan for zero-allocation calls with small field counts.
    /// </summary>
    /// <param name="fields">The field names to validate</param>
    /// <returns>Array of validated field names</returns>
    /// <exception cref="ArgumentException">Thrown when any field name is invalid</exception>
    public string[] ValidateFields(params ReadOnlySpan<string> fields)
    {
        if (fields.IsEmpty)
        {
            return [];
        }

        var validatedFields = new string[fields.Length];
        for (int i = 0; i < fields.Length; i++)
        {
            validatedFields[i] = ValidateField(fields[i]);
        }

        return validatedFields;
    }

    /// <summary>
    /// Validates a WSL path conversion is safe (if applicable).
    /// </summary>
    /// <param name="wslPath">The WSL path to validate</param>
    /// <returns>The validated WSL path</returns>
    /// <exception cref="ArgumentException">Thrown when the WSL path contains dangerous characters</exception>
    /// <remarks>
    /// SECURITY: Validates that the converted WSL path (/mnt/c/path/to/file) does not contain
    /// shell metacharacters that could be exploited when passed to WSL via wsl.exe.
    /// </remarks>
    public string ValidateWslPath(string wslPath)
    {
        if (string.IsNullOrWhiteSpace(wslPath))
        {
            throw new ArgumentException("WSL path cannot be null or empty", nameof(wslPath));
        }

        // Check for shell metacharacters
        if (wslPath.IndexOfAny(ShellMetacharacters) >= 0)
        {
            _logger?.LogError("SECURITY: Shell metacharacters detected in WSL path: {Path}", wslPath);
            throw new ArgumentException("WSL path contains forbidden shell metacharacters", nameof(wslPath));
        }

        // Check for quotes or other dangerous characters
        if (wslPath.Contains('"', StringComparison.Ordinal) || wslPath.Contains('\'', StringComparison.Ordinal) || wslPath.Contains('`', StringComparison.Ordinal))
        {
            _logger?.LogError("SECURITY: Quote characters detected in WSL path: {Path}", wslPath);
            throw new ArgumentException("WSL path contains forbidden quote characters", nameof(wslPath));
        }

        _logger?.LogDebug("WSL path validated successfully: {Path}", wslPath);
        return wslPath;
    }
}
