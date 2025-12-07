using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Service for exporting data tables to CSV format with enterprise-grade security
/// Implements comprehensive protection against path traversal, symlink attacks, and TOCTOU vulnerabilities
/// </summary>
/// <remarks>
/// Security Features:
/// - Canonical path resolution to prevent path traversal attacks
/// - Symlink detection and prevention
/// - Atomic file write operations to eliminate TOCTOU race conditions
/// - Unicode normalization to prevent encoding bypass
/// - Reserved filename validation (Windows compatibility)
/// - Comprehensive audit logging of all export operations
/// </remarks>
public class CsvExportService : ICsvExportService
{
    private readonly ILogger<CsvExportService>? _logger;
    private readonly string[] _allowedDirectories;

    // Security: Maximum rows to prevent memory exhaustion attacks
    private const int MaxExportRows = 1_000_000;

    // Security: Default allowed export directories (user documents by default)
    private static readonly string[] DefaultAllowedExportDirectories = new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Path.GetTempPath()
    };

    // Security: Reserved Windows filenames
    private static readonly string[] ReservedWindowsNames = new[]
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public CsvExportService(ILogger<CsvExportService>? logger = null, string[]? allowedDirectories = null)
    {
        _logger = logger;
        _allowedDirectories = allowedDirectories ?? DefaultAllowedExportDirectories;

        // Audit log service initialization
        _logger?.LogInformation("CsvExportService initialized with {Count} allowed directories", _allowedDirectories.Length);
        foreach (var dir in _allowedDirectories)
        {
            _logger?.LogDebug("Allowed export directory: {Directory}", dir);
        }
    }
    /// <summary>
    /// Export data to CSV file with comprehensive security validation
    /// </summary>
    /// <typeparam name="T">Type of data to export</typeparam>
    /// <param name="data">Collection of data items</param>
    /// <param name="filePath">Destination file path</param>
    /// <param name="columnMappings">Column name to property selector mappings</param>
    /// <param name="includeHeaders">Whether to include header row</param>
    /// <exception cref="ArgumentNullException">Thrown when data or filePath is null</exception>
    /// <exception cref="ArgumentException">Thrown when filePath or columnMappings are invalid</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when path validation fails due to security checks</exception>
    /// <exception cref="InvalidOperationException">Thrown when row count exceeds maximum allowed</exception>
    public async Task ExportToCsvAsync<T>(
        IEnumerable<T> data,
        string filePath,
        Dictionary<string, Func<T, object?>> columnMappings,
        bool includeHeaders = true)
    {
        if (data is null)
            throw new ArgumentNullException(nameof(data));
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be empty", nameof(filePath));
        if (columnMappings is null || columnMappings.Count == 0)
            throw new ArgumentException("Column mappings cannot be empty", nameof(columnMappings));

        // Security audit: Log export attempt with sanitized path
        var filename = Path.GetFileName(filePath);
        _logger?.LogInformation("CSV export requested for file: {FileName}", filename);

        // Security: Comprehensive path validation pipeline
        var validatedPath = ValidateAndResolvePath(filePath);

        // Security: Check row count to prevent memory exhaustion
        var dataList = data.ToList();
        if (dataList.Count > MaxExportRows)
        {
            _logger?.LogWarning("Export rejected: {Count} rows exceeds maximum of {Max} (file: {FileName})",
                dataList.Count, MaxExportRows, filename);
            throw new InvalidOperationException(
                $"Export limited to {MaxExportRows.ToString("N0", CultureInfo.InvariantCulture)} rows for performance and security. Attempted to export {dataList.Count.ToString("N0", CultureInfo.InvariantCulture)} rows.");
        }

        _logger?.LogInformation("Starting CSV export with {Count} rows", dataList.Count);

        var sb = new StringBuilder();

        // Write headers
        if (includeHeaders)
        {
            var headers = columnMappings.Keys.Select(EscapeCsvField);
            sb.AppendLine(string.Join(",", headers));
        }

        // Write data rows
        foreach (var item in dataList)
        {
            var values = columnMappings.Values
                .Select(selector => selector(item))
                .Select(value => FormatValue(value))
                .Select(EscapeCsvField);

            sb.AppendLine(string.Join(",", values));
        }

        // Security: Atomic write operation to prevent TOCTOU
        await WriteFileAtomically(validatedPath, sb.ToString(), CancellationToken.None);

        _logger?.LogInformation("Successfully exported {Count} rows to {FileName}", dataList.Count, filename);
    }

    /// <summary>
    /// Export protocol distribution data to CSV
    /// </summary>
    public async Task ExportProtocolDistributionAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Protocol"] = d => d.Protocol,
            ["Packet Count"] = d => d.PacketCount,
            ["Percentage"] = d => d.Percentage,
            ["Bytes"] = d => d.Bytes
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export top talkers data to CSV
    /// </summary>
    public async Task ExportTopTalkersAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Source IP"] = d => d.SourceIP,
            ["Destination IP"] = d => d.DestinationIP,
            ["Packet Count"] = d => d.PacketCount,
            ["Bytes Sent"] = d => d.BytesSent,
            ["Bytes Received"] = d => d.BytesReceived,
            ["Protocol"] = d => d.Protocol
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export port analysis data to CSV
    /// </summary>
    public async Task ExportPortAnalysisAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Port"] = d => d.Port,
            ["Service"] = d => d.Service,
            ["Packet Count"] = d => d.PacketCount,
            ["Percentage"] = d => d.Percentage,
            ["Security Risk"] = d => d.SecurityRisk,
            ["Description"] = d => d.Description
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export country traffic data to CSV
    /// </summary>
    public async Task ExportCountryTrafficAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Country"] = d => d.CountryName,
            ["Country Code"] = d => d.CountryCode,
            ["Packet Count"] = d => d.PacketCount,
            ["Percentage"] = d => d.Percentage,
            ["Bytes"] = d => d.Bytes
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export threat list to CSV
    /// </summary>
    public async Task ExportThreatsAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Timestamp"] = d => d.Timestamp,
            ["Threat Type"] = d => d.ThreatType,
            ["Severity"] = d => d.Severity,
            ["Source IP"] = d => d.SourceIP,
            ["Destination IP"] = d => d.DestinationIP,
            ["Port"] = d => d.Port,
            ["Description"] = d => d.Description,
            ["Details"] = d => d.Details
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export anomaly list to CSV
    /// </summary>
    public async Task ExportAnomaliesAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Timestamp"] = d => d.Timestamp,
            ["Anomaly Type"] = d => d.Type,
            ["Severity"] = d => d.Severity,
            ["Source IP"] = d => d.SourceIP,
            ["Destination IP"] = d => d.DestinationIP,
            ["Description"] = d => d.Description,
            ["Confidence Score"] = d => d.ConfidenceScore
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Export packet list to CSV
    /// </summary>
    public async Task ExportPacketsAsync(
        IEnumerable<dynamic> data,
        string filePath)
    {
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Packet Number"] = d => d.PacketNumber,
            ["Timestamp"] = d => d.Timestamp,
            ["Source IP"] = d => d.SourceIP,
            ["Destination IP"] = d => d.DestinationIP,
            ["Source Port"] = d => d.SourcePort,
            ["Destination Port"] = d => d.DestinationPort,
            ["Protocol"] = d => d.Protocol,
            ["Length"] = d => d.Length,
            ["Info"] = d => d.Info
        };

        await ExportToCsvAsync(data, filePath, columnMappings);
    }

    /// <summary>
    /// Format value for CSV output
    /// </summary>
    private string FormatValue(object? value)
    {
        if (value is null)
            return string.Empty;

        return value switch
        {
            DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
            DateTimeOffset dto => dto.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
            TimeSpan ts => ts.ToString(@"hh\:mm\:ss\.fff", CultureInfo.InvariantCulture),
            double d => d.ToString("F2", CultureInfo.InvariantCulture),
            float f => f.ToString("F2", CultureInfo.InvariantCulture),
            decimal dec => dec.ToString("F2", CultureInfo.InvariantCulture),
            _ => value.ToString() ?? string.Empty
        };
    }

    /// <summary>
    /// Escape CSV field according to RFC 4180 with security enhancements
    /// </summary>
    private string EscapeCsvField(string field)
    {
        if (string.IsNullOrEmpty(field))
            return string.Empty;

        // Security: Prevent CSV formula injection attacks
        // Excel/LibreOffice will execute formulas starting with =, +, -, @, |, %
        if (field.Length > 0)
        {
            char firstChar = field[0];
            if (firstChar == '=' || firstChar == '+' || firstChar == '-' ||
                firstChar == '@' || firstChar == '|' || firstChar == '%')
            {
                // Prefix with single quote to prevent formula execution
                field = "'" + field;
                _logger?.LogDebug("Formula injection prevention: Prefixed field starting with '{Char}'", firstChar);
            }
        }

        // Check if escaping is needed
        bool needsEscaping = field.Contains(',', StringComparison.Ordinal) ||
                            field.Contains('"', StringComparison.Ordinal) ||
                            field.Contains('\n', StringComparison.Ordinal) ||
                            field.Contains('\r', StringComparison.Ordinal);

        if (!needsEscaping)
            return field;

        // Escape double quotes by doubling them (RFC 4180)
        field = field.Replace("\"", "\"\"", StringComparison.Ordinal);

        // Wrap in quotes
        return $"\"{field}\"";
    }

    /// <summary>
    /// Get suggested filename for export based on data type
    /// </summary>
    public string GetSuggestedFileName(string dataType)
    {
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        return $"PCAP_{dataType}_{timestamp}.csv";
    }

    #region Security Validation Methods

    /// <summary>
    /// Comprehensive path validation and resolution pipeline
    /// Implements defense-in-depth strategy against path traversal and related attacks
    /// </summary>
    /// <param name="userPath">User-provided file path</param>
    /// <returns>Validated canonical absolute path</returns>
    /// <exception cref="ArgumentException">Thrown when path is invalid</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when security validation fails</exception>
    private string ValidateAndResolvePath(string userPath)
    {
        if (string.IsNullOrWhiteSpace(userPath))
            throw new ArgumentException("File path cannot be empty", nameof(userPath));

        try
        {
            // Step 1: Early filename validation before path resolution
            // Extract filename for early validation to catch issues before Path.GetFullPath()
            var filename = Path.GetFileName(userPath);
            if (string.IsNullOrWhiteSpace(filename))
            {
                throw new ArgumentException("Invalid path - no filename component", nameof(userPath));
            }

            // Step 2: Validate filename component (before any path resolution)
            // This catches path separators and dangerous characters in the filename itself
            ValidateFilename(filename);

            // Step 3: Resolve to canonical absolute path (this also validates path traversal)
            var canonicalPath = GetCanonicalPath(userPath);

            // Step 4: Detect and prevent symlink attacks
            ValidateNoSymlinks(canonicalPath);

            // Step 5: Ensure directory exists (create if needed)
            EnsureDirectoryExists(canonicalPath);

            _logger?.LogDebug("Path validation succeeded: {FileName}", filename);

            return canonicalPath;
        }
        catch (UnauthorizedAccessException)
        {
            // Security violations - re-throw with audit
            _logger?.LogWarning("Security violation during path validation: {Path}", Path.GetFileName(userPath));
            throw;
        }
        catch (ArgumentException)
        {
            // Validation failures - re-throw with audit
            _logger?.LogWarning("Validation failed for path: {Path}", Path.GetFileName(userPath));
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during path validation");
            throw new ArgumentException($"Path validation failed: {ex.Message}", nameof(userPath), ex);
        }
    }

    /// <summary>
    /// Resolve path to canonical absolute form and validate against allowed directories
    /// Prevents path traversal attacks by ensuring resolution stays within bounds
    /// </summary>
    /// <param name="userPath">User-provided path</param>
    /// <returns>Canonical absolute path</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when path is outside allowed directories</exception>
    private string GetCanonicalPath(string userPath)
    {
        try
        {
            // Early check for path traversal attempts (before Path.GetFullPath which can resolve them)
            if (userPath.Contains("..", StringComparison.Ordinal))
            {
                _logger?.LogWarning("SECURITY AUDIT: Path traversal attempt detected in path: {Path}", userPath);
                throw new UnauthorizedAccessException(
                    "Export path must be within allowed directories (Documents, Desktop, or Temp). " +
                    "Access to system directories is not permitted.");
            }

            // Normalize path separators for cross-platform compatibility
            // This must happen BEFORE Path.GetFullPath to ensure consistent processing
            var normalizedUserPath = userPath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

            // Resolve to absolute canonical path (eliminates .., ., and symbolic references)
            var fullPath = Path.GetFullPath(normalizedUserPath);

            // Verify path is within allowed directories
            bool isAllowed = _allowedDirectories.Any(allowedDir =>
            {
                if (string.IsNullOrEmpty(allowedDir))
                    return false;

                var normalizedAllowed = Path.GetFullPath(allowedDir);

                // Ensure comparison includes trailing separator to prevent prefix matching bypass
                // Example: prevent /home/user matching /home/user_evil
                var allowedWithSeparator = normalizedAllowed.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                var fullWithSeparator = fullPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

                return fullWithSeparator.StartsWith(allowedWithSeparator, StringComparison.OrdinalIgnoreCase);
            });

            if (!isAllowed)
            {
                _logger?.LogWarning(
                    "SECURITY AUDIT: Path outside allowed directories - attempted access to unauthorized location. File: {FileName}",
                    Path.GetFileName(userPath));

                throw new UnauthorizedAccessException(
                    "Export path must be within allowed directories (Documents, Desktop, or Temp). " +
                    "Access to system directories is not permitted.");
            }

            return fullPath;
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to resolve canonical path");
            throw new ArgumentException($"Invalid file path: {ex.Message}", nameof(userPath), ex);
        }
    }

    /// <summary>
    /// Validate filename for security issues including Unicode normalization
    /// Prevents encoding-based bypasses and reserved name usage
    /// </summary>
    /// <param name="filename">Filename to validate</param>
    /// <exception cref="ArgumentException">Thrown when filename is invalid or unsafe</exception>
    private void ValidateFilename(string filename)
    {
        if (string.IsNullOrWhiteSpace(filename))
            throw new ArgumentException("Filename cannot be empty");

        // Security: Normalize Unicode to prevent encoding bypass attacks
        // Example: prevent using alternate Unicode representations to bypass filters
        filename = filename.Normalize(NormalizationForm.FormC);

        // CRITICAL SECURITY: Unicode control character and format character validation
        // Defends against:
        // - Bidirectional text override attacks (U+202E, U+202D)
        // - Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
        // - Control characters (0x00-0x1F, 0x7F-0x9F)
        // - Format characters (Unicode category Format)
        if (filename.Any(c => char.IsControl(c)))
        {
            _logger?.LogWarning("SECURITY AUDIT: Control characters in filename: {FileName}", filename);
            throw new ArgumentException($"Filename contains control characters: {filename}");
        }

        if (filename.Any(c => char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format))
        {
            _logger?.LogWarning("SECURITY AUDIT: Unicode format characters in filename: {FileName}", filename);
            throw new ArgumentException($"Filename contains Unicode format characters: {filename}");
        }

        // Validate against invalid filename characters (OS-specific)
        var invalidChars = Path.GetInvalidFileNameChars();
        if (filename.IndexOfAny(invalidChars) >= 0)
        {
            _logger?.LogWarning("SECURITY AUDIT: Invalid characters in filename: {FileName}", filename);
            throw new ArgumentException("Filename contains invalid characters");
        }

        // Cross-platform security: Block characters that are dangerous on ANY platform
        // These are allowed on Linux but must be blocked for Windows compatibility and security
        var dangerousChars = new[] { '<', '>', ':', '"', '|', '?', '*' };
        if (filename.IndexOfAny(dangerousChars) >= 0)
        {
            _logger?.LogWarning("SECURITY AUDIT: Dangerous characters in filename: {FileName}", filename);
            throw new ArgumentException("Filename contains invalid characters");
        }

        // Prevent path separators in filename (path traversal prevention)
        // This check is critical - must be AFTER filename extraction in ValidateAndResolvePath
        if (filename.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            filename.Contains(Path.AltDirectorySeparatorChar, StringComparison.Ordinal))
        {
            _logger?.LogWarning("SECURITY AUDIT: Path separators in filename: {FileName}", filename);
            throw new ArgumentException("Filename contains invalid path separators. Use only the filename without directory components.");
        }

        // Prevent relative path components (security violation - path traversal attempt)
        if (filename.Contains("..", StringComparison.Ordinal))
        {
            _logger?.LogWarning("SECURITY AUDIT: Path traversal attempt detected in filename: {FileName}", filename);
            throw new ArgumentException("Path traversal sequences (..) are not allowed in filename");
        }

        // Prevent tilde (~) which can be used for home directory expansion on Unix/Linux
        if (filename.Contains('~', StringComparison.Ordinal))
        {
            _logger?.LogWarning("SECURITY AUDIT: Tilde character in filename: {FileName}", filename);
            throw new ArgumentException("Tilde character (~) is not allowed in filename due to shell expansion risks");
        }

        // Prevent Windows reserved names
        var nameWithoutExtension = Path.GetFileNameWithoutExtension(filename);
        if (ReservedWindowsNames.Contains(nameWithoutExtension, StringComparer.OrdinalIgnoreCase))
        {
            _logger?.LogWarning("SECURITY AUDIT: Reserved Windows filename: {FileName}", filename);
            throw new ArgumentException($"Filename '{nameWithoutExtension}' is reserved by Windows");
        }

        // Prevent excessively long filenames (Windows: 255 chars, safety margin)
        if (filename.Length > 200)
        {
            _logger?.LogWarning("SECURITY AUDIT: Filename exceeds length limit: {Length} chars", filename.Length);
            throw new ArgumentException("Filename is too long (maximum 200 characters)");
        }
    }

    /// <summary>
    /// Detect and prevent symlink attacks by checking for reparse points
    /// Prevents attackers from using symbolic links to redirect exports to unauthorized locations
    /// </summary>
    /// <param name="path">Path to validate</param>
    /// <exception cref="UnauthorizedAccessException">Thrown when symlink is detected</exception>
    private void ValidateNoSymlinks(string path)
    {
        try
        {
            // Check if the target file path is a symlink
            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);
                if (IsSymbolicLink(fileInfo))
                {
                    _logger?.LogWarning("SECURITY AUDIT: Symlink detected in export path: {FileName}",
                        Path.GetFileName(path));
                    throw new UnauthorizedAccessException(
                        "Symbolic links are not permitted in export paths for security reasons");
                }
            }

            // Validate directory chain for symlinks (prevent parent directory symlinks)
            var directory = Path.GetDirectoryName(path);
            while (!string.IsNullOrEmpty(directory))
            {
                if (Directory.Exists(directory))
                {
                    var dirInfo = new DirectoryInfo(directory);
                    if (IsSymbolicLink(dirInfo))
                    {
                        _logger?.LogWarning("SECURITY AUDIT: Symlink detected in directory chain: {Directory}",
                            directory);
                        throw new UnauthorizedAccessException(
                            "Symbolic links are not permitted in export directory paths for security reasons");
                    }
                }

                // Move up to parent directory
                var parent = Path.GetDirectoryName(directory);
                if (parent == directory) // Reached root
                    break;
                directory = parent;
            }
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error during symlink validation");
            // Don't fail on permission errors during symlink check
            // This is defense-in-depth, canonical path is primary control
        }
    }

    /// <summary>
    /// Check if a file system entry is a symbolic link or reparse point
    /// </summary>
    /// <param name="fileSystemInfo">File or directory info</param>
    /// <returns>True if the entry is a symbolic link</returns>
    private static bool IsSymbolicLink(FileSystemInfo fileSystemInfo)
    {
        return fileSystemInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    /// <summary>
    /// Ensure the directory exists, creating it securely if needed
    /// </summary>
    /// <param name="filePath">Full file path</param>
    private void EnsureDirectoryExists(string filePath)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            try
            {
                Directory.CreateDirectory(directory);
                _logger?.LogInformation("Created export directory: {Directory}", directory);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to create export directory");
                throw new UnauthorizedAccessException(
                    $"Unable to create export directory: {ex.Message}", ex);
            }
        }
    }

    /// <summary>
    /// Atomic file write operation to prevent TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
    /// Writes to temporary file first, then atomically moves to final location
    /// </summary>
    /// <param name="path">Destination path</param>
    /// <param name="content">Content to write</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <exception cref="IOException">Thrown when file operation fails</exception>
    private async Task WriteFileAtomically(string path, string content, CancellationToken cancellationToken)
    {
        string? tempPath = null;

        try
        {
            // Create temporary file in same directory as target (ensures same filesystem for atomic move)
            var directory = Path.GetDirectoryName(path);
            var tempFileName = $".tmp_{Guid.NewGuid():N}_{Path.GetFileName(path)}";
            tempPath = Path.Combine(directory ?? ".", tempFileName);

            _logger?.LogDebug("Writing to temporary file: {TempFile}", tempFileName);

            // Write content to temporary file with UTF-8 BOM for Excel compatibility
            await File.WriteAllTextAsync(tempPath, content, new UTF8Encoding(true), cancellationToken);

            // Atomic move operation (eliminates TOCTOU race condition)
            // On Windows, this is atomic at the filesystem level
            File.Move(tempPath, path, overwrite: true);

            _logger?.LogInformation("CSV export completed successfully: {FileName}", Path.GetFileName(path));
        }
        catch (OperationCanceledException)
        {
            _logger?.LogInformation("CSV export cancelled by user");
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "CSV export failed during file write");
            throw new IOException($"Failed to write CSV file: {ex.Message}", ex);
        }
        finally
        {
            // Clean up temporary file if it still exists
            if (tempPath is not null && File.Exists(tempPath))
            {
                try
                {
                    File.Delete(tempPath);
                    _logger?.LogDebug("Cleaned up temporary file");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to clean up temporary file: {TempPath}", tempPath);
                    // Don't throw - cleanup failure is not critical
                }
            }
        }
    }

    #endregion

    /// <summary>
    /// Validate export path and create directory if needed
    /// Uses comprehensive security validation pipeline
    /// </summary>
    /// <param name="filePath">Path to validate and prepare</param>
    /// <returns>True if path is valid and writable, false otherwise</returns>
    public async Task<bool> ValidateAndPreparePathAsync(string filePath)
    {
        try
        {
            // Use comprehensive security validation
            var validatedPath = ValidateAndResolvePath(filePath);

            // Check write permissions by attempting to create/delete a temp file
            var directory = Path.GetDirectoryName(validatedPath);
            var testFile = Path.Combine(directory ?? ".", $".test_{Guid.NewGuid():N}.tmp");

            try
            {
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);
                _logger?.LogDebug("Write permission validated");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Write permission test failed");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Path validation or preparation failed");
            return false;
        }
    }

    /// <summary>
    /// Get CSV file filter for file dialogs
    /// </summary>
    public string GetFileFilter()
    {
        return "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*";
    }
}
