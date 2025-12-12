// MAC Vendor Service Implementation
// Provides OUI-based vendor lookup with IEEE database download support

using System.Collections.Frozen;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.Core.Services.MacVendor;

/// <summary>
/// Service for MAC vendor lookup using IEEE OUI database.
/// Supports both embedded curated database and downloadable IEEE registry.
/// </summary>
public sealed class MacVendorService : IMacVendorService, IDisposable
{
    private readonly ILogger<MacVendorService>? _logger;
    private readonly HttpClient _httpClient;
    private readonly string _appDataPath;
    private readonly object _loadLock = new();

    // Frozen dictionaries for O(1) lookup - immutable after load
    private FrozenDictionary<string, MacVendorEntry> _vendors = FrozenDictionary<string, MacVendorEntry>.Empty;
    private FrozenDictionary<string, MacVendorEntry> _curatedVendors = FrozenDictionary<string, MacVendorEntry>.Empty;

    private MacDatabaseStats _stats;
    private bool _disposed;

    // IEEE OUI registry URLs
    private const string IeeeOuiUrl = "https://standards-oui.ieee.org/oui/oui.csv";
    private const string IeeeMamUrl = "https://standards-oui.ieee.org/oui28/mam.csv";
    private const string IeeeMasUrl = "https://standards-oui.ieee.org/oui36/oui36.csv";

    // Well-known broadcast MAC
    private const string BroadcastMac = "FF:FF:FF:FF:FF:FF";

    public MacVendorService(ILogger<MacVendorService>? logger = null, HttpClient? httpClient = null)
    {
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        _appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PCAPAnalyzer", "MacVendors");

        // Load databases on construction
        LoadDatabases();
    }

    #region IMacVendorService Implementation

    public MacLookupResult LookupVendor(string? macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress))
            return new MacLookupResult(null, MacAddressType.Invalid);

        // Normalize MAC address
        var normalized = NormalizeMacAddress(macAddress);
        if (string.IsNullOrEmpty(normalized) || normalized.Length < 8)
            return new MacLookupResult(null, MacAddressType.Invalid);

        // Check for broadcast first
        if (normalized.Equals(BroadcastMac, StringComparison.OrdinalIgnoreCase))
            return new MacLookupResult(null, MacAddressType.Broadcast);

        // Classify MAC address type
        var addressType = ClassifyMacAddress(normalized);

        // For special addresses, return early with classification
        if (addressType != MacAddressType.Global)
            return new MacLookupResult(null, addressType);

        // Extract OUI (first 3 octets)
        var oui = ExtractOui(normalized);
        if (string.IsNullOrEmpty(oui))
            return new MacLookupResult(null, MacAddressType.Global);

        // Lookup in curated database first (has device type hints)
        if (_curatedVendors.TryGetValue(oui, out var curatedEntry))
        {
            return new MacLookupResult(
                curatedEntry.Vendor,
                MacAddressType.Global,
                curatedEntry.DeviceTypeHint,
                curatedEntry.OsHint);
        }

        // Lookup in full IEEE database
        if (_vendors.TryGetValue(oui, out var entry))
        {
            return new MacLookupResult(
                entry.Vendor,
                MacAddressType.Global,
                entry.DeviceTypeHint,
                entry.OsHint);
        }

        return new MacLookupResult(null, MacAddressType.Global);
    }

    public async Task<MacDatabaseUpdateResult> UpdateDatabaseAsync(
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        var newVendors = new Dictionary<string, MacVendorEntry>(50000);
        int newEntries = 0;
        int updatedEntries = 0;

        try
        {
            _logger?.LogInformation("Starting IEEE OUI database update");

            // Ensure directory exists
            Directory.CreateDirectory(_appDataPath);

            // Download and parse MA-L (OUI) - ~35K entries, largest
            progress?.Report(5);
            var malCount = await DownloadAndParseIeeeCsvAsync(IeeeOuiUrl, newVendors, 24, cancellationToken);
            _logger?.LogInformation("Downloaded MA-L registry: {Count} entries", malCount);

            progress?.Report(50);

            // Download and parse MA-M - ~5K entries
            var mamCount = await DownloadAndParseIeeeCsvAsync(IeeeMamUrl, newVendors, 28, cancellationToken);
            _logger?.LogInformation("Downloaded MA-M registry: {Count} entries", mamCount);

            progress?.Report(75);

            // Download and parse MA-S - ~3K entries
            var masCount = await DownloadAndParseIeeeCsvAsync(IeeeMasUrl, newVendors, 36, cancellationToken);
            _logger?.LogInformation("Downloaded MA-S registry: {Count} entries", masCount);

            progress?.Report(90);

            // Calculate new/updated counts
            foreach (var (oui, entry) in newVendors)
            {
                if (!_vendors.ContainsKey(oui))
                    newEntries++;
                else if (_vendors[oui].Vendor != entry.Vendor)
                    updatedEntries++;
            }

            // Save to disk
            var dbPath = Path.Combine(_appDataPath, "ieee-oui.json");
            var metaPath = Path.Combine(_appDataPath, "ieee-oui.meta.json");

            var database = new IeeeDatabaseFile
            {
                Version = DateTime.UtcNow.ToString("yyyy.MM.dd", CultureInfo.InvariantCulture),
                GeneratedAt = DateTime.UtcNow,
                Entries = [.. newVendors.Values]
            };

            var options = new JsonSerializerOptions { WriteIndented = false };
            await File.WriteAllTextAsync(dbPath, JsonSerializer.Serialize(database, options), cancellationToken);

            var meta = new DatabaseMetadata
            {
                LastUpdated = DateTime.UtcNow,
                EntryCount = newVendors.Count,
                Version = database.Version
            };
            await File.WriteAllTextAsync(metaPath, JsonSerializer.Serialize(meta, options), cancellationToken);

            progress?.Report(95);

            // Reload databases
            LoadDatabases();

            progress?.Report(100);

            var duration = DateTime.UtcNow - startTime;
            _logger?.LogInformation(
                "IEEE OUI database update complete: {Total} entries ({New} new, {Updated} updated) in {Duration:F1}s",
                newVendors.Count, newEntries, updatedEntries, duration.TotalSeconds);

            return new MacDatabaseUpdateResult(true, newVendors.Count, newEntries, updatedEntries, duration);
        }
        catch (OperationCanceledException)
        {
            _logger?.LogWarning("IEEE OUI database update cancelled");
            return new MacDatabaseUpdateResult(false, 0, 0, 0, DateTime.UtcNow - startTime, "Update cancelled");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to update IEEE OUI database");
            return new MacDatabaseUpdateResult(false, 0, 0, 0, DateTime.UtcNow - startTime, ex.Message);
        }
    }

    public MacDatabaseStats GetDatabaseStats() => _stats;

    public async Task<bool> IsUpdateAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Check if local database is older than 30 days
            var metaPath = Path.Combine(_appDataPath, "ieee-oui.meta.json");
            if (!File.Exists(metaPath))
                return true;

            var metaJson = await File.ReadAllTextAsync(metaPath, cancellationToken);
            var meta = JsonSerializer.Deserialize<DatabaseMetadata>(metaJson);

            if (meta?.LastUpdated == null)
                return true;

            // IEEE updates monthly, so check if > 30 days old
            return (DateTime.UtcNow - meta.LastUpdated.Value).TotalDays > 30;
        }
        catch
        {
            return true;
        }
    }

    #endregion

    #region MAC Address Classification

    /// <summary>
    /// Classify a MAC address based on IEEE standards.
    /// </summary>
    public static MacAddressType ClassifyMacAddress(string normalizedMac)
    {
        if (string.IsNullOrEmpty(normalizedMac) || normalizedMac.Length < 2)
            return MacAddressType.Invalid;

        // Parse first octet
        if (!byte.TryParse(normalizedMac.AsSpan(0, 2), NumberStyles.HexNumber, null, out var firstOctet))
            return MacAddressType.Invalid;

        // Bit 0 (LSB): 0 = Unicast, 1 = Multicast
        bool isMulticast = (firstOctet & 0x01) != 0;

        // Bit 1: 0 = Globally Unique (OUI), 1 = Locally Administered
        bool isLocallyAdministered = (firstOctet & 0x02) != 0;

        if (isMulticast)
            return MacAddressType.Multicast;

        if (isLocallyAdministered)
        {
            // Randomized MACs are locally administered + unicast
            // iOS 14+, Android 10+, Windows 10+ use this for privacy
            // Pattern: second hex char is 2, 6, A, or E
            return MacAddressType.Randomized;
        }

        return MacAddressType.Global;
    }

    /// <summary>
    /// Normalize MAC address to XX:XX:XX:XX:XX:XX format (uppercase).
    /// </summary>
    public static string? NormalizeMacAddress(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
            return null;

        // Remove common separators and whitespace
        Span<char> cleaned = stackalloc char[12];
        int pos = 0;

        foreach (var c in mac)
        {
            if (char.IsAsciiHexDigit(c))
            {
                if (pos >= 12) break;
                cleaned[pos++] = char.ToUpperInvariant(c);
            }
        }

        if (pos != 12)
            return null;

        // Format as XX:XX:XX:XX:XX:XX
        return $"{cleaned[0]}{cleaned[1]}:{cleaned[2]}{cleaned[3]}:{cleaned[4]}{cleaned[5]}:" +
               $"{cleaned[6]}{cleaned[7]}:{cleaned[8]}{cleaned[9]}:{cleaned[10]}{cleaned[11]}";
    }

    /// <summary>
    /// Extract OUI (first 3 octets) from normalized MAC.
    /// </summary>
    private static string? ExtractOui(string normalizedMac)
    {
        if (normalizedMac.Length < 8)
            return null;

        // Return first 3 octets: XX:XX:XX
        return normalizedMac[..8];
    }

    #endregion

    #region Database Loading

    private void LoadDatabases()
    {
        lock (_loadLock)
        {
            var curatedDict = new Dictionary<string, MacVendorEntry>(200, StringComparer.OrdinalIgnoreCase);
            var ieeeDict = new Dictionary<string, MacVendorEntry>(50000, StringComparer.OrdinalIgnoreCase);

            // Load embedded curated database (always available)
            LoadCuratedDatabase(curatedDict);

            // Load IEEE database from AppData if available
            var ieeeLoaded = LoadIeeeDatabase(ieeeDict);

            // Merge: IEEE base, curated overrides (curated has device type hints)
            var merged = new Dictionary<string, MacVendorEntry>(ieeeDict.Count + curatedDict.Count, StringComparer.OrdinalIgnoreCase);

            foreach (var (oui, entry) in ieeeDict)
                merged[oui] = entry;

            foreach (var (oui, entry) in curatedDict)
                merged[oui] = entry; // Curated overrides IEEE

            _vendors = merged.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
            _curatedVendors = curatedDict.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

            // Update stats
            DateTime? lastUpdated = null;
            string? version = null;

            var metaPath = Path.Combine(_appDataPath, "ieee-oui.meta.json");
            if (File.Exists(metaPath))
            {
                try
                {
                    var meta = JsonSerializer.Deserialize<DatabaseMetadata>(File.ReadAllText(metaPath));
                    lastUpdated = meta?.LastUpdated;
                    version = meta?.Version;
                }
                catch { /* Ignore meta read errors */ }
            }

            _stats = new MacDatabaseStats(
                _vendors.Count,
                curatedDict.Count,
                ieeeDict.Count,
                lastUpdated,
                version);

            _logger?.LogInformation(
                "MAC vendor database loaded: {Total} entries ({Curated} curated, {IEEE} IEEE)",
                _vendors.Count, curatedDict.Count, ieeeDict.Count);
        }
    }

    private void LoadCuratedDatabase(Dictionary<string, MacVendorEntry> dict)
    {
        try
        {
            // Try embedded resource first
            var assembly = typeof(MacVendorService).Assembly;
            var resourceName = assembly.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("MacVendors.json", StringComparison.OrdinalIgnoreCase));

            Stream? stream = null;

            if (resourceName != null)
            {
                stream = assembly.GetManifestResourceStream(resourceName);
            }

            // Fallback to file path (development)
            if (stream == null)
            {
                var filePath = Path.Combine(
                    AppContext.BaseDirectory,
                    "Data", "OsFingerprinting", "MacVendors.json");

                if (File.Exists(filePath))
                    stream = File.OpenRead(filePath);
            }

            if (stream == null)
            {
                _logger?.LogWarning("Curated MAC vendor database not found");
                return;
            }

            using (stream)
            {
                var json = JsonSerializer.Deserialize<CuratedDatabaseFile>(stream);
                if (json?.Vendors == null) return;

                foreach (var vendor in json.Vendors)
                {
                    var oui = NormalizeMacAddress(vendor.Oui + ":00:00:00");
                    if (oui != null)
                    {
                        var ouiPrefix = oui[..8]; // XX:XX:XX
                        dict[ouiPrefix] = new MacVendorEntry
                        {
                            OuiPrefix = ouiPrefix,
                            Vendor = vendor.Vendor,
                            DeviceTypeHint = vendor.DeviceTypeHint,
                            OsHint = vendor.OsHint
                        };
                    }
                }
            }

            _logger?.LogDebug("Loaded {Count} curated MAC vendor entries", dict.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load curated MAC vendor database");
        }
    }

    private bool LoadIeeeDatabase(Dictionary<string, MacVendorEntry> dict)
    {
        try
        {
            var dbPath = Path.Combine(_appDataPath, "ieee-oui.json");
            if (!File.Exists(dbPath))
            {
                _logger?.LogDebug("IEEE OUI database not found at {Path}", dbPath);
                return false;
            }

            using var stream = File.OpenRead(dbPath);
            var json = JsonSerializer.Deserialize<IeeeDatabaseFile>(stream);
            if (json?.Entries == null) return false;

            foreach (var entry in json.Entries)
            {
                if (!string.IsNullOrEmpty(entry.OuiPrefix))
                    dict[entry.OuiPrefix] = entry;
            }

            _logger?.LogDebug("Loaded {Count} IEEE OUI entries", dict.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load IEEE OUI database");
            return false;
        }
    }

    #endregion

    #region IEEE CSV Parsing

    private async Task<int> DownloadAndParseIeeeCsvAsync(
        string url,
        Dictionary<string, MacVendorEntry> vendors,
        int ouiBits,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream);

        // Skip header line
        await reader.ReadLineAsync(cancellationToken);

        int count = 0;
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // IEEE CSV format: Registry,Assignment,Organization Name,Address
            // Example: MA-L,2C3361,Apple Inc.,"1 Apple Park Way Cupertino CA 95014 US"
            var entry = ParseIeeeCsvLine(line, ouiBits);
            if (entry != null)
            {
                vendors[entry.OuiPrefix] = entry;
                count++;
            }
        }

        return count;
    }

    private static MacVendorEntry? ParseIeeeCsvLine(string line, int ouiBits)
    {
        // Simple CSV parsing - IEEE format is well-structured
        var parts = SplitCsvLine(line);
        if (parts.Count < 3)
            return null;

        var assignment = parts[1].Trim();
        var organization = parts[2].Trim().Trim('"');

        if (string.IsNullOrEmpty(assignment) || string.IsNullOrEmpty(organization))
            return null;

        // Convert assignment to OUI format
        // MA-L (24-bit): "2C3361" -> "2C:33:61"
        // MA-M (28-bit): "2C33610" -> "2C:33:61:0" (first nibble of 4th octet)
        // MA-S (36-bit): "2C3361000" -> "2C:33:61:00:0" (first nibble of 5th octet)

        string ouiPrefix;
        if (ouiBits == 24 && assignment.Length >= 6)
        {
            ouiPrefix = $"{assignment[0..2]}:{assignment[2..4]}:{assignment[4..6]}".ToUpperInvariant();
        }
        else if (ouiBits == 28 && assignment.Length >= 7)
        {
            // For MA-M, we still use 24-bit OUI for lookup (common case)
            ouiPrefix = $"{assignment[0..2]}:{assignment[2..4]}:{assignment[4..6]}".ToUpperInvariant();
        }
        else if (ouiBits == 36 && assignment.Length >= 9)
        {
            // For MA-S, we still use 24-bit OUI for lookup (common case)
            ouiPrefix = $"{assignment[0..2]}:{assignment[2..4]}:{assignment[4..6]}".ToUpperInvariant();
        }
        else
        {
            return null;
        }

        return new MacVendorEntry
        {
            OuiPrefix = ouiPrefix,
            Vendor = organization
        };
    }

    private static List<string> SplitCsvLine(string line)
    {
        var result = new List<string>();
        var inQuotes = false;
        var current = new System.Text.StringBuilder();

        foreach (var c in line)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        result.Add(current.ToString());
        return result;
    }

    #endregion

    #region JSON Models

    private sealed class CuratedDatabaseFile
    {
        [JsonPropertyName("version")]
        public string? Version { get; set; }

        [JsonPropertyName("vendors")]
        public List<CuratedVendorEntry>? Vendors { get; set; }
    }

    private sealed class CuratedVendorEntry
    {
        [JsonPropertyName("oui")]
        public string Oui { get; set; } = "";

        [JsonPropertyName("vendor")]
        public string Vendor { get; set; } = "";

        [JsonPropertyName("deviceTypeHint")]
        public string? DeviceTypeHint { get; set; }

        [JsonPropertyName("osHint")]
        public string? OsHint { get; set; }
    }

    private sealed class IeeeDatabaseFile
    {
        [JsonPropertyName("version")]
        public string? Version { get; set; }

        [JsonPropertyName("generatedAt")]
        public DateTime? GeneratedAt { get; set; }

        [JsonPropertyName("entries")]
        public List<MacVendorEntry>? Entries { get; set; }
    }

    private sealed class DatabaseMetadata
    {
        [JsonPropertyName("lastUpdated")]
        public DateTime? LastUpdated { get; set; }

        [JsonPropertyName("entryCount")]
        public int EntryCount { get; set; }

        [JsonPropertyName("version")]
        public string? Version { get; set; }
    }

    #endregion

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
        }
    }
}

/// <summary>
/// MAC vendor entry for OUI lookup.
/// </summary>
public sealed class MacVendorEntry
{
    [JsonPropertyName("oui")]
    public string OuiPrefix { get; set; } = "";

    [JsonPropertyName("vendor")]
    public string Vendor { get; set; } = "";

    [JsonPropertyName("deviceType")]
    public string? DeviceTypeHint { get; set; }

    [JsonPropertyName("os")]
    public string? OsHint { get; set; }
}
