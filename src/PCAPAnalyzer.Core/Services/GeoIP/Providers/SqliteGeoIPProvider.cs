using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.GeoIP.Configuration;

namespace PCAPAnalyzer.Core.Services.GeoIP.Providers
{
    /// <summary>
    /// GeoIP provider using SQLite database for persistent storage.
    /// Extracted from EnhancedGeoIPService with improved error handling and performance.
    /// Supports IP range lookups with confidence scoring and metadata.
    /// </summary>
    public class SqliteGeoIPProvider : IGeoIPProvider
    {
        private readonly ILogger? _logger;
        private readonly string _databasePath;
        private bool _isReady;
        private readonly object _lock = new();

        public string ProviderName => "SQLite Database";

        public bool IsReady => _isReady;

        /// <summary>
        /// Creates a new SQLite provider with specified database path
        /// </summary>
        public SqliteGeoIPProvider(string? databasePath = null, ILogger? logger = null)
        {
            _logger = logger;
            _databasePath = databasePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PCAPAnalyzer", "GeoIP", "geoip.db");
        }

        /// <summary>
        /// Creates a new SQLite provider from configuration
        /// </summary>
        public SqliteGeoIPProvider(ProviderConfiguration config, ILogger? logger = null)
        {
            _logger = logger;
            _databasePath = config.GetSetting("DatabasePath") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PCAPAnalyzer", "GeoIP", "geoip.db");
        }

        public Task<bool> InitializeAsync()
        {
            if (_isReady) return Task.FromResult(true);

            lock (_lock)
            {
                if (_isReady) return Task.FromResult(true);

                try
                {
                    _logger?.LogInformation("[{Provider}] Starting initialization...", ProviderName);

                    // Create directory if it doesn't exist
                    var directory = Path.GetDirectoryName(_databasePath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                        _logger?.LogInformation("[{Provider}] Created directory: {Directory}", ProviderName, directory);
                    }

                    // Initialize database schema - run synchronously within lock
                    var initTask = InitializeDatabaseSchema();
                    initTask.GetAwaiter().GetResult();

                    // Check if database has data - run synchronously within lock
                    var checkTask = CheckDatabaseHasData();
                    var hasData = checkTask.GetAwaiter().GetResult();
                    if (hasData)
                    {
                        _isReady = true;
                        _logger?.LogInformation("[{Provider}] Successfully initialized with existing data", ProviderName);
                    }
                    else
                    {
                        _logger?.LogWarning("[{Provider}] Database is empty. Call ImportData to populate.", ProviderName);
                        _isReady = true; // Still mark as ready, but lookups will return null
                    }

                    return Task.FromResult(true);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "[{Provider}] Initialization failed", ProviderName);
                    return Task.FromResult(false);
                }
            }
        }

        public async Task<GeoLocation?> LookupAsync(string ipAddress)
        {
            if (!_isReady || string.IsNullOrWhiteSpace(ipAddress))
                return null;

            if (!IPAddress.TryParse(ipAddress, out _))
                return null;

            try
            {
                var ipNumeric = IPToLong(ipAddress);

                using var connection = new SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync();

                var sql = @"
                    SELECT country_code, country_name, continent_code, continent_name,
                           confidence_score, source, isp, organization, asn
                    FROM ip_ranges
                    WHERE start_ip_numeric <= @ip AND end_ip_numeric >= @ip
                    ORDER BY confidence_score DESC, last_verified DESC
                    LIMIT 1";

                using var command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@ip", ipNumeric);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    return new GeoLocation
                    {
                        IpAddress = ipAddress,
                        CountryCode = reader.GetString(0) ?? "Unknown",
                        CountryName = reader.GetString(1) ?? "Unknown",
                        ContinentCode = reader.IsDBNull(2) ? null : reader.GetString(2),
                        ContinentName = reader.IsDBNull(3) ? null : reader.GetString(3),
                        ConfidenceScore = reader.IsDBNull(4) ? 1.0 : reader.GetDouble(4),
                        Source = reader.IsDBNull(5) ? ProviderName : reader.GetString(5),
                        ISP = reader.IsDBNull(6) ? null : reader.GetString(6),
                        Organization = reader.IsDBNull(7) ? null : reader.GetString(7),
                        ASN = reader.IsDBNull(8) ? null : reader.GetString(8),
                        IsPublicIP = true,
                        LastUpdated = DateTime.UtcNow
                    };
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Lookup error for IP: {IpAddress}", ProviderName, ipAddress);
            }

            return null;
        }

        public async Task<GeoIPDatabaseStats?> GetStatsAsync()
        {
            if (!_isReady || !File.Exists(_databasePath))
                return null;

            try
            {
                using var connection = new SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync();

                var stats = new GeoIPDatabaseStats
                {
                    Provider = ProviderName,
                    IsLoaded = _isReady
                };

                // Get total ranges
                using (var cmd = new SqliteCommand("SELECT COUNT(*) FROM ip_ranges", connection))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    stats.TotalRecords = result != null ? Convert.ToInt32(result) : 0;
                }

                // Get database file size
                var fileInfo = new FileInfo(_databasePath);
                stats.DatabaseSizeBytes = fileInfo.Length;
                stats.LastUpdate = fileInfo.LastWriteTime;

                return stats;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error getting stats", ProviderName);
                return null;
            }
        }

        public async Task DisposeAsync()
        {
            await Task.Run(() =>
            {
                _isReady = false;
                _logger?.LogInformation("[{Provider}] Disposed", ProviderName);
            });
        }

        /// <summary>
        /// Imports IP range data into the database
        /// </summary>
        public async Task<int> ImportIPRangesAsync(IEnumerable<IPRangeCountryMapping> ranges)
        {
            if (!_isReady)
                throw new InvalidOperationException("Provider not initialized");

            var imported = 0;

            try
            {
                using var connection = new SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync();

                using var transaction = connection.BeginTransaction();

                var sql = @"
                    INSERT OR REPLACE INTO ip_ranges
                    (start_ip, end_ip, start_ip_numeric, end_ip_numeric, country_code, country_name,
                     continent_code, continent_name, source, confidence_score, isp, organization, asn)
                    VALUES
                    (@start, @end, @startNum, @endNum, @code, @name, @contCode, @contName,
                     @source, @confidence, @isp, @org, @asn)";

                foreach (var range in ranges)
                {
                    using var cmd = new SqliteCommand(sql, connection, transaction);
                    cmd.Parameters.AddWithValue("@start", range.StartIP);
                    cmd.Parameters.AddWithValue("@end", range.EndIP);
                    cmd.Parameters.AddWithValue("@startNum", range.StartIPNumeric);
                    cmd.Parameters.AddWithValue("@endNum", range.EndIPNumeric);
                    cmd.Parameters.AddWithValue("@code", range.CountryCode);
                    cmd.Parameters.AddWithValue("@name", range.CountryName);
                    cmd.Parameters.AddWithValue("@contCode", range.ContinentCode ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@contName", range.ContinentName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@source", range.Source);
                    cmd.Parameters.AddWithValue("@confidence", range.ConfidenceScore);
                    cmd.Parameters.AddWithValue("@isp", range.ISP ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@org", range.Organization ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@asn", range.ASN ?? (object)DBNull.Value);

                    await cmd.ExecuteNonQueryAsync();
                    imported++;
                }

                transaction.Commit();
                _logger?.LogInformation("[{Provider}] Imported {Count} IP ranges", ProviderName, imported);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error importing IP ranges", ProviderName);
                throw;
            }

            return imported;
        }

        /// <summary>
        /// Optimizes the database by removing expired entries and rebuilding indices
        /// </summary>
        public async Task OptimizeDatabaseAsync()
        {
            if (!_isReady)
                return;

            try
            {
                using var connection = new SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync();

                // Remove expired cache entries
                using (var cmd = new SqliteCommand("DELETE FROM lookup_cache WHERE expires_at < @now", connection))
                {
                    cmd.Parameters.AddWithValue("@now", DateTime.UtcNow);
                    await cmd.ExecuteNonQueryAsync();
                }

                // Vacuum database
                using (var cmd = new SqliteCommand("VACUUM", connection))
                {
                    await cmd.ExecuteNonQueryAsync();
                }

                // Analyze for query optimization
                using (var cmd = new SqliteCommand("ANALYZE", connection))
                {
                    await cmd.ExecuteNonQueryAsync();
                }

                _logger?.LogInformation("[{Provider}] Database optimized", ProviderName);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error optimizing database", ProviderName);
            }
        }

        private async Task InitializeDatabaseSchema()
        {
            using var connection = new SqliteConnection($"Data Source={_databasePath}");
            await connection.OpenAsync();

            var createTablesSql = @"
                CREATE TABLE IF NOT EXISTS ip_ranges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_ip TEXT NOT NULL,
                    end_ip TEXT NOT NULL,
                    start_ip_numeric INTEGER NOT NULL,
                    end_ip_numeric INTEGER NOT NULL,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    continent_code TEXT,
                    continent_name TEXT,
                    source TEXT NOT NULL,
                    confidence_score REAL DEFAULT 1.0,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_verified DATETIME,
                    is_verified BOOLEAN DEFAULT 0,
                    isp TEXT,
                    organization TEXT,
                    asn TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ip_numeric ON ip_ranges(start_ip_numeric, end_ip_numeric);
                CREATE INDEX IF NOT EXISTS idx_country_code ON ip_ranges(country_code);
                CREATE INDEX IF NOT EXISTS idx_source ON ip_ranges(source);
                CREATE INDEX IF NOT EXISTS idx_confidence ON ip_ranges(confidence_score);

                CREATE TABLE IF NOT EXISTS lookup_cache (
                    ip_address TEXT PRIMARY KEY,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    continent_code TEXT,
                    confidence_score REAL,
                    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    hit_count INTEGER DEFAULT 0,
                    source TEXT
                );";

            using var command = new SqliteCommand(createTablesSql, connection);
            await command.ExecuteNonQueryAsync();
        }

        private async Task<bool> CheckDatabaseHasData()
        {
            try
            {
                using var connection = new SqliteConnection($"Data Source={_databasePath}");
                await connection.OpenAsync();

                using var command = new SqliteCommand("SELECT COUNT(*) FROM ip_ranges LIMIT 1", connection);
                var count = (long?)await command.ExecuteScalarAsync();
                return count.HasValue && count.Value > 0;
            }
            catch
            {
                return false;
            }
        }

        private long IPToLong(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    var bytes = ip.GetAddressBytes();
                    if (bytes.Length == 4) // IPv4
                    {
                        return ((long)bytes[0] << 24) | ((long)bytes[1] << 16) |
                               ((long)bytes[2] << 8) | bytes[3];
                    }
                }
            }
            catch { /* Return 0 for invalid IP - safe fallback */ }

            return 0;
        }
    }
}
