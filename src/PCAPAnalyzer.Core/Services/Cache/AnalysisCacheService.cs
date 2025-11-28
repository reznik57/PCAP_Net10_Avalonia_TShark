using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Cache
{
    /// <summary>
    /// SQLite-based cache service for storing PCAP analysis results.
    /// Dramatically reduces load times for previously analyzed files.
    /// </summary>
    public class AnalysisCacheService : IAnalysisCacheService
    {
        private const string ANALYSIS_VERSION = "1.0"; // Increment when analysis logic changes

        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly SemaphoreSlim _dbLock = new(1, 1);
        private bool _isInitialized;
        private bool _disposed;

        // JSON serialization options
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        public AnalysisCacheService(string? databasePath = null)
        {
            // Default to %LocalAppData%/PCAPAnalyzer/analysis_cache.db
            if (string.IsNullOrEmpty(databasePath))
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var appFolder = Path.Combine(localAppData, "PCAPAnalyzer");
                Directory.CreateDirectory(appFolder);
                _dbPath = Path.Combine(appFolder, "analysis_cache.db");
            }
            else
            {
                _dbPath = databasePath;
                var directory = Path.GetDirectoryName(_dbPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }
            }

            _connectionString = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared";

            DebugLogger.Log($"[AnalysisCacheService] Database path: {_dbPath}");
        }

        /// <summary>
        /// Initializes the database schema if not already created.
        /// </summary>
        private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
        {
            if (_isInitialized) return;

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                if (_isInitialized) return;

                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                // Enable WAL mode for better concurrency
                using (var walCmd = connection.CreateCommand())
                {
                    walCmd.CommandText = "PRAGMA journal_mode=WAL;";
                    await walCmd.ExecuteNonQueryAsync(cancellationToken);
                }

                // Create schema
                using var createCmd = connection.CreateCommand();
                createCmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS AnalysisCache (
                        CacheKey TEXT PRIMARY KEY,
                        FileHash TEXT NOT NULL,
                        FilePath TEXT NOT NULL,
                        PacketCount INTEGER NOT NULL,
                        AnalysisType TEXT NOT NULL,
                        AnalysisVersion TEXT NOT NULL,
                        ResultData BLOB NOT NULL,
                        CreatedAt INTEGER NOT NULL,
                        LastAccessedAt INTEGER NOT NULL,
                        DataSizeMB REAL NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_filehash ON AnalysisCache(FileHash);
                    CREATE INDEX IF NOT EXISTS idx_last_accessed ON AnalysisCache(LastAccessedAt);
                    CREATE INDEX IF NOT EXISTS idx_analysis_type ON AnalysisCache(AnalysisType);
                ";
                await createCmd.ExecuteNonQueryAsync(cancellationToken);

                _isInitialized = true;
                DebugLogger.Log("[AnalysisCacheService] Database initialized successfully");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error initializing database: {ex.Message}");
                throw;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public Task<string> ComputeCacheKeyAsync(string filePath, CancellationToken cancellationToken = default)
        {
            try
            {
                // Get file info for hash computation
                var fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists)
                {
                    throw new FileNotFoundException($"PCAP file not found: {filePath}");
                }

                // Compute SHA256 hash of file path + size + last modified (cryptographically secure)
                var hashInput = $"{filePath}|{fileInfo.Length}|{fileInfo.LastWriteTimeUtc:O}";
                using var sha256 = SHA256.Create();
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(hashInput));
                var fileHash = BitConverter.ToString(hashBytes).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();

                // ✅ CACHE FIX: Stable cache key without packet count to prevent key mutation during analysis
                // Cache key format: {FileHash}_{AnalysisVersion}
                // Packet count validation is now handled in result metadata, not cache key
                var cacheKey = $"{fileHash}_{ANALYSIS_VERSION}";

                return Task.FromResult(cacheKey);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error computing cache key: {ex.Message}");
                throw;
            }
        }

        public async Task<bool> IsCachedAsync(string cacheKey, string analysisType, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT COUNT(*)
                    FROM AnalysisCache
                    WHERE CacheKey = @CacheKey AND AnalysisType = @AnalysisType
                ";
                cmd.Parameters.AddWithValue("@CacheKey", cacheKey);
                cmd.Parameters.AddWithValue("@AnalysisType", analysisType);

                var count = (long)(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0L);

                // Update last accessed time if exists
                if (count > 0)
                {
                    await UpdateLastAccessedAsync(cacheKey, analysisType, connection, cancellationToken);
                }

                return count > 0;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task SaveThreatsAsync(string cacheKey, List<EnhancedSecurityThreat> threats, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            var startTime = DateTime.Now;
            DebugLogger.Log($"[AnalysisCacheService] Saving {threats.Count:N0} threats to cache...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                // Serialize and compress data
                var json = JsonSerializer.Serialize(threats, _jsonOptions);
                var compressedData = await CompressDataAsync(json, cancellationToken);
                var dataSizeMB = compressedData.Length / 1024.0 / 1024.0;

                DebugLogger.Log($"[AnalysisCacheService] Compressed {threats.Count:N0} threats: {json.Length / 1024.0:F2} KB -> {dataSizeMB:F2} MB");

                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                // Extract file hash from cache key
                var fileHash = cacheKey.Split('_')[0];

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO AnalysisCache
                    (CacheKey, FileHash, FilePath, PacketCount, AnalysisType, AnalysisVersion,
                     ResultData, CreatedAt, LastAccessedAt, DataSizeMB)
                    VALUES
                    (@CacheKey, @FileHash, @FilePath, @PacketCount, @AnalysisType, @AnalysisVersion,
                     @ResultData, @CreatedAt, @LastAccessedAt, @DataSizeMB)
                ";
                cmd.Parameters.AddWithValue("@CacheKey", cacheKey);
                cmd.Parameters.AddWithValue("@FileHash", fileHash);
                cmd.Parameters.AddWithValue("@FilePath", "");
                cmd.Parameters.AddWithValue("@PacketCount", 0);
                cmd.Parameters.AddWithValue("@AnalysisType", "Threats");
                cmd.Parameters.AddWithValue("@AnalysisVersion", ANALYSIS_VERSION);
                cmd.Parameters.AddWithValue("@ResultData", compressedData);
                cmd.Parameters.AddWithValue("@CreatedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                cmd.Parameters.AddWithValue("@LastAccessedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                cmd.Parameters.AddWithValue("@DataSizeMB", dataSizeMB);

                await cmd.ExecuteNonQueryAsync(cancellationToken);

                var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
                DebugLogger.Log($"[AnalysisCacheService] Threats saved to cache in {elapsed:F0}ms");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error saving threats to cache: {ex.Message}");
                // Don't throw - cache failures should not break analysis
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<List<EnhancedSecurityThreat>?> LoadThreatsAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            var startTime = DateTime.Now;
            DebugLogger.Log($"[AnalysisCacheService] Loading threats from cache...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT ResultData
                    FROM AnalysisCache
                    WHERE CacheKey = @CacheKey AND AnalysisType = @AnalysisType
                ";
                cmd.Parameters.AddWithValue("@CacheKey", cacheKey);
                cmd.Parameters.AddWithValue("@AnalysisType", "Threats");

                using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    var compressedData = (byte[])reader["ResultData"];
                    var json = await DecompressDataAsync(compressedData, cancellationToken);
                    var threats = JsonSerializer.Deserialize<List<EnhancedSecurityThreat>>(json, _jsonOptions);

                    // Update last accessed time
                    await UpdateLastAccessedAsync(cacheKey, "Threats", connection, cancellationToken);

                    var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
                    DebugLogger.Log($"[AnalysisCacheService] Loaded {threats?.Count ?? 0:N0} threats from cache in {elapsed:F0}ms (CACHE HIT)");

                    return threats;
                }

                DebugLogger.Log($"[AnalysisCacheService] Cache miss for threats");
                return null;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error loading threats from cache: {ex.Message}");
                return null; // Return null on error - will trigger fresh analysis
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task SaveVoiceQoSAsync(string cacheKey, VoiceQoSAnalysisResult qosData, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            var startTime = DateTime.Now;
            var totalItems = qosData.QoSTraffic.Count + qosData.HighLatencyConnections.Count + qosData.HighJitterConnections.Count;
            DebugLogger.Log($"[AnalysisCacheService] Saving VoiceQoS data to cache ({totalItems} items)...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                // Serialize and compress data
                var json = JsonSerializer.Serialize(qosData, _jsonOptions);
                var compressedData = await CompressDataAsync(json, cancellationToken);
                var dataSizeMB = compressedData.Length / 1024.0 / 1024.0;

                DebugLogger.Log($"[AnalysisCacheService] Compressed VoiceQoS data: {json.Length / 1024.0:F2} KB -> {dataSizeMB:F2} MB");

                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                // Extract file hash from cache key
                var fileHash = cacheKey.Split('_')[0];

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO AnalysisCache
                    (CacheKey, FileHash, FilePath, PacketCount, AnalysisType, AnalysisVersion,
                     ResultData, CreatedAt, LastAccessedAt, DataSizeMB)
                    VALUES
                    (@CacheKey, @FileHash, @FilePath, @PacketCount, @AnalysisType, @AnalysisVersion,
                     @ResultData, @CreatedAt, @LastAccessedAt, @DataSizeMB)
                ";
                cmd.Parameters.AddWithValue("@CacheKey", cacheKey);
                cmd.Parameters.AddWithValue("@FileHash", fileHash);
                cmd.Parameters.AddWithValue("@FilePath", "");
                cmd.Parameters.AddWithValue("@PacketCount", totalItems);
                cmd.Parameters.AddWithValue("@AnalysisType", "VoiceQoS");
                cmd.Parameters.AddWithValue("@AnalysisVersion", ANALYSIS_VERSION);
                cmd.Parameters.AddWithValue("@ResultData", compressedData);
                cmd.Parameters.AddWithValue("@CreatedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                cmd.Parameters.AddWithValue("@LastAccessedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                cmd.Parameters.AddWithValue("@DataSizeMB", dataSizeMB);

                await cmd.ExecuteNonQueryAsync(cancellationToken);

                var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
                DebugLogger.Log($"[AnalysisCacheService] VoiceQoS data saved to cache in {elapsed:F0}ms");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error saving VoiceQoS to cache: {ex.Message}");
                // Don't throw - cache failures should not break analysis
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<VoiceQoSAnalysisResult?> LoadVoiceQoSAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            var startTime = DateTime.Now;
            DebugLogger.Log($"[AnalysisCacheService] Loading VoiceQoS data from cache...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT ResultData
                    FROM AnalysisCache
                    WHERE CacheKey = @CacheKey AND AnalysisType = @AnalysisType
                ";
                cmd.Parameters.AddWithValue("@CacheKey", cacheKey);
                cmd.Parameters.AddWithValue("@AnalysisType", "VoiceQoS");

                using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    var compressedData = (byte[])reader["ResultData"];
                    var json = await DecompressDataAsync(compressedData, cancellationToken);
                    var qosData = JsonSerializer.Deserialize<VoiceQoSAnalysisResult>(json, _jsonOptions);

                    // Update last accessed time
                    await UpdateLastAccessedAsync(cacheKey, "VoiceQoS", connection, cancellationToken);

                    var elapsed = (DateTime.Now - startTime).TotalMilliseconds;
                    DebugLogger.Log($"[AnalysisCacheService] Loaded VoiceQoS data from cache in {elapsed:F0}ms (CACHE HIT)");

                    return qosData;
                }

                DebugLogger.Log($"[AnalysisCacheService] Cache miss for VoiceQoS");
                return null;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[AnalysisCacheService] Error loading VoiceQoS from cache: {ex.Message}");
                return null; // Return null on error - will trigger fresh analysis
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<int> ClearOldCacheAsync(int maxAgeDays = 30, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            DebugLogger.Log($"[AnalysisCacheService] Clearing cache entries older than {maxAgeDays} days...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                var cutoffTime = DateTimeOffset.UtcNow.AddDays(-maxAgeDays).ToUnixTimeSeconds();

                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    DELETE FROM AnalysisCache
                    WHERE LastAccessedAt < @CutoffTime
                ";
                cmd.Parameters.AddWithValue("@CutoffTime", cutoffTime);

                var deletedCount = await cmd.ExecuteNonQueryAsync(cancellationToken);

                DebugLogger.Log($"[AnalysisCacheService] Deleted {deletedCount} old cache entries");
                return deletedCount;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<long> GetCacheSizeMBAsync(CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                if (File.Exists(_dbPath))
                {
                    var fileInfo = new FileInfo(_dbPath);
                    return fileInfo.Length / 1024 / 1024;
                }
                return 0;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<Dictionary<string, object>> GetCacheStatisticsAsync(CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                var stats = new Dictionary<string, object>();

                // Total entries
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM AnalysisCache";
                    stats["TotalEntries"] = (long)(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0L);
                }

                // Threats count
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM AnalysisCache WHERE AnalysisType = 'Threats'";
                    stats["ThreatsEntries"] = (long)(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0L);
                }

                // VoiceQoS count
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM AnalysisCache WHERE AnalysisType = 'VoiceQoS'";
                    stats["VoiceQoSEntries"] = (long)(await cmd.ExecuteScalarAsync(cancellationToken) ?? 0L);
                }

                // Total data size
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "SELECT SUM(DataSizeMB) FROM AnalysisCache";
                    var totalSize = await cmd.ExecuteScalarAsync(cancellationToken);
                    stats["TotalSizeMB"] = totalSize != DBNull.Value ? Convert.ToDouble(totalSize) : 0.0;
                }

                stats["DatabaseSizeMB"] = await GetCacheSizeMBAsync(cancellationToken);

                return stats;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task DeleteCacheForFileAsync(string fileHash, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM AnalysisCache WHERE FileHash = @FileHash";
                cmd.Parameters.AddWithValue("@FileHash", fileHash);

                var deletedCount = await cmd.ExecuteNonQueryAsync(cancellationToken);
                DebugLogger.Log($"[AnalysisCacheService] Deleted {deletedCount} cache entries for file hash {fileHash}");
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task OptimizeDatabaseAsync(CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            DebugLogger.Log("[AnalysisCacheService] Optimizing database...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = "VACUUM";
                await cmd.ExecuteNonQueryAsync(cancellationToken);

                DebugLogger.Log("[AnalysisCacheService] Database optimization complete");
            }
            finally
            {
                _dbLock.Release();
            }
        }

        public async Task<int> ClearAllCacheAsync(CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken);

            DebugLogger.Log("[AnalysisCacheService] Clearing ALL cache entries...");

            await _dbLock.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM AnalysisCache";

                var deletedCount = await cmd.ExecuteNonQueryAsync(cancellationToken);

                // Vacuum to reclaim space
                using var vacuumCmd = connection.CreateCommand();
                vacuumCmd.CommandText = "VACUUM";
                await vacuumCmd.ExecuteNonQueryAsync(cancellationToken);

                DebugLogger.Log($"[AnalysisCacheService] Cleared ALL {deletedCount} cache entries and vacuumed database");
                return deletedCount;
            }
            finally
            {
                _dbLock.Release();
            }
        }

        private static async Task UpdateLastAccessedAsync(string cacheKey, string analysisType, SqliteConnection connection, CancellationToken cancellationToken)
        {
            using var updateCmd = connection.CreateCommand();
            updateCmd.CommandText = @"
                UPDATE AnalysisCache
                SET LastAccessedAt = @LastAccessedAt
                WHERE CacheKey = @CacheKey AND AnalysisType = @AnalysisType
            ";
            updateCmd.Parameters.AddWithValue("@CacheKey", cacheKey);
            updateCmd.Parameters.AddWithValue("@AnalysisType", analysisType);
            updateCmd.Parameters.AddWithValue("@LastAccessedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            await updateCmd.ExecuteNonQueryAsync(cancellationToken);
        }

        private static async Task<byte[]> CompressDataAsync(string data, CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            using var outputStream = new MemoryStream();
            using (var gzipStream = new GZipStream(outputStream, CompressionLevel.Optimal))
            {
                await gzipStream.WriteAsync(bytes, cancellationToken);
            }
            return outputStream.ToArray();
        }

        private static async Task<string> DecompressDataAsync(byte[] compressedData, CancellationToken cancellationToken)
        {
            using var inputStream = new MemoryStream(compressedData);
            using var gzipStream = new GZipStream(inputStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream();
            await gzipStream.CopyToAsync(outputStream, cancellationToken);
            return Encoding.UTF8.GetString(outputStream.ToArray());
        }

        public void Dispose()
        {
            if (_disposed) return;

            _dbLock?.Dispose();
            _disposed = true;

            GC.SuppressFinalize(this);
        }
    }
}
