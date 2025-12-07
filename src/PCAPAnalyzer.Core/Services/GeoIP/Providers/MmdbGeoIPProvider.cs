using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.GeoIP.Configuration;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.GeoIP.Providers
{
    /// <summary>
    /// GeoIP provider using MaxMind MMDB (binary database) format.
    /// High-performance local lookups with no API limits or rate restrictions.
    /// Supports both IPv4 and IPv6 addresses.
    /// </summary>
    public class MmdbGeoIPProvider : IGeoIPProvider, IDisposable
    {
        private DatabaseReader? _ipv4Reader;
        private DatabaseReader? _ipv6Reader;
        private readonly Dictionary<string, string> _countryCodeToName = [];
        private readonly ILogger? _logger;
        private bool _isReady;
        private string? _ipv4DatabasePath;
        private string? _ipv6DatabasePath;
        private string? _configuredPath;
        private bool _disposed;

        public string ProviderName => "MaxMind MMDB (IPv4+IPv6)";

        public bool IsReady => _isReady;

        /// <summary>
        /// Creates a new MMDB provider with default settings
        /// </summary>
        public MmdbGeoIPProvider(ILogger? logger = null)
        {
            _logger = logger;
        }

        /// <summary>
        /// Creates a new MMDB provider with specific database path
        /// </summary>
        public MmdbGeoIPProvider(string databasePath, ILogger? logger = null)
        {
            _logger = logger;
            _configuredPath = databasePath;
        }

        /// <summary>
        /// Creates a new MMDB provider from configuration
        /// </summary>
        public MmdbGeoIPProvider(ProviderConfiguration config, ILogger? logger = null)
        {
            _logger = logger;
            _configuredPath = config.GetSetting("DatabasePath");
        }

        public async Task<bool> InitializeAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // CRITICAL FIX: Dispose old readers if re-initializing
                    if (_ipv4Reader != null)
                    {
                        DebugLogger.Log($"[{ProviderName}] Disposing previous IPv4 DatabaseReader to prevent memory leak");
                        _ipv4Reader.Dispose();
                        _ipv4Reader = null;
                    }
                    if (_ipv6Reader != null)
                    {
                        DebugLogger.Log($"[{ProviderName}] Disposing previous IPv6 DatabaseReader to prevent memory leak");
                        _ipv6Reader.Dispose();
                        _ipv6Reader = null;
                    }
                    _isReady = false;

                    _logger?.LogInformation("[{Provider}] Starting initialization...", ProviderName);
                    DebugLogger.Log($"[{ProviderName}] Starting initialization...");

                    // Initialize country name mappings
                    InitializeCountryNames();
                    _logger?.LogDebug("[{Provider}] Country name mappings initialized", ProviderName);

                    // Build search paths for both IPv4 and IPv6 databases
                    var baseSearchLocations = new[]
                    {
                        AppDomain.CurrentDomain.BaseDirectory,
                        Directory.GetCurrentDirectory(),
                        Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? "",
                        @"C:\Claude Code\PCAP_Net9_Avalonia_TShark",
                        "/mnt/c/Claude Code/PCAP_Net9_Avalonia_TShark",
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCAPAnalyzer")
                    };

                    bool ipv4Loaded = false;
                    bool ipv6Loaded = false;

                    // Try to load IPv4 database
                    DebugLogger.Log($"[{ProviderName}] Searching for IPv4 database (GeoLite2-Country.mmdb)...");
                    foreach (var baseLocation in baseSearchLocations)
                    {
                        var ipv4Path = Path.Combine(baseLocation, "GeoLite2-Country.mmdb");
                        if (File.Exists(ipv4Path))
                        {
                            try
                            {
                                DebugLogger.Log($"[{ProviderName}] Loading IPv4 database from: {ipv4Path}");
                                _ipv4Reader = new DatabaseReader(ipv4Path);
                                _ipv4DatabasePath = ipv4Path;
                                ipv4Loaded = true;
                                DebugLogger.Log($"[{ProviderName}] ✓ IPv4 database loaded successfully!");
                                break;
                            }
                            catch (Exception ex)
                            {
                                DebugLogger.Log($"[{ProviderName}] ✗ Failed to load IPv4 database: {ex.Message}");
                            }
                        }
                    }

                    // Try to load IPv6 database (optional but recommended)
                    DebugLogger.Log($"[{ProviderName}] Searching for IPv6 database (GeoLite2-Country-IPv6.mmdb)...");
                    foreach (var baseLocation in baseSearchLocations)
                    {
                        // Try both naming conventions
                        var ipv6Paths = new[]
                        {
                            Path.Combine(baseLocation, "GeoLite2-Country-IPv6.mmdb"),
                            Path.Combine(baseLocation, "GeoLite2-Country.mmdb") // Combined database supports both
                        };

                        foreach (var ipv6Path in ipv6Paths)
                        {
                            if (File.Exists(ipv6Path) && ipv6Path != _ipv4DatabasePath)
                            {
                                try
                                {
                                    DebugLogger.Log($"[{ProviderName}] Loading IPv6 database from: {ipv6Path}");
                                    _ipv6Reader = new DatabaseReader(ipv6Path);
                                    _ipv6DatabasePath = ipv6Path;
                                    ipv6Loaded = true;
                                    DebugLogger.Log($"[{ProviderName}] ✓ IPv6 database loaded successfully!");
                                    break;
                                }
                                catch (Exception ex)
                                {
                                    DebugLogger.Log($"[{ProviderName}] ✗ Failed to load IPv6 database: {ex.Message}");
                                }
                            }
                        }

                        if (ipv6Loaded) break;
                    }

                    // If IPv6 database not found separately, use IPv4 database for both (MaxMind Country DB supports both)
                    if (!ipv6Loaded && ipv4Loaded && _ipv4Reader != null)
                    {
                        DebugLogger.Log($"[{ProviderName}] No separate IPv6 database found, using combined IPv4/IPv6 database");
                        _ipv6Reader = _ipv4Reader; // Same reader supports both IPv4 and IPv6
                        _ipv6DatabasePath = _ipv4DatabasePath;
                        ipv6Loaded = true;
                    }

                    // Summary
                    if (ipv4Loaded && ipv6Loaded)
                    {
                        _isReady = true;
                        DebugLogger.Log($"[{ProviderName}] ✓✓ SUCCESS: Both IPv4 and IPv6 databases ready!");
                        DebugLogger.Log($"[{ProviderName}]   IPv4: {_ipv4DatabasePath}");
                        DebugLogger.Log($"[{ProviderName}]   IPv6: {_ipv6DatabasePath}");
                        return true;
                    }
                    else if (ipv4Loaded)
                    {
                        _isReady = true;
                        DebugLogger.Log($"[{ProviderName}] ⚠ PARTIAL SUCCESS: IPv4 database loaded, IPv6 will use classification fallback");
                        DebugLogger.Log($"[{ProviderName}]   IPv4: {_ipv4DatabasePath}");
                        return true;
                    }
                    else
                    {
                        DebugLogger.Log($"[{ProviderName}] ✗✗ CRITICAL ERROR: No GeoIP databases found!");
                        DebugLogger.Log($"[{ProviderName}] Searched locations:");
                        foreach (var loc in baseSearchLocations)
                        {
                            DebugLogger.Log($"[{ProviderName}]   - {loc}");
                        }
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "[{Provider}] Initialization failed", ProviderName);
                    DebugLogger.Log($"[{ProviderName}] ERROR: Initialization failed - {ex.Message}");
                    DebugLogger.Log($"[{ProviderName}] Stack trace: {ex.StackTrace}");
                    return false;
                }
            });
        }

        public async Task<GeoLocation?> LookupAsync(string ipAddress)
        {
            return await Task.Run(() =>
            {
                if (!_isReady || string.IsNullOrEmpty(ipAddress))
                    return null;

                try
                {
                    // Parse IP to determine version
                    if (!System.Net.IPAddress.TryParse(ipAddress, out var ip))
                        return null;

                    // Select appropriate database reader based on IP version
                    DatabaseReader? reader = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                        ? _ipv6Reader
                        : _ipv4Reader;

                    if (reader == null)
                        return null;

                    var response = reader.Country(ipAddress);
                    if (response?.Country == null)
                        return null;

                    var countryCode = response.Country.IsoCode ?? "XX";
                    var countryName = _countryCodeToName.TryGetValue(countryCode, out var name)
                        ? name
                        : response.Country.Name ?? "Unknown";

                    var continentCode = response.Continent?.Code ?? "XX";
                    var continentName = response.Continent?.Name ?? "Unknown";

                    return new GeoLocation
                    {
                        IpAddress = ipAddress,
                        CountryCode = countryCode,
                        CountryName = countryName,
                        ContinentCode = continentCode,
                        ContinentName = continentName,
                        City = string.Empty, // MMDB Country database doesn't include city
                        IsPublicIP = true,
                        LastUpdated = DateTime.UtcNow,
                        Source = ProviderName,
                        ConfidenceScore = 0.95 // MMDB is highly reliable
                    };
                }
                catch (GeoIP2Exception)
                {
                    // IP not found in database
                    return null;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[{Provider}] Lookup error for IP: {IpAddress}", ProviderName, ipAddress);
                    return null;
                }
            });
        }

        public async Task<GeoIPDatabaseStats?> GetStatsAsync()
        {
            return await Task.Run(() =>
            {
                if (!_isReady)
                    return null;

                try
                {
                    long totalSize = 0;
                    DateTime lastUpdate = DateTime.MinValue;

                    if (!string.IsNullOrEmpty(_ipv4DatabasePath))
                    {
                        var ipv4Info = new FileInfo(_ipv4DatabasePath);
                        totalSize += ipv4Info.Length;
                        if (ipv4Info.LastWriteTime > lastUpdate)
                            lastUpdate = ipv4Info.LastWriteTime;
                    }

                    if (!string.IsNullOrEmpty(_ipv6DatabasePath) && _ipv6DatabasePath != _ipv4DatabasePath)
                    {
                        var ipv6Info = new FileInfo(_ipv6DatabasePath);
                        totalSize += ipv6Info.Length;
                        if (ipv6Info.LastWriteTime > lastUpdate)
                            lastUpdate = ipv6Info.LastWriteTime;
                    }

                    return new GeoIPDatabaseStats
                    {
                        Provider = ProviderName,
                        IsLoaded = _isReady,
                        DatabaseSizeBytes = totalSize,
                        LastUpdate = lastUpdate,
                        TotalRecords = -1 // MMDB doesn't expose record count easily
                    };
                }
                catch
                {
                    return null;
                }
            });
        }

        public async Task DisposeAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    if (_ipv4Reader != null && _ipv4Reader != _ipv6Reader)
                    {
                        _ipv4Reader.Dispose();
                        _ipv4Reader = null;
                    }

                    if (_ipv6Reader != null)
                    {
                        _ipv6Reader.Dispose();
                        _ipv6Reader = null;
                    }

                    _isReady = false;
                    _logger?.LogInformation("[{Provider}] Disposed successfully", ProviderName);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "[{Provider}] Error during disposal", ProviderName);
                }
            });
        }

        private void InitializeCountryNames()
        {
            // Comprehensive country code to name mappings
            var countryMappings = new Dictionary<string, string>
            {
                { "US", "United States" },
                { "CA", "Canada" },
                { "GB", "United Kingdom" },
                { "DE", "Germany" },
                { "FR", "France" },
                { "IT", "Italy" },
                { "ES", "Spain" },
                { "NL", "Netherlands" },
                { "BE", "Belgium" },
                { "CH", "Switzerland" },
                { "AT", "Austria" },
                { "SE", "Sweden" },
                { "NO", "Norway" },
                { "DK", "Denmark" },
                { "FI", "Finland" },
                { "PL", "Poland" },
                { "CZ", "Czech Republic" },
                { "HU", "Hungary" },
                { "RO", "Romania" },
                { "BG", "Bulgaria" },
                { "GR", "Greece" },
                { "PT", "Portugal" },
                { "IE", "Ireland" },
                { "RU", "Russia" },
                { "CN", "China" },
                { "JP", "Japan" },
                { "KR", "South Korea" },
                { "IN", "India" },
                { "AU", "Australia" },
                { "NZ", "New Zealand" },
                { "BR", "Brazil" },
                { "MX", "Mexico" },
                { "AR", "Argentina" },
                { "CL", "Chile" },
                { "CO", "Colombia" },
                { "PE", "Peru" },
                { "VE", "Venezuela" },
                { "ZA", "South Africa" },
                { "EG", "Egypt" },
                { "NG", "Nigeria" },
                { "KE", "Kenya" },
                { "SA", "Saudi Arabia" },
                { "AE", "United Arab Emirates" },
                { "IL", "Israel" },
                { "TR", "Turkey" },
                { "UA", "Ukraine" },
                { "BY", "Belarus" },
                { "KZ", "Kazakhstan" },
                { "SG", "Singapore" },
                { "MY", "Malaysia" },
                { "TH", "Thailand" },
                { "VN", "Vietnam" },
                { "PH", "Philippines" },
                { "ID", "Indonesia" },
                { "XX", "Unknown" }
            };

            foreach (var mapping in countryMappings)
            {
                _countryCodeToName[mapping.Key] = mapping.Value;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                if (_ipv4Reader != null && _ipv4Reader != _ipv6Reader)
                {
                    _ipv4Reader.Dispose();
                }

                if (_ipv6Reader != null)
                {
                    _ipv6Reader.Dispose();
                }

                _isReady = false;
            }
            // Dispose unmanaged resources (if any) here

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
