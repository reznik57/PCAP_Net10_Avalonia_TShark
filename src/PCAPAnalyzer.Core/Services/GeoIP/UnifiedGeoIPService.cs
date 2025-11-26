using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.GeoIP.Configuration;
using PCAPAnalyzer.Core.Services.GeoIP.Providers;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.GeoIP
{
    /// <summary>
    /// Unified GeoIP service using provider strategy pattern.
    /// Supports fallback cascade through multiple providers with configuration support.
    /// Thread-safe with in-memory caching and automatic provider initialization.
    /// </summary>
    public class UnifiedGeoIPService : IGeoIPService
    {
        private readonly List<IGeoIPProvider> _providers = new();
        private readonly ConcurrentDictionary<string, CachedGeoLocation> _cache = new();
        private readonly GeoIPConfiguration _configuration;
        private readonly ILogger? _logger;
        private bool _isInitialized;
        private bool _disposed;

        // ✅ DIAGNOSTIC: Track cache statistics for aggregate logging
        private int _cacheMissCount;
        private int _cacheHitCount;
        private DateTime _lastCacheLogTime = DateTime.UtcNow;

        // High-risk countries based on common cybersecurity threat intelligence
        private readonly HashSet<string> _highRiskCountries = new()
        {
            "CN", "RU", "KP", "IR", "SY", "CU", "VE", "BY", "MM", "ZW", "NG"
        };

        /// <summary>
        /// Creates a new UnifiedGeoIPService with default configuration (MMDB only)
        /// </summary>
        public UnifiedGeoIPService(ILogger? logger = null)
            : this(GeoIPConfiguration.CreateDefault(), logger)
        {
        }

        /// <summary>
        /// Creates a new UnifiedGeoIPService with specific configuration
        /// </summary>
        public UnifiedGeoIPService(GeoIPConfiguration configuration, ILogger? logger = null)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger;

            // Validate configuration
            if (!_configuration.Validate(out var errors))
            {
                throw new ArgumentException($"Invalid configuration: {string.Join(", ", errors)}");
            }

            // Initialize providers from configuration
            InitializeProvidersFromConfiguration();
        }

        /// <summary>
        /// Creates a new UnifiedGeoIPService with custom providers (legacy constructor)
        /// </summary>
        public UnifiedGeoIPService(params IGeoIPProvider[] providers)
        {
            _configuration = GeoIPConfiguration.CreateDefault();

            foreach (var provider in providers)
            {
                RegisterProvider(provider);
            }
        }

        private void InitializeProvidersFromConfiguration()
        {
            // Sort providers by priority (lower number = higher priority)
            var sortedProviders = _configuration.Providers
                .Where(p => p.IsEnabled)
                .OrderBy(p => p.Priority)
                .ToList();

            foreach (var providerConfig in sortedProviders)
            {
                try
                {
                    // CA2000 suppressed: Providers are stored in _providers list and disposed via Dispose()
#pragma warning disable CA2000
                    IGeoIPProvider? provider = providerConfig.ProviderType switch
                    {
                        ProviderType.Mmdb => new MmdbGeoIPProvider(),
                        ProviderType.Sqlite => new SqliteGeoIPProvider(providerConfig, _logger),
                        ProviderType.Api => new ApiGeoIPProvider(providerConfig, _logger),
                        _ => null
                    };
#pragma warning restore CA2000

                    if (provider != null)
                    {
                        RegisterProvider(provider);
                        _logger?.LogInformation("Registered provider: {ProviderType} with priority {Priority}",
                            providerConfig.ProviderType, providerConfig.Priority);
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to create provider: {ProviderType}", providerConfig.ProviderType);
                }
            }
        }

        public void RegisterProvider(IGeoIPProvider provider)
        {
            if (provider == null) return;
            _providers.Add(provider);
            DebugLogger.Log($"[UnifiedGeoIPService] Registered provider: {provider.ProviderName}");
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            DebugLogger.Log($"[UnifiedGeoIPService] Initializing {_providers.Count} provider(s)");

            foreach (var provider in _providers)
            {
                try
                {
                    var success = await provider.InitializeAsync();
                    DebugLogger.Log($"[UnifiedGeoIPService] Provider {provider.ProviderName}: {(success ? "SUCCESS" : "FAILED")}");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] Provider {provider.ProviderName} initialization error: {ex.Message}");
                }
            }

            _isInitialized = true;
            var readyCount = _providers.Count(p => p.IsReady);
            DebugLogger.Log($"[UnifiedGeoIPService] Initialization complete: {readyCount}/{_providers.Count} providers ready");
        }

        public async Task<GeoLocation?> GetLocationAsync(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            // Wait for initialization if not yet complete (max 5 seconds)
            if (!_isInitialized)
            {
                var waitStart = DateTime.UtcNow;
                while (!_isInitialized && (DateTime.UtcNow - waitStart).TotalSeconds < 5)
                {
                    await Task.Delay(50); // Poll every 50ms
                }

                if (!_isInitialized)
                {
                    DebugLogger.Log("[UnifiedGeoIPService] Initialization incomplete after 5s wait - proceeding anyway");
                }
            }

            // Check cache first if enabled
            if (_configuration.EnableCache && _cache.TryGetValue(ipAddress, out var cached))
            {
                // Check if cache entry is still valid
                if (DateTime.UtcNow < cached.ExpiresAt)
                {
                    cached.HitCount++;
                    System.Threading.Interlocked.Increment(ref _cacheHitCount);

                    // ✅ PERFORMANCE FIX: Aggregate logging instead of per-IP spam
                    // Log aggregate stats every 10 seconds instead of every 100 hits per IP
                    var now = DateTime.UtcNow;
                    if ((now - _lastCacheLogTime).TotalSeconds > 10)
                    {
                        var totalLookups = _cacheHitCount + _cacheMissCount;
                        var hitRate = totalLookups > 0
                            ? (_cacheHitCount * 100.0 / totalLookups)
                            : 0;

                        DebugLogger.Log($"[GeoIP Cache] 📊 Stats: {_cacheHitCount:N0} hits, {_cacheMissCount:N0} misses ({hitRate:F1}% hit rate), {_cache.Count} cached IPs");
                        _lastCacheLogTime = now;
                    }

                    if (_configuration.EnableDetailedLogging)
                    {
                        _logger?.LogDebug("Cache hit for IP: {IpAddress}", ipAddress);
                    }
                    return cached.Location;
                }

                // Remove expired entry
                _cache.TryRemove(ipAddress, out _);

                // ✅ DIAGNOSTIC: Cache expiration logging
                DebugLogger.Log($"[GeoIP Cache] ⏱️  EXPIRED for {ipAddress} (cached at {cached.CachedAt:HH:mm:ss}, expired at {cached.ExpiresAt:HH:mm:ss})");
            }
            else if (_configuration.EnableCache)
            {
                // ✅ PERFORMANCE FIX: Track misses for aggregate stats (removed verbose logging)
                System.Threading.Interlocked.Increment(ref _cacheMissCount);
            }

            // Try each provider in order until one succeeds
            foreach (var provider in _providers.Where(p => p.IsReady))
            {
                try
                {
                    var result = await provider.LookupAsync(ipAddress);
                    if (result != null)
                    {
                        // Cache the result if caching is enabled
                        if (_configuration.EnableCache)
                        {
                            CacheResult(ipAddress, result);
                        }

                        if (_configuration.EnableDetailedLogging)
                        {
                            _logger?.LogDebug("Lookup successful for IP: {IpAddress} via provider: {Provider}",
                                ipAddress, provider.ProviderName);
                        }

                        return result;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[UnifiedGeoIPService] Provider {Provider} lookup error for IP: {IpAddress}",
                        provider.ProviderName, ipAddress);

                    // Continue to next provider if fallback is enabled
                    if (!_configuration.EnableProviderFallback)
                    {
                        throw;
                    }
                }
            }

            _logger?.LogWarning("No provider could resolve IP: {IpAddress}", ipAddress);
            return null;
        }

        private void CacheResult(string ipAddress, GeoLocation location)
        {
            var cachedEntry = new CachedGeoLocation
            {
                Location = location,
                CachedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(_configuration.CacheExpiration),
                HitCount = 0
            };

            _cache[ipAddress] = cachedEntry;

            // ✅ DIAGNOSTIC: Cache storage logging (throttled - every 1000 entries)
            if (_cache.Count % 1000 == 0)
            {
                DebugLogger.Log($"[GeoIP Cache] 💾 Cached {_cache.Count} IPs (max: {_configuration.MaxCacheSize})");
            }

            // Enforce max cache size
            if (_cache.Count > _configuration.MaxCacheSize)
            {
                // Remove oldest entries (simple LRU)
                var toRemove = _cache
                    .OrderBy(kvp => kvp.Value.CachedAt)
                    .Take(_cache.Count - _configuration.MaxCacheSize)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in toRemove)
                {
                    _cache.TryRemove(key, out _);
                }
            }
        }

        // Suppress complexity warning - method complexity is justified for performance-optimized parallel processing
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Parallel processing logic requires branching for thread-local aggregation and merging")]
        public async Task<Dictionary<string, CountryTrafficStatistics>> AnalyzeCountryTrafficAsync(IEnumerable<PacketInfo> packets, object? progressStage = null)
        {
            DebugLogger.Log($"[UnifiedGeoIPService] ===== AnalyzeCountryTrafficAsync CALLED =====");
            DebugLogger.Log($"[UnifiedGeoIPService] Initialized: {_isInitialized}, Providers: {_providers.Count}, Ready providers: {_providers.Count(p => p.IsReady)}");

            // ✅ TIMING FIX: Start timing when actual work begins
            if (progressStage != null)
            {
                try
                {
                    // Use dynamic to avoid tight coupling between Core and UI layers
                    dynamic stage = progressStage;
                    stage.StartTiming();
                    DebugLogger.Log($"[UnifiedGeoIPService] ⏱️  Started timing for stage: {stage.Name}");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] ⚠️  Failed to start stage timing: {ex.Message}");
                }
            }

            var countryStats = new Dictionary<string, CountryTrafficStatistics>();
            var packetList = packets.ToList();

            DebugLogger.Log($"[UnifiedGeoIPService] Analyzing traffic for {packetList.Count} packets");

            // Collect unique public IPs
            var uniqueIPs = new HashSet<string>();
            var totalIPs = 0;
            var privateIPs = 0;
            var publicIPs = 0;

            foreach (var packet in packetList)
            {
                if (!string.IsNullOrEmpty(packet.SourceIP))
                {
                    totalIPs++;
                    if (IsPublicIP(packet.SourceIP))
                    {
                        uniqueIPs.Add(packet.SourceIP);
                        publicIPs++;
                    }
                    else
                    {
                        privateIPs++;
                    }
                }

                if (!string.IsNullOrEmpty(packet.DestinationIP))
                {
                    totalIPs++;
                    if (IsPublicIP(packet.DestinationIP))
                    {
                        uniqueIPs.Add(packet.DestinationIP);
                        publicIPs++;
                    }
                    else
                    {
                        privateIPs++;
                    }
                }
            }

            DebugLogger.Log($"[UnifiedGeoIPService] Total IPs processed: {totalIPs}, Public: {publicIPs}, Private: {privateIPs}");
            DebugLogger.Log($"[UnifiedGeoIPService] Found {uniqueIPs.Count} unique public IPs");

            // ✅ DIAGNOSTIC: Report cache state before lookups
            var cacheStats = GetCacheStatistics();
            DebugLogger.Log($"[GeoIP Cache] 📊 PRE-LOOKUP Stats: {cacheStats.TotalEntries} entries, {cacheStats.TotalHits} total hits, {cacheStats.HitRate:P1} hit rate");

            // Reset miss counter for this analysis
            _cacheMissCount = 0;

            // Lookup all unique IPs in parallel for speed (use cache + parallel processing)
            DebugLogger.Log($"[UnifiedGeoIPService] Starting PARALLEL IP lookups for {uniqueIPs.Count} unique IPs...");
            var startLookup = DateTime.Now;
            var ipToCountry = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
            var lookupCount = 0;
            var ipList = uniqueIPs.ToList();

            // Process in parallel batches (50 concurrent lookups at a time for optimal throughput)
            using var semaphore = new System.Threading.SemaphoreSlim(50);
            var lookupTasks = ipList.Select(async ip =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var location = await GetLocationAsync(ip);
                    if (location != null)
                    {
                        ipToCountry[ip] = location.CountryCode;
                    }

                    // Progress reporting (thread-safe) - Log only at 25%, 50%, 75% milestones
                    var currentCount = System.Threading.Interlocked.Increment(ref lookupCount);
                    if (currentCount % 100 == 0)
                    {
                        var progressPercent = (currentCount * 100.0 / uniqueIPs.Count);
                        if ((progressPercent >= 24.5 && progressPercent < 26) ||
                            (progressPercent >= 49.5 && progressPercent < 51) ||
                            (progressPercent >= 74.5 && progressPercent < 76))
                        {
                            var elapsed = (DateTime.Now - startLookup).TotalSeconds;
                            var rate = elapsed > 0 ? currentCount / elapsed : 0;
                            DebugLogger.Log($"[GeoIP] {progressPercent:F0}% ({currentCount:N0}/{uniqueIPs.Count:N0} IPs) @ {rate:F0}/s");
                        }
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(lookupTasks);
            var lookupElapsed = (DateTime.Now - startLookup).TotalSeconds;
            var successCount = ipToCountry.Count;

            DebugLogger.Log($"[UnifiedGeoIPService] PARALLEL IP lookups complete: {successCount}/{uniqueIPs.Count} IPs resolved in {lookupElapsed:F2}s ({(uniqueIPs.Count / lookupElapsed):F0} lookups/s)");

            // ✅ DIAGNOSTIC: Report cache performance after lookups
            var postCacheStats = GetCacheStatistics();
            var cacheMisses = _cacheMissCount;
            var cacheHits = uniqueIPs.Count - cacheMisses;
            var hitRate = uniqueIPs.Count > 0 ? (double)cacheHits / uniqueIPs.Count * 100 : 0;
            DebugLogger.Log($"[GeoIP Cache] 📊 POST-LOOKUP Stats: {postCacheStats.TotalEntries} entries, {cacheHits}/{uniqueIPs.Count} hits ({hitRate:F1}%), {cacheMisses} misses");

            // Analyze packets by country using parallel processing
            var aggregationStart = DateTime.Now;
            DebugLogger.Log($"[UnifiedGeoIPService] Starting PARALLEL packet aggregation for {packetList.Count:N0} packets...");

            // Temporary thread-safe wrapper for parallel aggregation (memory optimization)
            var tempStats = new ConcurrentDictionary<string, TempCountryStats>();

            Parallel.ForEach(
                packetList,
                packet =>
                {
                    // Classify source IP (include Internal and IPv6 as pseudo-countries)
                    string? sourceCountry = null;
                    if (!string.IsNullOrEmpty(packet.SourceIP))
                    {
                        if (ipToCountry.TryGetValue(packet.SourceIP, out var sc))
                        {
                            sourceCountry = sc; // Public IP with GeoIP lookup
                        }
                        else if (!IsPublicIP(packet.SourceIP))
                        {
                            // Only classify non-public IPs (private IPv4, IPv6 special types)
                            sourceCountry = ClassifyNonPublicIP(packet.SourceIP);
                        }
                        // else: Public IP with failed GeoIP lookup - skip this packet
                    }

                    // Classify destination IP (include Internal and IPv6 as pseudo-countries)
                    string? destCountry = null;
                    if (!string.IsNullOrEmpty(packet.DestinationIP))
                    {
                        if (ipToCountry.TryGetValue(packet.DestinationIP, out var dc))
                        {
                            destCountry = dc; // Public IP with GeoIP lookup
                        }
                        else if (!IsPublicIP(packet.DestinationIP))
                        {
                            // Only classify non-public IPs (private IPv4, IPv6 special types)
                            destCountry = ClassifyNonPublicIP(packet.DestinationIP);
                        }
                        // else: Public IP with failed GeoIP lookup - skip this packet
                    }

                    if (sourceCountry != null)
                    {
                        var stats = tempStats.GetOrAdd(sourceCountry, _ => new TempCountryStats { CountryCode = sourceCountry });

                        System.Threading.Interlocked.Increment(ref stats.TotalPackets);
                        System.Threading.Interlocked.Add(ref stats.OutgoingBytes, packet.Length);
                        System.Threading.Interlocked.Increment(ref stats.OutgoingPackets);

                        // Lock-free thread-safe collection (no HashSet duplication!)
                        stats.OutgoingIPs.Add(packet.SourceIP);
                        stats.UniqueIPs.Add(packet.SourceIP);
                    }

                    if (destCountry != null)
                    {
                        var stats = tempStats.GetOrAdd(destCountry, _ => new TempCountryStats { CountryCode = destCountry });

                        System.Threading.Interlocked.Increment(ref stats.TotalPackets);
                        System.Threading.Interlocked.Add(ref stats.IncomingBytes, packet.Length);
                        System.Threading.Interlocked.Increment(ref stats.IncomingPackets);

                        // Lock-free thread-safe collection (no HashSet duplication!)
                        stats.IncomingIPs.Add(packet.DestinationIP);
                        stats.UniqueIPs.Add(packet.DestinationIP);
                    }
                });

            // Convert temporary stats to final HashSet-based model ONCE at the end (deduplication)
            DebugLogger.Log($"[UnifiedGeoIPService] Deduplicating IPs for {tempStats.Count} countries...");
            foreach (var kvp in tempStats)
            {
                var temp = kvp.Value;

                // Convert ConcurrentBag to HashSet (single deduplication per country)
                countryStats[kvp.Key] = new CountryTrafficStatistics
                {
                    CountryCode = temp.CountryCode,
                    TotalPackets = temp.TotalPackets,
                    OutgoingBytes = temp.OutgoingBytes,
                    IncomingBytes = temp.IncomingBytes,
                    OutgoingPackets = temp.OutgoingPackets,
                    IncomingPackets = temp.IncomingPackets,
                    OutgoingIPs = new HashSet<string>(temp.OutgoingIPs),
                    IncomingIPs = new HashSet<string>(temp.IncomingIPs),
                    UniqueIPs = new HashSet<string>(temp.UniqueIPs)
                };
            }

            var aggregationElapsed = (DateTime.Now - aggregationStart).TotalSeconds;
            DebugLogger.Log($"[UnifiedGeoIPService] PARALLEL packet aggregation complete in {aggregationElapsed:F2}s ({(packetList.Count / aggregationElapsed):F0} packets/s)");

            // Calculate total bytes and percentages
            foreach (var stat in countryStats.Values)
            {
                stat.TotalBytes = stat.IncomingBytes + stat.OutgoingBytes;
            }

            var totalTraffic = countryStats.Values.Sum(s => s.TotalBytes);
            foreach (var stat in countryStats.Values)
            {
                stat.Percentage = totalTraffic > 0 ? (double)stat.TotalBytes / totalTraffic * 100 : 0;
            }

            DebugLogger.Log($"[UnifiedGeoIPService] Analysis complete: {countryStats.Count} countries");

            // ✅ TIMING FIX: Stop timing when work completes
            if (progressStage != null)
            {
                try
                {
                    dynamic stage = progressStage;
                    stage.StopTiming();
                    DebugLogger.Log($"[UnifiedGeoIPService] ⏹️  Stopped timing for stage: {stage.Name}");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] ⚠️  Failed to stop stage timing: {ex.Message}");
                }
            }

            return countryStats;
        }

        public async Task<List<TrafficFlowDirection>> AnalyzeTrafficFlowsAsync(IEnumerable<PacketInfo> packets, object? progressStage = null)
        {
            // ✅ TIMING FIX: Start timing when actual work begins
            if (progressStage != null)
            {
                try
                {
                    dynamic stage = progressStage;
                    stage.StartTiming();
                    DebugLogger.Log($"[UnifiedGeoIPService] ⏱️  Started timing for stage: {stage.Name}");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] ⚠️  Failed to start stage timing: {ex.Message}");
                }
            }

            var flows = new List<TrafficFlowDirection>();
            var packetList = packets.ToList();

            DebugLogger.Log($"[UnifiedGeoIPService] AnalyzeTrafficFlowsAsync: Processing {packetList.Count} packets for flow analysis");

            // Group by source/dest country pairs
            var flowMap = new Dictionary<(string source, string dest), TrafficFlowDirection>();

            foreach (var packet in packetList)
            {
                if (string.IsNullOrEmpty(packet.SourceIP) || string.IsNullOrEmpty(packet.DestinationIP))
                    continue;

                // Classify source IP (public via GeoIP, non-public via classification)
                string? sourceCountry = null;
                string? sourceCountryName = null;

                if (IsPublicIP(packet.SourceIP))
                {
                    var sourceLoc = await GetLocationAsync(packet.SourceIP);
                    if (sourceLoc != null)
                    {
                        sourceCountry = sourceLoc.CountryCode;
                        sourceCountryName = sourceLoc.CountryName;
                    }
                    // else: Public IP with failed GeoIP lookup - will be skipped below
                }
                else
                {
                    // Non-public IP (private IPv4, IPv6 special types)
                    sourceCountry = ClassifyNonPublicIP(packet.SourceIP);
                    sourceCountryName = GetFriendlyNameForCode(sourceCountry);
                }

                // Classify destination IP (public via GeoIP, non-public via classification)
                string? destCountry = null;
                string? destCountryName = null;

                if (IsPublicIP(packet.DestinationIP))
                {
                    var destLoc = await GetLocationAsync(packet.DestinationIP);
                    if (destLoc != null)
                    {
                        destCountry = destLoc.CountryCode;
                        destCountryName = destLoc.CountryName;
                    }
                    // else: Public IP with failed GeoIP lookup - will be skipped below
                }
                else
                {
                    // Non-public IP (private IPv4, IPv6 special types)
                    destCountry = ClassifyNonPublicIP(packet.DestinationIP);
                    destCountryName = GetFriendlyNameForCode(destCountry);
                }

                // Skip if either classification failed
                if (string.IsNullOrEmpty(sourceCountry) || string.IsNullOrEmpty(destCountry))
                    continue;

                var key = (sourceCountry, destCountry);
                if (!flowMap.ContainsKey(key))
                {
                    flowMap[key] = new TrafficFlowDirection
                    {
                        SourceCountry = sourceCountry,
                        DestinationCountry = destCountry,
                        SourceCountryName = sourceCountryName ?? sourceCountry,
                        DestinationCountryName = destCountryName ?? destCountry
                    };
                }

                flowMap[key].PacketCount++;
                flowMap[key].ByteCount += packet.Length;
            }

            DebugLogger.Log($"[UnifiedGeoIPService] AnalyzeTrafficFlowsAsync: Generated {flowMap.Count} unique flows");

            // ✅ TIMING FIX: Stop timing when work completes
            if (progressStage != null)
            {
                try
                {
                    dynamic stage = progressStage;
                    stage.StopTiming();
                    DebugLogger.Log($"[UnifiedGeoIPService] ⏹️  Stopped timing for stage: {stage.Name}");
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] ⚠️  Failed to stop stage timing: {ex.Message}");
                }
            }

            return await Task.FromResult(flowMap.Values.OrderByDescending(f => f.ByteCount).ToList());
        }

        public async Task<List<CountryRiskProfile>> GetHighRiskCountriesAsync()
        {
            var profiles = new List<CountryRiskProfile>();

            var riskData = new Dictionary<string, (string name, string reason, List<string> threats)>
            {
                ["CN"] = ("China", "Known source of cyber attacks and state-sponsored hacking",
                    new List<string> { "APT groups", "Data theft", "Espionage" }),
                ["RU"] = ("Russia", "Major source of ransomware and cybercrime operations",
                    new List<string> { "Ransomware", "Financial fraud", "State-sponsored attacks" }),
                ["KP"] = ("North Korea", "State-sponsored cyber warfare and cryptocurrency theft",
                    new List<string> { "Cryptocurrency theft", "Destructive malware", "Espionage" }),
                ["IR"] = ("Iran", "State-sponsored attacks on critical infrastructure",
                    new List<string> { "Infrastructure attacks", "Data wiping", "Espionage" }),
                ["NG"] = ("Nigeria", "High volume of financial fraud and scams",
                    new List<string> { "Financial fraud", "Business email compromise", "Romance scams" })
            };

            foreach (var (code, (name, reason, threats)) in riskData)
            {
                profiles.Add(new CountryRiskProfile
                {
                    CountryCode = code,
                    CountryName = name,
                    Risk = code is "CN" or "RU" or "KP" ? RiskLevel.Critical : RiskLevel.High,
                    Reason = reason,
                    KnownThreats = threats,
                    LastAssessment = DateTime.UtcNow
                });
            }

            return await Task.FromResult(profiles);
        }

        public bool IsPublicIP(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            if (!IPAddress.TryParse(ipAddress, out var ip))
                return false;

            // Check for IPv6
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();
                // Link-local (fe80::/10)
                if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                    return false;
                // Unique local (fc00::/7)
                if ((bytes[0] & 0xfe) == 0xfc)
                    return false;
                // Loopback (::1)
                if (ip.Equals(IPAddress.IPv6Loopback))
                    return false;
                return true;
            }

            // IPv4 checks
            byte[] bytes4 = ip.GetAddressBytes();
            if (bytes4.Length != 4)
                return false;

            // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (bytes4[0] == 10) return false;
            if (bytes4[0] == 172 && (bytes4[1] >= 16 && bytes4[1] <= 31)) return false;
            if (bytes4[0] == 192 && bytes4[1] == 168) return false;

            // Loopback: 127.0.0.0/8
            if (bytes4[0] == 127) return false;

            // Link-local: 169.254.0.0/16
            if (bytes4[0] == 169 && bytes4[1] == 254) return false;

            // Multicast: 224.0.0.0/4
            if (bytes4[0] >= 224 && bytes4[0] <= 239) return false;

            return true;
        }

        /// <summary>
        /// Classifies non-public IPs with comprehensive IPv6 type detection:
        /// - IPv4 Private/Internal
        /// - IPv6 Link-Local (fe80::/10)
        /// - IPv6 Loopback (::1)
        /// - IPv6 Multicast (ff00::/8)
        /// - IPv6 Unique Local (fc00::/7, fd00::/8)
        /// - IPv6 Site-Local (fec0::/10 - deprecated but still used)
        /// - IPv6 Global Unicast (public, routable)
        /// Returns null for invalid IPs.
        /// </summary>
        private string? ClassifyNonPublicIP(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            if (!IPAddress.TryParse(ipAddress, out var ip))
                return null;

            // IPv6 Classification (comprehensive)
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();

                // 1. Loopback (::1)
                if (ip.Equals(IPAddress.IPv6Loopback))
                {
                    return "IP6_LOOP";
                }

                // 2. Link-Local (fe80::/10)
                if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                {
                    return "IP6_LINK";
                }

                // 3. Multicast (ff00::/8)
                if (bytes[0] == 0xff)
                {
                    return "IP6_MCAST";
                }

                // 4. Unique Local Address - ULA (fc00::/7, primarily fd00::/8 in practice)
                if ((bytes[0] & 0xfe) == 0xfc)
                {
                    return "IP6_ULA";
                }

                // 5. Site-Local (fec0::/10 - deprecated per RFC 3879, but may still exist)
                if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0)
                {
                    return "IP6_SITE";
                }

                // 6. IPv4-mapped IPv6 (::ffff:0:0/96) - treat as IPv4
                if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
                    bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
                    bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0xff && bytes[11] == 0xff)
                {
                    // Extract IPv4 part and reclassify
                    var ipv4Address = new IPAddress(new byte[] { bytes[12], bytes[13], bytes[14], bytes[15] });
                    return ClassifyIPv4(ipv4Address);
                }

                // 7. Public IPv6 Global Unicast (should have been looked up via GeoIP)
                // If we're here, it wasn't in the GeoIP database
                // 2000::/3 is the global unicast prefix
                if ((bytes[0] & 0xe0) == 0x20)
                {
                    return "IP6_GLOBAL";
                }

                // 8. Anycast - Cannot detect from address alone (same format as unicast)
                // Anycast uses same address space as unicast, distinction is in routing
                // If we can't determine type, default to generic IPv6

                // 9. Other IPv6 (documentation, 6to4, Teredo, etc.)
                return "IP6";
            }

            // IPv4 Classification
            return ClassifyIPv4(ip);
        }

        /// <summary>
        /// Classifies IPv4 addresses as Internal or returns public indicator
        /// </summary>
        private string ClassifyIPv4(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length != 4)
                return "Internal";

            // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (bytes[0] == 10)
                return "Internal";

            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return "Internal";

            if (bytes[0] == 192 && bytes[1] == 168)
                return "Internal";

            // Loopback: 127.0.0.0/8
            if (bytes[0] == 127)
                return "Internal";

            // Link-local: 169.254.0.0/16
            if (bytes[0] == 169 && bytes[1] == 254)
                return "Internal";

            // Multicast: 224.0.0.0/4
            if (bytes[0] >= 224 && bytes[0] <= 239)
                return "Internal";

            // Broadcast: 255.255.255.255
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
                return "Internal";

            // If it's not public and not in the above ranges, still classify as Internal
            return "Internal";
        }

        /// <summary>
        /// Gets friendly display name for country/pseudo-country codes
        /// </summary>
        private string GetFriendlyNameForCode(string? code)
        {
            if (string.IsNullOrWhiteSpace(code))
                return "Unknown";

            return code switch
            {
                // IPv4 Private/Internal
                "Internal" or "PRIV" or "PRV" or "INT" => "Internal Network",

                // IPv6 Specific Types
                "IP6" => "IPv6 Traffic",
                "IP6_LINK" => "IPv6 Link-Local",
                "IP6_LOOP" => "IPv6 Loopback",
                "IP6_MCAST" => "IPv6 Multicast",
                "IP6_GLOBAL" => "IPv6 Global",
                "IP6_ULA" => "IPv6 Unique Local",
                "IP6_SITE" => "IPv6 Site-Local",
                "IP6_ANY" => "IPv6 Anycast",

                // Default: return the code as-is (regular country codes)
                _ => code
            };
        }

        public bool IsHighRiskCountry(string countryCode)
        {
            return _highRiskCountries.Contains(countryCode?.ToUpperInvariant() ?? "");
        }

        public async Task<bool> UpdateDatabaseAsync()
        {
            // Placeholder - database updates would be provider-specific
            return await Task.FromResult(false);
        }

        private void EnsureCountryStats(Dictionary<string, CountryTrafficStatistics> stats, string countryCode)
        {
            if (!stats.ContainsKey(countryCode))
            {
                stats[countryCode] = new CountryTrafficStatistics
                {
                    CountryCode = countryCode,
                    CountryName = countryCode, // Will be enriched later
                    UniqueIPs = new HashSet<string>()
                };
            }
        }

        /// <summary>
        /// Async disposal - gracefully disposes all GeoIP providers.
        /// Preferred disposal method.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;

            foreach (var provider in _providers)
            {
                try
                {
                    await provider.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] Error disposing provider {provider.ProviderName}: {ex.Message}");
                }
            }

            _cache.Clear();
            _providers.Clear();
            DebugLogger.Log("[UnifiedGeoIPService] Disposed asynchronously");

            _disposed = true;
        }

        /// <summary>
        /// Synchronous disposal - aggressive cleanup without waiting.
        /// Use DisposeAsync() when possible.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Aggressive cleanup - don't wait for async disposal
                foreach (var provider in _providers)
                {
                    try
                    {
                        if (provider is IDisposable syncDisposable)
                            syncDisposable.Dispose();
                        // Skip async disposal in sync Dispose to avoid blocking
                    }
                    catch (Exception ex)
                    {
                        DebugLogger.Log($"[UnifiedGeoIPService] Error disposing provider {provider.ProviderName}: {ex.Message}");
                    }
                }

                _cache.Clear();
                _providers.Clear();
                DebugLogger.Log("[UnifiedGeoIPService] Disposed synchronously (aggressive cleanup)");
            }

            _disposed = true;
        }

        /// <summary>
        /// Gets cache statistics
        /// </summary>
        public CacheStatistics GetCacheStatistics()
        {
            return new CacheStatistics
            {
                TotalEntries = _cache.Count,
                MaxSize = _configuration.MaxCacheSize,
                Expiration = _configuration.CacheExpiration,
                TotalHits = _cache.Values.Sum(c => c.HitCount)
            };
        }

        /// <summary>
        /// Clears the cache
        /// </summary>
        public void ClearCache()
        {
            _cache.Clear();
            _logger?.LogInformation("Cache cleared");
        }

        /// <summary>
        /// Cache entry wrapper
        /// </summary>
        private class CachedGeoLocation
        {
            public GeoLocation Location { get; set; } = null!;
            public DateTime CachedAt { get; set; }
            public DateTime ExpiresAt { get; set; }
            public int HitCount { get; set; }
        }

        /// <summary>
        /// Temporary thread-safe wrapper for parallel aggregation with fields for Interlocked operations
        /// </summary>
        private class TempCountryStats
        {
            public string CountryCode = string.Empty;
            public long TotalPackets;
            public long OutgoingBytes;
            public long IncomingBytes;
            public long OutgoingPackets;
            public long IncomingPackets;
            public readonly ConcurrentBag<string> OutgoingIPs = new();
            public readonly ConcurrentBag<string> IncomingIPs = new();
            public readonly ConcurrentBag<string> UniqueIPs = new();
        }
    }

    /// <summary>
    /// Cache statistics
    /// </summary>
    public class CacheStatistics
    {
        public int TotalEntries { get; set; }
        public int MaxSize { get; set; }
        public TimeSpan Expiration { get; set; }
        public long TotalHits { get; set; }
        public double HitRate => TotalEntries > 0 ? (double)TotalHits / TotalEntries : 0;
    }
}
