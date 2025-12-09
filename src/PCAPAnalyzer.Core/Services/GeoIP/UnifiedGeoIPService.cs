using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PCAPAnalyzer.Core.Configuration.Options;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.GeoIP.Configuration;
using PCAPAnalyzer.Core.Services.GeoIP.Providers;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.GeoIP;

/// <summary>
/// Unified GeoIP service using provider strategy pattern.
/// Supports fallback cascade through multiple providers with configuration support.
/// Thread-safe with in-memory caching and automatic provider initialization.
/// </summary>
public sealed class UnifiedGeoIPService : IGeoIPService
{
    private readonly List<IGeoIPProvider> _providers = [];
    private readonly ConcurrentDictionary<string, CachedGeoLocation> _cache = [];
    private readonly GeoIPConfiguration _configuration;
    private readonly ILogger? _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private bool _isInitialized;
    private bool _disposed;

    // Diagnostic: Track cache statistics for aggregate logging
    private int _cacheMissCount;
    private int _cacheHitCount;
    private DateTime _lastCacheLogTime;

    // High-risk countries - defaults used when IOptions<CountryConfiguration> not injected
    private static readonly HashSet<string> DefaultHighRiskCountries =
    [
        "CN", "RU", "KP", "IR", "SY", "CU", "VE", "BY", "MM", "ZW", "NG"
    ];

    // Actual high-risk countries (from config or defaults)
    private readonly HashSet<string> _highRiskCountries;

    /// <summary>
    /// Creates a new UnifiedGeoIPService with default configuration (MMDB only)
    /// </summary>
    public UnifiedGeoIPService(ILogger? logger = null, TimeProvider? timeProvider = null)
        : this(GeoIPConfiguration.CreateDefault(), null, logger, timeProvider)
    {
    }

    /// <summary>
    /// Creates a new UnifiedGeoIPService with IOptions pattern for country configuration (DI-friendly)
    /// </summary>
    public UnifiedGeoIPService(IOptions<CountryConfiguration>? countryOptions, ILogger? logger = null, TimeProvider? timeProvider = null)
        : this(GeoIPConfiguration.CreateDefault(), countryOptions, logger, timeProvider)
    {
    }

    /// <summary>
    /// Creates a new UnifiedGeoIPService with specific configuration
    /// </summary>
    public UnifiedGeoIPService(GeoIPConfiguration configuration, IOptions<CountryConfiguration>? countryOptions = null, ILogger? logger = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        _configuration = configuration;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCacheLogTime = _timeProvider.GetUtcNow().UtcDateTime;

        // Use configured high-risk countries or defaults
        var configuredCountries = countryOptions?.Value?.HighRiskCountries;
        _highRiskCountries = configuredCountries is { Count: > 0 }
            ? new HashSet<string>(configuredCountries, StringComparer.OrdinalIgnoreCase)
            : DefaultHighRiskCountries;

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
        _timeProvider = TimeProvider.System;
        _lastCacheLogTime = _timeProvider.GetUtcNow().UtcDateTime;
        _highRiskCountries = DefaultHighRiskCountries;

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

                if (provider is not null)
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
        if (provider is null) return;
        _providers.Add(provider);
        DebugLogger.Log($"[UnifiedGeoIPService] Registered provider: {provider.ProviderName}");
    }

    public async Task InitializeAsync()
    {
        // Fast path: already initialized (no lock needed)
        if (_isInitialized) return;

        // Acquire lock to prevent race condition with concurrent callers
        await _initLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Double-check after acquiring lock
            if (_isInitialized)
            {
                DebugLogger.Log("[UnifiedGeoIPService] Already initialized (after lock)");
                return;
            }

            DebugLogger.Log($"[UnifiedGeoIPService] Initializing {_providers.Count} provider(s)");

            foreach (var provider in _providers)
            {
                try
                {
                    var success = await provider.InitializeAsync().ConfigureAwait(false);
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
        finally
        {
            _initLock.Release();
        }
    }

    public async Task<GeoLocation?> GetLocationAsync(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return null;

        // Wait for initialization if not yet complete (max 5 seconds)
        if (!_isInitialized)
        {
            var waitStart = _timeProvider.GetUtcNow();
            while (!_isInitialized && (_timeProvider.GetUtcNow() - waitStart).TotalSeconds < 5)
            {
                await Task.Delay(50);
            }

            if (!_isInitialized)
            {
                DebugLogger.Log("[UnifiedGeoIPService] Initialization incomplete after 5s wait");
            }
        }

        // Check cache first if enabled
        if (_configuration.EnableCache && _cache.TryGetValue(ipAddress, out var cached))
        {
            if (_timeProvider.GetUtcNow().UtcDateTime < cached.ExpiresAt)
            {
                cached.HitCount++;
                Interlocked.Increment(ref _cacheHitCount);

                // Aggregate logging every 10 seconds
                var now = _timeProvider.GetUtcNow().UtcDateTime;
                if ((now - _lastCacheLogTime).TotalSeconds > 10)
                {
                    var totalLookups = _cacheHitCount + _cacheMissCount;
                    var hitRate = totalLookups > 0 ? (_cacheHitCount * 100.0 / totalLookups) : 0;
                    DebugLogger.Log($"[GeoIP Cache] Stats: {_cacheHitCount:N0} hits, {_cacheMissCount:N0} misses ({hitRate:F1}% hit rate), {_cache.Count} cached IPs");
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
            DebugLogger.Log($"[GeoIP Cache] EXPIRED for {ipAddress}");
        }
        else if (_configuration.EnableCache)
        {
            Interlocked.Increment(ref _cacheMissCount);
        }

        // Try each provider in order until one succeeds
        foreach (var provider in _providers.Where(p => p.IsReady))
        {
            try
            {
                var result = await provider.LookupAsync(ipAddress);
                if (result is not null)
                {
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
        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;
        var cachedEntry = new CachedGeoLocation
        {
            Location = location,
            CachedAt = utcNow,
            ExpiresAt = utcNow.Add(_configuration.CacheExpiration),
            HitCount = 0
        };

        _cache[ipAddress] = cachedEntry;

        // Throttled logging every 1000 entries
        if (_cache.Count % 1000 == 0)
        {
            DebugLogger.Log($"[GeoIP Cache] Cached {_cache.Count} IPs (max: {_configuration.MaxCacheSize})");
        }

        // Enforce max cache size
        if (_cache.Count > _configuration.MaxCacheSize)
        {
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

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Parallel processing logic requires branching for thread-local aggregation")]
    public async Task<Dictionary<string, CountryTrafficStatistics>> AnalyzeCountryTrafficAsync(IEnumerable<PacketInfo> packets, object? progressStage = null)
    {
        DebugLogger.Log("[UnifiedGeoIPService] AnalyzeCountryTrafficAsync CALLED");

        StartProgressTiming(progressStage);

        var countryStats = new Dictionary<string, CountryTrafficStatistics>();
        var packetList = packets.ToList();

        DebugLogger.Log($"[UnifiedGeoIPService] Analyzing traffic for {packetList.Count} packets");

        // Collect unique public IPs
        var uniqueIPs = new HashSet<string>();
        var publicIPs = 0;
        var privateIPs = 0;

        foreach (var packet in packetList)
        {
            if (!string.IsNullOrEmpty(packet.SourceIP))
            {
                if (IPClassifier.IsPublicIP(packet.SourceIP))
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
                if (IPClassifier.IsPublicIP(packet.DestinationIP))
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

        DebugLogger.Log($"[UnifiedGeoIPService] Public: {publicIPs}, Private: {privateIPs}, Unique public IPs: {uniqueIPs.Count}");

        // Reset miss counter for this analysis
        _cacheMissCount = 0;

        // Lookup all unique IPs in parallel
        DebugLogger.Log($"[UnifiedGeoIPService] Starting parallel IP lookups for {uniqueIPs.Count} unique IPs...");
        var lookupStopwatch = Stopwatch.StartNew();
        var ipToCountry = new ConcurrentDictionary<string, string>();
        var lookupCount = 0;
        var ipList = uniqueIPs.ToList();

        // Process in parallel batches (50 concurrent lookups)
        using var semaphore = new SemaphoreSlim(50);
        var lookupTasks = ipList.Select(async ip =>
        {
            await semaphore.WaitAsync();
            try
            {
                var location = await GetLocationAsync(ip);
                if (location is not null)
                {
                    ipToCountry[ip] = ISO3166Data.ValidateCountryCode(location.CountryCode);
                }

                var currentCount = Interlocked.Increment(ref lookupCount);
                if (currentCount % 100 == 0)
                {
                    var progressPercent = currentCount * 100.0 / uniqueIPs.Count;
                    if ((progressPercent >= 24.5 && progressPercent < 26) ||
                        (progressPercent >= 49.5 && progressPercent < 51) ||
                        (progressPercent >= 74.5 && progressPercent < 76))
                    {
                        var elapsed = lookupStopwatch.Elapsed.TotalSeconds;
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
        lookupStopwatch.Stop();
        DebugLogger.Log($"[UnifiedGeoIPService] IP lookups complete: {ipToCountry.Count}/{uniqueIPs.Count} resolved in {lookupStopwatch.Elapsed.TotalSeconds:F2}s");

        // Aggregate packets by country using parallel processing
        var aggregationStopwatch = Stopwatch.StartNew();
        var tempStats = new ConcurrentDictionary<string, TempCountryStats>();

        Parallel.ForEach(packetList, packet =>
        {
            ProcessPacketForCountryStats(packet, ipToCountry, tempStats);
        });

        // Convert temporary stats to final model
        foreach (var kvp in tempStats)
        {
            var temp = kvp.Value;
            countryStats[kvp.Key] = new CountryTrafficStatistics
            {
                CountryCode = temp.CountryCode,
                TotalPackets = temp.TotalPackets,
                OutgoingBytes = temp.OutgoingBytes,
                IncomingBytes = temp.IncomingBytes,
                OutgoingPackets = temp.OutgoingPackets,
                IncomingPackets = temp.IncomingPackets,
                OutgoingIPs = temp.GetOutgoingIPs(),
                IncomingIPs = temp.GetIncomingIPs(),
                UniqueIPs = temp.GetUniqueIPs()
            };
        }

        aggregationStopwatch.Stop();
        DebugLogger.Log($"[UnifiedGeoIPService] Packet aggregation complete in {aggregationStopwatch.Elapsed.TotalSeconds:F2}s");

        // Calculate totals and percentages
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
        StopProgressTiming(progressStage);

        return countryStats;
    }

    private void ProcessPacketForCountryStats(
        PacketInfo packet,
        ConcurrentDictionary<string, string> ipToCountry,
        ConcurrentDictionary<string, TempCountryStats> tempStats)
    {
        // Classify source IP
        string? sourceCountry = null;
        if (!string.IsNullOrEmpty(packet.SourceIP))
        {
            if (ipToCountry.TryGetValue(packet.SourceIP, out var sc))
            {
                sourceCountry = sc;
            }
            else if (!IPClassifier.IsPublicIP(packet.SourceIP))
            {
                sourceCountry = IPClassifier.ClassifyNonPublicIP(packet.SourceIP);
            }
        }

        // Classify destination IP
        string? destCountry = null;
        if (!string.IsNullOrEmpty(packet.DestinationIP))
        {
            if (ipToCountry.TryGetValue(packet.DestinationIP, out var dc))
            {
                destCountry = dc;
            }
            else if (!IPClassifier.IsPublicIP(packet.DestinationIP))
            {
                destCountry = IPClassifier.ClassifyNonPublicIP(packet.DestinationIP);
            }
        }

        if (sourceCountry is not null)
        {
            var stats = tempStats.GetOrAdd(sourceCountry, _ => new TempCountryStats { CountryCode = sourceCountry });
            Interlocked.Increment(ref stats.TotalPackets);
            Interlocked.Add(ref stats.OutgoingBytes, packet.Length);
            Interlocked.Increment(ref stats.OutgoingPackets);
            stats.AddOutgoingIP(packet.SourceIP);
            stats.AddUniqueIP(packet.SourceIP);
        }

        if (destCountry is not null)
        {
            var stats = tempStats.GetOrAdd(destCountry, _ => new TempCountryStats { CountryCode = destCountry });
            Interlocked.Increment(ref stats.TotalPackets);
            Interlocked.Add(ref stats.IncomingBytes, packet.Length);
            Interlocked.Increment(ref stats.IncomingPackets);
            stats.AddIncomingIP(packet.DestinationIP);
            stats.AddUniqueIP(packet.DestinationIP);
        }
    }

    public async Task<List<TrafficFlowDirection>> AnalyzeTrafficFlowsAsync(IEnumerable<PacketInfo> packets, object? progressStage = null)
    {
        StartProgressTiming(progressStage);

        var flows = new List<TrafficFlowDirection>();
        var packetList = packets.ToList();

        DebugLogger.Log($"[UnifiedGeoIPService] AnalyzeTrafficFlowsAsync: Processing {packetList.Count} packets");

        var flowMap = new Dictionary<(string source, string dest), TrafficFlowDirection>();

        foreach (var packet in packetList)
        {
            if (string.IsNullOrEmpty(packet.SourceIP) || string.IsNullOrEmpty(packet.DestinationIP))
                continue;

            // Classify source IP
            string? sourceCountry = null;
            string? sourceCountryName = null;

            if (IPClassifier.IsPublicIP(packet.SourceIP))
            {
                var sourceLoc = await GetLocationAsync(packet.SourceIP);
                if (sourceLoc is not null)
                {
                    sourceCountry = sourceLoc.CountryCode;
                    sourceCountryName = sourceLoc.CountryName;
                }
            }
            else
            {
                sourceCountry = IPClassifier.ClassifyNonPublicIP(packet.SourceIP);
                sourceCountryName = ISO3166Data.GetFriendlyName(sourceCountry);
            }

            // Classify destination IP
            string? destCountry = null;
            string? destCountryName = null;

            if (IPClassifier.IsPublicIP(packet.DestinationIP))
            {
                var destLoc = await GetLocationAsync(packet.DestinationIP);
                if (destLoc is not null)
                {
                    destCountry = destLoc.CountryCode;
                    destCountryName = destLoc.CountryName;
                }
            }
            else
            {
                destCountry = IPClassifier.ClassifyNonPublicIP(packet.DestinationIP);
                destCountryName = ISO3166Data.GetFriendlyName(destCountry);
            }

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
        StopProgressTiming(progressStage);

        return await Task.FromResult(flowMap.Values.OrderByDescending(f => f.ByteCount).ToList());
    }

    public async Task<List<CountryRiskProfile>> GetHighRiskCountriesAsync()
    {
        var profiles = new List<CountryRiskProfile>
        {
            CreateRiskProfile("CN", "China", RiskLevel.Critical, "Known source of cyber attacks and state-sponsored hacking",
                ["APT groups", "Data theft", "Espionage"]),
            CreateRiskProfile("RU", "Russia", RiskLevel.Critical, "Major source of ransomware and cybercrime operations",
                ["Ransomware", "Financial fraud", "State-sponsored attacks"]),
            CreateRiskProfile("KP", "North Korea", RiskLevel.Critical, "State-sponsored cyber warfare and cryptocurrency theft",
                ["Cryptocurrency theft", "Destructive malware", "Espionage"]),
            CreateRiskProfile("IR", "Iran", RiskLevel.High, "State-sponsored attacks on critical infrastructure",
                ["Infrastructure attacks", "Data wiping", "Espionage"]),
            CreateRiskProfile("NG", "Nigeria", RiskLevel.High, "High volume of financial fraud and scams",
                ["Financial fraud", "Business email compromise", "Romance scams"])
        };

        return await Task.FromResult(profiles);
    }

    private CountryRiskProfile CreateRiskProfile(string code, string name, RiskLevel risk, string reason, List<string> threats)
    {
        return new CountryRiskProfile
        {
            CountryCode = code,
            CountryName = name,
            Risk = risk,
            Reason = reason,
            KnownThreats = threats,
            LastAssessment = _timeProvider.GetUtcNow().UtcDateTime
        };
    }

    public bool IsPublicIP(string ipAddress) => IPClassifier.IsPublicIP(ipAddress);

    public bool IsHighRiskCountry(string countryCode)
    {
        return _highRiskCountries.Contains(countryCode?.ToUpperInvariant() ?? "");
    }

    public async Task<bool> UpdateDatabaseAsync()
    {
        // Placeholder - database updates would be provider-specific
        return await Task.FromResult(false);
    }

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

    public void ClearCache()
    {
        _cache.Clear();
        _logger?.LogInformation("Cache cleared");
    }

    private static void StartProgressTiming(object? progressStage)
    {
        if (progressStage is null) return;
        try
        {
            dynamic stage = progressStage;
            stage.StartTiming();
            DebugLogger.Log($"[UnifiedGeoIPService] Started timing for stage: {stage.Name}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[UnifiedGeoIPService] Failed to start stage timing: {ex.Message}");
        }
    }

    private static void StopProgressTiming(object? progressStage)
    {
        if (progressStage is null) return;
        try
        {
            dynamic stage = progressStage;
            stage.StopTiming();
            DebugLogger.Log($"[UnifiedGeoIPService] Stopped timing for stage: {stage.Name}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[UnifiedGeoIPService] Failed to stop stage timing: {ex.Message}");
        }
    }

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
        _initLock.Dispose();
        DebugLogger.Log("[UnifiedGeoIPService] Disposed asynchronously");

        _disposed = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            foreach (var provider in _providers)
            {
                try
                {
                    if (provider is IDisposable syncDisposable)
                        syncDisposable.Dispose();
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[UnifiedGeoIPService] Error disposing provider {provider.ProviderName}: {ex.Message}");
                }
            }

            _cache.Clear();
            _providers.Clear();
            _initLock.Dispose();
            DebugLogger.Log("[UnifiedGeoIPService] Disposed synchronously");
        }

        _disposed = true;
    }

    /// <summary>
    /// Cache entry wrapper
    /// </summary>
    private sealed class CachedGeoLocation
    {
        public GeoLocation Location { get; set; } = null!;
        public DateTime CachedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public int HitCount { get; set; }
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
