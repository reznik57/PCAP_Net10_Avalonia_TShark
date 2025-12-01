# GeoIP Country Specialist Agent

## When to Use This Agent
Use this agent when working on:
- GeoIP lookup and enrichment
- Country traffic visualization
- Multi-provider GeoIP architecture
- MaxMind database integration
- Country statistics and aggregation
- Map visualization
- Geographic traffic analysis

## Domain Knowledge

### Architecture Overview
```
IP Address
    ↓
UnifiedGeoIPService
    ↓
┌───┴───┬──────────┬──────────┐
↓       ↓          ↓          ↓
Mmdb   API      SQLite     Cache
Provider Provider Provider   Layer
    ↓
GeoLocation Result
    ↓
CountryTrafficViewModel
    ↓
┌───┴───┬──────────┬──────────┬──────────┐
↓       ↓          ↓          ↓          ↓
Data   Filter   Statistics  Table    Visualization
VM      VM         VM         VM         VM
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.Core/Services/GeoIP/UnifiedGeoIPService.cs` | Multi-provider service | 1,034 |
| `src/PCAPAnalyzer.Core/Data/CountryGeographicData.cs` | Country metadata | ~200 |
| `src/PCAPAnalyzer.UI/ViewModels/CountryTrafficViewModel.cs` | Main country tab | ~800 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryDataViewModel.cs` | Country data handling | ~200 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryFilterViewModel.cs` | Country filtering | ~150 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryStatisticsViewModel.cs` | Country stats | ~200 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryTableViewModel.cs` | Country table | ~250 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryVisualizationViewModel.cs` | Map visualization | ~300 |
| `src/PCAPAnalyzer.UI/ViewModels/Components/CountryUIStateViewModel.cs` | UI state | ~100 |
| `src/PCAPAnalyzer.UI/ViewModels/CountryDetailsViewModel.cs` | Detail drill-down | ~200 |
| `src/PCAPAnalyzer.UI/Helpers/CountryNameHelper.cs` | ISO code mapping | ~100 |
| `GeoLite2-Country.mmdb` | MaxMind database | Binary |

### GeoIP Providers

#### 1. MmdbGeoIPProvider (Primary)
```csharp
public class MmdbGeoIPProvider : IGeoIPProvider
{
    private readonly DatabaseReader _reader;

    public string ProviderName => "MaxMind GeoLite2";
    public int Priority => 1;  // Highest priority

    public async Task<GeoLocation?> LookupAsync(string ipAddress, CancellationToken ct)
    {
        try
        {
            if (_reader.TryCountry(IPAddress.Parse(ipAddress), out var response))
            {
                return new GeoLocation
                {
                    CountryCode = response.Country.IsoCode,
                    CountryName = response.Country.Name,
                    Continent = response.Continent.Name
                };
            }
        }
        catch (AddressNotFoundException) { }

        return null;
    }
}
```

#### 2. ApiGeoIPProvider (Fallback)
```csharp
public class ApiGeoIPProvider : IGeoIPProvider
{
    public string ProviderName => "API Fallback";
    public int Priority => 2;

    public async Task<GeoLocation?> LookupAsync(string ipAddress, CancellationToken ct)
    {
        // Rate-limited API calls for IPs not in MMDB
        var response = await _httpClient.GetAsync($"https://api.example.com/geoip/{ipAddress}", ct);
        // Parse response...
    }
}
```

#### 3. SqliteGeoIPProvider (Alternative)
```csharp
public class SqliteGeoIPProvider : IGeoIPProvider
{
    public string ProviderName => "SQLite Database";
    public int Priority => 3;

    // Uses local SQLite database with IP ranges
}
```

### UnifiedGeoIPService Pattern
```csharp
public class UnifiedGeoIPService : IGeoIPService
{
    private readonly IReadOnlyList<IGeoIPProvider> _providers;
    private readonly IMemoryCache _cache;

    public async Task<GeoLocation?> LookupAsync(string ipAddress, CancellationToken ct)
    {
        // Check cache first
        var cacheKey = $"geoip:{ipAddress}";
        if (_cache.TryGetValue(cacheKey, out GeoLocation cached))
            return cached;

        // Try providers in priority order
        foreach (var provider in _providers.OrderBy(p => p.Priority))
        {
            try
            {
                var result = await provider.LookupAsync(ipAddress, ct);
                if (result != null)
                {
                    _cache.Set(cacheKey, result, TimeSpan.FromHours(24));
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Provider {Provider} failed for {IP}",
                    provider.ProviderName, ipAddress);
            }
        }

        return null;
    }

    // Batch enrichment for efficiency
    public async Task EnrichPacketsAsync(
        IList<PacketInfo> packets,
        IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var uniqueIps = packets
            .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
            .Where(ip => !IsPrivateIp(ip))
            .Distinct()
            .ToList();

        var lookupTasks = uniqueIps
            .Select(ip => LookupAsync(ip, ct))
            .ToList();

        var results = await Task.WhenAll(lookupTasks);

        // Map results back to packets
        var ipToLocation = uniqueIps
            .Zip(results)
            .Where(pair => pair.Second != null)
            .ToDictionary(pair => pair.First, pair => pair.Second);

        foreach (var packet in packets)
        {
            if (ipToLocation.TryGetValue(packet.SourceIP, out var srcLoc))
                packet.SourceCountry = srcLoc.CountryCode;
            if (ipToLocation.TryGetValue(packet.DestinationIP, out var dstLoc))
                packet.DestinationCountry = dstLoc.CountryCode;
        }
    }
}
```

### GeoLocation Model
```csharp
public class GeoLocation
{
    public string CountryCode { get; set; }   // ISO 3166-1 alpha-2 (e.g., "US")
    public string CountryName { get; set; }   // Full name (e.g., "United States")
    public string Continent { get; set; }     // e.g., "North America"
    public double? Latitude { get; set; }     // Optional
    public double? Longitude { get; set; }    // Optional
    public string City { get; set; }          // Optional, if available
    public string Region { get; set; }        // Optional, state/province
}
```

### Country Statistics Model
```csharp
public class CountryStatistics
{
    public string CountryCode { get; set; }
    public string CountryName { get; set; }

    // Traffic metrics
    public long InboundBytes { get; set; }
    public long OutboundBytes { get; set; }
    public long TotalBytes => InboundBytes + OutboundBytes;

    public int InboundPackets { get; set; }
    public int OutboundPackets { get; set; }
    public int TotalPackets => InboundPackets + OutboundPackets;

    // Connection metrics
    public int UniqueSourceIPs { get; set; }
    public int UniqueDestinationIPs { get; set; }
    public HashSet<int> PortsUsed { get; set; }

    // Protocol breakdown
    public Dictionary<string, int> ProtocolDistribution { get; set; }

    // Time range
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}
```

### Private IP Detection
```csharp
public static class IpHelper
{
    private static readonly (byte[], byte[])[] PrivateRanges = new[]
    {
        (new byte[] { 10, 0, 0, 0 }, new byte[] { 255, 0, 0, 0 }),           // 10.0.0.0/8
        (new byte[] { 172, 16, 0, 0 }, new byte[] { 255, 240, 0, 0 }),       // 172.16.0.0/12
        (new byte[] { 192, 168, 0, 0 }, new byte[] { 255, 255, 0, 0 }),      // 192.168.0.0/16
        (new byte[] { 127, 0, 0, 0 }, new byte[] { 255, 0, 0, 0 }),          // 127.0.0.0/8
        (new byte[] { 169, 254, 0, 0 }, new byte[] { 255, 255, 0, 0 }),      // 169.254.0.0/16
    };

    public static bool IsPrivateIp(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return true;  // Invalid = treat as private

        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return true;  // IPv6 = different handling

        var bytes = ip.GetAddressBytes();

        foreach (var (network, mask) in PrivateRanges)
        {
            var isMatch = true;
            for (int i = 0; i < 4; i++)
            {
                if ((bytes[i] & mask[i]) != (network[i] & mask[i]))
                {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) return true;
        }

        return false;
    }
}
```

### Country UI Architecture
```
CountryTrafficViewModel (main coordinator)
├── CountryDataViewModel
│   └── Raw country statistics data
├── CountryFilterViewModel
│   └── Country selection, search
├── CountryStatisticsViewModel
│   └── Summary statistics, aggregations
├── CountryTableViewModel
│   └── Sortable country table
├── CountryVisualizationViewModel
│   └── Map/chart rendering
└── CountryUIStateViewModel
    └── View mode, loading state
```

### Country Name Helper
```csharp
public static class CountryNameHelper
{
    private static readonly Dictionary<string, string> IsoToName = new()
    {
        ["US"] = "United States",
        ["GB"] = "United Kingdom",
        ["DE"] = "Germany",
        ["FR"] = "France",
        ["CN"] = "China",
        ["RU"] = "Russia",
        ["JP"] = "Japan",
        // ... 200+ entries
    };

    public static string GetCountryName(string isoCode)
    {
        return IsoToName.TryGetValue(isoCode?.ToUpperInvariant() ?? "", out var name)
            ? name
            : isoCode ?? "Unknown";
    }

    public static string GetFlagEmoji(string isoCode)
    {
        if (string.IsNullOrEmpty(isoCode) || isoCode.Length != 2)
            return "🏳️";

        // Convert ISO code to regional indicator symbols
        var upper = isoCode.ToUpperInvariant();
        return string.Concat(
            char.ConvertFromUtf32(upper[0] - 'A' + 0x1F1E6),
            char.ConvertFromUtf32(upper[1] - 'A' + 0x1F1E6));
    }
}
```

### MaxMind Database Management
```csharp
// Database location
private readonly string _databasePath = Path.Combine(
    AppContext.BaseDirectory,
    "GeoLite2-Country.mmdb");

// Database update check
public bool IsDatabaseOutdated()
{
    if (!File.Exists(_databasePath))
        return true;

    var fileInfo = new FileInfo(_databasePath);
    return fileInfo.LastWriteTime < DateTime.Now.AddMonths(-1);
}

// Database initialization
public void Initialize()
{
    if (!File.Exists(_databasePath))
    {
        throw new FileNotFoundException(
            "GeoLite2-Country.mmdb not found. " +
            "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data");
    }

    _reader = new DatabaseReader(_databasePath);
}
```

### Caching Strategy
```csharp
// Two-level cache: Memory + optional persistent
private readonly MemoryCache _memoryCache;
private readonly SqliteCache? _persistentCache;

public async Task<GeoLocation?> LookupWithCacheAsync(string ip, CancellationToken ct)
{
    // Level 1: Memory (fast, limited size)
    var memKey = $"geo:{ip}";
    if (_memoryCache.TryGetValue(memKey, out GeoLocation memResult))
        return memResult;

    // Level 2: Persistent (slower, unlimited)
    if (_persistentCache != null)
    {
        var persisted = await _persistentCache.GetAsync(ip, ct);
        if (persisted != null)
        {
            _memoryCache.Set(memKey, persisted, TimeSpan.FromHours(1));
            return persisted;
        }
    }

    // Level 3: Provider lookup
    var result = await LookupFromProvidersAsync(ip, ct);
    if (result != null)
    {
        _memoryCache.Set(memKey, result, TimeSpan.FromHours(1));
        _persistentCache?.SetAsync(ip, result, ct);
    }

    return result;
}
```

## Instructions for This Agent

1. **Read UnifiedGeoIPService** before modifying GeoIP logic
2. **Handle private IPs** - never look up 10.x, 192.168.x, etc.
3. **Use batch enrichment** for performance (not per-packet)
4. **Cache aggressively** - GeoIP data doesn't change often
5. **Support offline mode** - MMDB should work without network
6. **Handle missing database** - graceful degradation
7. **Respect rate limits** - API providers have quotas
8. **Update database monthly** - MaxMind releases updates
