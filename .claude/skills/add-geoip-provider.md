---
name: pcap:add-geoip-provider
description: Use when adding a new GeoIP data source (database, API, etc.) - ensures proper provider pattern implementation, caching, fallback handling, and integration
---

# Add GeoIP Provider Skill

This skill guides you through adding a new GeoIP provider to the unified GeoIP service.

## Prerequisites

Before starting, determine:
- Data source type (database file, REST API, local cache)
- Data format and fields available
- Rate limits or licensing requirements
- Priority relative to existing providers

## Current Providers

| Provider | Priority | Type | Notes |
|----------|----------|------|-------|
| MmdbGeoIPProvider | 1 | MaxMind MMDB | Primary, offline |
| ApiGeoIPProvider | 2 | REST API | Fallback, rate-limited |
| SqliteGeoIPProvider | 3 | SQLite DB | Alternative storage |

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Interface Implementation
- [ ] Create `{Name}GeoIPProvider` class implementing `IGeoIPProvider`
- [ ] Define `ProviderName` property
- [ ] Define `Priority` property (lower = higher priority)
- [ ] Implement `LookupAsync` method
- [ ] Handle provider-specific initialization

### Phase 2: Error Handling
- [ ] Handle network failures gracefully (for API providers)
- [ ] Handle database corruption (for file providers)
- [ ] Return `null` for unknown IPs (don't throw)
- [ ] Log warnings for recoverable errors
- [ ] Log errors for fatal issues

### Phase 3: Caching Strategy
- [ ] Determine cache duration (typically 24h for GeoIP)
- [ ] Implement provider-level caching if needed
- [ ] Integrate with UnifiedGeoIPService cache

### Phase 4: Integration
- [ ] Register provider in `ServiceConfiguration.cs`
- [ ] Add to provider collection in `UnifiedGeoIPService`
- [ ] Update configuration options if needed

### Phase 5: Testing
- [ ] Create test class for new provider
- [ ] Test successful lookup
- [ ] Test unknown IP handling
- [ ] Test error conditions
- [ ] Test private IP rejection (should skip lookup)

### Phase 6: Validation
- [ ] Run `dotnet build` — zero warnings
- [ ] Run `dotnet test` — all tests pass
- [ ] Test with real IPs from various countries
- [ ] Verify fallback works if this provider fails

## Provider Pattern

### Interface
```csharp
public interface IGeoIPProvider
{
    string ProviderName { get; }
    int Priority { get; }  // Lower = higher priority

    Task<GeoLocation?> LookupAsync(
        string ipAddress,
        CancellationToken cancellationToken = default);

    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);
}
```

### Implementation Template
```csharp
public class MyNewGeoIPProvider : IGeoIPProvider
{
    private readonly ILogger<MyNewGeoIPProvider> _logger;
    private readonly IHttpClientFactory? _httpClientFactory;  // For API providers
    private readonly string? _databasePath;  // For file providers

    public string ProviderName => "My New Provider";
    public int Priority => 4;  // After existing providers

    public MyNewGeoIPProvider(
        ILogger<MyNewGeoIPProvider> logger,
        IOptions<MyProviderOptions>? options = null)
    {
        _logger = logger;
        // Initialize from options...
    }

    public async Task<GeoLocation?> LookupAsync(
        string ipAddress,
        CancellationToken cancellationToken = default)
    {
        // Validate input
        if (string.IsNullOrEmpty(ipAddress))
            return null;

        // Skip private IPs (should be filtered by caller, but defensive)
        if (IpHelper.IsPrivateIp(ipAddress))
            return null;

        try
        {
            // Provider-specific lookup
            var result = await DoLookupAsync(ipAddress, cancellationToken)
                .ConfigureAwait(false);

            if (result != null)
            {
                _logger.LogDebug(
                    "GeoIP lookup for {IP}: {Country} via {Provider}",
                    ipAddress, result.CountryCode, ProviderName);
            }

            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "GeoIP lookup failed for {IP} via {Provider}",
                ipAddress, ProviderName);
            return null;  // Allow fallback to next provider
        }
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        // Check if provider is operational
        // - For file providers: check file exists
        // - For API providers: check connectivity
        return true;
    }

    private async Task<GeoLocation?> DoLookupAsync(
        string ipAddress,
        CancellationToken cancellationToken)
    {
        // Provider-specific implementation
        throw new NotImplementedException();
    }
}
```

## Provider Types

### File-Based Provider (e.g., MMDB, CSV)
```csharp
public class FileBasedGeoIPProvider : IGeoIPProvider
{
    private readonly DatabaseReader? _reader;

    public FileBasedGeoIPProvider(IOptions<FileGeoIPOptions> options)
    {
        var path = options.Value.DatabasePath;
        if (File.Exists(path))
        {
            _reader = new DatabaseReader(path);
        }
    }

    public async Task<GeoLocation?> LookupAsync(string ip, CancellationToken ct)
    {
        if (_reader == null) return null;

        // Synchronous lookup, wrap in Task.Run if needed
        if (_reader.TryCountry(IPAddress.Parse(ip), out var response))
        {
            return new GeoLocation
            {
                CountryCode = response.Country.IsoCode,
                CountryName = response.Country.Name
            };
        }

        return null;
    }
}
```

### API-Based Provider
```csharp
public class ApiGeoIPProvider : IGeoIPProvider
{
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _rateLimiter;

    public ApiGeoIPProvider(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("GeoIP");
        _rateLimiter = new SemaphoreSlim(10);  // Max concurrent requests
    }

    public async Task<GeoLocation?> LookupAsync(string ip, CancellationToken ct)
    {
        await _rateLimiter.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var response = await _httpClient
                .GetFromJsonAsync<GeoIpApiResponse>($"/lookup/{ip}", ct)
                .ConfigureAwait(false);

            return MapToGeoLocation(response);
        }
        finally
        {
            _rateLimiter.Release();
        }
    }
}
```

## Integration in UnifiedGeoIPService

```csharp
public class UnifiedGeoIPService : IGeoIPService
{
    private readonly IReadOnlyList<IGeoIPProvider> _providers;

    public UnifiedGeoIPService(
        MmdbGeoIPProvider mmdbProvider,
        ApiGeoIPProvider apiProvider,
        SqliteGeoIPProvider sqliteProvider,
        MyNewGeoIPProvider myNewProvider)  // Add new provider
    {
        _providers = new IGeoIPProvider[]
        {
            mmdbProvider,
            apiProvider,
            sqliteProvider,
            myNewProvider
        }
        .OrderBy(p => p.Priority)
        .ToList();
    }

    public async Task<GeoLocation?> LookupAsync(string ip, CancellationToken ct)
    {
        foreach (var provider in _providers)
        {
            var result = await provider.LookupAsync(ip, ct).ConfigureAwait(false);
            if (result != null)
                return result;
        }
        return null;
    }
}
```

## Configuration Options

```csharp
// Add to appsettings.json support
public class MyProviderOptions
{
    public string DatabasePath { get; set; }
    public string ApiKey { get; set; }
    public string BaseUrl { get; set; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
}

// Register in ServiceConfiguration.cs
services.Configure<MyProviderOptions>(
    configuration.GetSection("GeoIP:MyProvider"));
services.AddSingleton<MyNewGeoIPProvider>();
```

## Testing Template

```csharp
public class MyNewGeoIPProviderTests
{
    [Fact]
    public async Task LookupAsync_KnownIP_ReturnsLocation()
    {
        // Arrange
        var provider = CreateProvider();

        // Act
        var result = await provider.LookupAsync("8.8.8.8");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("US", result.CountryCode);
    }

    [Fact]
    public async Task LookupAsync_PrivateIP_ReturnsNull()
    {
        var provider = CreateProvider();
        var result = await provider.LookupAsync("192.168.1.1");
        Assert.Null(result);
    }

    [Fact]
    public async Task LookupAsync_InvalidIP_ReturnsNull()
    {
        var provider = CreateProvider();
        var result = await provider.LookupAsync("invalid");
        Assert.Null(result);
    }

    [Fact]
    public async Task LookupAsync_ProviderUnavailable_ReturnsNull()
    {
        var provider = CreateUnavailableProvider();
        var result = await provider.LookupAsync("8.8.8.8");
        Assert.Null(result);  // Graceful fallback
    }
}
```

## Common Mistakes to Avoid

1. **Throwing on unknown IPs** — Return null, allow fallback
2. **Not handling rate limits** — Use SemaphoreSlim for APIs
3. **Blocking on initialization** — Use lazy/async initialization
4. **Missing private IP check** — Don't waste lookups on 10.x, 192.168.x
5. **Wrong priority** — Lower number = tried first

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
