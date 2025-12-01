# .NET Service Architect Agent

## When to Use This Agent
Use this agent when working on:
- Backend service design and implementation
- Dependency injection configuration
- Async/await patterns and best practices
- Caching strategies (in-memory, SQLite)
- Decorator patterns (e.g., EnhancedCachedStatisticsService)
- Service interfaces and contracts
- Cross-cutting concerns (logging, validation)

## Domain Knowledge

### Architecture Overview
```
ServiceConfiguration.cs (DI Root)
        ↓
┌───────┴───────┐
↓               ↓
Core Services   UI Services
    ↓               ↓
Interfaces      ViewModels
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.UI/ServiceConfiguration.cs` | Central DI registration | ~300 |
| `src/PCAPAnalyzer.Core/Orchestration/AnalysisOrchestrator.cs` | Main coordinator | 783 |
| `src/PCAPAnalyzer.Core/Services/Statistics/StatisticsService.cs` | Statistics calculation | 586 |
| `src/PCAPAnalyzer.Core/Services/Statistics/EnhancedCachedStatisticsService.cs` | Caching decorator | ~200 |
| `src/PCAPAnalyzer.Core/Services/UnifiedAnomalyDetectionService.cs` | Detector orchestration | 256 |
| `src/PCAPAnalyzer.Core/Services/GeoIP/UnifiedGeoIPService.cs` | Multi-provider GeoIP | 1,034 |
| `src/PCAPAnalyzer.Core/Services/Caching/SessionAnalysisCache.cs` | Result caching | ~200 |

### DI Registration Patterns

#### Service Lifetimes
```csharp
// Singleton - One instance for app lifetime
services.AddSingleton<ISessionAnalysisCache, SessionAnalysisCache>();
services.AddSingleton<IGeoIPService, UnifiedGeoIPService>();

// Scoped - One instance per scope (rarely used in desktop)
services.AddScoped<IAnalysisOrchestrator, AnalysisOrchestrator>();

// Transient - New instance each time
services.AddTransient<ITabFilterService, TabFilterService>();
services.AddTransient<ITSharkService, TSharkService>();
```

#### Decorator Pattern Registration
```csharp
// Base service
services.AddSingleton<StatisticsService>();

// Decorator wrapping base
services.AddSingleton<IStatisticsService>(sp =>
    new EnhancedCachedStatisticsService(
        sp.GetRequiredService<StatisticsService>(),
        sp.GetRequiredService<IMemoryCache>(),
        sp.GetRequiredService<ILogger<EnhancedCachedStatisticsService>>()));
```

#### Options Pattern
```csharp
services.Configure<TSharkOptions>(configuration.GetSection("TShark"));
services.Configure<CacheOptions>(configuration.GetSection("Caching"));

// Usage
public class MyService
{
    public MyService(IOptions<TSharkOptions> options)
    {
        _timeout = options.Value.ProcessTimeout;
    }
}
```

### Async/Await Best Practices (Enforced)

#### ConfigureAwait(false) Policy
```csharp
// CORRECT - Library code should use ConfigureAwait(false)
public async Task<Result> ProcessAsync(CancellationToken ct)
{
    var data = await _service.GetDataAsync(ct).ConfigureAwait(false);
    var result = await _processor.ProcessAsync(data, ct).ConfigureAwait(false);
    return result;
}

// WRONG - Missing ConfigureAwait
public async Task<Result> ProcessAsync(CancellationToken ct)
{
    var data = await _service.GetDataAsync(ct);  // ❌ Captures sync context
    return data;
}
```

#### CancellationToken Propagation
```csharp
// CORRECT - Propagate token to all async calls
public async Task AnalyzeAsync(CancellationToken cancellationToken)
{
    cancellationToken.ThrowIfCancellationRequested();

    await _step1.ExecuteAsync(cancellationToken).ConfigureAwait(false);
    await _step2.ExecuteAsync(cancellationToken).ConfigureAwait(false);
}

// WRONG - Token not propagated
public async Task AnalyzeAsync(CancellationToken cancellationToken)
{
    await _step1.ExecuteAsync(default).ConfigureAwait(false);  // ❌ Lost cancellation
}
```

#### No Sync-Over-Async (Phase 12 Fix)
```csharp
// WRONG - Blocking on async
var result = service.GetDataAsync().Result;  // ❌ Deadlock risk
var result = service.GetDataAsync().GetAwaiter().GetResult();  // ❌ Still blocking

// CORRECT - Async all the way
var result = await service.GetDataAsync().ConfigureAwait(false);
```

### Service Interface Patterns

#### Standard Service Interface
```csharp
public interface IAnalysisService
{
    Task<AnalysisResult> AnalyzeAsync(
        IReadOnlyList<PacketInfo> packets,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken cancellationToken = default);
}
```

#### Provider Pattern (Multiple Implementations)
```csharp
public interface IGeoIPProvider
{
    string ProviderName { get; }
    int Priority { get; }
    Task<GeoLocation?> LookupAsync(string ipAddress, CancellationToken ct);
}

// Implementations
public class MmdbGeoIPProvider : IGeoIPProvider { }
public class ApiGeoIPProvider : IGeoIPProvider { }
public class SqliteGeoIPProvider : IGeoIPProvider { }
```

### Caching Strategies

#### In-Memory Cache (IMemoryCache)
```csharp
public async Task<T> GetOrCreateAsync<T>(string key, Func<Task<T>> factory)
{
    if (_cache.TryGetValue(key, out T cached))
        return cached;

    var value = await factory().ConfigureAwait(false);

    var options = new MemoryCacheEntryOptions()
        .SetSlidingExpiration(TimeSpan.FromMinutes(30))
        .SetAbsoluteExpiration(TimeSpan.FromHours(2));

    _cache.Set(key, value, options);
    return value;
}
```

#### Session Analysis Cache
```csharp
// Stores complete AnalysisResult for instant tab switching
public interface ISessionAnalysisCache
{
    bool TryGet(string filePath, out AnalysisResult? result);
    void Set(string filePath, AnalysisResult result);
    void Invalidate(string filePath);
    void Clear();
}
```

### Environment-Based Configuration
```csharp
// Environment variables control behavior
var useLargeFileMode = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LARGE_FILE_MODE") == "1";
var useLowMemory = Environment.GetEnvironmentVariable("PCAP_ANALYZER_LOW_MEMORY") == "1";
var useDuckDb = Environment.GetEnvironmentVariable("PCAP_ANALYZER_USE_DUCKDB") == "1";
var cacheEnabled = Environment.GetEnvironmentVariable("PCAP_ANALYZER_CACHE_ENABLED") != "0";
```

### Logging Patterns
```csharp
public class MyService
{
    private readonly ILogger<MyService> _logger;

    public async Task ProcessAsync(string input)
    {
        _logger.LogDebug("Starting processing for input length: {Length}", input.Length);

        try
        {
            // Process...
            _logger.LogInformation("Processing completed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Processing failed for input");
            throw;
        }
    }
}
```

### Error Handling Patterns
```csharp
// Result pattern for operations that can fail
public class Result<T>
{
    public bool IsSuccess { get; }
    public T? Value { get; }
    public string? Error { get; }

    public static Result<T> Success(T value) => new(true, value, null);
    public static Result<T> Failure(string error) => new(false, default, error);
}

// Usage
public async Task<Result<Statistics>> CalculateAsync(...)
{
    try
    {
        var stats = await DoCalculation().ConfigureAwait(false);
        return Result<Statistics>.Success(stats);
    }
    catch (Exception ex)
    {
        return Result<Statistics>.Failure(ex.Message);
    }
}
```

### Progress Reporting Pattern
```csharp
public async Task AnalyzeAsync(
    IProgress<AnalysisProgress>? progress,
    CancellationToken cancellationToken)
{
    progress?.Report(new AnalysisProgress
    {
        Phase = "Loading",
        PercentComplete = 0,
        Message = "Starting analysis..."
    });

    // Phase 1
    await LoadPacketsAsync(cancellationToken).ConfigureAwait(false);
    progress?.Report(new AnalysisProgress { Phase = "Loading", PercentComplete = 50 });

    // Phase 2
    await AnalyzeAsync(cancellationToken).ConfigureAwait(false);
    progress?.Report(new AnalysisProgress { Phase = "Complete", PercentComplete = 100 });
}
```

## Instructions for This Agent

1. **Read ServiceConfiguration.cs** before adding new services
2. **Use ConfigureAwait(false)** on ALL async calls in library code
3. **Propagate CancellationToken** to all async methods
4. **Never use .Result or .Wait()** - async all the way
5. **Follow existing patterns** - decorator, provider, options
6. **Add structured logging** - use templates, not interpolation
7. **Consider memory** - large PCAP processing, avoid allocations
8. **Test with DI** - services should be mockable via interfaces
