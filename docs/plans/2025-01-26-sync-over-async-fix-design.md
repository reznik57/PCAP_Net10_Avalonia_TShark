# Sync-over-Async Technical Debt Fix

## Problem Statement

17 instances of sync-over-async anti-patterns causing:
- UI thread blocking (potential freezes)
- Thread pool starvation under load
- Potential deadlocks with SynchronizationContext

## Scope

### Priority 1 - UI Thread Blocking (Critical)
| File | Method | Issue |
|------|--------|-------|
| `ViewModels/ViewModelBase.cs:30` | `SetPropertyThreadSafe` | `.Wait()` blocks UI |
| `ViewModels/ViewModelBase.cs:59` | `RunOnUIThreadSync` | `.Wait()` blocks UI |
| `ViewModels/Base/ViewModelBase.cs:39` | `InvokeOnUIThread` | `.Wait()` blocks UI |

### Priority 2 - Core Services (High)
| File | Line | Issue |
|------|------|-------|
| `StreamAnalyzer.cs` | 413 | `GetLocationAsync().GetAwaiter().GetResult()` |
| `SqliteGeoIPProvider.cs` | 73,77 | `GetAwaiter().GetResult()` in lock |
| `SpecializedTrafficAnomalyService.cs` | 31,37,43,49,56,63 | 6 sync wrappers |
| `EnhancedCachedStatisticsService.cs` | 60 | Sync wrapper over async |

### Out of Scope (Acceptable)
- `Program.cs:66` - Main entry point (required)
- `PacketListViewModel.cs` - SemaphoreSlim.Wait() (correct usage)

## Technical Approach

### ViewModelBase Fix
```csharp
// Async version (preferred)
protected async Task SetPropertyThreadSafeAsync(Action propertyUpdate)
{
    if (Dispatcher.UIThread.CheckAccess())
        propertyUpdate();
    else
        await Dispatcher.UIThread.InvokeAsync(propertyUpdate);
}

// Sync version (fire-and-forget, non-blocking)
protected void SetPropertyThreadSafe(Action propertyUpdate)
{
    if (Dispatcher.UIThread.CheckAccess())
        propertyUpdate();
    else
        Dispatcher.UIThread.Post(propertyUpdate);
}
```

### SqliteGeoIPProvider Fix
Replace `lock` with `SemaphoreSlim` for async-compatible locking:
```csharp
private readonly SemaphoreSlim _initLock = new(1, 1);

public async Task<bool> InitializeAsync()
{
    if (_isReady) return true;

    await _initLock.WaitAsync();
    try
    {
        if (_isReady) return true;
        await InitializeDatabaseSchema();
        _isReady = await CheckDatabaseHasData();
        return true;
    }
    finally { _initLock.Release(); }
}
```

### StreamAnalyzer Fix
Convert sync method to async, propagate through call chain:
```csharp
private async Task<GeoSecurityInfo?> AnalyzeGeoIPAsync(string ip, List<string> warnings, string direction)
{
    // ...
    geoInfo = await _geoIPService.GetLocationAsync(ip);
    // ...
}
```

### SpecializedTrafficAnomalyService Fix
Add async methods, mark sync as obsolete:
```csharp
[Obsolete("Use DetectCryptoMiningAsync instead")]
public IEnumerable<SpecializedAnomaly> DetectCryptoMining(IEnumerable<PacketInfo> packets)

public async Task<IEnumerable<SpecializedAnomaly>> DetectCryptoMiningAsync(IEnumerable<PacketInfo> packets)
```

## Implementation Phases

1. **Phase 1**: ViewModelBase (2 files) - Low risk
2. **Phase 2**: SqliteGeoIPProvider - Medium risk
3. **Phase 3**: StreamAnalyzer + callers - Medium risk
4. **Phase 4**: SpecializedTrafficAnomalyService - Low risk
5. **Phase 5**: EnhancedCachedStatisticsService - Low risk

## Verification

- [ ] Build: 0 errors, 0 warnings
- [ ] Tests: 903 passing
- [ ] No new `GetAwaiter().GetResult()` or `.Wait()` patterns
- [ ] UI responsiveness maintained

## Estimated Effort

- Files affected: 15-20
- Lines changed: ~200
- Risk: Medium (async propagation can have side effects)
