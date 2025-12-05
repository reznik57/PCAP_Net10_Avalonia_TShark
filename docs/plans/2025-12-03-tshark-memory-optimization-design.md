# TShark Memory Optimization Design

**Date:** 2025-12-03
**Goal:** Reduce RAM usage by ~60% through string interning and hot path optimization
**Scope:** TSharkParserOptimized, StringPool infrastructure

---

## Problem Statement

Current implementation allocates new strings for every packet:
- IP addresses: 2M allocations for 1M packets (only ~5000 unique)
- L7Protocol: 1M allocations (only ~50 unique values)
- Info strings: Many duplicates ("TCP [SYN, ACK]" patterns)

**Result:** ~148MB of string memory that could be ~60MB.

---

## Solution: String Interning + Hot Path Optimization

### Component 1: StringPool Class

Thread-safe string pool using hash-based deduplication:

```csharp
// src/PCAPAnalyzer.Core/Utilities/StringPool.cs
public sealed class StringPool
{
    private readonly ConcurrentDictionary<int, string> _pool = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Intern(ReadOnlySpan<char> span)
    {
        if (span.IsEmpty) return string.Empty;

        var hash = string.GetHashCode(span);
        if (_pool.TryGetValue(hash, out var existing) &&
            existing.AsSpan().SequenceEqual(span))
            return existing;

        var newString = span.ToString();
        _pool.TryAdd(hash, newString);
        return newString;
    }

    public void Clear() => _pool.Clear();
    public int Count => _pool.Count;
}
```

### Component 2: Function Reordering by Call Frequency

Reorder TSharkParserOptimized.cs functions for CPU cache locality:

**TIER 1: ULTRA-HOT (millions of calls)**
1. `GetField()` - 18+ calls per packet
2. `FindTabIndices()` - 1 call per packet
3. `ParseLine()` - main entry point
4. `ParsePort()` - 2 calls per packet
5. `ExtractL4Protocol()` - 1 call per packet
6. `GetLastProtocol()` - 1 call per packet

**TIER 2: HOT (TCP packets ~60%)**
7. `ParseTcpFields()` - TCP only
8. `ExtractL7Protocol()` - per packet

**TIER 3: WARM (conditional)**
9. `HasCredentialData()` - early exit check
10. `GetFieldString()` - only when credentials found

**TIER 4: COLD (rare)**
11. `ExtractCredentialFields()` - <1% of packets
12. `ExtractOsFingerprintFields()` - <5% of packets

### Component 3: Static Pools in Parser

```csharp
public static class TSharkParserOptimized
{
    // Static pools - thread-safe, shared across all parsing
    private static readonly StringPool IpPool = new();
    private static readonly StringPool ProtocolPool = new();

    public static void ResetPools()
    {
        IpPool.Clear();
        ProtocolPool.Clear();
    }

    // In ParseLine():
    var srcIp = !ipSrcSpan.IsEmpty ? IpPool.Intern(ipSrcSpan) :
               !ipv6SrcSpan.IsEmpty ? IpPool.Intern(ipv6SrcSpan) : string.Empty;
    var dstIp = !ipDstSpan.IsEmpty ? IpPool.Intern(ipDstSpan) :
               !ipv6DstSpan.IsEmpty ? IpPool.Intern(ipv6DstSpan) : string.Empty;
    var l7Protocol = ProtocolPool.Intern(ExtractL7Protocol(...));
}
```

### Component 4: Lifecycle Management

Reset pools before each new PCAP analysis:

```csharp
// In AnalysisOrchestrator.AnalyzeAsync()
public async Task<AnalysisResult?> AnalyzeAsync(string pcapPath, ...)
{
    TSharkParserOptimized.ResetPools();
    // ... analysis
}
```

---

## Files to Modify

| File | Action | Changes |
|------|--------|---------|
| `Core/Utilities/StringPool.cs` | CREATE | New string interning class |
| `TShark/TSharkParserOptimized.cs` | MODIFY | Add pools, reorder functions, use Intern() |
| `TShark/ParallelTSharkService.cs` | MODIFY | Reset pools before analysis |
| `Core/Orchestration/AnalysisOrchestrator.cs` | MODIFY | Reset pools before analysis |

---

## Expected Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| IP string memory | ~40 MB | ~400 KB | 99% |
| Protocol string memory | ~8 MB | ~5 KB | 99% |
| Info string memory | ~100 MB | ~60 MB | 40% |
| **Total string memory** | ~148 MB | ~60 MB | **60%** |

---

## Risk Assessment

- **Breaking changes:** None - PacketInfo API unchanged
- **Thread safety:** ConcurrentDictionary handles parallel parsing
- **Memory leaks:** Prevented by ResetPools() on new analysis
- **Testing:** Existing unit tests validate correctness

---

## Verification Plan

1. Build succeeds with 0 warnings
2. All 1093 tests pass
3. Memory benchmark: Load 1M packet PCAP, measure working set
4. Performance benchmark: Parse time unchanged or improved
