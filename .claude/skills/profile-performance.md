---
name: pcap:profile-performance
description: Use when analysis is slow or memory usage is high - systematic approach to profiling, identifying bottlenecks, and optimizing PCAP processing
---

# Profile Performance Skill

This skill guides you through systematic performance profiling and optimization of PCAP analysis.

## When to Use

- Analysis takes longer than expected
- Memory usage exceeds acceptable limits
- UI becomes unresponsive during analysis
- Processing rate drops below targets (2.5M packets/70s)

## Performance Targets

| Metric | Target | Action Threshold |
|--------|--------|------------------|
| 2.5M packets | <70 seconds | Investigate if >90s |
| 40M packets | <90 seconds | Investigate if >120s |
| Memory peak | <20GB | Investigate if >25GB |
| UI responsiveness | No freezes | Investigate any freeze >500ms |

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Measure Baseline
- [ ] Record current performance (time, memory, CPU)
- [ ] Identify the specific operation that's slow
- [ ] Document test conditions (file size, packet count, hardware)
- [ ] Establish target metrics

### Phase 2: Profile
- [ ] Add timing instrumentation to suspect areas
- [ ] Use built-in `PerformanceProfiler`
- [ ] Capture memory allocation patterns
- [ ] Identify GC pressure points
- [ ] Profile with real PCAP files (not synthetic)

### Phase 3: Analyze
- [ ] Identify top 3 time consumers
- [ ] Identify top 3 memory allocators
- [ ] Check for sync-over-async issues
- [ ] Check for unnecessary allocations
- [ ] Check for unbounded collections

### Phase 4: Optimize (One at a Time)
- [ ] Implement single optimization
- [ ] Measure improvement
- [ ] Verify no regression in functionality
- [ ] Document the change and its impact
- [ ] Repeat for next optimization

### Phase 5: Validate
- [ ] Run full test suite
- [ ] Benchmark with reference PCAP files
- [ ] Verify targets are met
- [ ] Document final performance

## Profiling Tools

### Built-in PerformanceProfiler
```csharp
// Add timing to operations
using var profiler = PerformanceProfiler.Start("OperationName");

// ... operation code ...

profiler.AddMetric("PacketCount", packets.Count);
profiler.AddMetric("MemoryMB", GC.GetTotalMemory(false) / 1024 / 1024);
```

### Manual Stopwatch
```csharp
private readonly Stopwatch _sw = Stopwatch.StartNew();

public void MeasureOperation()
{
    _sw.Restart();

    // ... operation ...

    _sw.Stop();
    _logger.LogDebug("Operation completed in {ElapsedMs}ms", _sw.ElapsedMilliseconds);
}
```

### Memory Snapshot
```csharp
public void LogMemoryState(string label)
{
    var gen0 = GC.CollectionCount(0);
    var gen1 = GC.CollectionCount(1);
    var gen2 = GC.CollectionCount(2);
    var totalMB = GC.GetTotalMemory(false) / 1024 / 1024;

    _logger.LogInformation(
        "{Label}: Memory={TotalMB}MB, GC0={Gen0}, GC1={Gen1}, GC2={Gen2}",
        label, totalMB, gen0, gen1, gen2);
}
```

## Common Bottlenecks

### 1. String Allocations in Parser
```csharp
// BAD - Creates many strings
var parts = line.Split('\t');  // Allocates array + N strings

// GOOD - Span-based parsing
var span = line.AsSpan();
var tabIndex = span.IndexOf('\t');
var field = span.Slice(0, tabIndex);  // No allocation
```

### 2. Collection Resizing
```csharp
// BAD - Multiple resizes
var list = new List<PacketInfo>();
foreach (var p in packets) list.Add(p);

// GOOD - Pre-allocate
var list = new List<PacketInfo>(packets.Count);
foreach (var p in packets) list.Add(p);
```

### 3. LINQ Materializaton
```csharp
// BAD - Materializes entire collection
var filtered = packets.Where(p => p.Length > 100).ToList();
var sorted = filtered.OrderBy(p => p.Timestamp).ToList();

// GOOD - Chain without intermediate materialization
var result = packets
    .Where(p => p.Length > 100)
    .OrderBy(p => p.Timestamp)
    .ToList();  // Single materialization
```

### 4. Unbounded Channels
```csharp
// RISK - Memory exhaustion
var channel = Channel.CreateUnbounded<PacketInfo>();

// SAFE - Backpressure
var channel = Channel.CreateBounded<PacketInfo>(100_000);
```

### 5. Sync-Over-Async
```csharp
// BAD - Blocks thread
var result = service.GetDataAsync().Result;

// GOOD - Async all the way
var result = await service.GetDataAsync().ConfigureAwait(false);
```

### 6. GC Pressure from Large Object Heap
```csharp
// BAD - Large arrays on LOH (>85KB)
var buffer = new byte[100_000];

// GOOD - Use ArrayPool
var buffer = ArrayPool<byte>.Shared.Rent(100_000);
try
{
    // Use buffer...
}
finally
{
    ArrayPool<byte>.Shared.Return(buffer);
}
```

## Investigation Decision Tree

```
Analysis is slow
├── Is it TShark process?
│   ├── Yes → Check file splitting, parallel processing
│   └── No → Continue
├── Is it packet parsing?
│   ├── Yes → Check StreamingOutputParser, span usage
│   └── No → Continue
├── Is it statistics calculation?
│   ├── Yes → Check grouping operations, caching
│   └── No → Continue
├── Is it anomaly detection?
│   ├── Yes → Check individual detectors, parallelization
│   └── No → Continue
├── Is it GeoIP enrichment?
│   ├── Yes → Check cache hit rate, batch lookups
│   └── No → Continue
└── Is it UI rendering?
    ├── Yes → Check virtualization, collection updates
    └── No → Profile deeper
```

## Optimization Priorities

1. **Algorithm improvements** (O(n²) → O(n log n)) — Biggest wins
2. **Reduce allocations** — Lower GC pressure
3. **Parallelization** — Use multiple cores
4. **Caching** — Avoid redundant work
5. **Lazy loading** — Defer until needed

## Benchmark Template
```csharp
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
public class MyBenchmarks
{
    private List<PacketInfo> _packets;

    [GlobalSetup]
    public void Setup()
    {
        // Load test data
        _packets = LoadTestPackets();
    }

    [Benchmark(Baseline = true)]
    public int Original()
    {
        return OriginalImplementation(_packets);
    }

    [Benchmark]
    public int Optimized()
    {
        return OptimizedImplementation(_packets);
    }
}
```

## Documentation Template

When documenting performance changes:

```markdown
## Performance Optimization: [Component Name]

### Problem
[Describe the performance issue]

### Analysis
- Baseline: X ms / Y MB
- Bottleneck: [Specific operation]
- Root cause: [Why it was slow]

### Solution
[Describe the optimization]

### Results
- Before: X ms / Y MB
- After: X' ms / Y' MB
- Improvement: Z%

### Trade-offs
[Any downsides or limitations]
```

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
