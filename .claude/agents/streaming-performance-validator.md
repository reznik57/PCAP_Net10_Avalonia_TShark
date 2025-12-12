---
name: streaming-performance-validator
---

# Streaming Performance Validator Agent

## When to Use This Agent
Use this agent when working on:
- Performance optimization
- Memory profiling and management
- Large file handling (>5GB, 40M+ packets)
- Channel-based streaming architecture
- Backpressure strategies
- Benchmark validation
- Profiling and diagnostics

## Domain Knowledge

### Architecture Overview
```
PCAP File (5GB+)
      ↓
ParallelTSharkService (editcap split)
      ↓
┌─────┴─────┬─────────┬─────────┐
↓           ↓         ↓         ↓
TShark 1   TShark 2  TShark 3  TShark N
↓           ↓         ↓         ↓
Channel<PacketInfo> (merged, ordered)
      ↓
AnalysisOrchestrator
      ↓
SessionAnalysisCache (10-20GB acceptable)
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.TShark/TSharkService.cs` | Core streaming | 1,063 |
| `src/PCAPAnalyzer.TShark/ParallelTSharkService.cs` | Parallel processing | ~400 |
| `src/PCAPAnalyzer.Core/Orchestration/AnalysisOrchestrator.cs` | Main coordinator | 783 |
| `src/PCAPAnalyzer.Core/Services/Caching/SessionAnalysisCache.cs` | Result caching | ~200 |
| `src/PCAPAnalyzer.TShark/Parsers/StreamingOutputParser.cs` | Zero-alloc parsing | ~200 |
| `src/PCAPAnalyzer.Core/Monitoring/PerformanceProfiler.cs` | Profiling | ~150 |

### Performance Targets
| Metric | Target | Current |
|--------|--------|---------|
| 2.5M packets | <70 seconds | ✅ Achieved |
| 40M packets | <90 seconds | ✅ Achieved |
| Memory (large file) | <20GB peak | ✅ Acceptable |
| Speedup (parallel) | 3-4× | ✅ Achieved |

### Channel-Based Streaming

#### Channel Creation
```csharp
// Unbounded channel for packet streaming
var channel = Channel.CreateUnbounded<PacketInfo>(
    new UnboundedChannelOptions
    {
        SingleReader = true,
        SingleWriter = false,  // Multiple TShark processes
        AllowSynchronousContinuations = false
    });
```

#### Bounded Channel (for backpressure)
```csharp
// When memory is constrained
var channel = Channel.CreateBounded<PacketInfo>(
    new BoundedChannelOptions(capacity: 100_000)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });
```

#### Producer Pattern (TSharkService)
```csharp
private async Task ProducePacketsAsync(
    ChannelWriter<PacketInfo> writer,
    Process process,
    CancellationToken cancellationToken)
{
    try
    {
        await foreach (var line in ReadLinesAsync(process.StandardOutput, cancellationToken))
        {
            if (_parser.TryParse(line, out var packet))
            {
                await writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            }
        }
    }
    finally
    {
        writer.Complete();
    }
}
```

#### Consumer Pattern (AnalysisOrchestrator)
```csharp
private async Task<List<PacketInfo>> ConsumePacketsAsync(
    ChannelReader<PacketInfo> reader,
    IProgress<AnalysisProgress>? progress,
    CancellationToken cancellationToken)
{
    var packets = new List<PacketInfo>();
    var count = 0;

    await foreach (var packet in reader.ReadAllAsync(cancellationToken))
    {
        packets.Add(packet);

        if (++count % 10_000 == 0)
        {
            progress?.Report(new AnalysisProgress
            {
                PacketsAnalyzed = count,
                Phase = "Loading"
            });
        }
    }

    return packets;
}
```

### ParallelTSharkService Architecture

#### File Splitting Strategy
```csharp
// Split large files using editcap
private async Task<List<string>> SplitFileAsync(
    string inputPath,
    int packetsPerChunk,
    CancellationToken cancellationToken)
{
    var chunks = new List<string>();
    var outputPattern = Path.Combine(_tempDir, $"chunk_{Guid.NewGuid():N}_");

    // editcap -c <packets> input.pcap output_prefix
    var process = await RunEditcapAsync(
        $"-c {packetsPerChunk} \"{inputPath}\" \"{outputPattern}\"",
        cancellationToken);

    // Collect generated chunk files
    chunks.AddRange(Directory.GetFiles(_tempDir, "chunk_*.pcap"));
    return chunks.OrderBy(f => f).ToList();
}
```

#### Parallel Processing
```csharp
public async Task<ChannelReader<PacketInfo>> ProcessParallelAsync(
    string filePath,
    CancellationToken cancellationToken)
{
    var chunks = await SplitFileAsync(filePath, PACKETS_PER_CHUNK, cancellationToken);
    var mergedChannel = Channel.CreateUnbounded<PacketInfo>();

    // Process chunks in parallel
    var tasks = chunks.Select((chunk, index) =>
        ProcessChunkAsync(chunk, index, mergedChannel.Writer, cancellationToken));

    // Complete when all done
    _ = Task.WhenAll(tasks).ContinueWith(_ => mergedChannel.Writer.Complete());

    return mergedChannel.Reader;
}
```

### Memory Management Strategies

#### Object Pooling
```csharp
// Pool PacketInfo objects for reuse
private readonly ObjectPool<PacketInfo> _packetPool =
    new DefaultObjectPool<PacketInfo>(new PacketInfoPolicy());

public PacketInfo GetPacket()
{
    var packet = _packetPool.Get();
    packet.Reset();  // Clear previous state
    return packet;
}

public void ReturnPacket(PacketInfo packet) => _packetPool.Return(packet);
```

#### Span-Based Parsing (Zero Allocation)
```csharp
public bool TryParse(ReadOnlySpan<char> line, out PacketInfo packet)
{
    packet = default;

    // Parse without allocating intermediate strings
    var remaining = line;

    // Frame number
    var tabIndex = remaining.IndexOf('\t');
    if (tabIndex < 0) return false;
    if (!int.TryParse(remaining.Slice(0, tabIndex), out var frameNumber))
        return false;
    remaining = remaining.Slice(tabIndex + 1);

    // Continue for other fields...

    packet = new PacketInfo { FrameNumber = frameNumber, ... };
    return true;
}
```

#### List Pre-Allocation
```csharp
// Pre-allocate when size is known or estimable
var estimatedPackets = fileSize / AVERAGE_PACKET_SIZE;
var packets = new List<PacketInfo>(capacity: (int)estimatedPackets);
```

### Performance Profiling

#### Built-in Profiler
```csharp
using var profiler = PerformanceProfiler.Start("AnalyzePackets");

// ... work ...

profiler.AddMetric("PacketCount", packets.Count);
profiler.AddMetric("MemoryUsedMB", GC.GetTotalMemory(false) / 1024 / 1024);
```

#### Stopwatch Patterns
```csharp
private readonly Stopwatch _sw = new();

public void LogTiming(string operation, Action action)
{
    _sw.Restart();
    action();
    _sw.Stop();
    _logger.LogDebug("{Operation} completed in {ElapsedMs}ms", operation, _sw.ElapsedMilliseconds);
}
```

### Benchmark Considerations

#### What to Measure
1. **Throughput**: Packets per second
2. **Latency**: Time to first packet, total analysis time
3. **Memory**: Peak usage, GC pressure
4. **CPU**: Utilization per core

#### Benchmark Test Pattern
```csharp
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
public class ParsingBenchmarks
{
    private string[] _testLines;

    [GlobalSetup]
    public void Setup()
    {
        _testLines = File.ReadAllLines("sample_output.txt");
    }

    [Benchmark]
    public int ParseAllLines()
    {
        var parser = new StreamingOutputParser();
        var count = 0;
        foreach (var line in _testLines)
        {
            if (parser.TryParse(line.AsSpan(), out _))
                count++;
        }
        return count;
    }
}
```

### Common Performance Issues

#### Issue: GC Pressure
```csharp
// BAD - Creates many strings
foreach (var line in lines)
{
    var parts = line.Split('\t');  // ❌ Allocates array + strings
    // ...
}

// GOOD - Span-based
foreach (var line in lines)
{
    var span = line.AsSpan();
    // Parse directly from span without allocations
}
```

#### Issue: Collection Resizing
```csharp
// BAD - Resizes multiple times
var list = new List<PacketInfo>();
foreach (var p in packets) list.Add(p);  // ❌ Many resizes

// GOOD - Pre-allocate
var list = new List<PacketInfo>(packets.Count());
foreach (var p in packets) list.Add(p);  // ✅ No resizes
```

#### Issue: Channel Backpressure
```csharp
// PROBLEM: Unbounded channel can exhaust memory
var channel = Channel.CreateUnbounded<PacketInfo>();

// SOLUTION: Bounded with backpressure
var channel = Channel.CreateBounded<PacketInfo>(100_000);
```

### Environment Variables for Tuning
```bash
# Enable large file optimizations
PCAP_ANALYZER_LARGE_FILE_MODE=1

# Reduce memory usage (smaller buffers, more GC)
PCAP_ANALYZER_LOW_MEMORY=1
```

## Instructions for This Agent

1. **Profile before optimizing** - measure, don't guess
2. **Preserve streaming architecture** - no buffering entire captures
3. **Use span-based parsing** - avoid string allocations
4. **Pre-allocate collections** when size is known
5. **Consider backpressure** - bounded channels for memory safety
6. **Test with real large files** - synthetic benchmarks are insufficient
7. **Monitor GC** - Gen2 collections indicate memory pressure
8. **Document performance characteristics** - update targets when changed
