---
name: pcap:add-voip-metric
description: Use when adding a new VoIP/QoS measurement (e.g., R-factor, codec detection, SIP metrics) - ensures proper calculation, UI binding, and visualization integration
---

# Add VoIP Metric Skill

This skill guides you through adding a new VoIP quality metric to the PCAP analyzer.

## Prerequisites

Before starting, determine:
- The metric formula/calculation method
- Required packet data (RTP headers, timing, etc.)
- ITU-T or RFC standards that define the metric
- How the metric should be displayed (number, gauge, chart)

## Current Metrics

| Metric | Standard | Range | Description |
|--------|----------|-------|-------------|
| Jitter | RFC 3550 | 0-∞ ms | Inter-arrival variation |
| Packet Loss | - | 0-100% | Missing packets |
| MOS | ITU-T G.107 | 1.0-5.0 | Mean Opinion Score |
| Latency | - | 0-∞ ms | One-way delay (if measurable) |

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Model Definition
- [ ] Add metric property to `VoiceQoSMetrics` model
- [ ] Add metric property to `VoiceQoSTimePoint` (if time-series)
- [ ] Define calculation constants with standards reference

### Phase 2: Calculation Implementation
- [ ] Implement calculation in `VoiceQoSAnalyzer` or appropriate service
- [ ] Handle edge cases (insufficient data, single packet)
- [ ] Add unit tests for calculation
- [ ] Validate against known test data

### Phase 3: Time Series Support
- [ ] Add metric to `VoiceQoSTimeSeriesGenerator`
- [ ] Calculate per-interval values
- [ ] Handle interval boundaries

### Phase 4: ViewModel Integration
- [ ] Add property to `VoiceQoSStatisticsViewModel`
- [ ] Add to summary display
- [ ] Add quality rating interpretation

### Phase 5: Visualization
- [ ] Add chart for metric if time-series
- [ ] Add gauge/indicator for current value
- [ ] Update quality color coding

### Phase 6: Testing & Validation
- [ ] Unit test calculation with known values
- [ ] Test with real VoIP PCAP files
- [ ] Verify display accuracy
- [ ] Run `dotnet build` — zero warnings

## Metric Implementation Examples

### Example 1: R-Factor (ITU-T G.107)

The R-factor is a voice quality metric from 0-100.

```csharp
// VoiceQoSModels.cs - Add to model
public class VoiceQoSMetrics
{
    // Existing properties...
    public double Jitter { get; set; }
    public double PacketLossRate { get; set; }
    public double MOS { get; set; }

    // New metric
    public double RFactor { get; set; }
    public RFactorRating RFactorQuality { get; set; }
}

public enum RFactorRating
{
    Excellent,  // 90-100
    Good,       // 80-90
    Fair,       // 70-80
    Poor,       // 60-70
    Bad         // <60
}
```

```csharp
// VoiceQoSCalculator.cs
public class VoiceQoSCalculator
{
    // ITU-T G.107 E-model constants
    private const double DEFAULT_R0 = 93.2;  // Base R-factor
    private const double DEFAULT_Is = 0;      // Simultaneous impairment
    private const double DEFAULT_A = 0;       // Advantage factor

    /// <summary>
    /// Calculate R-factor using simplified E-model (ITU-T G.107)
    /// </summary>
    public double CalculateRFactor(
        double latencyMs,
        double jitterMs,
        double packetLossPercent)
    {
        // Effective latency including jitter buffer delay
        // Assumes adaptive jitter buffer at 2x jitter
        double jitterBufferDelay = jitterMs * 2;
        double effectiveLatency = latencyMs + jitterBufferDelay;

        // Delay impairment (Id)
        double Id = CalculateDelayImpairment(effectiveLatency);

        // Equipment impairment (Ie-eff) based on packet loss
        double IeEff = CalculatePacketLossImpairment(packetLossPercent);

        // Final R-factor
        double R = DEFAULT_R0 - DEFAULT_Is - Id - IeEff + DEFAULT_A;

        // Clamp to valid range
        return Math.Clamp(R, 0, 100);
    }

    private double CalculateDelayImpairment(double latencyMs)
    {
        if (latencyMs <= 177.3)
        {
            return 0.024 * latencyMs +
                   0.11 * (latencyMs - 177.3) * HeavisideStep(latencyMs - 177.3);
        }
        return 0.024 * latencyMs;
    }

    private double CalculatePacketLossImpairment(double lossPercent)
    {
        // Simplified Ie-eff for G.711 codec
        // Full model varies by codec
        const double Ie = 0;      // Equipment impairment for G.711
        const double Bpl = 25.1;  // Packet loss robustness

        return Ie + (95 - Ie) * (lossPercent / (lossPercent + Bpl));
    }

    private double HeavisideStep(double x) => x >= 0 ? 1 : 0;

    public static RFactorRating GetRFactorRating(double rFactor)
    {
        return rFactor switch
        {
            >= 90 => RFactorRating.Excellent,
            >= 80 => RFactorRating.Good,
            >= 70 => RFactorRating.Fair,
            >= 60 => RFactorRating.Poor,
            _ => RFactorRating.Bad
        };
    }
}
```

### Example 2: Codec Detection

```csharp
// RTP payload type to codec mapping
public class CodecDetector
{
    private static readonly Dictionary<int, string> PayloadTypeToCodec = new()
    {
        [0] = "G.711 μ-law (PCMU)",
        [3] = "GSM",
        [4] = "G.723",
        [8] = "G.711 A-law (PCMA)",
        [9] = "G.722",
        [18] = "G.729",
        [96] = "Dynamic (Opus/Others)",
        [97] = "Dynamic",
        [98] = "Dynamic",
    };

    public string DetectCodec(byte rtpPayloadType)
    {
        return PayloadTypeToCodec.TryGetValue(rtpPayloadType, out var codec)
            ? codec
            : $"Unknown ({rtpPayloadType})";
    }

    public CodecInfo GetCodecInfo(byte payloadType)
    {
        return payloadType switch
        {
            0 => new CodecInfo("G.711 μ-law", 64, 8000, 20, 4.1),
            8 => new CodecInfo("G.711 A-law", 64, 8000, 20, 4.1),
            9 => new CodecInfo("G.722", 64, 16000, 20, 4.0),
            18 => new CodecInfo("G.729", 8, 8000, 20, 3.9),
            _ => new CodecInfo("Unknown", 0, 0, 20, 0)
        };
    }
}

public record CodecInfo(
    string Name,
    int BitRateKbps,
    int SampleRate,
    int FrameSizeMs,
    double MaxMOS  // Maximum achievable MOS for this codec
);
```

### Example 3: Burst Loss Metric

```csharp
/// <summary>
/// Measures burstiness of packet loss (consecutive lost packets)
/// </summary>
public class BurstLossCalculator
{
    public BurstLossMetrics Calculate(IReadOnlyList<RtpPacketInfo> packets)
    {
        var sortedPackets = packets.OrderBy(p => p.SequenceNumber).ToList();
        var lostBursts = new List<int>();
        var currentBurstLength = 0;

        for (int i = 1; i < sortedPackets.Count; i++)
        {
            var expected = (sortedPackets[i - 1].SequenceNumber + 1) % 65536;
            var actual = sortedPackets[i].SequenceNumber;

            if (actual != expected)
            {
                // Gap detected
                var gapSize = (actual - expected + 65536) % 65536;
                currentBurstLength += gapSize;
            }
            else if (currentBurstLength > 0)
            {
                // End of burst
                lostBursts.Add(currentBurstLength);
                currentBurstLength = 0;
            }
        }

        if (currentBurstLength > 0)
            lostBursts.Add(currentBurstLength);

        return new BurstLossMetrics
        {
            TotalBursts = lostBursts.Count,
            MaxBurstLength = lostBursts.Count > 0 ? lostBursts.Max() : 0,
            AverageBurstLength = lostBursts.Count > 0 ? lostBursts.Average() : 0,
            BurstRatio = (double)lostBursts.Sum() /
                        (sortedPackets.Count + lostBursts.Sum())
        };
    }
}

public class BurstLossMetrics
{
    public int TotalBursts { get; set; }
    public int MaxBurstLength { get; set; }
    public double AverageBurstLength { get; set; }
    public double BurstRatio { get; set; }  // Bursty loss vs total loss
}
```

## Time Series Integration

```csharp
// VoiceQoSTimeSeriesGenerator.cs
public class VoiceQoSTimePoint
{
    public DateTime Timestamp { get; set; }
    public double Jitter { get; set; }
    public double PacketLoss { get; set; }
    public double MOS { get; set; }
    public double RFactor { get; set; }  // New metric
    public int PacketsPerSecond { get; set; }
}

public IReadOnlyList<VoiceQoSTimePoint> GenerateTimeSeries(
    IReadOnlyList<RtpPacketInfo> packets,
    TimeSpan interval)
{
    return packets
        .GroupBy(p => RoundToInterval(p.Timestamp, interval))
        .Select(g => new VoiceQoSTimePoint
        {
            Timestamp = g.Key,
            Jitter = CalculateIntervalJitter(g),
            PacketLoss = CalculateIntervalLoss(g),
            MOS = CalculateIntervalMOS(g),
            RFactor = _calculator.CalculateRFactor(  // New
                estimatedLatency, CalculateIntervalJitter(g), CalculateIntervalLoss(g)),
            PacketsPerSecond = g.Count()
        })
        .OrderBy(p => p.Timestamp)
        .ToList();
}
```

## ViewModel Integration

```csharp
// VoiceQoSStatisticsViewModel.cs
public class VoiceQoSStatisticsViewModel : ViewModelBase
{
    [Reactive] public double AverageJitter { get; set; }
    [Reactive] public double PacketLossRate { get; set; }
    [Reactive] public double MOS { get; set; }
    [Reactive] public double RFactor { get; set; }  // New
    [Reactive] public string RFactorQualityLabel { get; set; }  // New

    public void UpdateFromMetrics(VoiceQoSMetrics metrics)
    {
        AverageJitter = metrics.Jitter;
        PacketLossRate = metrics.PacketLossRate;
        MOS = metrics.MOS;
        RFactor = metrics.RFactor;
        RFactorQualityLabel = GetQualityLabel(metrics.RFactorQuality);
    }

    private string GetQualityLabel(RFactorRating rating)
    {
        return rating switch
        {
            RFactorRating.Excellent => "Excellent (≥90)",
            RFactorRating.Good => "Good (80-90)",
            RFactorRating.Fair => "Fair (70-80)",
            RFactorRating.Poor => "Poor (60-70)",
            RFactorRating.Bad => "Bad (<60)",
            _ => "Unknown"
        };
    }
}
```

## UI Display

```xml
<!-- VoiceQoSView.axaml -->
<StackPanel>
    <!-- Existing metrics -->
    <TextBlock Text="{Binding Statistics.MOS, StringFormat='MOS: {0:F2}'}" />
    <TextBlock Text="{Binding Statistics.AverageJitter, StringFormat='Jitter: {0:F1} ms'}" />

    <!-- New R-Factor metric -->
    <StackPanel Orientation="Horizontal" Spacing="8">
        <TextBlock Text="{Binding Statistics.RFactor, StringFormat='R-Factor: {0:F1}'}" />
        <Border Background="{Binding Statistics.RFactor, Converter={StaticResource QualityToBrush}}"
                Padding="4,2" CornerRadius="4">
            <TextBlock Text="{Binding Statistics.RFactorQualityLabel}"
                       FontSize="11" />
        </Border>
    </StackPanel>
</StackPanel>
```

## Common Mistakes to Avoid

1. **Wrong standard reference** — Cite ITU-T/RFC correctly
2. **Integer overflow in sequence numbers** — RTP seq is 16-bit, wrap at 65536
3. **Missing codec consideration** — MOS/R-Factor depends on codec
4. **One-way vs round-trip** — Be clear about latency measurement
5. **Insufficient samples** — Need minimum packets for statistical validity

## References

- ITU-T G.107: The E-model
- ITU-T G.114: One-way transmission time
- RFC 3550: RTP specification
- RFC 3611: RTP Control Protocol Extended Reports (RTCP XR)

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
