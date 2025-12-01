# Anomaly Detector Specialist Agent

## When to Use This Agent
Use this agent when working on:
- Creating new anomaly detection rules
- Tuning detection thresholds
- Modifying existing detector logic
- Adding new threat categories
- Reducing false positive rates
- Cross-detector correlation

## Domain Knowledge

### Architecture Overview
```
Packets → UnifiedAnomalyDetectionService → 7 Specialized Detectors → List<NetworkAnomaly>
                                                    ↓
                                          ThreatsViewModel (UI)
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.Core/Services/UnifiedAnomalyDetectionService.cs` | Orchestrates all detectors | 256 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/NetworkAnomalyDetector.cs` | SYN floods, ARP spoofing, ICMP | ~280 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/TCPAnomalyDetector.cs` | Retransmissions, duplicate ACKs | ~250 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/ApplicationAnomalyDetector.cs` | Protocol misuse, payloads | ~220 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/CryptoMiningDetector.cs` | Pool connections, Stratum | 264 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/DataExfiltrationDetector.cs` | Large transfers, DNS exfil | 329 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/IoTAnomalyDetector.cs` | Device patterns, botnets | 292 |
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/VoipAnomalyDetector.cs` | RTP quality, call anomalies | 302 |
| `src/PCAPAnalyzer.Core/Models/NetworkAnomaly.cs` | Anomaly data model | ~100 |

### The 7 Detector Types

#### 1. NetworkAnomalyDetector
**Detects:** Network-layer attacks
- SYN flood (threshold: 100+ SYN/sec, SYN→SYN-ACK ratio <50%)
- ARP spoofing (duplicate IP-MAC mappings)
- ICMP flood (threshold: 50+ ICMP/sec)
- IP fragmentation attacks

#### 2. TCPAnomalyDetector
**Detects:** TCP-layer anomalies
- Excessive retransmissions (threshold: >3% of packets)
- Duplicate ACKs
- Out-of-order packets
- Zero window conditions
- RST storms

#### 3. ApplicationAnomalyDetector
**Detects:** Application-layer issues
- Protocol violations (HTTP malformed, DNS tunneling indicators)
- Suspicious payloads
- Unusual port usage (HTTP on non-80/443)

#### 4. CryptoMiningDetector
**Detects:** Cryptocurrency mining activity
- Mining pool connections (ports 3333, 3334, 45560, etc.)
- Stratum protocol patterns
- 6+ unique pool connections = botnet indicator
- Known mining pool domains

#### 5. DataExfiltrationDetector
**Detects:** Data theft patterns
- Large outbound transfers (>500MB in 5min)
- DNS exfiltration (>1000 DNS requests in 60s, data in TXT records)
- Beaconing patterns (regular interval connections)
- Unusual destination countries

#### 6. IoTAnomalyDetector
**Detects:** IoT device anomalies
- Device fingerprinting anomalies
- Botnet C2 patterns
- Unusual protocol usage for device type
- Mass scanning behavior

#### 7. VoipAnomalyDetector
**Detects:** VoIP/RTP issues
- Call quality degradation (high jitter, packet loss)
- SIP credential attacks
- RTP stream anomalies
- Toll fraud patterns

### NetworkAnomaly Model
```csharp
public class NetworkAnomaly
{
    public string Id { get; set; }
    public AnomalyType Type { get; set; }
    public AnomalySeverity Severity { get; set; }
    public double SeverityScore { get; set; }  // 0.0 - 1.0
    public string Description { get; set; }
    public string DetailedAnalysis { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int OccurrenceCount { get; set; }
    public List<string> AffectedIPs { get; set; }
    public List<int> AffectedPorts { get; set; }
    public List<int> SampleFrameNumbers { get; set; }  // Limited to 100
    public Dictionary<string, object> Metadata { get; set; }
}
```

### Standard Detection Pattern
```csharp
public async Task<IEnumerable<NetworkAnomaly>> DetectAsync(
    IReadOnlyList<PacketInfo> packets,
    CancellationToken cancellationToken = default)
{
    var anomalies = new List<NetworkAnomaly>();

    // 1. Filter relevant packets
    var relevantPackets = packets
        .Where(p => IsRelevant(p))
        .ToList();

    // 2. Group by analysis dimension
    var groups = relevantPackets
        .GroupBy(p => GetGroupKey(p));

    // 3. Analyze each group
    foreach (var group in groups)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var pattern = AnalyzePattern(group);
        if (pattern.ExceedsThreshold(THRESHOLD))
        {
            anomalies.Add(CreateAnomaly(pattern, group));
        }
    }

    return anomalies;
}
```

### Threshold Constants (Current Values)
```csharp
// NetworkAnomalyDetector
private const int SYN_FLOOD_THRESHOLD = 100;        // SYN packets per second
private const double SYN_ACK_RATIO_THRESHOLD = 0.5; // Min acceptable ratio
private const int ICMP_FLOOD_THRESHOLD = 50;        // ICMP packets per second

// TCPAnomalyDetector
private const double RETRANSMISSION_THRESHOLD = 0.03; // 3% of packets

// DataExfiltrationDetector
private const long LARGE_TRANSFER_BYTES = 500_000_000; // 500MB
private const int LARGE_TRANSFER_WINDOW_SECONDS = 300; // 5 minutes
private const int DNS_EXFIL_REQUEST_THRESHOLD = 1000;  // Requests in window
private const int DNS_EXFIL_WINDOW_SECONDS = 60;

// CryptoMiningDetector
private const int MINING_POOL_DIVERSITY_THRESHOLD = 6; // Unique pools
```

### Severity Scoring Guidelines
| Score | Severity | Criteria |
|-------|----------|----------|
| 0.0-0.3 | Low | Informational, likely benign |
| 0.3-0.6 | Medium | Suspicious, warrants investigation |
| 0.6-0.8 | High | Likely malicious, prioritize |
| 0.8-1.0 | Critical | Active attack, immediate action |

### Testing Patterns
```csharp
[Fact]
public async Task Detector_WhenPatternPresent_ReturnsAnomaly()
{
    // Arrange
    var packets = CreatePacketsWithPattern();
    var detector = new SpecificDetector();

    // Act
    var anomalies = await detector.DetectAsync(packets);

    // Assert
    Assert.Single(anomalies);
    Assert.Equal(AnomalyType.Expected, anomalies[0].Type);
    Assert.True(anomalies[0].SeverityScore >= EXPECTED_MIN_SEVERITY);
}
```

## Instructions for This Agent

1. **Read detector code before modifying** - understand existing patterns
2. **Preserve threshold constants** at top of file with clear documentation
3. **Limit SampleFrameNumbers** to 100 max (memory constraint)
4. **Use async patterns** with CancellationToken support
5. **Test for false positives** - add negative test cases
6. **Document detection logic** in DetailedAnalysis field
7. **Consider small captures** - thresholds may need minimum packet counts
8. **Cross-detector correlation** - check if related detectors should share signals
