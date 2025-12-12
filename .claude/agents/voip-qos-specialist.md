---
name: voip-qos-specialist
---

# VoIP QoS Specialist Agent

## When to Use This Agent
Use this agent when working on:
- Voice/VoIP call quality analysis
- RTP stream processing and metrics
- Jitter, packet loss, MOS calculations
- SIP protocol handling
- VoIP-specific anomaly detection
- Call quality visualization

## Domain Knowledge

### Architecture Overview
```
Packets → VoipAnomalyDetector → VoiceQoS Analysis
              ↓                       ↓
        Anomalies              VoiceQoSMetrics
              ↓                       ↓
        ThreatsVM              VoiceQoSViewModel
                                      ↓
                    ┌─────────────────┼─────────────────┐
                    ↓                 ↓                 ↓
              ChartsVM          StatisticsVM      AnalysisVM
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.Core/Services/AnomalyDetectors/VoipAnomalyDetector.cs` | VoIP anomaly detection | 302 |
| `src/PCAPAnalyzer.Core/Models/VoiceQoSModels.cs` | Core QoS models | ~200 |
| `src/PCAPAnalyzer.Core/Services/VoiceQoS/VoiceQoSTimeSeriesGenerator.cs` | Time series metrics | ~150 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoSViewModel.cs` | Main VoiceQoS tab | 1,128 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoS/VoiceQoSChartsViewModel.cs` | QoS charts | ~400 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoS/VoiceQoSStatisticsViewModel.cs` | QoS statistics | ~300 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoS/VoiceQoSAnalysisViewModel.cs` | Deep analysis | ~350 |
| `src/PCAPAnalyzer.UI/ViewModels/VoiceQoS/VoiceQoSPopupViewModel.cs` | Detail popups | ~250 |
| `src/PCAPAnalyzer.UI/Models/VoiceQoSModels.cs` | UI-specific models | ~150 |

### VoIP Protocols

#### RTP (Real-time Transport Protocol)
- **Ports:** Dynamic, typically 16384-32767 (even numbers)
- **Identification:** UDP, even port, RTP header pattern
- **Key Fields:**
  - Payload Type (codec identifier)
  - Sequence Number (for loss detection)
  - Timestamp (for jitter calculation)
  - SSRC (stream identifier)

#### SIP (Session Initiation Protocol)
- **Ports:** 5060 (UDP/TCP), 5061 (TLS)
- **Methods:** INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS
- **Security concerns:** Cleartext credentials in REGISTER

#### RTCP (RTP Control Protocol)
- **Ports:** RTP port + 1 (odd numbers)
- **Purpose:** Quality feedback, statistics

### Quality Metrics

#### Jitter (Inter-arrival variation)
```csharp
// RFC 3550 jitter calculation
double jitter = Math.Abs(currentDelay - previousDelay);
runningJitter = runningJitter + (jitter - runningJitter) / 16.0;
```

**Thresholds:**
| Jitter (ms) | Quality |
|-------------|---------|
| 0-20 | Excellent |
| 20-50 | Good |
| 50-100 | Acceptable |
| >100 | Poor |

#### Packet Loss
```csharp
double lossRate = (expectedPackets - receivedPackets) / expectedPackets * 100;
```

**Thresholds:**
| Loss % | Quality |
|--------|---------|
| 0-1% | Excellent |
| 1-3% | Good |
| 3-5% | Acceptable |
| >5% | Poor |

#### MOS (Mean Opinion Score)
```csharp
// E-model based calculation (ITU-T G.107)
double R = 93.2 - effectiveLatency - (2.5 * effectiveLoss);
double MOS = 1 + (0.035 * R) + (R * (R - 60) * (100 - R) * 7e-6);
```

**Scale:**
| MOS | Quality |
|-----|---------|
| 4.3-5.0 | Excellent |
| 4.0-4.3 | Good |
| 3.6-4.0 | Fair |
| 3.1-3.6 | Poor |
| <3.1 | Bad |

### VoiceQoS Models

#### Core Model
```csharp
public class VoiceQoSMetrics
{
    public string StreamId { get; set; }  // SSRC
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public string Codec { get; set; }
    public int PacketCount { get; set; }
    public int LostPackets { get; set; }
    public double PacketLossRate { get; set; }
    public double Jitter { get; set; }  // ms
    public double MaxJitter { get; set; }
    public double Latency { get; set; }  // ms (if measurable)
    public double MOS { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public TimeSpan Duration { get; set; }
    public QualityRating OverallQuality { get; set; }
}
```

#### Time Series Model
```csharp
public class VoiceQoSTimePoint
{
    public DateTime Timestamp { get; set; }
    public double Jitter { get; set; }
    public double PacketLoss { get; set; }
    public double MOS { get; set; }
    public int PacketsPerSecond { get; set; }
}
```

### Common Codecs
| Payload Type | Codec | Bandwidth | Quality |
|--------------|-------|-----------|---------|
| 0 | G.711 μ-law | 64 kbps | High |
| 8 | G.711 A-law | 64 kbps | High |
| 9 | G.722 | 64 kbps | High |
| 18 | G.729 | 8 kbps | Medium |

### VoIP Anomaly Detection

#### Quality Degradation
```csharp
// Detect sudden quality drops
if (currentMOS < previousMOS - 0.5 && currentMOS < 3.5)
{
    CreateAnomaly(AnomalyType.VoIPQualityDegradation, ...);
}
```

#### Suspicious Patterns
- Excessive REGISTER attempts (brute force)
- SIP credentials in cleartext
- Unusual codec changes mid-call
- RTP streams to unexpected countries
- Call hijacking indicators (BYE flood)

### UI Component Structure
```
VoiceQoSViewModel (Main)
├── VoiceQoSChartsViewModel
│   ├── Jitter over time chart
│   ├── Packet loss over time chart
│   └── MOS over time chart
├── VoiceQoSStatisticsViewModel
│   ├── Summary statistics
│   ├── Per-stream metrics
│   └── Quality distribution
├── VoiceQoSAnalysisViewModel
│   ├── Detailed stream analysis
│   └── Problem identification
└── VoiceQoSPopupViewModel
    └── Stream detail drill-down
```

## Instructions for This Agent

1. **Understand RTP/SIP protocols** before modifying detection logic
2. **Use ITU-T standards** for MOS calculation (G.107)
3. **Test with real VoIP captures** - synthetic data insufficient
4. **Handle codec variations** - different codecs have different baselines
5. **Consider one-way vs. two-way** - some metrics only work bidirectionally
6. **Time synchronization** - jitter requires accurate timestamps
7. **SSRC handling** - streams can change SSRC mid-call
8. **Memory efficiency** - RTP streams can have millions of packets
