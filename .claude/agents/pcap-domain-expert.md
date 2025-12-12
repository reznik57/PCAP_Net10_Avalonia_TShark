---
name: pcap-domain-expert
---

# PCAP Domain Expert Agent

## When to Use This Agent
Use this agent when working on:
- TShark process integration and command building
- Packet parsing and field extraction
- Protocol analysis and dissection
- PacketInfo model modifications
- Cross-platform execution (Windows native, WSL2, Linux)
- PCAP file handling and validation

## Domain Knowledge

### Architecture Overview
```
PCAP File → TSharkService → StreamingOutputParser → Channel<PacketInfo> → AnalysisOrchestrator
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.TShark/TSharkService.cs` | Core TShark process management | 1,063 |
| `src/PCAPAnalyzer.TShark/Parsers/StreamingOutputParser.cs` | High-perf span-based parsing | ~200 |
| `src/PCAPAnalyzer.TShark/ParallelTSharkService.cs` | 3-4× speedup via editcap splitting | ~400 |
| `src/PCAPAnalyzer.TShark/Commands/SecureTSharkCommandBuilder.cs` | Secure command construction | ~150 |
| `src/PCAPAnalyzer.TShark/Security/TSharkInputValidator.cs` | Injection prevention | ~100 |
| `src/PCAPAnalyzer.Core/Models/PacketInfo.cs` | Core packet structure | ~150 |

### TShark Field Extraction (15 fields)
The system extracts these tab-delimited fields via `-T fields`:
```
1. frame.number        - Packet sequence number
2. frame.time_epoch    - Unix timestamp (preferred)
3. frame.time_relative - Time since capture start
4. frame.len           - Packet length in bytes
5. ip.src              - Source IP address
6. ip.dst              - Destination IP address
7. tcp.srcport         - Source port (TCP/UDP)
8. tcp.dstport         - Destination port (TCP/UDP)
9. ip.proto            - IP protocol number (6=TCP, 17=UDP, 1=ICMP)
10. _ws.col.info       - TShark enriched info column
11. tcp.flags          - TCP flags (SYN, ACK, FIN, RST, PSH, URG)
12. tcp.seq            - TCP sequence number
13. tcp.ack            - TCP acknowledgment number
14. tcp.window_size    - TCP window size
15. _ws.col.protocol   - L7 protocol (TLS, HTTP, DNS, etc.)
```

### PacketInfo Model Structure
```csharp
public class PacketInfo
{
    public int FrameNumber { get; set; }
    public DateTime Timestamp { get; set; }
    public double RelativeTime { get; set; }
    public int Length { get; set; }
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public string L4Protocol { get; set; }  // TCP, UDP, ICMP
    public string L7Protocol { get; set; }  // TLS, HTTP, DNS, etc.
    public string Info { get; set; }
    public TcpFlags? TcpFlags { get; set; }
    public uint? TcpSequence { get; set; }
    public uint? TcpAck { get; set; }
    public int? TcpWindowSize { get; set; }
}
```

### Cross-Platform Execution Modes
1. **Windows Native**: Direct tshark.exe execution
2. **WSL2**: Path conversion via `wsl.exe wslpath -u` + `wsl.exe tshark`
3. **Linux**: Direct tshark execution

Path conversion pattern:
```csharp
// Windows: D:\captures\file.pcap
// WSL2:    /mnt/d/captures/file.pcap
```

### Security Considerations
- **NEVER** pass unsanitized user input to TShark commands
- Use `TSharkInputValidator` for all file paths
- Use `SecureTSharkCommandBuilder` for command construction
- Validate PCAP file headers before processing
- Sanitize file paths in log output

### StreamingOutputParser Patterns
```csharp
// Zero-allocation span-based parsing
ReadOnlySpan<char> line = inputLine.AsSpan();
int tabIndex = line.IndexOf('\t');
ReadOnlySpan<char> field = line.Slice(0, tabIndex);
```

### Common Edge Cases to Handle
1. **Malformed TShark output** - Quoted fields, escaped tabs
2. **Missing fields** - Null/empty handling for optional fields
3. **Timestamp variations** - Epoch vs. relative vs. formatted
4. **Large payloads** - Truncation of Info field
5. **Unicode in paths** - File path encoding issues
6. **Process hangs** - Timeout handling for stuck tshark
7. **Corrupted PCAP** - Graceful error recovery

### ParallelTSharkService Architecture
For files >5GB:
1. Split file using `editcap -c <packets_per_chunk>`
2. Spawn N parallel TShark processes
3. Merge packet streams maintaining frame order
4. Cleanup temporary chunk files

## Instructions for This Agent

1. **Always read the key files** before making changes
2. **Preserve zero-allocation patterns** in StreamingOutputParser
3. **Use structured logging** - no sensitive data in logs
4. **Test cross-platform** - changes must work on Windows, WSL2, Linux
5. **Validate all inputs** via TSharkInputValidator
6. **Handle cancellation** - respect CancellationToken throughout
7. **Consider memory** - streaming architecture, no buffering entire captures
