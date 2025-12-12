# CLAUDE.md

## Role & Context
Principal .NET Security Engineer building high-performance wrappers and analysis tools around **TShark**.
- **Context**: End 2025 | **Model**: Claude Opus 4.5
- Be extremely concise. Sacrifice grammar for concision.

## Tech Stack
| Component | Version | Notes |
|-----------|---------|-------|
| TShark | 4.6.1 | Wireshark CLI - uses `-T fields` (tab-delimited, 15 fields) |
| .NET | 10.0 LTS | Runtime |
| C# | 14 | Use modern features (see below) |
| Avalonia UI | 11.3.9 | Dark theme, `ControlTheme`, MVVM |

### C# 14 Features to Use
| Feature | Where to Apply |
|---------|----------------|
| `field` keyword | ViewModels, models - `set => field = value;` |
| `extension` members | TShark builders, Span utilities, filter helpers |
| Implicit Span conversions | `StreamingOutputParser`, zero-alloc parsing |
| Null-conditional assignment | `packet?.Field = value;` in parsers |
| Lambda modifiers | `(text, out result) => TryParse(...)` |

## Build Commands
```bash
dotnet build                                    # Build solution
dotnet test                                     # Run tests
dotnet test --filter "FullyQualifiedName~Name" # Single test
dotnet run --project src/PCAPAnalyzer.UI       # Run app
dotnet clean && dotnet build                   # Clean build
```

## Architecture

### Solution Structure
```
PCAPAnalyzer.sln
├── src/PCAPAnalyzer.Core      # Business logic, models, services
├── src/PCAPAnalyzer.TShark    # TShark CLI integration
├── src/PCAPAnalyzer.UI        # Avalonia MVVM desktop app
├── src/PCAPAnalyzer.API       # Optional REST API
└── tests/PCAPAnalyzer.Tests   # xUnit tests (mock TShark output)
```

### Data Flow
```
PCAP → TSharkService → PacketInfo Channel → AnalysisOrchestrator
                                                   ↓
                                    ┌──────────────┼──────────────┐
                                    ↓              ↓              ↓
                             Statistics      Anomaly         GeoIP
                                    ↓              ↓              ↓
                                    └──────────────┴──────────────┘
                                                   ↓
                                         AnalysisResult (cached)
                                                   ↓
                                         MainWindowViewModel → Tabs
```

### Key Services
- **ITSharkService** (`TShark/TSharkService.cs`): Spawns TShark with `-T fields`, streams via `System.Threading.Channels`
- **StreamingOutputParser**: Zero-allocation Span<T>-based tab-delimited parsing
- **ParallelTSharkService**: Splits large files with editcap for 3-4× speedup
- **AnalysisOrchestrator** (`Core/Orchestration/`): Phases - Load (2-50%), Analyze (50-92%), Cache (92-100%)
- **SessionAnalysisCache**: SQLite-backed cache for instant tab switching
- **IUnifiedAnomalyDetectionService**: 7 detectors (TCP, Network, Application, CryptoMining, DataExfiltration, IoT, VoIP)

### TShark Field Extraction (15 fields via `-T fields`)
```
frame.number, frame.time_epoch, frame.time_relative, frame.len,
ip.src, ip.dst, tcp.srcport, tcp.dstport, ip.proto,
_ws.col.info, tcp.flags, tcp.seq, tcp.ack, tcp.window_size, _ws.col.protocol
```

### UI (MVVM)
- **MainWindowViewModel**: Composition of 5 components (FileManager, Analysis, UIState, PacketManager, Charts)
- **Tab ViewModels**: Dashboard, Threats, VoiceQoS, CountryTraffic, Anomalies, HostInventory
- **Filter System**: `ITabFilterService` (transient, tab-isolated), `SmartFilterBuilderService` (INCLUDE/EXCLUDE, AND/OR)
- **Component Pattern**: Large VMs decomposed → `{Tab}{Component}ViewModel` (50+ files)

### Environment Variables
```
PCAP_ANALYZER_LARGE_FILE_MODE=1   # Large file optimization
PCAP_ANALYZER_LOW_MEMORY=1        # Reduced memory usage
PCAP_ANALYZER_CACHE_ENABLED=0     # Disable SQLite cache
```

## Quality Gates

### TShark Orchestration
- **Never** shell out blindly - use `SecureTSharkCommandBuilder`
- Handle TShark crashing/hanging on malformed packets gracefully
- Validate `tshark --version` on startup via `WiresharkToolDetector`
- **Streaming**: Parse stdout via Span<T>-based `StreamingOutputParser`
- **Zero strings in hot path** - process packet-by-packet

### Memory Safety
- No buffering full PCAP files or full TShark outputs
- Process packet-by-packet via Channels, never full-file loads

### Security
- Sanitize display filters (prevent command injection) - see `TSharkInputValidator`
- Redact sensitive fields from logs (e.g., `http.auth`)
- Convert Windows paths to WSL format when needed

## Development Rules

### Concurrent Execution
- Batch ALL file operations in single message
- Batch ALL todos in ONE TodoWrite call
- Chain bash commands: `dotnet build && dotnet test`

### File Organization
Never save to root. Use: `/src`, `/tests`, `/docs`, `/config`, `/scripts`

### Build Requirements
Fix all warnings/errors during `dotnet build`. Check after every task.
Environment: WSL2 on Windows 11.

### Plan Mode
Use for: new features, major refactors, architecture changes, multi-file mods.
Always ask if unclear on approach.

## Thinking Protocol
For complex analysis features, trigger **UltraThink** (`/ultrathink`) to debate:
- TShark display filter vs .NET-side LINQ processing
- Memory/performance trade-offs (streaming vs buffering)
- Security implications

### UltraThink Perspectives
- **Architect**: System design, Channels/streaming, memory management
- **Security Analyst**: Utility, workflow efficiency, credential detection, visualization
- **Devil's Advocate**: Edge cases, malformed packets, process hangs
