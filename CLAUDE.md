# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build solution
dotnet build

# Run tests
dotnet test

# Run single test (by method name)
dotnet test --filter "FullyQualifiedName~MethodName"

# Run tests in specific class
dotnet test --filter "FullyQualifiedName~StatisticsServiceTests"

# Run application
dotnet run --project src/PCAPAnalyzer.UI

# Clean build
dotnet clean && dotnet build
```

## Architecture Overview

### Solution Structure
```
PCAPAnalyzer.sln (.NET 10.0)
├── src/PCAPAnalyzer.Core      # Business logic, models, services
├── src/PCAPAnalyzer.TShark    # TShark CLI integration
├── src/PCAPAnalyzer.UI        # Avalonia MVVM desktop app
├── src/PCAPAnalyzer.API       # Optional REST API
└── tests/PCAPAnalyzer.Tests   # xUnit tests
```

### Data Flow Architecture

```
PCAP File → TSharkService → PacketInfo Channel → AnalysisOrchestrator
                                                        ↓
                                          ┌─────────────┼─────────────┐
                                          ↓             ↓             ↓
                                   StatisticsService  AnomalyService  GeoIPService
                                          ↓             ↓             ↓
                                          └─────────────┴─────────────┘
                                                        ↓
                                              AnalysisResult (cached)
                                                        ↓
                                              MainWindowViewModel → Tab ViewModels
```

### Key Services

**ITSharkService** (`src/PCAPAnalyzer.TShark/TSharkService.cs`):
- Spawns TShark process with `-T fields` output
- Streams packets via `System.Threading.Channels`
- Supports Windows native, WSL2, Linux execution modes
- `ParallelTSharkService` splits large files with editcap for 3-4× speedup

**AnalysisOrchestrator** (`src/PCAPAnalyzer.Core/Orchestration/AnalysisOrchestrator.cs`):
- Central coordinator for complete PCAP analysis
- Phase 1: Load all packets (2-50% progress)
- Phase 2: Parallel analysis - Statistics, Threats, VoiceQoS (50-92%)
- Phase 3: Cache result in `SessionAnalysisCache` (92-100%)
- Returns `AnalysisResult` for instant tab switching

**IStatisticsService** (`src/PCAPAnalyzer.Core/Services/Statistics/`):
- `StatisticsService` - Core statistics calculation
- `EnhancedCachedStatisticsService` - Decorator with enterprise caching
- Includes GeoIP enrichment via `EnrichWithGeoAsync()`

**IUnifiedAnomalyDetectionService** (`src/PCAPAnalyzer.Core/Services/`):
- Orchestrates 7 specialized detectors:
  - TCPAnomalyDetector, NetworkAnomalyDetector, ApplicationAnomalyDetector
  - CryptoMiningDetector, DataExfiltrationDetector, IoTAnomalyDetector, VoipAnomalyDetector

### UI Architecture (MVVM)

**MainWindowViewModel** (`src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs`):
- Orchestrates 5 component ViewModels via composition pattern
- Components: `FileManager`, `Analysis`, `UIState`, `PacketManager`, `Charts`
- Tab ViewModels: `DashboardViewModel`, `ThreatsViewModel`, `VoiceQoSViewModel`, `CountryTrafficViewModel`
- Uses `ITabFilterService` for tab-isolated filtering (not global)

**Filter System**:
- `ITabFilterService` (transient) - Tab-specific filter instances
- `IGlobalFilterService` (singleton) - DEPRECATED, kept for compatibility
- `SmartFilterBuilderService` - INCLUDE/EXCLUDE groups, AND/OR logic, port ranges

**ServiceConfiguration** (`src/PCAPAnalyzer.UI/ServiceConfiguration.cs`):
- Central DI registration for all services
- Environment variables control behavior:
  - `PCAP_ANALYZER_LARGE_FILE_MODE=1` - Optimized for large files
  - `PCAP_ANALYZER_LOW_MEMORY=1` - Reduced memory usage
  - `PCAP_ANALYZER_USE_DUCKDB=1` - Use DuckDB instead of in-memory store
  - `PCAP_ANALYZER_CACHE_ENABLED=0` - Disable SQLite analysis cache

### Key Models

**PacketInfo** (`src/PCAPAnalyzer.Core/Models/PacketInfo.cs`):
- Core packet data structure (FrameNumber, Timestamp, IPs, Ports, Protocol, Length)
- L4Protocol (TCP/UDP/ICMP) vs L7Protocol (TLS, HTTP, DNS)

**NetworkStatistics** (`src/PCAPAnalyzer.Core/Models/`):
- Aggregated analysis results: ProtocolDistribution, CountryStatistics, TopTalkers
- AllUniqueIPs, TrafficFlows, PortStatistics

**AnalysisResult** (`src/PCAPAnalyzer.Core/Models/AnalysisResult.cs`):
- Complete preloaded result for all tabs
- Cached in `SessionAnalysisCache` for instant tab switching

## Project-Specific Rules

### Communication Style
Be extremely concise. Sacrifice grammar for concision.

### Plan Mode
Use `/plan` for: new features, major refactors, architecture changes, multi-file modifications.
Always ask if unclear on approach.

### Concurrent Execution
- Batch ALL file operations in single message
- Batch ALL todos in ONE TodoWrite call
- Chain bash commands: `dotnet build && dotnet test`

### File Organization
Never save to root. Use: `/src`, `/tests`, `/docs`, `/config`, `/scripts`

### TShark Integration
- Validate command inputs (prevent injection) - see `TSharkInputValidator`
- Convert Windows paths to WSL format when needed
- Use `WiresharkToolDetector` for cross-platform tool detection

### Build Requirements
Fix all warnings and errors during `dotnet build`. Check after every task.
Environment: WSL2 on Windows 11.
