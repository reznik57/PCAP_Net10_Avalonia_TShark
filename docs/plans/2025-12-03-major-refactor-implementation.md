# Major Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce all files to <25k tokens (~75KB) while improving maintainability

**Architecture:** Component extraction pattern for ViewModels, external JSON for data files, registry pattern for services

**Tech Stack:** .NET 10, Avalonia, CommunityToolkit.Mvvm, System.Text.Json, FrozenDictionary

---

## Phase 1: External JSON Data Extraction

### Task 1.1: Create PortDatabase JSON Schema and Data File

**Files:**
- Create: `src/PCAPAnalyzer.Core/Resources/Data/ports.json`
- Create: `src/PCAPAnalyzer.Core/Models/PortDataModels.cs`

**Step 1: Create the models file**

```csharp
// src/PCAPAnalyzer.Core/Models/PortDataModels.cs
namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// JSON-serializable port data file structure
/// </summary>
public sealed record PortDataFile
{
    public required string Version { get; init; }
    public required string LastUpdated { get; init; }
    public required List<PortEntry> Ports { get; init; }
}

/// <summary>
/// Individual port entry from JSON
/// </summary>
public sealed record PortEntry
{
    public required int Port { get; init; }
    public required string Transport { get; init; } // "TCP", "UDP", "Both"
    public required string ServiceName { get; init; }
    public required string Description { get; init; }
    public required string Risk { get; init; } // "Low", "Medium", "High", "Critical"
    public string? Category { get; init; }
    public string? Recommendation { get; init; }
}
```

**Step 2: Create ports.json with first 50 entries**

Create `src/PCAPAnalyzer.Core/Resources/Data/ports.json` - extract first 50 port entries from PortDatabase.cs static constructor into JSON format.

**Step 3: Verify JSON is valid**

Run: `dotnet build src/PCAPAnalyzer.Core`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.Core/Models/PortDataModels.cs src/PCAPAnalyzer.Core/Resources/Data/
git commit -m "feat(data): add port database JSON schema and initial data"
```

---

### Task 1.2: Extract Remaining Port Data to JSON

**Files:**
- Modify: `src/PCAPAnalyzer.Core/Resources/Data/ports.json`

**Step 1: Extract remaining ~550 port entries**

Continue extracting port entries from PortDatabase.cs lines 70-900 into ports.json, organized by category.

**Step 2: Validate JSON completeness**

Count entries in JSON matches count in original PortDatabase.cs (~600 ports).

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.Core/Resources/Data/ports.json
git commit -m "feat(data): complete port database JSON extraction (~600 entries)"
```

---

### Task 1.3: Create New PortDatabase Loader

**Files:**
- Create: `src/PCAPAnalyzer.Core/Security/PortDatabaseLoader.cs`
- Modify: `src/PCAPAnalyzer.Core/PCAPAnalyzer.Core.csproj` (add embedded resource)

**Step 1: Update .csproj for embedded resource**

Add to PCAPAnalyzer.Core.csproj:
```xml
<ItemGroup>
  <EmbeddedResource Include="Resources\Data\ports.json" />
</ItemGroup>
```

**Step 2: Create the loader class**

```csharp
// src/PCAPAnalyzer.Core/Security/PortDatabaseLoader.cs
using System.Collections.Frozen;
using System.Text.Json;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// Loads port database from embedded JSON resource
/// </summary>
public static class PortDatabaseLoader
{
    private static readonly Lazy<FrozenDictionary<PortKey, PortInfo>> _database = new(LoadDatabase);

    public static FrozenDictionary<PortKey, PortInfo> Database => _database.Value;

    private static FrozenDictionary<PortKey, PortInfo> LoadDatabase()
    {
        var assembly = typeof(PortDatabaseLoader).Assembly;
        using var stream = assembly.GetManifestResourceStream(
            "PCAPAnalyzer.Core.Resources.Data.ports.json")
            ?? throw new InvalidOperationException("ports.json not found as embedded resource");

        var data = JsonSerializer.Deserialize<PortDataFile>(stream)
            ?? throw new InvalidOperationException("Failed to deserialize ports.json");

        var dict = new Dictionary<PortKey, PortInfo>();
        foreach (var entry in data.Ports)
        {
            var transport = entry.Transport switch
            {
                "TCP" => TransportProtocol.TCP,
                "UDP" => TransportProtocol.UDP,
                "Both" => TransportProtocol.Both,
                _ => TransportProtocol.TCP
            };

            var risk = entry.Risk switch
            {
                "Low" => PortRisk.Low,
                "Medium" => PortRisk.Medium,
                "High" => PortRisk.High,
                "Critical" => PortRisk.Critical,
                _ => PortRisk.Unknown
            };

            var info = new PortInfo
            {
                ServiceName = entry.ServiceName,
                Description = entry.Description,
                Risk = risk,
                Category = entry.Category,
                Recommendation = entry.Recommendation
            };

            dict[new PortKey((ushort)entry.Port, transport)] = info;
        }

        return dict.ToFrozenDictionary();
    }
}
```

**Step 3: Build and verify**

Run: `dotnet build src/PCAPAnalyzer.Core`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.Core/Security/PortDatabaseLoader.cs src/PCAPAnalyzer.Core/PCAPAnalyzer.Core.csproj
git commit -m "feat(data): add PortDatabaseLoader for JSON resource"
```

---

### Task 1.4: Migrate PortDatabase to Use Loader

**Files:**
- Modify: `src/PCAPAnalyzer.Core/Security/PortDatabase.cs`

**Step 1: Replace static constructor with loader delegation**

Rewrite PortDatabase.cs to:
1. Keep public API (PortRisk enum, PortInfo record, PortKey record, lookup methods)
2. Remove all AddPort() calls from static constructor
3. Delegate to PortDatabaseLoader for data

Target size: ~150 lines (from ~900 lines)

**Step 2: Build and run tests**

Run: `dotnet build && dotnet test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.Core/Security/PortDatabase.cs
git commit -m "refactor(PortDatabase): migrate to JSON loader, reduce from 900 to ~150 lines"
```

---

### Task 1.5: Extract InsecurePortDetector Data to JSON

**Files:**
- Create: `src/PCAPAnalyzer.Core/Resources/Data/insecure-ports.json`
- Modify: `src/PCAPAnalyzer.Core/Services/InsecurePortDetector.cs`

**Step 1: Create insecure-ports.json**

Extract `_insecurePortDatabase` dictionary from InsecurePortDetector.cs (lines 37-532) to JSON format:

```json
{
  "version": "1.0",
  "lastUpdated": "2025-12-03",
  "ports": [
    {
      "port": 23,
      "protocol": "TCP",
      "serviceName": "Telnet",
      "riskLevel": "Critical",
      "isEncrypted": false,
      "knownVulnerabilities": ["CVE-2020-10188", "Plaintext credentials", "MITM attacks"],
      "recommendedAlternative": "SSH (Port 22)",
      "securityNotes": "Telnet transmits all data including passwords in plaintext.",
      "requiresImmediateAction": true
    }
  ]
}
```

**Step 2: Update .csproj**

Add embedded resource for insecure-ports.json.

**Step 3: Create InsecurePortDataLoader**

Similar pattern to PortDatabaseLoader.

**Step 4: Refactor InsecurePortDetector**

Remove inline dictionary initialization, load from JSON.
Target size: ~400 lines (from ~1192 lines)

**Step 5: Build and test**

Run: `dotnet build && dotnet test`
Expected: All tests pass

**Step 6: Commit**

```bash
git add src/PCAPAnalyzer.Core/Resources/Data/insecure-ports.json src/PCAPAnalyzer.Core/Services/InsecurePortDetector.cs
git commit -m "refactor(InsecurePortDetector): extract data to JSON, reduce from 1192 to ~400 lines"
```

---

## Phase 2: ThreatsViewModel Further Decomposition

ThreatsViewModel.cs is 81KB with some components already extracted. Need to move more logic to components.

### Task 2.1: Audit ThreatsViewModel Current State

**Files:**
- Read: `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`

**Step 1: Identify remaining responsibilities**

Read full file and list:
- Properties that should move to components
- Methods that should move to components
- What's already delegated vs what's inline

**Step 2: Document findings in TODO comments**

Add `// TODO: Move to {ComponentName}` comments.

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs
git commit -m "chore(ThreatsViewModel): audit and document remaining extraction targets"
```

---

### Task 2.2: Move Sorting Logic to ThreatsStatisticsViewModel

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ViewModels/Threats/ThreatsStatisticsViewModel.cs`
- Modify: `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`

**Step 1: Move SortOptions and sorting logic**

Move from ThreatsViewModel:
- `SortOptions` collection
- `SelectedSortOption` property
- `OnSelectedSortOptionChanged` partial method
- Sorting implementation in `UpdateThreatsList()`

**Step 2: Update ThreatsViewModel to delegate**

```csharp
public ObservableCollection<string> SortOptions => Statistics.SortOptions;
public string SelectedSortOption
{
    get => Statistics.SelectedSortOption;
    set => Statistics.SelectedSortOption = value;
}
```

**Step 3: Build and test**

Run: `dotnet build && dotnet test`

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Threats/ThreatsStatisticsViewModel.cs src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs
git commit -m "refactor(Threats): move sorting logic to ThreatsStatisticsViewModel"
```

---

### Task 2.3: Move Quick Filter Logic to ThreatsFilterViewModel

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ViewModels/Threats/ThreatsFilterViewModel.cs`
- Modify: `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`

**Step 1: Move quick filter properties and logic**

Move from ThreatsViewModel:
- `IsInsecureProtocolFilterActive`, `IsKnownCVEFilterActive`, etc.
- `ActiveQuickFilterChips` collection
- Quick filter toggle handlers

**Step 2: Build and test**

Run: `dotnet build && dotnet test`

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Threats/ThreatsFilterViewModel.cs src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs
git commit -m "refactor(Threats): move quick filter logic to ThreatsFilterViewModel"
```

---

### Task 2.4: Verify ThreatsViewModel Size Reduction

**Step 1: Check file size**

Run: `wc -c src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs`
Expected: <75KB

**Step 2: If still too large, identify next extraction candidates**

Continue extracting until under target.

---

## Phase 3: DashboardViewModel Decomposition

DashboardViewModel.cs is 76KB.

### Task 3.1: Audit DashboardViewModel

Similar to Task 2.1 - identify what's already extracted vs what remains.

### Task 3.2-3.5: Extract Components

Follow same pattern as ThreatsViewModel:
- Move chart-related properties to DashboardChartsViewModel
- Move statistics to DashboardStatisticsViewModel
- Move filter logic to appropriate components

---

## Phase 4: Service Decomposition

### Task 4.1: Split ProtocolDeepDiveService

**Files:**
- Create: `src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/IProtocolAnalyzer.cs`
- Create: `src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/ProtocolAnalyzerRegistry.cs`
- Create: `src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/Analyzers/DnsAnalyzer.cs`
- Create: `src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/Analyzers/HttpAnalyzer.cs`
- Create: `src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/Analyzers/TlsAnalyzer.cs`
- Modify: `src/PCAPAnalyzer.Core/Services/ProtocolDeepDiveService.cs`

**Step 1: Create interface**

```csharp
// IProtocolAnalyzer.cs
namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis;

public interface IProtocolAnalyzer
{
    string Protocol { get; }
    bool CanAnalyze(PacketInfo packet);
    ProtocolAnalysisResult Analyze(IReadOnlyList<PacketInfo> packets);
}
```

**Step 2: Extract DNS analyzer**

Move DNS-related analysis from ProtocolDeepDiveService to DnsAnalyzer.cs.

**Step 3: Extract HTTP analyzer**

Move HTTP-related analysis to HttpAnalyzer.cs.

**Step 4: Extract TLS analyzer**

Move TLS-related analysis to TlsAnalyzer.cs.

**Step 5: Create registry**

```csharp
// ProtocolAnalyzerRegistry.cs
public class ProtocolAnalyzerRegistry
{
    private readonly FrozenDictionary<string, IProtocolAnalyzer> _analyzers;

    public ProtocolAnalyzerRegistry(IEnumerable<IProtocolAnalyzer> analyzers)
    {
        _analyzers = analyzers.ToFrozenDictionary(a => a.Protocol, StringComparer.OrdinalIgnoreCase);
    }

    public IProtocolAnalyzer? GetAnalyzer(string protocol)
        => _analyzers.GetValueOrDefault(protocol);
}
```

**Step 6: Refactor ProtocolDeepDiveService**

Delegate to registry instead of inline switch statements.

**Step 7: Register in DI**

Update ServiceConfiguration.cs.

**Step 8: Build and test**

Run: `dotnet build && dotnet test`

**Step 9: Commit**

```bash
git add src/PCAPAnalyzer.Core/Services/ProtocolAnalysis/
git commit -m "refactor(ProtocolDeepDive): extract per-protocol analyzers with registry pattern"
```

---

## Phase 5: TSharkService Decomposition

### Task 5.1: Extract TSharkOutputParser

**Files:**
- Create: `src/PCAPAnalyzer.TShark/Processing/TSharkOutputParser.cs`
- Modify: `src/PCAPAnalyzer.TShark/TSharkService.cs`

Move field parsing logic to dedicated class.

### Task 5.2: Extract TSharkProcessManager

**Files:**
- Create: `src/PCAPAnalyzer.TShark/Processing/TSharkProcessManager.cs`

Move process spawning and lifecycle management.

### Task 5.3: Extract Platform Adapters

**Files:**
- Create: `src/PCAPAnalyzer.TShark/Platform/ITSharkPlatformAdapter.cs`
- Create: `src/PCAPAnalyzer.TShark/Platform/WindowsTSharkAdapter.cs`
- Create: `src/PCAPAnalyzer.TShark/Platform/WslTSharkAdapter.cs`
- Create: `src/PCAPAnalyzer.TShark/Platform/LinuxTSharkAdapter.cs`

Move platform-specific path handling and process configuration.

---

## Phase 6: Controls Decomposition

### Task 6.1: Extract ContinentMapControl Renderers

**Files:**
- Create: `src/PCAPAnalyzer.UI/Controls/Maps/Rendering/IMapRenderer.cs`
- Create: `src/PCAPAnalyzer.UI/Controls/Maps/Rendering/ContinentPathRenderer.cs`
- Create: `src/PCAPAnalyzer.UI/Controls/Maps/Rendering/TrafficHeatmapRenderer.cs`
- Modify: `src/PCAPAnalyzer.UI/Controls/ContinentMapControlV2.cs`

### Task 6.2: Extract Interaction Handlers

**Files:**
- Create: `src/PCAPAnalyzer.UI/Controls/Maps/Interaction/MapInteractionHandler.cs`
- Create: `src/PCAPAnalyzer.UI/Controls/Maps/Interaction/ContinentSelectionManager.cs`

---

## Phase 7: Final Verification

### Task 7.1: Verify All Files Under Limit

**Step 1: Check all file sizes**

```bash
find src -name "*.cs" -exec sh -c 'size=$(wc -c < "$1"); if [ $size -gt 75000 ]; then echo "$size $1"; fi' _ {} \;
```

Expected: No output (all files under 75KB)

### Task 7.2: Full Test Suite

Run: `dotnet test`
Expected: All tests pass

### Task 7.3: Manual Smoke Test

Launch application, verify:
- [ ] Dashboard tab loads
- [ ] Threats tab loads
- [ ] VoiceQoS tab loads
- [ ] CountryTraffic tab loads
- [ ] PCAP file loads and analyzes correctly

---

## Summary

| Phase | Files Modified | Estimated Tasks |
|-------|---------------|-----------------|
| 1. JSON Data | 6 | 5 |
| 2. ThreatsViewModel | 4 | 4 |
| 3. DashboardViewModel | 4 | 4 |
| 4. Services | 8 | 3 |
| 5. TShark | 6 | 3 |
| 6. Controls | 6 | 2 |
| 7. Verification | 0 | 3 |
| **Total** | **34** | **24** |
