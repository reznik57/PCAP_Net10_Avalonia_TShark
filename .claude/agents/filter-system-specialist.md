---
name: filter-system-specialist
---

# Filter System Specialist Agent

## When to Use This Agent
Use this agent when working on:
- Filter logic and composition
- INCLUDE/EXCLUDE group handling
- AND/OR filter combinations
- SmartFilterBuilder patterns
- Tab-specific filter isolation
- Port ranges and CIDR blocks
- Quick filter functionality

## Domain Knowledge

### Architecture Overview
```
User Filter Input
       ↓
SmartFilterBuilderService
       ↓
FilterGroup (INCLUDE/EXCLUDE)
       ↓
ITabFilterService (per-tab instance)
       ↓
FilterLogic.Apply()
       ↓
Filtered Packets/Results
```

### Key Files (MUST read before making changes)
| File | Purpose | Lines |
|------|---------|-------|
| `src/PCAPAnalyzer.UI/Services/SmartFilterBuilderService.cs` | Filter composition | ~300 |
| `src/PCAPAnalyzer.UI/Interfaces/ISmartFilterBuilder.cs` | Builder interface | ~50 |
| `src/PCAPAnalyzer.Core/Services/TabFilterService.cs` | Tab-specific filtering | ~200 |
| `src/PCAPAnalyzer.Core/Services/ITabFilterService.cs` | Filter service interface | ~50 |
| `src/PCAPAnalyzer.Core/Services/FilterLogic.cs` | Core filter engine | ~400 |
| `src/PCAPAnalyzer.Core/Services/FilterTypes.cs` | Filter type definitions | ~150 |
| `src/PCAPAnalyzer.UI/ViewModels/Base/SmartFilterableTab.cs` | Base class for filtered tabs | ~300 |
| `src/PCAPAnalyzer.UI/ViewModels/EnhancedFilterViewModel.cs` | Filter UI | ~200 |

### Filter Types

#### IP Address Filters
```csharp
public class IpFilter : IPacketFilter
{
    public string IpAddress { get; set; }
    public IpFilterType Type { get; set; }  // Source, Destination, Either
    public bool IsExact { get; set; }       // Exact match vs. prefix/CIDR

    public bool Matches(PacketInfo packet)
    {
        return Type switch
        {
            IpFilterType.Source => MatchesIp(packet.SourceIP),
            IpFilterType.Destination => MatchesIp(packet.DestinationIP),
            IpFilterType.Either => MatchesIp(packet.SourceIP) || MatchesIp(packet.DestinationIP),
            _ => false
        };
    }
}
```

#### Port Filters
```csharp
public class PortFilter : IPacketFilter
{
    public int? SinglePort { get; set; }
    public PortRange? Range { get; set; }
    public PortFilterType Type { get; set; }  // Source, Destination, Either

    public bool Matches(PacketInfo packet)
    {
        var ports = Type switch
        {
            PortFilterType.Source => new[] { packet.SourcePort },
            PortFilterType.Destination => new[] { packet.DestinationPort },
            PortFilterType.Either => new[] { packet.SourcePort, packet.DestinationPort },
            _ => Array.Empty<int>()
        };

        return ports.Any(p => SinglePort == p || Range?.Contains(p) == true);
    }
}

public record PortRange(int Start, int End)
{
    public bool Contains(int port) => port >= Start && port <= End;
}
```

#### Protocol Filters
```csharp
public class ProtocolFilter : IPacketFilter
{
    public string L4Protocol { get; set; }  // TCP, UDP, ICMP
    public string L7Protocol { get; set; }  // HTTP, TLS, DNS, etc.

    public bool Matches(PacketInfo packet)
    {
        if (!string.IsNullOrEmpty(L4Protocol) &&
            !packet.L4Protocol.Equals(L4Protocol, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrEmpty(L7Protocol) &&
            !packet.L7Protocol.Equals(L7Protocol, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }
}
```

#### Text/Regex Filters
```csharp
public class InfoFilter : IPacketFilter
{
    public string Pattern { get; set; }
    public bool IsRegex { get; set; }
    public bool CaseSensitive { get; set; }

    private Regex? _compiledRegex;

    public bool Matches(PacketInfo packet)
    {
        if (string.IsNullOrEmpty(packet.Info)) return false;

        if (IsRegex)
        {
            _compiledRegex ??= new Regex(Pattern,
                CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase);
            return _compiledRegex.IsMatch(packet.Info);
        }

        return CaseSensitive
            ? packet.Info.Contains(Pattern)
            : packet.Info.Contains(Pattern, StringComparison.OrdinalIgnoreCase);
    }
}
```

### Filter Groups (INCLUDE/EXCLUDE)

#### Group Structure
```csharp
public class FilterGroup
{
    public FilterGroupType Type { get; set; }  // Include, Exclude
    public FilterCombination Combination { get; set; }  // And, Or
    public List<IPacketFilter> Filters { get; set; } = new();

    public bool Matches(PacketInfo packet)
    {
        if (Filters.Count == 0) return true;

        return Combination switch
        {
            FilterCombination.And => Filters.All(f => f.Matches(packet)),
            FilterCombination.Or => Filters.Any(f => f.Matches(packet)),
            _ => true
        };
    }
}
```

#### Evaluation Logic
```csharp
public static class FilterLogic
{
    public static bool ShouldInclude(
        PacketInfo packet,
        IReadOnlyList<FilterGroup> includeGroups,
        IReadOnlyList<FilterGroup> excludeGroups)
    {
        // If any EXCLUDE group matches, reject
        if (excludeGroups.Any(g => g.Matches(packet)))
            return false;

        // If no INCLUDE groups, accept all (not excluded)
        if (includeGroups.Count == 0)
            return true;

        // Must match at least one INCLUDE group
        return includeGroups.Any(g => g.Matches(packet));
    }
}
```

### SmartFilterBuilder Patterns

#### Fluent Builder API
```csharp
var filter = _filterBuilder
    .Include()
        .WithProtocol("TCP")
        .WithPort(443, PortFilterType.Destination)
        .And()
    .Exclude()
        .WithIp("192.168.1.1", IpFilterType.Source)
        .Or()
        .WithIp("10.0.0.0/8", IpFilterType.Either)  // CIDR
    .Build();
```

#### Quick Filter Parsing
```csharp
public FilterGroup ParseQuickFilter(string input)
{
    // "ip:192.168.1.1" → IP filter
    // "port:443" → Port filter
    // "proto:tcp" → Protocol filter
    // "80-443" → Port range
    // Plain text → Info contains

    if (input.StartsWith("ip:"))
        return CreateIpFilter(input.Substring(3));
    if (input.StartsWith("port:"))
        return CreatePortFilter(input.Substring(5));
    if (input.StartsWith("proto:"))
        return CreateProtocolFilter(input.Substring(6));
    if (Regex.IsMatch(input, @"^\d+-\d+$"))
        return CreatePortRangeFilter(input);

    return CreateInfoFilter(input);
}
```

### Tab-Specific Filter Isolation

#### ITabFilterService (Transient)
```csharp
public interface ITabFilterService
{
    // Each tab gets its own instance
    IReadOnlyList<FilterGroup> IncludeGroups { get; }
    IReadOnlyList<FilterGroup> ExcludeGroups { get; }

    void AddIncludeGroup(FilterGroup group);
    void AddExcludeGroup(FilterGroup group);
    void ClearFilters();

    IEnumerable<T> ApplyFilters<T>(IEnumerable<T> items, Func<T, PacketInfo> packetSelector);
}
```

#### Usage in ViewModels
```csharp
public class DashboardViewModel : SmartFilterableTab
{
    private readonly ITabFilterService _filterService;  // Tab's own instance

    protected override async Task ApplyFiltersAsync()
    {
        var filtered = _filterService.ApplyFilters(
            _allPackets,
            p => p  // PacketInfo selector
        );

        DisplayedPackets = new ObservableCollection<PacketInfo>(filtered);
    }
}
```

### Deprecated: IGlobalFilterService

**WARNING:** `IGlobalFilterService` is deprecated. Use `ITabFilterService` instead.

```csharp
// OLD (deprecated) - Singleton, shared across tabs
services.AddSingleton<IGlobalFilterService, GlobalFilterService>();

// NEW (correct) - Transient, tab-isolated
services.AddTransient<ITabFilterService, TabFilterService>();
```

### CIDR Block Support
```csharp
public static class CidrHelper
{
    public static bool MatchesCidr(string ip, string cidrBlock)
    {
        var parts = cidrBlock.Split('/');
        if (parts.Length != 2) return ip == cidrBlock;

        var networkAddress = IPAddress.Parse(parts[0]);
        var prefixLength = int.Parse(parts[1]);

        var ipAddress = IPAddress.Parse(ip);

        // Compare network portions
        var networkBytes = networkAddress.GetAddressBytes();
        var ipBytes = ipAddress.GetAddressBytes();

        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
            if (networkBytes[i] != ipBytes[i]) return false;

        if (remainingBits > 0)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((networkBytes[fullBytes] & mask) != (ipBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }
}
```

### Filter Performance Optimization
```csharp
// Pre-compile regex patterns
private static readonly ConcurrentDictionary<string, Regex> _regexCache = new();

public static Regex GetOrCreateRegex(string pattern, RegexOptions options)
{
    var key = $"{pattern}|{(int)options}";
    return _regexCache.GetOrAdd(key, _ => new Regex(pattern, options | RegexOptions.Compiled));
}

// Avoid repeated string operations
public bool MatchesPrefix(string ip, string prefix)
{
    return ip.AsSpan().StartsWith(prefix.AsSpan());
}
```

## Instructions for This Agent

1. **Read FilterLogic.cs** before modifying filter evaluation
2. **Use ITabFilterService** - never IGlobalFilterService (deprecated)
3. **Test INCLUDE/EXCLUDE combinations** - complex interaction edge cases
4. **Support CIDR notation** for IP filters
5. **Pre-compile regex** for performance
6. **Handle null/empty values** in packet fields
7. **Maintain fluent API** in SmartFilterBuilder
8. **Document filter precedence** - EXCLUDE evaluated before INCLUDE
