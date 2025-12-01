---
name: pcap:add-filter-type
description: Use when adding a new filter capability (e.g., country filter, time range filter, payload filter) - ensures proper integration with SmartFilterBuilder and tab filter services
---

# Add Filter Type Skill

This skill guides you through adding a new filter type to the PCAP analyzer's filter system.

## Prerequisites

Before starting, determine:
- What data field the filter operates on
- Filter matching logic (exact, contains, range, regex)
- Whether it's an INCLUDE or EXCLUDE filter (or both)
- UI representation (dropdown, text input, slider)

## Current Filter Types

| Filter | Field | Matching |
|--------|-------|----------|
| IpFilter | SourceIP, DestinationIP | Exact, CIDR, Prefix |
| PortFilter | SourcePort, DestinationPort | Exact, Range |
| ProtocolFilter | L4Protocol, L7Protocol | Exact |
| InfoFilter | Info | Contains, Regex |

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Filter Model
- [ ] Create filter class implementing `IPacketFilter`
- [ ] Define filter properties (value, matching mode, etc.)
- [ ] Implement `Matches(PacketInfo packet)` method
- [ ] Add to `FilterTypes.cs`

### Phase 2: SmartFilterBuilder Integration
- [ ] Add fluent builder method(s) for new filter
- [ ] Update `ISmartFilterBuilder` interface
- [ ] Implement in `SmartFilterBuilderService`

### Phase 3: Quick Filter Parsing (Optional)
- [ ] Add parsing pattern for quick filter syntax
- [ ] Update `ParseQuickFilter` method
- [ ] Document quick filter syntax

### Phase 4: UI Components
- [ ] Add filter input component to `EnhancedFilterViewModel`
- [ ] Create AXAML for filter UI
- [ ] Wire up to SmartFilterBuilder

### Phase 5: Testing
- [ ] Unit test filter matching logic
- [ ] Test edge cases (null values, empty strings)
- [ ] Test INCLUDE/EXCLUDE behavior
- [ ] Integration test with full filter pipeline

### Phase 6: Validation
- [ ] Run `dotnet build` — zero warnings
- [ ] Run `dotnet test` — all tests pass
- [ ] Manual UI testing

## Filter Implementation Pattern

### Step 1: Create Filter Class
```csharp
// FilterTypes.cs (add new filter)
public class CountryFilter : IPacketFilter
{
    public string CountryCode { get; set; }
    public CountryFilterType Type { get; set; }

    public bool Matches(PacketInfo packet)
    {
        if (string.IsNullOrEmpty(CountryCode))
            return true;  // No filter = match all

        return Type switch
        {
            CountryFilterType.Source =>
                MatchesCountry(packet.SourceCountry),
            CountryFilterType.Destination =>
                MatchesCountry(packet.DestinationCountry),
            CountryFilterType.Either =>
                MatchesCountry(packet.SourceCountry) ||
                MatchesCountry(packet.DestinationCountry),
            _ => true
        };
    }

    private bool MatchesCountry(string? packetCountry)
    {
        if (string.IsNullOrEmpty(packetCountry))
            return false;

        return packetCountry.Equals(CountryCode, StringComparison.OrdinalIgnoreCase);
    }
}

public enum CountryFilterType
{
    Source,
    Destination,
    Either
}
```

### Step 2: Create Time Range Filter (Complex Example)
```csharp
public class TimeRangeFilter : IPacketFilter
{
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }

    public bool Matches(PacketInfo packet)
    {
        if (StartTime.HasValue && packet.Timestamp < StartTime.Value)
            return false;

        if (EndTime.HasValue && packet.Timestamp > EndTime.Value)
            return false;

        return true;
    }
}
```

### Step 3: Create Payload Size Filter
```csharp
public class PayloadSizeFilter : IPacketFilter
{
    public int? MinSize { get; set; }
    public int? MaxSize { get; set; }

    public bool Matches(PacketInfo packet)
    {
        if (MinSize.HasValue && packet.Length < MinSize.Value)
            return false;

        if (MaxSize.HasValue && packet.Length > MaxSize.Value)
            return false;

        return true;
    }
}
```

## SmartFilterBuilder Integration

### Update Interface
```csharp
// ISmartFilterBuilder.cs
public interface ISmartFilterBuilder
{
    // Existing methods...
    ISmartFilterBuilder WithIp(string ip, IpFilterType type);
    ISmartFilterBuilder WithPort(int port, PortFilterType type);
    ISmartFilterBuilder WithProtocol(string protocol);

    // New methods
    ISmartFilterBuilder WithCountry(string countryCode, CountryFilterType type);
    ISmartFilterBuilder WithTimeRange(DateTime? start, DateTime? end);
    ISmartFilterBuilder WithPayloadSize(int? min, int? max);
}
```

### Implement Builder Methods
```csharp
// SmartFilterBuilderService.cs
public ISmartFilterBuilder WithCountry(string countryCode, CountryFilterType type)
{
    _currentGroup.Filters.Add(new CountryFilter
    {
        CountryCode = countryCode,
        Type = type
    });
    return this;
}

public ISmartFilterBuilder WithTimeRange(DateTime? start, DateTime? end)
{
    _currentGroup.Filters.Add(new TimeRangeFilter
    {
        StartTime = start,
        EndTime = end
    });
    return this;
}

public ISmartFilterBuilder WithPayloadSize(int? min, int? max)
{
    _currentGroup.Filters.Add(new PayloadSizeFilter
    {
        MinSize = min,
        MaxSize = max
    });
    return this;
}
```

## Quick Filter Syntax

### Add Parsing Support
```csharp
// SmartFilterBuilderService.cs
public FilterGroup ParseQuickFilter(string input)
{
    // Existing patterns
    if (input.StartsWith("ip:"))
        return CreateIpFilter(input.Substring(3));
    if (input.StartsWith("port:"))
        return CreatePortFilter(input.Substring(5));
    if (input.StartsWith("proto:"))
        return CreateProtocolFilter(input.Substring(6));

    // New patterns
    if (input.StartsWith("country:"))
        return CreateCountryFilter(input.Substring(8));
    if (input.StartsWith("size:"))
        return CreateSizeFilter(input.Substring(5));
    if (input.StartsWith("time:"))
        return CreateTimeFilter(input.Substring(5));

    // Default: text search in Info field
    return CreateInfoFilter(input);
}

private FilterGroup CreateCountryFilter(string value)
{
    // Format: country:US or country:src:US or country:dst:DE
    var parts = value.Split(':');
    var type = CountryFilterType.Either;
    var code = value;

    if (parts.Length == 2)
    {
        type = parts[0].ToLower() switch
        {
            "src" => CountryFilterType.Source,
            "dst" => CountryFilterType.Destination,
            _ => CountryFilterType.Either
        };
        code = parts[1];
    }

    return new FilterGroup
    {
        Type = FilterGroupType.Include,
        Filters = { new CountryFilter { CountryCode = code, Type = type } }
    };
}

private FilterGroup CreateSizeFilter(string value)
{
    // Format: size:>1000 or size:<500 or size:100-1000
    int? min = null, max = null;

    if (value.StartsWith(">"))
        min = int.Parse(value.Substring(1));
    else if (value.StartsWith("<"))
        max = int.Parse(value.Substring(1));
    else if (value.Contains("-"))
    {
        var range = value.Split('-');
        min = int.Parse(range[0]);
        max = int.Parse(range[1]);
    }

    return new FilterGroup
    {
        Type = FilterGroupType.Include,
        Filters = { new PayloadSizeFilter { MinSize = min, MaxSize = max } }
    };
}
```

## UI Component

### AXAML
```xml
<!-- EnhancedFilterView.axaml -->
<StackPanel Spacing="8">
    <!-- Country Filter -->
    <DockPanel>
        <TextBlock Text="Country:" DockPanel.Dock="Left" Width="80"/>
        <ComboBox x:Name="CountryTypeCombo"
                  DockPanel.Dock="Left" Width="100"
                  SelectedIndex="{Binding CountryFilterType}">
            <ComboBoxItem Content="Either" />
            <ComboBoxItem Content="Source" />
            <ComboBoxItem Content="Destination" />
        </ComboBox>
        <AutoCompleteBox x:Name="CountryInput"
                         Text="{Binding CountryCode}"
                         ItemsSource="{Binding AvailableCountries}"
                         Watermark="US, DE, CN..." />
    </DockPanel>

    <!-- Size Filter -->
    <DockPanel>
        <TextBlock Text="Size:" DockPanel.Dock="Left" Width="80"/>
        <NumericUpDown Value="{Binding MinPayloadSize}"
                       Watermark="Min" Width="100" />
        <TextBlock Text=" - " VerticalAlignment="Center" />
        <NumericUpDown Value="{Binding MaxPayloadSize}"
                       Watermark="Max" Width="100" />
    </DockPanel>
</StackPanel>
```

### ViewModel Properties
```csharp
// EnhancedFilterViewModel.cs
[Reactive] public string CountryCode { get; set; }
[Reactive] public int CountryFilterType { get; set; }
[Reactive] public int? MinPayloadSize { get; set; }
[Reactive] public int? MaxPayloadSize { get; set; }

public ObservableCollection<string> AvailableCountries { get; } =
    new(CountryNameHelper.GetAllCountryCodes());

private void ApplyFilters()
{
    var builder = _filterBuilder.Include();

    if (!string.IsNullOrEmpty(CountryCode))
    {
        builder.WithCountry(CountryCode, (CountryFilterType)CountryFilterType);
    }

    if (MinPayloadSize.HasValue || MaxPayloadSize.HasValue)
    {
        builder.WithPayloadSize(MinPayloadSize, MaxPayloadSize);
    }

    var filters = builder.Build();
    _filterService.SetFilters(filters);
}
```

## Testing Template

```csharp
public class CountryFilterTests
{
    [Theory]
    [InlineData("US", "US", CountryFilterType.Source, true)]
    [InlineData("US", "DE", CountryFilterType.Source, false)]
    [InlineData("US", "US", CountryFilterType.Either, true)]
    [InlineData("US", null, CountryFilterType.Source, false)]
    public void Matches_ReturnsExpected(
        string filterCode,
        string packetCountry,
        CountryFilterType type,
        bool expected)
    {
        var filter = new CountryFilter
        {
            CountryCode = filterCode,
            Type = type
        };

        var packet = new PacketInfo { SourceCountry = packetCountry };

        Assert.Equal(expected, filter.Matches(packet));
    }
}
```

## Common Mistakes to Avoid

1. **Null handling** — Always handle null/empty packet fields
2. **Case sensitivity** — Use StringComparison.OrdinalIgnoreCase
3. **Missing builder method** — Update interface AND implementation
4. **Filter order** — EXCLUDE evaluated before INCLUDE
5. **Quick filter conflicts** — Ensure syntax doesn't overlap existing patterns

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
