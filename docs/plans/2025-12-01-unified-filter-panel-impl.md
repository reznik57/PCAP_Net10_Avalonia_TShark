# Unified Filter Panel Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current 3-section filter UI (~350px) with a unified panel (~180px) featuring global mode toggle, summary rows, and tabbed filter organization.

**Architecture:** Global filter state singleton stores Include/Exclude criteria. UI shows mode toggle + active filter summary at top, category tabs below. Filters apply globally with lazy per-tab computation via version checking.

**Tech Stack:** Avalonia UI, CommunityToolkit.Mvvm, C# 12, .NET 10

---

## Phase 1: Global Filter State Infrastructure

### Task 1.1: Create GlobalFilterState Model

**Files:**
- Create: `src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs`
- Test: `tests/PCAPAnalyzer.Tests/Models/GlobalFilterStateTests.cs`

**Step 1: Write the failing test**

```csharp
// tests/PCAPAnalyzer.Tests/Models/GlobalFilterStateTests.cs
using PCAPAnalyzer.UI.Models;
using Xunit;

namespace PCAPAnalyzer.Tests.Models;

public class GlobalFilterStateTests
{
    [Fact]
    public void AddIncludeFilter_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var initialVersion = state.Version;

        state.AddIncludeProtocol("TCP");

        Assert.Equal(initialVersion + 1, state.Version);
    }

    [Fact]
    public void AddExcludeFilter_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var initialVersion = state.Version;

        state.AddExcludeIP("192.168.1.1");

        Assert.Equal(initialVersion + 1, state.Version);
    }

    [Fact]
    public void Clear_ResetsAllFiltersAndIncreasesVersion()
    {
        var state = new GlobalFilterState();
        state.AddIncludeProtocol("TCP");
        state.AddExcludeIP("10.0.0.1");
        var versionAfterAdds = state.Version;

        state.Clear();

        Assert.Empty(state.IncludeFilters.Protocols);
        Assert.Empty(state.ExcludeFilters.IPs);
        Assert.Equal(versionAfterAdds + 1, state.Version);
    }

    [Fact]
    public void HasActiveFilters_ReturnsTrueWhenFiltersExist()
    {
        var state = new GlobalFilterState();
        Assert.False(state.HasActiveFilters);

        state.AddIncludeProtocol("TCP");

        Assert.True(state.HasActiveFilters);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `dotnet test tests/PCAPAnalyzer.Tests --filter "FullyQualifiedName~GlobalFilterStateTests" -v n`
Expected: FAIL with "type or namespace 'GlobalFilterState' could not be found"

**Step 3: Write minimal implementation**

```csharp
// src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Global filter state singleton. Stores Include/Exclude criteria.
/// Version increments on every change for lazy per-tab evaluation.
/// </summary>
public partial class GlobalFilterState : ObservableObject
{
    [ObservableProperty] private FilterMode _currentMode = FilterMode.Include;
    [ObservableProperty] private int _version;

    public FilterCriteria IncludeFilters { get; } = new();
    public FilterCriteria ExcludeFilters { get; } = new();

    public bool HasActiveFilters => IncludeFilters.HasAny || ExcludeFilters.HasAny;

    public event Action? OnFilterChanged;

    public void AddIncludeProtocol(string protocol)
    {
        IncludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddExcludeProtocol(string protocol)
    {
        ExcludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddIncludeIP(string ip)
    {
        IncludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddExcludeIP(string ip)
    {
        ExcludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddIncludePort(string port)
    {
        IncludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void AddExcludePort(string port)
    {
        ExcludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void RemoveIncludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => IncludeFilters.Protocols.Remove(value),
            FilterCategory.IP => IncludeFilters.IPs.Remove(value),
            FilterCategory.Port => IncludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => IncludeFilters.QuickFilters.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void RemoveExcludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => ExcludeFilters.Protocols.Remove(value),
            FilterCategory.IP => ExcludeFilters.IPs.Remove(value),
            FilterCategory.Port => ExcludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => ExcludeFilters.QuickFilters.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void Clear()
    {
        IncludeFilters.Clear();
        ExcludeFilters.Clear();
        IncrementVersion();
    }

    private void IncrementVersion()
    {
        Version++;
        OnFilterChanged?.Invoke();
    }
}

public enum FilterMode { Include, Exclude }

public enum FilterCategory { Protocol, IP, Port, QuickFilter, Severity, ThreatCategory }

public class FilterCriteria
{
    public ObservableCollection<string> Protocols { get; } = new();
    public ObservableCollection<string> IPs { get; } = new();
    public ObservableCollection<string> Ports { get; } = new();
    public ObservableCollection<string> QuickFilters { get; } = new();
    public ObservableCollection<string> Severities { get; } = new();
    public ObservableCollection<string> ThreatCategories { get; } = new();
    public ObservableCollection<string> TlsVersions { get; } = new();
    public ObservableCollection<string> Countries { get; } = new();

    public bool HasAny => Protocols.Count > 0 || IPs.Count > 0 || Ports.Count > 0 ||
                          QuickFilters.Count > 0 || Severities.Count > 0 ||
                          ThreatCategories.Count > 0 || TlsVersions.Count > 0 ||
                          Countries.Count > 0;

    public void Clear()
    {
        Protocols.Clear();
        IPs.Clear();
        Ports.Clear();
        QuickFilters.Clear();
        Severities.Clear();
        ThreatCategories.Clear();
        TlsVersions.Clear();
        Countries.Clear();
    }
}
```

**Step 4: Run test to verify it passes**

Run: `dotnet test tests/PCAPAnalyzer.Tests --filter "FullyQualifiedName~GlobalFilterStateTests" -v n`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs tests/PCAPAnalyzer.Tests/Models/GlobalFilterStateTests.cs
git commit -m "feat(filters): add GlobalFilterState model with version tracking"
```

---

### Task 1.2: Register GlobalFilterState as Singleton

**Files:**
- Modify: `src/PCAPAnalyzer.UI/ServiceConfiguration.cs`

**Step 1: Add singleton registration**

Find the `ConfigureServices` method and add:

```csharp
// In ServiceConfiguration.cs, inside ConfigureServices method
// Add after other singleton registrations:

// Global filter state (singleton - shared across all tabs)
services.AddSingleton<GlobalFilterState>();
```

**Step 2: Build to verify**

Run: `dotnet build src/PCAPAnalyzer.UI`
Expected: Build succeeded. 0 Errors.

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ServiceConfiguration.cs
git commit -m "feat(filters): register GlobalFilterState as singleton"
```

---

## Phase 2: Active Filter Summary ViewModel

### Task 2.1: Create ActiveFilterChip Model

**Files:**
- Create: `src/PCAPAnalyzer.UI/Models/ActiveFilterChip.cs`

**Step 1: Write implementation**

```csharp
// src/PCAPAnalyzer.UI/Models/ActiveFilterChip.cs
using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents an active filter chip in the summary row.
/// </summary>
public class ActiveFilterChip
{
    public required string DisplayLabel { get; init; }
    public required string Value { get; init; }
    public required FilterCategory Category { get; init; }
    public required bool IsInclude { get; init; }
    public required ICommand RemoveCommand { get; init; }

    /// <summary>
    /// Format: "Protocol:TCP" or "IP:192.168.1.1" or "Port:443"
    /// </summary>
    public string TypedLabel => Category switch
    {
        FilterCategory.Protocol => DisplayLabel,
        FilterCategory.IP => DisplayLabel,
        FilterCategory.Port => $"Port:{DisplayLabel}",
        FilterCategory.QuickFilter => DisplayLabel,
        FilterCategory.Severity => DisplayLabel,
        FilterCategory.ThreatCategory => DisplayLabel,
        _ => DisplayLabel
    };
}
```

**Step 2: Build to verify**

Run: `dotnet build src/PCAPAnalyzer.UI`
Expected: Build succeeded.

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/Models/ActiveFilterChip.cs
git commit -m "feat(filters): add ActiveFilterChip model"
```

---

### Task 2.2: Create FilterSummaryViewModel

**Files:**
- Create: `src/PCAPAnalyzer.UI/ViewModels/Components/FilterSummaryViewModel.cs`

**Step 1: Write implementation**

```csharp
// src/PCAPAnalyzer.UI/ViewModels/Components/FilterSummaryViewModel.cs
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for the active filter summary rows.
/// Displays include/exclude chips with remove functionality.
/// </summary>
public partial class FilterSummaryViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    public ObservableCollection<ActiveFilterChip> IncludeChips { get; } = new();
    public ObservableCollection<ActiveFilterChip> ExcludeChips { get; } = new();

    [ObservableProperty] private bool _hasIncludeFilters;
    [ObservableProperty] private bool _hasExcludeFilters;

    public FilterSummaryViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        _filterState.OnFilterChanged += RefreshChips;
        RefreshChips();
    }

    private void RefreshChips()
    {
        RefreshIncludeChips();
        RefreshExcludeChips();
    }

    private void RefreshIncludeChips()
    {
        IncludeChips.Clear();

        foreach (var p in _filterState.IncludeFilters.Protocols)
            IncludeChips.Add(CreateChip(p, p, FilterCategory.Protocol, true));
        foreach (var ip in _filterState.IncludeFilters.IPs)
            IncludeChips.Add(CreateChip(ip, ip, FilterCategory.IP, true));
        foreach (var port in _filterState.IncludeFilters.Ports)
            IncludeChips.Add(CreateChip(port, port, FilterCategory.Port, true));
        foreach (var qf in _filterState.IncludeFilters.QuickFilters)
            IncludeChips.Add(CreateChip(qf, qf, FilterCategory.QuickFilter, true));
        foreach (var sev in _filterState.IncludeFilters.Severities)
            IncludeChips.Add(CreateChip(sev, sev, FilterCategory.Severity, true));
        foreach (var cat in _filterState.IncludeFilters.ThreatCategories)
            IncludeChips.Add(CreateChip(cat, cat, FilterCategory.ThreatCategory, true));

        HasIncludeFilters = IncludeChips.Count > 0;
    }

    private void RefreshExcludeChips()
    {
        ExcludeChips.Clear();

        foreach (var p in _filterState.ExcludeFilters.Protocols)
            ExcludeChips.Add(CreateChip(p, p, FilterCategory.Protocol, false));
        foreach (var ip in _filterState.ExcludeFilters.IPs)
            ExcludeChips.Add(CreateChip(ip, ip, FilterCategory.IP, false));
        foreach (var port in _filterState.ExcludeFilters.Ports)
            ExcludeChips.Add(CreateChip(port, port, FilterCategory.Port, false));
        foreach (var qf in _filterState.ExcludeFilters.QuickFilters)
            ExcludeChips.Add(CreateChip(qf, qf, FilterCategory.QuickFilter, false));
        foreach (var sev in _filterState.ExcludeFilters.Severities)
            ExcludeChips.Add(CreateChip(sev, sev, FilterCategory.Severity, false));
        foreach (var cat in _filterState.ExcludeFilters.ThreatCategories)
            ExcludeChips.Add(CreateChip(cat, cat, FilterCategory.ThreatCategory, false));

        HasExcludeFilters = ExcludeChips.Count > 0;
    }

    private ActiveFilterChip CreateChip(string label, string value, FilterCategory category, bool isInclude)
    {
        return new ActiveFilterChip
        {
            DisplayLabel = label,
            Value = value,
            Category = category,
            IsInclude = isInclude,
            RemoveCommand = new RelayCommand(() =>
            {
                if (isInclude)
                    _filterState.RemoveIncludeFilter(value, category);
                else
                    _filterState.RemoveExcludeFilter(value, category);
            })
        };
    }
}
```

**Step 2: Build to verify**

Run: `dotnet build src/PCAPAnalyzer.UI`
Expected: Build succeeded.

**Step 3: Commit**

```bash
git add src/PCAPAnalyzer.UI/ViewModels/Components/FilterSummaryViewModel.cs
git commit -m "feat(filters): add FilterSummaryViewModel for active filter chips"
```

---

## Phase 3: Unified Filter Panel UI

### Task 3.1: Create UnifiedFilterPanelControl AXAML

**Files:**
- Create: `src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml`
- Create: `src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml.cs`

**Step 1: Write AXAML**

```xml
<!-- src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml -->
<UserControl xmlns="https://github.com/avaloniaui"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
             xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
             mc:Ignorable="d" d:DesignWidth="900" d:DesignHeight="300"
             x:Class="PCAPAnalyzer.UI.Views.Controls.UnifiedFilterPanelControl">

    <Border Classes="modern-card-unified" Padding="16,12" Margin="0,0,0,16"
            BorderThickness="2" BorderBrush="#30363D">
        <StackPanel Spacing="12">

            <!-- Row 1: Mode Toggle + Apply/Clear Buttons -->
            <Grid ColumnDefinitions="Auto,16,Auto,*,Auto,8,Auto">
                <!-- Include Button -->
                <Button Grid.Column="0" Classes="mode-button include"
                        Command="{Binding SetIncludeModeCommand}"
                        IsEnabled="{Binding !IsIncludeMode}">
                    <StackPanel Orientation="Horizontal" Spacing="6">
                        <TextBlock Text="+" FontSize="14" FontWeight="Bold"/>
                        <TextBlock Text="Include" FontSize="12" FontWeight="SemiBold"/>
                    </StackPanel>
                </Button>

                <!-- Exclude Button -->
                <Button Grid.Column="2" Classes="mode-button exclude"
                        Command="{Binding SetExcludeModeCommand}"
                        IsEnabled="{Binding IsIncludeMode}">
                    <StackPanel Orientation="Horizontal" Spacing="6">
                        <TextBlock Text="−" FontSize="14" FontWeight="Bold"/>
                        <TextBlock Text="Exclude" FontSize="12" FontWeight="SemiBold"/>
                    </StackPanel>
                </Button>

                <!-- Apply Button -->
                <Button Grid.Column="4" Command="{Binding ApplyFiltersCommand}"
                        Classes="primary-action" Height="32" Padding="16,0">
                    <StackPanel Orientation="Horizontal" Spacing="6">
                        <TextBlock Text="Apply" FontSize="12" FontWeight="SemiBold"/>
                    </StackPanel>
                </Button>

                <!-- Clear Button -->
                <Button Grid.Column="6" Command="{Binding ClearFiltersCommand}"
                        Classes="secondary-action" Height="32" Padding="16,0">
                    <TextBlock Text="Clear" FontSize="12"/>
                </Button>
            </Grid>

            <!-- Row 2: Include Summary (visible when has includes) -->
            <Border Background="#0D1117" BorderBrush="#2EA043" BorderThickness="1"
                    CornerRadius="6" Padding="10,6"
                    IsVisible="{Binding Summary.HasIncludeFilters}">
                <StackPanel Orientation="Horizontal" Spacing="8">
                    <TextBlock Text="+" FontSize="12" FontWeight="Bold" Foreground="#3FB950"
                               VerticalAlignment="Center"/>
                    <TextBlock Text="Including:" FontSize="11" Foreground="#7EE787"
                               VerticalAlignment="Center"/>
                    <ItemsControl ItemsSource="{Binding Summary.IncludeChips}">
                        <ItemsControl.ItemsPanel>
                            <ItemsPanelTemplate>
                                <WrapPanel Orientation="Horizontal"/>
                            </ItemsPanelTemplate>
                        </ItemsControl.ItemsPanel>
                        <ItemsControl.ItemTemplate>
                            <DataTemplate>
                                <Border Background="#1A3D1A" BorderBrush="#2EA043" BorderThickness="1"
                                        CornerRadius="10" Padding="8,3" Margin="0,0,6,0">
                                    <StackPanel Orientation="Horizontal" Spacing="6">
                                        <TextBlock Text="{Binding TypedLabel}" FontSize="11"
                                                   Foreground="#7EE787" VerticalAlignment="Center"/>
                                        <Button Command="{Binding RemoveCommand}"
                                                Background="Transparent" BorderThickness="0"
                                                Padding="2" Cursor="Hand">
                                            <TextBlock Text="x" Foreground="#F85149" FontSize="10"/>
                                        </Button>
                                    </StackPanel>
                                </Border>
                            </DataTemplate>
                        </ItemsControl.ItemTemplate>
                    </ItemsControl>
                </StackPanel>
            </Border>

            <!-- Row 3: Exclude Summary (visible when has excludes) -->
            <Border Background="#0D1117" BorderBrush="#F85149" BorderThickness="1"
                    CornerRadius="6" Padding="10,6"
                    IsVisible="{Binding Summary.HasExcludeFilters}">
                <StackPanel Orientation="Horizontal" Spacing="8">
                    <TextBlock Text="−" FontSize="14" FontWeight="Bold" Foreground="#F85149"
                               VerticalAlignment="Center"/>
                    <TextBlock Text="Excluding:" FontSize="11" Foreground="#FF7B72"
                               VerticalAlignment="Center"/>
                    <ItemsControl ItemsSource="{Binding Summary.ExcludeChips}">
                        <ItemsControl.ItemsPanel>
                            <ItemsPanelTemplate>
                                <WrapPanel Orientation="Horizontal"/>
                            </ItemsPanelTemplate>
                        </ItemsControl.ItemsPanel>
                        <ItemsControl.ItemTemplate>
                            <DataTemplate>
                                <Border Background="#3D1A1A" BorderBrush="#F85149" BorderThickness="1"
                                        CornerRadius="10" Padding="8,3" Margin="0,0,6,0">
                                    <StackPanel Orientation="Horizontal" Spacing="6">
                                        <TextBlock Text="{Binding TypedLabel}" FontSize="11"
                                                   Foreground="#FF7B72" VerticalAlignment="Center"/>
                                        <Button Command="{Binding RemoveCommand}"
                                                Background="Transparent" BorderThickness="0"
                                                Padding="2" Cursor="Hand">
                                            <TextBlock Text="x" Foreground="#F85149" FontSize="10"/>
                                        </Button>
                                    </StackPanel>
                                </Border>
                            </DataTemplate>
                        </ItemsControl.ItemTemplate>
                    </ItemsControl>
                </StackPanel>
            </Border>

            <!-- Row 4: Filter Category Tabs -->
            <TabControl SelectedIndex="{Binding SelectedTabIndex}">
                <TabItem Header="General">
                    <ContentControl Content="{Binding GeneralFilterContent}"/>
                </TabItem>
                <TabItem Header="Threats">
                    <ContentControl Content="{Binding ThreatsFilterContent}"/>
                </TabItem>
                <TabItem Header="VoiceQoS">
                    <ContentControl Content="{Binding VoiceQoSFilterContent}"/>
                </TabItem>
                <TabItem Header="Country">
                    <ContentControl Content="{Binding CountryFilterContent}"/>
                </TabItem>
            </TabControl>

        </StackPanel>
    </Border>

    <UserControl.Styles>
        <Style Selector="Button.mode-button">
            <Setter Property="Height" Value="32"/>
            <Setter Property="Padding" Value="12,0"/>
            <Setter Property="CornerRadius" Value="4"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style Selector="Button.mode-button.include">
            <Setter Property="Background" Value="#1E5F4B"/>
            <Setter Property="BorderBrush" Value="#10B981"/>
            <Setter Property="Foreground" Value="#34D399"/>
        </Style>
        <Style Selector="Button.mode-button.include:disabled">
            <Setter Property="Background" Value="#2EA043"/>
            <Setter Property="BorderBrush" Value="#3FB950"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
        </Style>
        <Style Selector="Button.mode-button.exclude">
            <Setter Property="Background" Value="#3D1A1A"/>
            <Setter Property="BorderBrush" Value="#EF4444"/>
            <Setter Property="Foreground" Value="#F87171"/>
        </Style>
        <Style Selector="Button.mode-button.exclude:disabled">
            <Setter Property="Background" Value="#DC2626"/>
            <Setter Property="BorderBrush" Value="#F85149"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
        </Style>
    </UserControl.Styles>
</UserControl>
```

**Step 2: Write code-behind**

```csharp
// src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml.cs
using Avalonia.Controls;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class UnifiedFilterPanelControl : UserControl
{
    public UnifiedFilterPanelControl()
    {
        InitializeComponent();
    }
}
```

**Step 3: Build to verify**

Run: `dotnet build src/PCAPAnalyzer.UI`
Expected: Build succeeded.

**Step 4: Commit**

```bash
git add src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml.cs
git commit -m "feat(filters): add UnifiedFilterPanelControl skeleton UI"
```

---

## Phase 4: Integration (Deferred)

**Note:** Phases 4-6 involve:
- Creating UnifiedFilterPanelViewModel with tab content
- Creating GeneralFilterTabContent (protocols, IPs, ports, quick filters)
- Creating ThreatsFilterTabContent (severity, category, search)
- Creating VoiceQoSFilterTabContent (codecs, quality)
- Creating CountryFilterTabContent (regions, countries)
- Integrating with DashboardView to replace old FilterPanelControl
- Implementing lazy per-tab filter application
- Migrating filter logic from DashboardViewModel.Filters.cs

These phases are complex and should be implemented incrementally after Phase 3 is validated.

---

## Summary of Files

**New Files:**
- `src/PCAPAnalyzer.UI/Models/GlobalFilterState.cs`
- `src/PCAPAnalyzer.UI/Models/ActiveFilterChip.cs`
- `src/PCAPAnalyzer.UI/ViewModels/Components/FilterSummaryViewModel.cs`
- `src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml`
- `src/PCAPAnalyzer.UI/Views/Controls/UnifiedFilterPanelControl.axaml.cs`
- `tests/PCAPAnalyzer.Tests/Models/GlobalFilterStateTests.cs`

**Modified Files:**
- `src/PCAPAnalyzer.UI/ServiceConfiguration.cs` (add singleton)

**Files to Replace (later phases):**
- `src/PCAPAnalyzer.UI/Views/Controls/FilterPanelControl.axaml` (719 lines → deprecated)

---

## Execution Notes

1. Build after every step to catch errors early
2. Run tests after completing each Task
3. Commit frequently with descriptive messages
4. The UI can be iteratively refined after basic structure works
5. Tab content can be migrated from existing QuickFilterControl.axaml patterns
