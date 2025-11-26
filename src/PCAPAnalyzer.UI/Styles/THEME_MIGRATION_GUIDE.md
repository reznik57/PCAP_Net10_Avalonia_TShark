# Unified Dark Theme Migration Guide

## Overview
The PCAP Analyzer application now uses a single, comprehensive unified dark theme (`UnifiedDarkTheme.axaml`) that consolidates all styling into one coherent design system. This replaces the previous multiple theme files that were causing inconsistencies.

## Key Changes

### 1. Single Source of Truth
- **Before**: Multiple theme files (HarmonizedDesign.axaml, ModernDarkTheme.axaml, FinalHarmonization.axaml, etc.)
- **After**: One unified theme file (`UnifiedDarkTheme.axaml`)

### 2. Consistent Color Palette
The new theme uses a hierarchical color system:

#### Background Colors (darkest to lightest)
- `BackgroundLevel0`: #0A0B0F - Darkest background
- `BackgroundLevel1`: #0D1117 - Main window background
- `BackgroundLevel2`: #161B22 - Card background
- `BackgroundLevel3`: #1C2128 - Elevated background
- `BackgroundLevel4`: #22272E - Interactive background
- `BackgroundLevel5`: #2D333B - Hover background
- `BackgroundLevel6`: #373E47 - Active background

#### Text Colors
- `TextPrimary`: #F0F6FC - Main text
- `TextSecondary`: #8B949E - Secondary text
- `TextMuted`: #6E7681 - Muted text
- `TextDisabled`: #484F58 - Disabled text

#### Semantic Colors
- `Primary`: #3B82F6 - Primary actions
- `Success`: #10B981 - Success states
- `Warning`: #F59E0B - Warning states
- `Danger`: #EF4444 - Error/danger states
- `Info`: #8B5CF6 - Information

### 3. Standardized Components

#### Button Classes
```xml
<!-- Primary button -->
<Button Classes="primary">Click Me</Button>

<!-- Secondary button -->
<Button Classes="secondary">Cancel</Button>

<!-- Danger button -->
<Button Classes="danger">Delete</Button>

<!-- Ghost button (no background) -->
<Button Classes="ghost">Learn More</Button>
```

#### Card Styles
```xml
<!-- Standard card -->
<Border Classes="card">
    <!-- Content -->
</Border>

<!-- Statistics card -->
<Border Classes="stat-card">
    <!-- Stats content -->
</Border>

<!-- Packet card -->
<Border Classes="packet-card">
    <!-- Packet info -->
</Border>
```

#### Loading Indicators
```xml
<!-- Standard progress bar -->
<ProgressBar Classes="loading-bar" />

<!-- Loading spinner -->
<Border Classes="loading-spinner rotate" />

<!-- Shimmer effect for placeholders -->
<Border Classes="shimmer" Height="20" />

<!-- Stat card in loading state -->
<Border Classes="stat-card loading">
    <ProgressBar IsIndeterminate="True" />
</Border>
```

#### Typography Classes
```xml
<!-- Headings -->
<TextBlock Classes="heading-xxl">Page Title</TextBlock>
<TextBlock Classes="heading-xl">Section Title</TextBlock>
<TextBlock Classes="heading-lg">Subsection</TextBlock>
<TextBlock Classes="heading-md">Card Title</TextBlock>

<!-- Body text -->
<TextBlock Classes="body-lg">Large body text</TextBlock>
<TextBlock Classes="body-md">Normal body text</TextBlock>
<TextBlock Classes="body-sm">Small body text</TextBlock>

<!-- Special text -->
<TextBlock Classes="caption">Caption text</TextBlock>
<TextBlock Classes="label">Field Label</TextBlock>
```

#### Badges
```xml
<Border Classes="badge badge-primary">
    <TextBlock>Active</TextBlock>
</Border>

<Border Classes="badge badge-success">
    <TextBlock>Online</TextBlock>
</Border>

<Border Classes="badge badge-warning">
    <TextBlock>Pending</TextBlock>
</Border>

<Border Classes="badge badge-danger">
    <TextBlock>Error</TextBlock>
</Border>

<Border Classes="badge badge-info">
    <TextBlock>Info</TextBlock>
</Border>
```

### 4. Animation Classes
```xml
<!-- Fade in on load -->
<Border Classes="card fade-in" />

<!-- Scale in animation -->
<Border Classes="card scale-in" />

<!-- Slide in from right -->
<Border Classes="card slide-in-right" />

<!-- Continuous pulse -->
<Border Classes="pulse" />

<!-- Continuous rotation (for spinners) -->
<Border Classes="rotate" />

<!-- Shimmer loading effect -->
<Border Classes="shimmer" />
```

## Migration Steps

### Step 1: Update App.axaml
Remove all old theme references and add only the unified theme:

```xml
<Application.Styles>
    <FluentTheme />
    <StyleInclude Source="avares://Avalonia.Controls.DataGrid/Themes/Fluent.xaml"/>
    <!-- Single unified theme -->
    <StyleInclude Source="/Styles/UnifiedDarkTheme.axaml"/>
</Application.Styles>
```

### Step 2: Remove Local Style Definitions
Remove any local style definitions from individual views that override theme colors:

**Remove:**
```xml
<UserControl.Styles>
    <Style Selector="Border.stat-card">
        <Setter Property="Background" Value="#1E293B"/>
        <!-- Remove these local overrides -->
    </Style>
</UserControl.Styles>
```

### Step 3: Update Resource References
Replace old resource references with new ones:

**Old:**
```xml
Background="{DynamicResource BackgroundDarkBrush}"
Foreground="{DynamicResource TextPrimaryBrush}"
BorderBrush="{DynamicResource BorderSubtleBrush}"
```

**New:**
```xml
Background="{StaticResource BackgroundLevel2}"
Foreground="{StaticResource TextPrimary}"
BorderBrush="{StaticResource BorderSubtle}"
```

### Step 4: Update Class Names
Update class names to match the unified theme:

**Old:**
```xml
<Border Classes="modern-card stat-card-modern">
<Button Classes="primary-action">
<Button Classes="secondary-action">
```

**New:**
```xml
<Border Classes="stat-card">
<Button Classes="primary">
<Button Classes="secondary">
```

### Step 5: Standardize Loading States
Replace custom loading implementations with unified ones:

**Old:**
```xml
<!-- Custom loading implementation -->
<Grid IsVisible="{Binding IsLoading}">
    <Rectangle Fill="#80000000"/>
    <!-- Custom spinner -->
</Grid>
```

**New:**
```xml
<!-- Use unified loading indicator -->
<Border Classes="stat-card loading" IsVisible="{Binding IsLoading}">
    <ProgressBar Classes="loading-bar" IsIndeterminate="True" />
</Border>
```

## Benefits of the Unified Theme

1. **Consistency**: Single source of truth eliminates conflicting styles
2. **Maintainability**: Changes in one place affect the entire app
3. **Performance**: Reduced style resolution overhead
4. **Developer Experience**: Clear, documented style classes
5. **Accessibility**: Built-in WCAG 2.1 AA compliance
6. **Animations**: Smooth, consistent transitions throughout
7. **Responsive**: Scales properly across different screen sizes

## Common Issues and Solutions

### Issue: Colors look different after migration
**Solution**: This is expected. The unified theme uses a carefully chosen color palette. Update any hardcoded colors to use theme resources.

### Issue: Custom styles not working
**Solution**: Ensure custom styles are defined after the theme include and use proper selector specificity.

### Issue: Loading animations not showing
**Solution**: Add the appropriate animation classes (`rotate`, `pulse`, `shimmer`) to your loading elements.

### Issue: Buttons look different
**Solution**: Update button classes from old names (`primary-action`) to new names (`primary`).

## Theme Customization

To customize the theme while maintaining consistency:

1. Create a new file `CustomThemeOverrides.axaml`
2. Include it after `UnifiedDarkTheme.axaml` in App.axaml
3. Override only specific resources:

```xml
<Styles xmlns="https://github.com/avaloniaui"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
    <Styles.Resources>
        <!-- Override specific colors -->
        <Color x:Key="ColorPrimary">#YOUR_COLOR</Color>
        <SolidColorBrush x:Key="Primary" Color="{StaticResource ColorPrimary}"/>
    </Styles.Resources>
</Styles>
```

## Testing Checklist

After migration, verify:
- [ ] All tabs have consistent appearance
- [ ] Loading indicators work properly
- [ ] Stat cards have uniform styling
- [ ] Buttons have consistent hover/press effects
- [ ] DataGrids look uniform across views
- [ ] Tooltips appear correctly
- [ ] Animations are smooth
- [ ] Colors are consistent throughout
- [ ] Text is readable (proper contrast)
- [ ] Focus indicators are visible

## Support

For questions or issues with the unified theme:
1. Check this migration guide
2. Review the theme source at `/Styles/UnifiedDarkTheme.axaml`
3. Look for examples in migrated views
4. Test in different tabs to ensure consistency