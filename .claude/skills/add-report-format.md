---
name: pcap:add-report-format
description: Use when adding a new report export format (e.g., CSV, XML, DOCX) - ensures proper generator implementation, model mapping, and UI integration
---

# Add Report Format Skill

This skill guides you through adding a new report export format to the PCAP analyzer.

## Prerequisites

Before starting, determine:
- What format you're adding (CSV, XML, DOCX, etc.)
- What data should be included
- Any format-specific requirements (schema, styling)

## Mandatory Checklist

Create TodoWrite todos for EACH of these items:

### Phase 1: Interface & Model
- [ ] Add format to `ReportFormat` enum
- [ ] Create interface `I{Format}ReportGenerator` in `Services/Reporting/`
- [ ] Define any format-specific options in `ReportOptions`

### Phase 2: Generator Implementation
- [ ] Create `{Format}ReportGenerator` class
- [ ] Implement the generator interface
- [ ] Map `AnalysisReport` model to format output
- [ ] Handle all report sections (metadata, summary, threats, etc.)
- [ ] Implement proper error handling
- [ ] Use `ConfigureAwait(false)` on async calls

### Phase 3: Integration
- [ ] Register generator in `ServiceConfiguration.cs`
- [ ] Add format case to `ReportGeneratorService.GenerateReportAsync()`
- [ ] Update `ReportViewModel` to include new format option

### Phase 4: UI Integration
- [ ] Add format option to format selector in `ReportView.axaml`
- [ ] Add appropriate file extension to save dialog
- [ ] Test export flow end-to-end

### Phase 5: Testing
- [ ] Create test class `{Format}ReportGeneratorTests`
- [ ] Test with complete report data
- [ ] Test with minimal data (empty sections)
- [ ] Test large reports (1000+ anomalies)
- [ ] Validate output format correctness

### Phase 6: Validation
- [ ] Run `dotnet build` — zero warnings
- [ ] Run `dotnet test` — all tests pass
- [ ] Manual test: export real analysis to new format
- [ ] Verify output opens correctly in target application

## File Structure

```
src/PCAPAnalyzer.Core/Services/Reporting/
├── IHtmlReportGenerator.cs      (existing)
├── HtmlReportGenerator.cs       (existing)
├── IJsonReportGenerator.cs      (existing)
├── JsonReportGenerator.cs       (existing)
├── IPdfReportGenerator.cs       (existing)
├── PdfReportGenerator.cs        (existing)
├── I{Format}ReportGenerator.cs  ← NEW
├── {Format}ReportGenerator.cs   ← NEW
└── ReportingHelpers.cs          (shared utilities)
```

## Implementation Pattern

### Step 1: Create Interface
```csharp
// I{Format}ReportGenerator.cs
public interface ICsvReportGenerator
{
    Task<byte[]> GenerateAsync(
        AnalysisReport report,
        CancellationToken cancellationToken = default);

    Task<byte[]> GenerateAsync(
        AnalysisReport report,
        CsvReportOptions options,
        CancellationToken cancellationToken = default);
}

public class CsvReportOptions
{
    public char Delimiter { get; set; } = ',';
    public bool IncludeHeaders { get; set; } = true;
    public bool QuoteAllFields { get; set; } = false;
    public string DateFormat { get; set; } = "yyyy-MM-dd HH:mm:ss";
}
```

### Step 2: Implement Generator
```csharp
// CsvReportGenerator.cs
public class CsvReportGenerator : ICsvReportGenerator
{
    private readonly ILogger<CsvReportGenerator> _logger;

    public CsvReportGenerator(ILogger<CsvReportGenerator> logger)
    {
        _logger = logger;
    }

    public async Task<byte[]> GenerateAsync(
        AnalysisReport report,
        CancellationToken cancellationToken = default)
    {
        return await GenerateAsync(report, new CsvReportOptions(), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<byte[]> GenerateAsync(
        AnalysisReport report,
        CsvReportOptions options,
        CancellationToken cancellationToken = default)
    {
        var sb = new StringBuilder();

        // Metadata section
        AppendMetadata(sb, report.Metadata, options);

        // Threats section
        AppendThreats(sb, report.DetailedAnomalies, options);

        // Protocol distribution
        AppendProtocols(sb, report.Protocols, options);

        // Top talkers
        AppendTopTalkers(sb, report.TopTalkers, options);

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private void AppendMetadata(StringBuilder sb, ReportMetadata metadata, CsvReportOptions options)
    {
        if (options.IncludeHeaders)
            sb.AppendLine("Section,Key,Value");

        sb.AppendLine($"Metadata,ReportId,{Escape(metadata.ReportId, options)}");
        sb.AppendLine($"Metadata,GeneratedAt,{metadata.GeneratedAt.ToString(options.DateFormat)}");
        sb.AppendLine($"Metadata,AnalyzerVersion,{Escape(metadata.GeneratorVersion, options)}");
        sb.AppendLine();
    }

    private void AppendThreats(StringBuilder sb, List<AnomalyDetail> threats, CsvReportOptions options)
    {
        if (options.IncludeHeaders)
            sb.AppendLine("Type,Severity,Score,Description,FirstSeen,LastSeen,Count");

        foreach (var threat in threats)
        {
            sb.AppendLine(string.Join(options.Delimiter,
                Escape(threat.Type.ToString(), options),
                Escape(threat.Severity.ToString(), options),
                threat.SeverityScore.ToString("F2"),
                Escape(threat.Description, options),
                threat.FirstSeen.ToString(options.DateFormat),
                threat.LastSeen.ToString(options.DateFormat),
                threat.OccurrenceCount
            ));
        }
        sb.AppendLine();
    }

    private string Escape(string value, CsvReportOptions options)
    {
        if (string.IsNullOrEmpty(value)) return "";

        var needsQuotes = options.QuoteAllFields ||
                          value.Contains(options.Delimiter) ||
                          value.Contains('"') ||
                          value.Contains('\n');

        if (needsQuotes)
            return $"\"{value.Replace("\"", "\"\"")}\"";

        return value;
    }
}
```

### Step 3: Register in DI
```csharp
// ServiceConfiguration.cs
services.AddTransient<ICsvReportGenerator, CsvReportGenerator>();
```

### Step 4: Update ReportGeneratorService
```csharp
// ReportGeneratorService.cs
public async Task<byte[]> GenerateReportAsync(
    AnalysisResult result,
    ReportFormat format,
    ReportOptions options,
    CancellationToken cancellationToken = default)
{
    var report = BuildReportModel(result, options);

    return format switch
    {
        ReportFormat.Html => await _htmlGenerator.GenerateAsync(report, cancellationToken),
        ReportFormat.Json => await _jsonGenerator.GenerateAsync(report, cancellationToken),
        ReportFormat.Pdf => await _pdfGenerator.GenerateAsync(report, cancellationToken),
        ReportFormat.Csv => await _csvGenerator.GenerateAsync(report, cancellationToken),  // NEW
        _ => throw new ArgumentOutOfRangeException(nameof(format))
    };
}
```

### Step 5: Update UI
```xml
<!-- ReportView.axaml -->
<ComboBox SelectedIndex="{Binding SelectedFormatIndex}">
    <ComboBoxItem Content="HTML Report" />
    <ComboBoxItem Content="JSON Export" />
    <ComboBoxItem Content="PDF Document" />
    <ComboBoxItem Content="CSV Export" />  <!-- NEW -->
</ComboBox>
```

```csharp
// ReportViewModel.cs
private string GetFileExtension(ReportFormat format)
{
    return format switch
    {
        ReportFormat.Html => ".html",
        ReportFormat.Json => ".json",
        ReportFormat.Pdf => ".pdf",
        ReportFormat.Csv => ".csv",  // NEW
        _ => ".txt"
    };
}
```

## Security Checklist

- [ ] Sanitize all file paths in output
- [ ] No sensitive data (credentials) in reports
- [ ] Validate output format (prevent injection in CSV/XML)
- [ ] Handle special characters properly

## Common Mistakes to Avoid

1. **Missing format case in switch** — Update all switch statements
2. **Inconsistent escaping** — Handle delimiters, quotes, newlines
3. **Encoding issues** — Use UTF-8 with BOM for Excel compatibility
4. **Missing DI registration** — Generator won't be injected
5. **Incomplete sections** — Map all report sections

## When Done

Run the verification skill:
```
/superpowers:verification-before-completion
```
