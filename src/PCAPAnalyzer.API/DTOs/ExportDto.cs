namespace PCAPAnalyzer.API.DTOs;

/// <summary>
/// Export request
/// </summary>
public class ExportRequest
{
    public required string Format { get; set; } // pdf, csv, json, xml
    public List<string>? Sections { get; set; } // summary, protocols, conversations, anomalies
    public Dictionary<string, object>? Options { get; set; }
}

/// <summary>
/// Export response
/// </summary>
public class ExportResponse
{
    public required string ExportId { get; set; }
    public required string Format { get; set; }
    public required string DownloadUrl { get; set; }
    public long FileSize { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}
