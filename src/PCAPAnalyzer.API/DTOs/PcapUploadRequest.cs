namespace PCAPAnalyzer.API.DTOs;

/// <summary>
/// Request model for PCAP file upload
/// </summary>
public class PcapUploadRequest
{
    public string? FileName { get; set; }
    public long FileSize { get; set; }
    public string? ContentType { get; set; }
    public byte[]? FileData { get; set; }
    public Dictionary<string, string>? Metadata { get; set; }
}

/// <summary>
/// Response model for PCAP file upload
/// </summary>
public class PcapUploadResponse
{
    public required string PcapId { get; set; }
    public required string FileName { get; set; }
    public long FileSize { get; set; }
    public DateTime UploadedAt { get; set; }
    public required string Status { get; set; }
    public Dictionary<string, string>? Links { get; set; }
}

/// <summary>
/// Request model for PCAP analysis
/// </summary>
public class AnalyzeRequest
{
    public string? AnalysisType { get; set; } // full, quick, custom
    public List<string>? Protocols { get; set; }
    public bool IncludeAnomalies { get; set; } = true;
    public bool IncludeGeographic { get; set; } = true;
    public Dictionary<string, object>? Options { get; set; }
}

/// <summary>
/// Analysis status response
/// </summary>
public class AnalysisStatusResponse
{
    public required string PcapId { get; set; }
    public required string Status { get; set; } // pending, running, completed, failed
    public int ProgressPercent { get; set; }
    public string? CurrentStep { get; set; }
    public DateTime? StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public string? ErrorMessage { get; set; }
    public Dictionary<string, string>? Links { get; set; }
}

/// <summary>
/// Paginated results wrapper
/// </summary>
public class PaginatedResult<T>
{
    public required IEnumerable<T> Items { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
    public bool HasPrevious => Page > 1;
    public bool HasNext => Page < TotalPages;
    public Dictionary<string, string>? Links { get; set; }
}
