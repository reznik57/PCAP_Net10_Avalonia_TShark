namespace PCAPAnalyzer.API.DTOs;

/// <summary>
/// Anomaly detection DTO
/// </summary>
public class AnomalyDto
{
    public required string Id { get; set; }
    public required string Type { get; set; } // port_scan, ddos, unusual_traffic, etc.
    public required string Severity { get; set; } // low, medium, high, critical
    public required string Description { get; set; }
    public DateTime DetectedAt { get; set; }
    public double ConfidenceScore { get; set; }
    public Dictionary<string, object>? Details { get; set; }
    public List<string>? AffectedIPs { get; set; }
    public List<string>? Recommendations { get; set; }
}

/// <summary>
/// ML model training request
/// </summary>
public class TrainModelRequest
{
    public required string ModelType { get; set; }
    public List<string>? TrainingDataIds { get; set; }
    public Dictionary<string, object>? Hyperparameters { get; set; }
}

/// <summary>
/// ML model info DTO
/// </summary>
public class ModelInfoDto
{
    public required string ModelId { get; set; }
    public required string ModelType { get; set; }
    public required string Version { get; set; }
    public DateTime TrainedAt { get; set; }
    public double Accuracy { get; set; }
    public string? Status { get; set; }
    public Dictionary<string, object>? Metrics { get; set; }
}
