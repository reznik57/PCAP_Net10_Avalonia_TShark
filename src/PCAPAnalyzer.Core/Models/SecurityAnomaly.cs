using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Legacy security anomaly record maintained for compatibility while callers
/// transition to <see cref="NetworkAnomaly"/>. New features should prefer the
/// unified model.
/// </summary>
public class SecurityAnomaly
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public AnomalySeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; }
    public List<int> AffectedPackets { get; set; } = [];
    public Dictionary<string, object> Evidence { get; set; } = [];
    public string Recommendation { get; set; } = string.Empty;
}
