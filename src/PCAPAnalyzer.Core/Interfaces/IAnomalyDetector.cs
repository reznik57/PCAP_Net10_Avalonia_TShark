using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Base interface for all anomaly detectors.
/// Detectors implement specific detection logic and return NetworkAnomaly instances.
/// </summary>
public interface IAnomalyDetector
{
    /// <summary>
    /// Name of the detector (e.g., "Network Anomaly Detector")
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Primary category of anomalies this detector handles
    /// </summary>
    AnomalyCategory Category { get; }

    /// <summary>
    /// Detect anomalies in the given packet stream
    /// </summary>
    /// <param name="packets">Packet stream to analyze</param>
    /// <returns>List of detected anomalies</returns>
    List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets);
}

/// <summary>
/// Specialized detector interface for detectors that can determine
/// if they should run based on packet characteristics
/// </summary>
public interface ISpecializedDetector : IAnomalyDetector
{
    /// <summary>
    /// Determine if this detector can/should run on the given packets
    /// </summary>
    /// <param name="packets">Packet stream to check</param>
    /// <returns>True if detector should run, false otherwise</returns>
    bool CanDetect(IEnumerable<PacketInfo> packets);

    /// <summary>
    /// Priority for running this detector (higher = runs first)
    /// </summary>
    int Priority { get; }
}
