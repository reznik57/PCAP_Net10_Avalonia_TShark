using System;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Service for comparing packets between two PCAP files
/// </summary>
public interface IPacketComparer
{
    /// <summary>
    /// Compares two PCAP files and identifies common and unique packets
    /// </summary>
    /// <param name="fileAPath">Path to first PCAP file</param>
    /// <param name="fileBPath">Path to second PCAP file</param>
    /// <param name="progress">Progress reporter (0-100)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Comparison result with all packets and statistics</returns>
    Task<ComparisonResult> CompareAsync(
        string fileAPath,
        string fileBPath,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
