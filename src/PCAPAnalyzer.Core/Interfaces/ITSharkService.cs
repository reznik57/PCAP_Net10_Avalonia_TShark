using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Interfaces;

public interface ITSharkService : IDisposable, IAsyncDisposable
{
    ChannelReader<PacketInfo> PacketReader { get; }
    Task<bool> StartAnalysisAsync(string pcapPath, CancellationToken cancellationToken = default);
    Task StopAnalysisAsync();
    PacketStatistics GetStatistics();
    bool IsAnalyzing { get; }
    Task<long> GetTotalPacketCountAsync(string pcapPath, ProgressCoordinator? progressCoordinator = null);
    void ResetService();

    /// <summary>
    /// Quickly extracts capture time range (first/last packet timestamps) from a PCAP file.
    /// Uses TShark to read only first and last packet without full analysis.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file</param>
    /// <returns>Tuple of (FirstPacketTime, LastPacketTime) or (null, null) if unavailable</returns>
    Task<(DateTime? FirstPacketTime, DateTime? LastPacketTime)> GetCaptureTimeRangeAsync(string pcapPath);
}