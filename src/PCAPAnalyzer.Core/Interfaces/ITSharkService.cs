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
}