using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

public interface IPacketStore : IAsyncDisposable
{
    Task InitializeAsync(string databasePath, CancellationToken cancellationToken = default);
    Task InsertPacketsAsync(IEnumerable<PacketInfo> packets, CancellationToken cancellationToken = default);
    Task<PacketQueryResult> QueryPacketsAsync(PacketQuery query, CancellationToken cancellationToken = default);
    Task InsertFlowsAsync(IEnumerable<FlowRecord> flows, CancellationToken cancellationToken = default);
    Task ClearAsync(CancellationToken cancellationToken = default);
}
