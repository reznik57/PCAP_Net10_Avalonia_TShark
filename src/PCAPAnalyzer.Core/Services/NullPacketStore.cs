using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Null Object Pattern implementation of IPacketStore.
/// Does nothing, returns empty results. Used as a default/safe state.
/// </summary>
public class NullPacketStore : IPacketStore
{
    public Task InitializeAsync(string databasePath, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public Task InsertPacketsAsync(IEnumerable<PacketInfo> packets, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public Task<PacketQueryResult> QueryPacketsAsync(PacketQuery query, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new PacketQueryResult
        {
            Packets = Array.Empty<PacketInfo>(),
            TotalCount = 0,
            TotalBytes = 0,
            ThreatCount = 0
        });
    }

    public Task InsertFlowsAsync(IEnumerable<FlowRecord> flows, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }
}
