using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

public class OptimizedPacketProcessor : IDisposable
{
    private readonly Channel<PacketInfo> _packetChannel;
    private readonly List<PacketInfo> _summaryPackets;
    private readonly Lock _lockObj = new();
    private long _totalPacketsProcessed;
    private long _totalBytesProcessed;
    private bool _isDisposed;

    public event EventHandler<PacketBatchEventArgs>? BatchProcessed;
    public event EventHandler<ProgressEventArgs>? ProgressUpdated;
    public event EventHandler? ProcessingCompleted;

    public OptimizedPacketProcessor()
    {
        var options = new BoundedChannelOptions(PerformanceSettings.BatchProcessingSize)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        };
        
        _packetChannel = Channel.CreateBounded<PacketInfo>(options);
        _summaryPackets = new List<PacketInfo>(PerformanceSettings.MaxPacketsInUI);
    }

    public long TotalPacketsProcessed => Interlocked.Read(ref _totalPacketsProcessed);
    public long TotalBytesProcessed => Interlocked.Read(ref _totalBytesProcessed);

    public async Task<bool> AddPacketAsync(PacketInfo packet, CancellationToken cancellationToken = default)
    {
        if (_isDisposed) return false;

        try
        {
            await _packetChannel.Writer.WriteAsync(packet, cancellationToken);
            
            Interlocked.Increment(ref _totalPacketsProcessed);
            Interlocked.Add(ref _totalBytesProcessed, packet.Length);

            // Keep a sample of packets for UI display
            if (_totalPacketsProcessed <= PerformanceSettings.MaxPacketsInUI)
            {
                using (_lockObj.EnterScope())
                {
                    _summaryPackets.Add(packet);
                }
            }
            else if (_totalPacketsProcessed % 100 == 0) // Sample every 100th packet after limit
            {
                using (_lockObj.EnterScope())
                {
                    if (_summaryPackets.Count < PerformanceSettings.MaxPacketsInUI)
                    {
                        _summaryPackets.Add(packet);
                    }
                }
            }

            // Trigger GC periodically for large captures
            if (_totalPacketsProcessed % PerformanceSettings.GCInterval == 0)
            {
                GC.Collect(1, GCCollectionMode.Optimized);
            }

            return true;
        }
        catch (ChannelClosedException)
        {
            return false;
        }
    }

    public async Task ProcessPacketsAsync(CancellationToken cancellationToken = default)
    {
        var batch = new List<PacketInfo>(PerformanceSettings.BatchProcessingSize);
        var lastProgressUpdate = DateTime.UtcNow;

        await foreach (var packet in _packetChannel.Reader.ReadAllAsync(cancellationToken))
        {
            batch.Add(packet);

            if (batch.Count >= PerformanceSettings.BatchProcessingSize)
            {
                ProcessBatch(batch);
                batch.Clear();
            }

            // Update progress periodically
            var now = DateTime.UtcNow;
            if ((now - lastProgressUpdate).TotalMilliseconds >= PerformanceSettings.UIUpdateInterval)
            {
                UpdateProgress();
                lastProgressUpdate = now;
            }
        }

        // Process remaining packets
        if (batch.Count > 0)
        {
            ProcessBatch(batch);
        }

        ProcessingCompleted?.Invoke(this, EventArgs.Empty);
    }

    private void ProcessBatch(List<PacketInfo> batch)
    {
        if (batch.Count == 0) return;

        var stats = CalculateBatchStatistics(batch);
        
        BatchProcessed?.Invoke(this, new PacketBatchEventArgs
        {
            Packets = batch.ToList(),
            Statistics = stats,
            TotalProcessed = TotalPacketsProcessed
        });
    }

    private void UpdateProgress()
    {
        ProgressUpdated?.Invoke(this, new ProgressEventArgs
        {
            PacketsProcessed = TotalPacketsProcessed,
            BytesProcessed = TotalBytesProcessed,
            EstimatedMemoryUsage = GetEstimatedMemoryUsage()
        });
    }

    private BatchStatistics CalculateBatchStatistics(List<PacketInfo> batch)
    {
        return new BatchStatistics
        {
            PacketCount = batch.Count,
            TotalBytes = batch.Sum(p => (long)p.Length),
            UniqueSourceIPs = batch.Select(p => p.SourceIP).Distinct().Count(),
            UniqueDestinationIPs = batch.Select(p => p.DestinationIP).Distinct().Count(),
            ProtocolDistribution = batch.GroupBy(p => p.Protocol)
                .ToDictionary(g => g.Key.ToString(), g => g.Count()),
            TimeRange = batch.Any() 
                ? new TimeRange(batch.Min(p => p.Timestamp), batch.Max(p => p.Timestamp))
                : null
        };
    }

    public List<PacketInfo> GetDisplayPackets(int maxCount = -1)
    {
        using (_lockObj.EnterScope())
        {
            if (maxCount <= 0 || maxCount >= _summaryPackets.Count)
            {
                return _summaryPackets.ToList();
            }

            return _summaryPackets.Take(maxCount).ToList();
        }
    }

    public void CompleteAdding()
    {
        _packetChannel.Writer.TryComplete();
    }

    public long GetEstimatedMemoryUsage()
    {
        // Estimate: ~200 bytes per packet in memory
        return _summaryPackets.Count * 200L;
    }

    public void ClearMemory()
    {
        using (_lockObj.EnterScope())
        {
            _summaryPackets.Clear();
            _summaryPackets.TrimExcess();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_isDisposed) return;

        if (disposing)
        {
            // Dispose managed resources
            CompleteAdding();
            ClearMemory();
        }
        // Dispose unmanaged resources (if any) here

        _isDisposed = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}

public class PacketBatchEventArgs : EventArgs
{
    public List<PacketInfo> Packets { get; init; } = [];
    public BatchStatistics Statistics { get; init; } = new();
    public long TotalProcessed { get; init; }
}

public class ProgressEventArgs : EventArgs
{
    public long PacketsProcessed { get; init; }
    public long BytesProcessed { get; init; }
    public long EstimatedMemoryUsage { get; init; }
}

public class BatchStatistics
{
    public int PacketCount { get; init; }
    public long TotalBytes { get; init; }
    public int UniqueSourceIPs { get; init; }
    public int UniqueDestinationIPs { get; init; }
    public Dictionary<string, int> ProtocolDistribution { get; init; } = [];
    public TimeRange? TimeRange { get; init; }
}

public class TimeRange
{
    public DateTime Start { get; }
    public DateTime End { get; }
    public TimeSpan Duration => End - Start;

    public TimeRange(DateTime start, DateTime end)
    {
        Start = start;
        End = end;
    }
}