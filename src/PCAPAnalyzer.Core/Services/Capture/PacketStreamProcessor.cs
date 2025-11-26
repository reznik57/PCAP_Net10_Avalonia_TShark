using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Processes packet streams in real-time with optimized performance
/// </summary>
public class PacketStreamProcessor : IDisposable
{
    private readonly ILogger<PacketStreamProcessor> _logger;
    private readonly Channel<LivePacketData> _inputChannel;
    private readonly Channel<LivePacketData> _outputChannel;
    private readonly ConcurrentDictionary<string, PacketStreamStats> _streamStats;
    private readonly ConcurrentBag<Task> _processingTasks;
    private CancellationTokenSource? _processingCts;
    private readonly int _maxConcurrency;
    private readonly SemaphoreSlim _processingLock;

    public event EventHandler<LivePacketData>? PacketProcessed;
    public event EventHandler<PacketStreamStats>? StreamStatsUpdated;

    public PacketStreamProcessor(ILogger<PacketStreamProcessor> logger, int maxConcurrency = 4)
    {
        _logger = logger;
        _maxConcurrency = maxConcurrency;
        _processingLock = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        _inputChannel = Channel.CreateUnbounded<LivePacketData>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });

        _outputChannel = Channel.CreateUnbounded<LivePacketData>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });

        _streamStats = new ConcurrentDictionary<string, PacketStreamStats>();
        _processingTasks = new ConcurrentBag<Task>();
    }

    /// <summary>
    /// Starts processing packets from the input stream
    /// </summary>
    public void Start()
    {
        if (_processingCts != null)
        {
            throw new InvalidOperationException("Processor is already running");
        }

        _processingCts = new CancellationTokenSource();

        // Start multiple processing tasks for parallel processing
        for (int i = 0; i < _maxConcurrency; i++)
        {
            var task = Task.Run(() => ProcessPacketsAsync(_processingCts.Token), _processingCts.Token);
            _processingTasks.Add(task);
        }

        _logger.LogInformation("Packet stream processor started with {Concurrency} workers", _maxConcurrency);
    }

    /// <summary>
    /// Stops processing packets
    /// </summary>
    public async Task StopAsync()
    {
        if (_processingCts == null)
        {
            return;
        }

        _processingCts.Cancel();

        try
        {
            await Task.WhenAll(_processingTasks);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Some processing tasks failed during shutdown");
        }

        _processingCts.Dispose();
        _processingCts = null;

        _logger.LogInformation("Packet stream processor stopped");
    }

    /// <summary>
    /// Enqueues a packet for processing
    /// </summary>
    public async Task EnqueuePacketAsync(LivePacketData packet, CancellationToken cancellationToken = default)
    {
        await _inputChannel.Writer.WriteAsync(packet, cancellationToken);
    }

    /// <summary>
    /// Reads processed packets from the output channel
    /// </summary>
    public async IAsyncEnumerable<LivePacketData> ReadProcessedPacketsAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var packet in _outputChannel.Reader.ReadAllAsync(cancellationToken))
        {
            yield return packet;
        }
    }

    /// <summary>
    /// Gets current stream statistics
    /// </summary>
    public Dictionary<string, PacketStreamStats> GetStreamStatistics()
    {
        return new Dictionary<string, PacketStreamStats>(_streamStats);
    }

    /// <summary>
    /// Resets stream statistics
    /// </summary>
    public void ResetStatistics()
    {
        _streamStats.Clear();
    }

    private async Task ProcessPacketsAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var packet in _inputChannel.Reader.ReadAllAsync(cancellationToken))
            {
                await _processingLock.WaitAsync(cancellationToken);

                try
                {
                    await ProcessPacketAsync(packet, cancellationToken);
                }
                finally
                {
                    _processingLock.Release();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in packet processing loop");
        }
    }

    private async Task ProcessPacketAsync(LivePacketData packet, CancellationToken cancellationToken)
    {
        try
        {
            // Extract packet information (basic parsing)
            await ExtractPacketInfoAsync(packet, cancellationToken);

            // Update stream statistics
            UpdateStreamStatistics(packet);

            // Detect anomalies
            DetectAnomalies(packet);

            // Write to output channel
            await _outputChannel.Writer.WriteAsync(packet, cancellationToken);

            // Notify listeners
            OnPacketProcessed(packet);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing packet {Sequence}", packet.SequenceNumber);
        }
    }

    private async Task ExtractPacketInfoAsync(LivePacketData packet, CancellationToken cancellationToken)
    {
        // Basic packet parsing (in production, use proper packet parsing libraries)
        if (packet.RawData.Length == 0)
        {
            return;
        }

        await Task.CompletedTask;

        // Simple heuristic extraction (placeholder)
        // In production, use libraries like PacketDotNet or SharpPcap
        packet.Protocol = "Unknown";

        // Ethernet frame (14 bytes header)
        if (packet.RawData.Length >= 14)
        {
            packet.DestinationMac = BitConverter.ToString(packet.RawData, 0, 6);
            packet.SourceMac = BitConverter.ToString(packet.RawData, 6, 6);
        }

        // IP header detection (basic)
        if (packet.RawData.Length >= 34)
        {
            var ipVersion = (packet.RawData[14] >> 4) & 0x0F;
            if (ipVersion == 4)
            {
                packet.Protocol = "IPv4";
                // Source IP
                packet.SourceIp = $"{packet.RawData[26]}.{packet.RawData[27]}.{packet.RawData[28]}.{packet.RawData[29]}";
                // Destination IP
                packet.DestinationIp = $"{packet.RawData[30]}.{packet.RawData[31]}.{packet.RawData[32]}.{packet.RawData[33]}";

                var ipProtocol = packet.RawData[23];
                if (ipProtocol == 6) packet.Protocol = "TCP";
                else if (ipProtocol == 17) packet.Protocol = "UDP";
                else if (ipProtocol == 1) packet.Protocol = "ICMP";
            }
        }
    }

    private void UpdateStreamStatistics(LivePacketData packet)
    {
        var streamKey = $"{packet.SourceIp}:{packet.SourcePort}->{packet.DestinationIp}:{packet.DestinationPort}";

        _streamStats.AddOrUpdate(streamKey,
            key => new PacketStreamStats
            {
                StreamKey = key,
                PacketCount = 1,
                TotalBytes = packet.Length,
                FirstSeen = packet.Timestamp,
                LastSeen = packet.Timestamp,
                Protocol = packet.Protocol
            },
            (key, existing) =>
            {
                existing.PacketCount++;
                existing.TotalBytes += packet.Length;
                existing.LastSeen = packet.Timestamp;
                return existing;
            });

        // Periodically emit statistics updates
        if (packet.SequenceNumber % 1000 == 0)
        {
            var stats = _streamStats[streamKey];
            OnStreamStatsUpdated(stats);
        }
    }

    private void DetectAnomalies(LivePacketData packet)
    {
        // Basic anomaly detection (placeholder)
        var anomalies = new List<string>();

        // Large packet size
        if (packet.Length > 9000)
        {
            anomalies.Add("Jumbo frame detected");
        }

        // Unusual protocols
        if (packet.Protocol == "Unknown" && packet.RawData.Length > 0)
        {
            anomalies.Add("Unknown protocol");
        }

        // Private to public traffic patterns
        if (packet.SourceIp?.StartsWith("192.168.", StringComparison.Ordinal) == true &&
            !packet.DestinationIp?.StartsWith("192.168.", StringComparison.Ordinal) == true)
        {
            anomalies.Add("Private to public traffic");
        }

        if (anomalies.Count > 0)
        {
            packet.HasAnomaly = true;
            packet.Anomalies = anomalies;
        }
    }

    private void OnPacketProcessed(LivePacketData packet)
    {
        PacketProcessed?.Invoke(this, packet);
    }

    private void OnStreamStatsUpdated(PacketStreamStats stats)
    {
        StreamStatsUpdated?.Invoke(this, stats);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose managed resources
            _processingCts?.Cancel();
            _processingCts?.Dispose();
            _processingLock.Dispose();
        }
        // Dispose unmanaged resources (if any) here
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Statistics for a packet stream
/// </summary>
public class PacketStreamStats
{
    public string StreamKey { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public TimeSpan Duration => LastSeen - FirstSeen;
    public double PacketsPerSecond => Duration.TotalSeconds > 0 ? PacketCount / Duration.TotalSeconds : 0;
    public double BytesPerSecond => Duration.TotalSeconds > 0 ? TotalBytes / Duration.TotalSeconds : 0;
}
