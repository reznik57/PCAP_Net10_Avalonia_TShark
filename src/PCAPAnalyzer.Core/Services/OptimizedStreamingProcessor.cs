using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Optimized streaming processor that handles packets in chunks for better performance
    /// </summary>
    public class OptimizedStreamingProcessor : IDisposable
    {
        private readonly int _chunkSize;
        private readonly Channel<PacketChunk> _processingChannel;
        private readonly IStatisticsService _statisticsService;
        private readonly SemaphoreSlim _statisticsSemaphore;
        private NetworkStatistics? _cachedStatistics;
        private DateTime _lastStatisticsUpdate = DateTime.MinValue;
        private readonly TimeSpan _statisticsUpdateInterval = TimeSpan.FromSeconds(10);
        private bool _disposed;

        public OptimizedStreamingProcessor(IStatisticsService statisticsService, int chunkSize = 50000) // Increased for better performance
        {
            ArgumentNullException.ThrowIfNull(statisticsService);
            _statisticsService = statisticsService;
            _chunkSize = chunkSize;
            _processingChannel = Channel.CreateUnbounded<PacketChunk>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });
            _statisticsSemaphore = new SemaphoreSlim(1, 1);
        }

        public ChannelReader<PacketChunk> ChunkReader => _processingChannel.Reader;

        /// <summary>
        /// Process packets in optimized chunks
        /// </summary>
        public async Task ProcessStreamAsync(ChannelReader<PacketInfo> packetReader, CancellationToken cancellationToken)
        {
            var chunk = new List<PacketInfo>(_chunkSize);
            var chunkNumber = 0;
            var totalPackets = 0;

            try
            {
                await foreach (var packet in packetReader.ReadAllAsync(cancellationToken))
                {
                    chunk.Add(packet);
                    totalPackets++;

                    if (chunk.Count >= _chunkSize)
                    {
                        await ProcessAndEmitChunk(chunk, ++chunkNumber, totalPackets);
                        chunk = new List<PacketInfo>(_chunkSize);
                    }
                }

                // Process remaining packets
                if (chunk.Any())
                {
                    await ProcessAndEmitChunk(chunk, ++chunkNumber, totalPackets);
                }
            }
            finally
            {
                _processingChannel.Writer.TryComplete();
            }
        }

        private async Task ProcessAndEmitChunk(List<PacketInfo> packets, int chunkNumber, int totalPackets)
        {
            var chunk = new PacketChunk
            {
                ChunkNumber = chunkNumber,
                Packets = packets.ToList(), // Create a copy to avoid modification
                TotalPacketsProcessed = totalPackets,
                ProcessedAt = DateTime.Now
            };

            // Calculate basic statistics for this chunk (lightweight)
            chunk.ChunkStatistics = CalculateChunkStatistics(packets);

            await _processingChannel.Writer.WriteAsync(chunk);
        }

        private ChunkStatistics CalculateChunkStatistics(List<PacketInfo> packets)
        {
            if (!packets.Any())
                return new ChunkStatistics();

            return new ChunkStatistics
            {
                PacketCount = packets.Count,
                TotalBytes = packets.Sum(p => (long)p.Length),
                StartTime = packets.Min(p => p.Timestamp),
                EndTime = packets.Max(p => p.Timestamp),
                ProtocolCounts = packets
                    .GroupBy(p => p.Protocol)
                    .ToDictionary(g => g.Key, g => g.Count()),
                TopSourceIPs = packets
                    .GroupBy(p => p.SourceIP)
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .Select(g => new { IP = g.Key, Count = g.Count() })
                    .ToDictionary(x => x.IP, x => x.Count)
            };
        }

        /// <summary>
        /// Get cached statistics or calculate new ones if needed
        /// </summary>
        public async Task<NetworkStatistics?> GetStatisticsAsync(List<PacketInfo> allPackets)
        {
            // Return cached statistics if recent enough
            if (_cachedStatistics is not null && 
                (DateTime.Now - _lastStatisticsUpdate) < _statisticsUpdateInterval)
            {
                return _cachedStatistics;
            }

            // Calculate statistics in background without blocking
            await _statisticsSemaphore.WaitAsync();
            try
            {
                if (_cachedStatistics is not null && 
                    (DateTime.Now - _lastStatisticsUpdate) < _statisticsUpdateInterval)
                {
                    return _cachedStatistics;
                }

                _cachedStatistics = await Task.Run(() => _statisticsService.CalculateStatistics(allPackets));
                _lastStatisticsUpdate = DateTime.Now;
                return _cachedStatistics;
            }
            finally
            {
                _statisticsSemaphore.Release();
            }
        }

        /// <summary>
        /// Force statistics recalculation
        /// </summary>
        public void InvalidateStatisticsCache()
        {
            _cachedStatistics = null;
            _lastStatisticsUpdate = DateTime.MinValue;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _statisticsSemaphore?.Dispose();
            }
            // Dispose unmanaged resources (if any) here

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public class PacketChunk
    {
        public int ChunkNumber { get; set; }
        public List<PacketInfo> Packets { get; set; } = [];
        public int TotalPacketsProcessed { get; set; }
        public DateTime ProcessedAt { get; set; }
        public ChunkStatistics ChunkStatistics { get; set; } = new();
    }

    public class ChunkStatistics
    {
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public Dictionary<Protocol, int> ProtocolCounts { get; set; } = [];
        public Dictionary<string, int> TopSourceIPs { get; set; } = [];
        
        public double Duration => (EndTime - StartTime).TotalSeconds;
        public double PacketsPerSecond => Duration > 0 ? PacketCount / Duration : 0;
        public double BytesPerSecond => Duration > 0 ? TotalBytes / Duration : 0;
    }
}