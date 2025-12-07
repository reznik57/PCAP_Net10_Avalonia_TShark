using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Performance
{
    /// <summary>
    /// High-performance streaming packet processor using producer-consumer pattern
    /// Processes packets as they arrive without loading entire file into memory
    /// </summary>
    public sealed class StreamingPacketProcessor : IDisposable
    {
        private readonly Channel<PacketData> _packetChannel;
        private readonly ConcurrentBag<Task> _processorTasks;
        private readonly CancellationTokenSource _cancellationSource;
        private readonly int _maxConcurrency;
        private bool _disposed;
        private bool _isProcessing;

        /// <summary>
        /// Gets whether the processor is currently processing
        /// </summary>
        public bool IsProcessing => _isProcessing;

        /// <summary>
        /// Event raised when a packet is processed
        /// </summary>
        public event EventHandler<PacketProcessedEventArgs>? PacketProcessed;

        /// <summary>
        /// Event raised when an error occurs during processing
        /// </summary>
        public event EventHandler<ProcessingErrorEventArgs>? ProcessingError;

        /// <summary>
        /// Gets processing statistics
        /// </summary>
        public ProcessingStatistics Statistics { get; }

        /// <summary>
        /// Retrieves the current processing statistics snapshot
        /// </summary>
        public ProcessingStatistics GetProcessingStatistics() => Statistics;

        /// <summary>
        /// Initializes a new streaming packet processor
        /// </summary>
        /// <param name="maxConcurrency">Maximum number of concurrent processors (0 for CPU count)</param>
        /// <param name="channelCapacity">Capacity of the packet channel (0 for unbounded)</param>
        public StreamingPacketProcessor(int maxConcurrency = 0, int channelCapacity = 10000)
        {
            _maxConcurrency = maxConcurrency > 0 ? maxConcurrency : Environment.ProcessorCount;

            // Create bounded or unbounded channel
            _packetChannel = channelCapacity > 0
                ? Channel.CreateBounded<PacketData>(new BoundedChannelOptions(channelCapacity)
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = false,
                    SingleWriter = false
                })
                : Channel.CreateUnbounded<PacketData>(new UnboundedChannelOptions
                {
                    SingleReader = false,
                    SingleWriter = false
                });

            _processorTasks = new ConcurrentBag<Task>();
            _cancellationSource = new CancellationTokenSource();
            Statistics = new ProcessingStatistics();
        }

        /// <summary>
        /// Starts the packet processing pipeline
        /// </summary>
        /// <param name="packetHandler">Function to process each packet</param>
        public void StartProcessing(Func<PacketData, Task<ProcessingResult>> packetHandler)
        {
            if (packetHandler is null)
                throw new ArgumentNullException(nameof(packetHandler));

            if (_isProcessing)
                throw new InvalidOperationException("Processing already started");

            _isProcessing = true;

            // Start processor tasks
            for (int i = 0; i < _maxConcurrency; i++)
            {
                var task = Task.Run(async () => await ProcessPacketsAsync(packetHandler, _cancellationSource.Token));
                _processorTasks.Add(task);
            }
        }

        /// <summary>
        /// Enqueues a packet for processing
        /// </summary>
        /// <param name="packet">Packet data to process</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task EnqueuePacketAsync(PacketData packet, CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(StreamingPacketProcessor));

            using (PerformanceMonitor.Instance.Time("Packet_Enqueue"))
            {
                await _packetChannel.Writer.WriteAsync(packet, cancellationToken);
                Statistics.IncrementEnqueued();
            }
        }

        /// <summary>
        /// Enqueues multiple packets in batch
        /// </summary>
        /// <param name="packets">Collection of packets to process</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task EnqueueBatchAsync(IEnumerable<PacketData> packets, CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(StreamingPacketProcessor));

            using (PerformanceMonitor.Instance.Time("Batch_Enqueue"))
            {
                foreach (var packet in packets)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    await _packetChannel.Writer.WriteAsync(packet, cancellationToken);
                    Statistics.IncrementEnqueued();
                }
            }
        }

        /// <summary>
        /// Signals that no more packets will be enqueued
        /// </summary>
        public void CompleteAdding()
        {
            _packetChannel.Writer.Complete();
        }

        /// <summary>
        /// Waits for all packets to be processed
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WaitForCompletionAsync(CancellationToken cancellationToken = default)
        {
            // Wait for channel to be empty and all tasks to complete
            await _packetChannel.Reader.Completion;
            await Task.WhenAll(_processorTasks);
        }

        /// <summary>
        /// Packet processing worker method
        /// </summary>
        private async Task ProcessPacketsAsync(
            Func<PacketData, Task<ProcessingResult>> handler,
            CancellationToken cancellationToken)
        {
            await foreach (var packet in _packetChannel.Reader.ReadAllAsync(cancellationToken))
            {
                try
                {
                    using (PerformanceMonitor.Instance.Time("Packet_Processing"))
                    {
                        var result = await handler(packet);

                        Statistics.IncrementProcessed();

                        // Raise event
                        PacketProcessed?.Invoke(this, new PacketProcessedEventArgs
                        {
                            Packet = packet,
                            Result = result,
                            ProcessingTime = TimeSpan.Zero // Updated by timer
                        });
                    }
                }
                catch (Exception ex)
                {
                    Statistics.IncrementErrors();

                    ProcessingError?.Invoke(this, new ProcessingErrorEventArgs
                    {
                        Packet = packet,
                        Exception = ex
                    });
                }
            }
        }

        /// <summary>
        /// Cancels all processing operations
        /// </summary>
        public void Cancel()
        {
            _cancellationSource.Cancel();
        }

        public void Dispose()
        {
            if (_disposed) return;

            _cancellationSource.Cancel();
            _packetChannel.Writer.Complete();

            try
            {
                Task.WhenAll(_processorTasks).Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // Ignore timeout exceptions during disposal
            }

            _cancellationSource.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    /// Represents packet data for processing
    /// </summary>
    public sealed class PacketData
    {
        public long PacketNumber { get; init; }
        public DateTime Timestamp { get; init; }
        public ReadOnlyMemory<byte> Data { get; init; }
        public Dictionary<string, object> Metadata { get; init; } = [];
    }

    /// <summary>
    /// Result of packet processing
    /// </summary>
    public sealed class ProcessingResult
    {
        public bool Success { get; init; }
        public string? ErrorMessage { get; init; }
        public Dictionary<string, object> ExtractedData { get; init; } = [];
    }

    /// <summary>
    /// Event args for packet processed event
    /// </summary>
    public sealed class PacketProcessedEventArgs : EventArgs
    {
        public PacketData Packet { get; init; } = null!;
        public ProcessingResult Result { get; init; } = null!;
        public TimeSpan ProcessingTime { get; init; }
    }

    /// <summary>
    /// Event args for processing error event
    /// </summary>
    public sealed class ProcessingErrorEventArgs : EventArgs
    {
        public PacketData Packet { get; init; } = null!;
        public Exception Exception { get; init; } = null!;
    }

    /// <summary>
    /// Processing statistics
    /// </summary>
    public sealed class ProcessingStatistics
    {
        private long _enqueuedCount;
        private long _processedCount;
        private long _errorCount;

        public long EnqueuedCount => Interlocked.Read(ref _enqueuedCount);
        public long ProcessedCount => Interlocked.Read(ref _processedCount);
        public long ErrorCount => Interlocked.Read(ref _errorCount);
        public long PendingCount => EnqueuedCount - ProcessedCount;

        public double ProcessingRate => ProcessedCount / (DateTime.UtcNow - _startTime).TotalSeconds;
        public double ErrorRate => ProcessedCount > 0 ? (ErrorCount * 100.0) / ProcessedCount : 0;

        private readonly DateTime _startTime = DateTime.UtcNow;

        internal void IncrementEnqueued() => Interlocked.Increment(ref _enqueuedCount);
        internal void IncrementProcessed() => Interlocked.Increment(ref _processedCount);
        internal void IncrementErrors() => Interlocked.Increment(ref _errorCount);

        public void Reset()
        {
            Interlocked.Exchange(ref _enqueuedCount, 0);
            Interlocked.Exchange(ref _processedCount, 0);
            Interlocked.Exchange(ref _errorCount, 0);
        }

        public override string ToString()
        {
            return $"Enqueued: {EnqueuedCount}, Processed: {ProcessedCount}, " +
                   $"Errors: {ErrorCount}, Pending: {PendingCount}, " +
                   $"Rate: {ProcessingRate:F2} packets/sec";
        }
    }
}
