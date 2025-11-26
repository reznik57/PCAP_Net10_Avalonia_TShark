using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Optimized packet loader for ultra-fast UI display
    /// Stage 1 Optimization: Show packets in <5 seconds
    /// </summary>
    public class FastPacketLoader : IDisposable
    {
        private readonly Channel<PacketDisplayInfo> _packetChannel;
        private readonly Dictionary<string, string> _ipCache = new(10000);
        private readonly SemaphoreSlim _cacheLock = new(1, 1);
        private volatile bool _isLoading;
        private bool _disposed;
        
        /// <summary>
        /// Gets whether the loader is currently processing a file
        /// </summary>
        public bool IsLoading => _isLoading;
        
        public event EventHandler<FastLoadPacketBatchEventArgs>? PacketBatchReady;
        public event EventHandler<LoadingProgressEventArgs>? LoadingProgress;
        
        public FastPacketLoader()
        {
            // High-performance unbounded channel
            _packetChannel = Channel.CreateUnbounded<PacketDisplayInfo>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });
        }
        
        /// <summary>
        /// Load packets for immediate display (Stage 1: <5 seconds)
        /// </summary>
        public async Task<FastLoadResult> LoadPacketsForDisplayAsync(
            string pcapFile,
            CancellationToken cancellationToken = default)
        {
            _isLoading = true;
            var stopwatch = Stopwatch.StartNew();
            var result = new FastLoadResult { PcapFile = pcapFile };
            
            try
            {
                // Start UI update task
                var uiUpdateTask = UpdateUIProgressively(cancellationToken);
                
                // Start streaming packets
                var streamTask = StreamPacketsAsync(pcapFile, cancellationToken);
                
                // Wait for streaming to complete
                await streamTask;
                
                // Signal completion
                _packetChannel.Writer.TryComplete();
                
                // Wait for UI updates to finish
                await uiUpdateTask;
                
                stopwatch.Stop();
                result.LoadTime = stopwatch.Elapsed;
                result.Success = true;
                
                // Report completion
                LoadingProgress?.Invoke(this, new LoadingProgressEventArgs
                {
                    IsComplete = true,
                    Message = $"Loaded {result.TotalPackets:N0} packets in {stopwatch.Elapsed.TotalSeconds:F2}s",
                    PacketsPerSecond = result.TotalPackets / stopwatch.Elapsed.TotalSeconds
                });
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                _isLoading = false;
            }
            
            return result;
        }
        
        /// <summary>
        /// Stream packets from TShark with minimal parsing
        /// </summary>
        private async Task StreamPacketsAsync(string pcapFile, CancellationToken cancellationToken)
        {
            var tsharkPath = GetTSharkPath();
            
            // Use lightweight field extraction - ONLY what's needed for display
            var arguments = $"-r \"{pcapFile}\" -T fields " +
                          "-e frame.number " +
                          "-e frame.time_epoch " +
                          "-e frame.len " +
                          "-e ip.src " +
                          "-e ip.dst " +
                          "-e tcp.srcport " +
                          "-e tcp.dstport " +
                          "-e udp.srcport " +
                          "-e udp.dstport " +
                          "-e _ws.col.Protocol " +
                          "-e _ws.col.Info " +
                          "-E separator=|";
            
            var processInfo = new ProcessStartInfo
            {
                FileName = tsharkPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            
            using var process = Process.Start(processInfo);
            if (process == null)
                throw new InvalidOperationException("Failed to start TShark process");
            
            var reader = process.StandardOutput;
            string? line;
            var packetNumber = 0;
            var buffer = new List<PacketDisplayInfo>(1000);
            
            while ((line = await reader.ReadLineAsync()) != null)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;
                
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                
                packetNumber++;
                var packet = ParsePacketLine(line, packetNumber);
                
                if (packet != null)
                {
                    buffer.Add(packet);
                    
                    // Batch write to channel for efficiency
                    if (buffer.Count >= 100)
                    {
                        foreach (var p in buffer)
                        {
                            await _packetChannel.Writer.WriteAsync(p, cancellationToken);
                        }
                        buffer.Clear();
                    }
                }
            }
            
            // Flush remaining packets
            foreach (var p in buffer)
            {
                await _packetChannel.Writer.WriteAsync(p, cancellationToken);
            }
            
            await process.WaitForExitAsync(cancellationToken);
        }
        
        /// <summary>
        /// Parse packet line with minimal overhead
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private PacketDisplayInfo? ParsePacketLine(string line, int packetNumber)
        {
            var parts = line.Split('|');
            if (parts.Length < 11)
                return null;
            
            return new PacketDisplayInfo
            {
                FrameNumber = uint.TryParse(parts[0], out var fn) ? fn : (uint)packetNumber,
                Timestamp = ParseTimestamp(parts[1]),
                Length = uint.TryParse(parts[2], out var len) ? len : 0,
                SourceIP = parts[3] ?? "",
                DestinationIP = parts[4] ?? "",
                SourcePort = ParsePort(parts[5]) ?? ParsePort(parts[7]) ?? 0,
                DestinationPort = ParsePort(parts[6]) ?? ParsePort(parts[8]) ?? 0,
                Protocol = parts[9] ?? "Unknown",
                Info = parts.Length > 10 ? parts[10] : "",
                // Defer country lookup - not needed for initial display
                SourceCountry = null,
                DestinationCountry = null
            };
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private DateTime ParseTimestamp(string epochStr)
        {
            if (double.TryParse(epochStr, out var epoch))
            {
                return DateTimeOffset.FromUnixTimeSeconds((long)epoch).DateTime;
            }
            return DateTime.UtcNow;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ushort? ParsePort(string portStr)
        {
            if (ushort.TryParse(portStr, out var port))
                return port;
            return null;
        }
        
        /// <summary>
        /// Update UI progressively as packets arrive
        /// </summary>
        private async Task UpdateUIProgressively(CancellationToken cancellationToken)
        {
            var batch = new List<PacketDisplayInfo>(1000);
            var totalPackets = 0;
            var lastUpdate = DateTime.UtcNow;
            var stopwatch = Stopwatch.StartNew();
            
            await foreach (var packet in _packetChannel.Reader.ReadAllAsync(cancellationToken))
            {
                batch.Add(packet);
                totalPackets++;
                
                // Update UI every 1000 packets or 100ms
                var now = DateTime.UtcNow;
                if (batch.Count >= 1000 || (now - lastUpdate).TotalMilliseconds > 100)
                {
                    // Fire event for UI update
                    PacketBatchReady?.Invoke(this, new FastLoadPacketBatchEventArgs
                    {
                        Packets = batch.ToList(),
                        TotalPacketsSoFar = totalPackets,
                        IsFirstBatch = totalPackets <= 1000
                    });
                    
                    // Report progress
                    LoadingProgress?.Invoke(this, new LoadingProgressEventArgs
                    {
                        PacketsLoaded = totalPackets,
                        ElapsedTime = stopwatch.Elapsed,
                        PacketsPerSecond = totalPackets / stopwatch.Elapsed.TotalSeconds,
                        Message = $"Loading packets... {totalPackets:N0} loaded"
                    });
                    
                    batch.Clear();
                    lastUpdate = now;
                    
                    // Small delay to prevent UI flooding
                    if (totalPackets > 10000)
                    {
                        await Task.Delay(10, cancellationToken);
                    }
                }
            }
            
            // Final batch
            if (batch.Count > 0)
            {
                PacketBatchReady?.Invoke(this, new FastLoadPacketBatchEventArgs
                {
                    Packets = batch,
                    TotalPacketsSoFar = totalPackets,
                    IsLastBatch = true
                });
            }
        }
        
        /// <summary>
        /// Load GeoIP data lazily when needed
        /// </summary>
        public async Task<Dictionary<string, string>> LoadGeoIPAsync(
            IEnumerable<string> ipAddresses,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var results = new Dictionary<string, string>();
            var uniqueIPs = ipAddresses.Distinct().Where(ip => !string.IsNullOrEmpty(ip)).ToList();
            var processed = 0;
            
            await _cacheLock.WaitAsync(cancellationToken);
            try
            {
                foreach (var ip in uniqueIPs)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;
                    
                    // Check cache first
                    if (_ipCache.TryGetValue(ip, out var cached))
                    {
                        results[ip] = cached;
                    }
                    else
                    {
                        // Simulate GeoIP lookup (would use real service)
                        var country = GetCountryForIP(ip);
                        results[ip] = country;
                        _ipCache[ip] = country;
                    }
                    
                    processed++;
                    if (processed % 100 == 0)
                    {
                        progress?.Report((processed * 100) / uniqueIPs.Count);
                    }
                }
            }
            finally
            {
                _cacheLock.Release();
            }
            
            return results;
        }
        
        private string GetCountryForIP(string ip)
        {
            // Simplified logic - in production would use MaxMind GeoIP
            if (ip.StartsWith("192.168.", StringComparison.Ordinal) || ip.StartsWith("10.", StringComparison.Ordinal) || ip.StartsWith("172.", StringComparison.Ordinal))
                return "Local";
            
            // Simulate country detection
            var hash = ip.GetHashCode(StringComparison.Ordinal);
            var countries = new[] { "US", "DE", "CN", "JP", "GB", "FR", "CA", "AU" };
            return countries[Math.Abs(hash) % countries.Length];
        }
        
        private string GetTSharkPath()
        {
            var paths = new[]
            {
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe"
            };
            
            foreach (var path in paths)
            {
                if (File.Exists(path))
                    return path;
            }

            return "tshark"; // Hope it's in PATH
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _cacheLock?.Dispose();
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
    
    /// <summary>
    /// Lightweight packet info for display only
    /// </summary>
    public class PacketDisplayInfo
    {
        public uint FrameNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public uint Length { get; set; }
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public string Info { get; set; } = "";
        
        // Lazy-loaded properties
        public string? SourceCountry { get; set; }
        public string? DestinationCountry { get; set; }
        
        // Display helpers
        public string DisplayTime => Timestamp.ToString("HH:mm:ss.fff");
        public string DisplaySource => SourcePort > 0 ? $"{SourceIP}:{SourcePort}" : SourceIP;
        public string DisplayDestination => DestinationPort > 0 ? $"{DestinationIP}:{DestinationPort}" : DestinationIP;
    }
    
    public class FastLoadResult
    {
        public bool Success { get; set; }
        public string PcapFile { get; set; } = "";
        public int TotalPackets { get; set; }
        public TimeSpan LoadTime { get; set; }
        public string? ErrorMessage { get; set; }
        public double PacketsPerSecond => TotalPackets / Math.Max(0.001, LoadTime.TotalSeconds);
    }
    
    public class FastLoadPacketBatchEventArgs : EventArgs
    {
        public List<PacketDisplayInfo> Packets { get; set; } = new();
        public int TotalPacketsSoFar { get; set; }
        public bool IsFirstBatch { get; set; }
        public bool IsLastBatch { get; set; }
    }
    
    public class LoadingProgressEventArgs : EventArgs
    {
        public int PacketsLoaded { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public double PacketsPerSecond { get; set; }
        public string Message { get; set; } = "";
        public bool IsComplete { get; set; }
    }
}