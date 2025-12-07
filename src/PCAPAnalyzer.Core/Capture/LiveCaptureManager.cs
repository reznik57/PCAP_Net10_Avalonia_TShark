using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Capture.Events;
using PCAPAnalyzer.Core.Capture.Models;
using PCAPAnalyzer.Core.Performance;

namespace PCAPAnalyzer.Core.Capture
{
    /// <summary>
    /// Main orchestration service for live packet capture
    /// Coordinates TShark process, packet streaming, and real-time processing
    /// </summary>
    public sealed class LiveCaptureManager : IDisposable
    {
        private readonly NetworkInterfaceDiscovery _interfaceDiscovery;
        private readonly ConcurrentDictionary<string, CaptureSession> _activeSessions;
        private readonly StreamingPacketProcessor _packetProcessor;
        private readonly PerformanceMonitor _performanceMonitor;
        private readonly ObjectPool<byte[]> _bufferPool;
        private readonly SemaphoreSlim _sessionLock = new(1, 1);
        private bool _disposed;

        /// <summary>
        /// Event raised when a session starts
        /// </summary>
        public event EventHandler<SessionStartedEventArgs>? SessionStarted;

        /// <summary>
        /// Event raised when a session stops
        /// </summary>
        public event EventHandler<SessionStoppedEventArgs>? SessionStopped;

        /// <summary>
        /// Event raised when a packet is captured
        /// </summary>
        public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

        /// <summary>
        /// Event raised when statistics are updated
        /// </summary>
        public event EventHandler<StatisticsUpdatedEventArgs>? StatisticsUpdated;

        /// <summary>
        /// Event raised when a capture error occurs
        /// </summary>
        public event EventHandler<CaptureErrorEventArgs>? CaptureError;

        /// <summary>
        /// Gets the active capture sessions
        /// </summary>
        public IReadOnlyDictionary<string, CaptureSession> ActiveSessions =>
            _activeSessions.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        /// <summary>
        /// Gets the interface discovery service
        /// </summary>
        public NetworkInterfaceDiscovery InterfaceDiscovery => _interfaceDiscovery;

        /// <summary>
        /// Initializes a new live capture manager
        /// </summary>
        /// <param name="tsharkPath">Path to TShark executable (null for system default)</param>
        public LiveCaptureManager(string? tsharkPath = null)
        {
            _interfaceDiscovery = new NetworkInterfaceDiscovery(tsharkPath);
            _activeSessions = new ConcurrentDictionary<string, CaptureSession>();
            _packetProcessor = new StreamingPacketProcessor(
                maxConcurrency: Environment.ProcessorCount,
                channelCapacity: 10000);
            _performanceMonitor = PerformanceMonitor.Instance;
            _bufferPool = new ObjectPool<byte[]>(
                () => new byte[65536],
                buffer => Array.Clear(buffer, 0, buffer.Length),
                maxPoolSize: 100,
                preAllocate: 10);
        }

        /// <summary>
        /// Validates TShark installation
        /// </summary>
        public async Task<TSharkValidationResult> ValidateTSharkAsync(
            CancellationToken cancellationToken = default)
        {
            return await _interfaceDiscovery.ValidateTSharkInstallationAsync(cancellationToken);
        }

        /// <summary>
        /// Discovers available network interfaces
        /// </summary>
        public async Task<List<NetworkInterface>> DiscoverInterfacesAsync(
            bool forceRefresh = false,
            CancellationToken cancellationToken = default)
        {
            using (_performanceMonitor.Time("Interface_Discovery"))
            {
                return await _interfaceDiscovery.DiscoverInterfacesAsync(forceRefresh, cancellationToken);
            }
        }

        /// <summary>
        /// Starts a new capture session
        /// </summary>
        public async Task<string> StartCaptureAsync(
            CaptureConfiguration configuration,
            CancellationToken cancellationToken = default)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            configuration.Validate();

            await _sessionLock.WaitAsync(cancellationToken);
            try
            {
                using (_performanceMonitor.Time("Capture_Start"))
                {
                    // Get network interface
                    var networkInterface = await _interfaceDiscovery.GetInterfaceByIdAsync(
                        configuration.InterfaceId,
                        cancellationToken);

                    if (networkInterface == null)
                    {
                        throw new ArgumentException($"Network interface not found: {configuration.InterfaceId}");
                    }

                    if (!networkInterface.IsUp)
                    {
                        throw new InvalidOperationException($"Network interface is not up: {networkInterface.Name}");
                    }

                    // Create capture session
                    var session = new CaptureSession(configuration, networkInterface);

                    // Wire up events
                    session.StateChanged += OnSessionStateChanged;
                    session.ErrorOccurred += OnSessionError;

                    // Add to active sessions
                    if (!_activeSessions.TryAdd(session.SessionId, session))
                    {
                        throw new InvalidOperationException("Failed to register capture session");
                    }

                    // Start packet processing pipeline
                    if (!_packetProcessor.IsProcessing)
                    {
                        _packetProcessor.StartProcessing(ProcessPacketAsync);
                    }

                    // Start the session
                    await session.StartAsync(cancellationToken);

                    // Start packet capture stream
                    _ = Task.Run(() => CapturePacketsAsync(session, cancellationToken), cancellationToken);

                    // Start statistics monitoring
                    if (configuration.EnableStatistics)
                    {
                        _ = Task.Run(() => MonitorStatisticsAsync(session, cancellationToken), cancellationToken);
                    }

                    // Raise event
                    SessionStarted?.Invoke(this, new SessionStartedEventArgs
                    {
                        SessionId = session.SessionId,
                        Configuration = configuration,
                        StartTimestamp = session.StartTime,
                        Interface = networkInterface
                    });

                    return session.SessionId;
                }
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Stops a capture session
        /// </summary>
        public async Task StopCaptureAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            await _sessionLock.WaitAsync(cancellationToken);
            try
            {
                if (!_activeSessions.TryGetValue(sessionId, out var session))
                {
                    throw new ArgumentException($"Session not found: {sessionId}");
                }

                using (_performanceMonitor.Time("Capture_Stop"))
                {
                    await session.StopAsync(SessionStopReason.UserRequested);

                    // Remove from active sessions
                    _activeSessions.TryRemove(sessionId, out _);

                    // Raise event
                    SessionStopped?.Invoke(this, new SessionStoppedEventArgs
                    {
                        SessionId = sessionId,
                        StopTimestamp = DateTime.UtcNow,
                        Reason = SessionStopReason.UserRequested,
                        Statistics = session.Statistics.CreateSnapshot(),
                        Duration = session.Duration
                    });

                    // Dispose session
                    session.Dispose();
                }
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Stops all active capture sessions
        /// </summary>
        public async Task StopAllCapturesAsync(CancellationToken cancellationToken = default)
        {
            var sessionIds = _activeSessions.Keys.ToList();
            foreach (var sessionId in sessionIds)
            {
                try
                {
                    await StopCaptureAsync(sessionId, cancellationToken);
                }
                catch
                {
                    // Continue stopping other sessions
                }
            }
        }

        /// <summary>
        /// Gets statistics for a specific session
        /// </summary>
        public CaptureStatisticsSnapshot? GetSessionStatistics(string sessionId)
        {
            if (_activeSessions.TryGetValue(sessionId, out var session))
            {
                return session.Statistics.CreateSnapshot();
            }
            return null;
        }

        /// <summary>
        /// Gets statistics for all active sessions
        /// </summary>
        public Dictionary<string, CaptureStatisticsSnapshot> GetAllStatistics()
        {
            return _activeSessions.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Statistics.CreateSnapshot());
        }

        /// <summary>
        /// Captures packets from a session
        /// </summary>
        private async Task CapturePacketsAsync(
            CaptureSession session,
            CancellationToken cancellationToken)
        {
            try
            {
                // Get TShark process from session
                var process = session.GetTSharkProcess();
                if (process == null)
                {
                    throw new InvalidOperationException("TShark process not available");
                }

                // Read JSON output line by line from TShark
                var outputStream = process.StandardOutput;
                string? line;

                while (!cancellationToken.IsCancellationRequested &&
                       session.IsRunning &&
                       !process.HasExited)
                {
                    try
                    {
                        line = await outputStream.ReadLineAsync(cancellationToken);

                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        // Parse TShark JSON output
                        using (PerformanceMonitor.Instance.Time("TShark_JSON_Parse"))
                        {
                            var packetData = ParseTSharkJson(line, session);
                            if (packetData == null)
                                continue;

                            // Update statistics
                            session.Statistics.IncrementPacketsCaptured();
                            session.Statistics.IncrementPacketsReceived();
                            session.Statistics.AddBytesReceived(packetData.Data.Length);

                            // Enqueue for processing
                            if (session.Configuration.EnablePacketEvents)
                            {
                                await _packetProcessor.EnqueuePacketAsync(packetData, cancellationToken);
                            }

                            session.Statistics.IncrementPacketsProcessed();
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (JsonException jsonEx)
                    {
                        session.Statistics.IncrementProcessingErrors();
                        OnSessionError(session, new CaptureErrorEventArgs
                        {
                            SessionId = session.SessionId,
                            ErrorType = CaptureErrorType.ParsingError,
                            ErrorMessage = $"JSON parsing error: {jsonEx.Message}",
                            Exception = jsonEx,
                            ErrorTimestamp = DateTime.UtcNow,
                            IsRecoverable = true
                        });
                    }
                    catch (Exception ex)
                    {
                        session.Statistics.IncrementProcessingErrors();
                        OnSessionError(session, new CaptureErrorEventArgs
                        {
                            SessionId = session.SessionId,
                            ErrorType = CaptureErrorType.ParsingError,
                            ErrorMessage = ex.Message,
                            Exception = ex,
                            ErrorTimestamp = DateTime.UtcNow,
                            IsRecoverable = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                OnSessionError(session, new CaptureErrorEventArgs
                {
                    SessionId = session.SessionId,
                    ErrorType = CaptureErrorType.Unknown,
                    ErrorMessage = $"Capture loop error: {ex.Message}",
                    Exception = ex,
                    ErrorTimestamp = DateTime.UtcNow,
                    IsRecoverable = false
                });
            }
        }

        /// <summary>
        /// Parses TShark JSON output into PacketData
        /// </summary>
        /// <param name="jsonLine">JSON line from TShark output</param>
        /// <param name="session">Capture session</param>
        /// <returns>Parsed packet data or null if parsing failed</returns>
        private PacketData? ParseTSharkJson(string jsonLine, CaptureSession session)
        {
            try
            {
                using var jsonDoc = JsonDocument.Parse(jsonLine);
                var root = jsonDoc.RootElement;

                // TShark JSON format: { "_source": { "layers": { ... } } }
                if (!root.TryGetProperty("_source", out var source))
                    return null;

                if (!source.TryGetProperty("layers", out var layers))
                    return null;

                // Extract timestamp
                var timestamp = DateTime.UtcNow;
                if (layers.TryGetProperty("frame.time_epoch", out var timeEpoch))
                {
                    var timeArray = timeEpoch.EnumerateArray().FirstOrDefault();
                    if (timeArray.ValueKind == JsonValueKind.String &&
                        double.TryParse(timeArray.GetString(), out var epochSeconds))
                    {
                        timestamp = DateTimeOffset.FromUnixTimeSeconds((long)epochSeconds)
                            .AddSeconds(epochSeconds - (long)epochSeconds)
                            .UtcDateTime;
                    }
                }

                // Extract frame length
                var frameLength = 0;
                if (layers.TryGetProperty("frame.len", out var frameLenProp))
                {
                    var lenArray = frameLenProp.EnumerateArray().FirstOrDefault();
                    if (lenArray.ValueKind == JsonValueKind.String &&
                        int.TryParse(lenArray.GetString(), out var len))
                    {
                        frameLength = len;
                    }
                }

                // Extract protocol information
                var protocols = string.Empty;
                if (layers.TryGetProperty("frame.protocols", out var protocolsProp))
                {
                    var protoArray = protocolsProp.EnumerateArray().FirstOrDefault();
                    if (protoArray.ValueKind == JsonValueKind.String)
                    {
                        protocols = protoArray.GetString() ?? string.Empty;
                    }
                }

                // Extract IP addresses
                string? srcIp = ExtractFirstArrayValue(layers, "ip.src") ??
                               ExtractFirstArrayValue(layers, "ipv6.src");
                string? dstIp = ExtractFirstArrayValue(layers, "ip.dst") ??
                               ExtractFirstArrayValue(layers, "ipv6.dst");

                // Extract ports
                string? srcPort = ExtractFirstArrayValue(layers, "tcp.srcport") ??
                                 ExtractFirstArrayValue(layers, "udp.srcport");
                string? dstPort = ExtractFirstArrayValue(layers, "tcp.dstport") ??
                                 ExtractFirstArrayValue(layers, "udp.dstport");

                // Extract MAC addresses
                string? srcMac = ExtractFirstArrayValue(layers, "eth.src");
                string? dstMac = ExtractFirstArrayValue(layers, "eth.dst");

                // Create packet buffer (for now, we'll create a placeholder)
                // In a full implementation, we would have the actual packet bytes
                var buffer = _bufferPool.Rent();
                var bufferMemory = buffer.AsMemory(0, Math.Min(frameLength, buffer.Length));

                // Create metadata dictionary
                var metadata = new Dictionary<string, object>
                {
                    ["SessionId"] = session.SessionId,
                    ["InterfaceId"] = session.Interface.Id,
                    ["FrameLength"] = frameLength,
                    ["Protocols"] = protocols
                };

                if (srcIp != null) metadata["SourceIP"] = srcIp;
                if (dstIp != null) metadata["DestinationIP"] = dstIp;
                if (srcPort != null) metadata["SourcePort"] = srcPort;
                if (dstPort != null) metadata["DestinationPort"] = dstPort;
                if (srcMac != null) metadata["SourceMAC"] = srcMac;
                if (dstMac != null) metadata["DestinationMAC"] = dstMac;

                return new PacketData
                {
                    PacketNumber = session.Statistics.PacketsCaptured + 1,
                    Timestamp = timestamp,
                    Data = bufferMemory,
                    Metadata = metadata
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extracts the first value from a TShark JSON array property
        /// </summary>
        private static string? ExtractFirstArrayValue(JsonElement layers, string propertyName)
        {
            if (layers.TryGetProperty(propertyName, out var property))
            {
                var firstElement = property.EnumerateArray().FirstOrDefault();
                if (firstElement.ValueKind == JsonValueKind.String)
                {
                    return firstElement.GetString();
                }
            }
            return null;
        }

        /// <summary>
        /// Processes a captured packet
        /// </summary>
        private Task<ProcessingResult> ProcessPacketAsync(PacketData packet)
        {
            try
            {
                using (_performanceMonitor.Time("Packet_Processing"))
                {
                    // Extract session ID from metadata
                    var sessionId = packet.Metadata.TryGetValue("SessionId", out var sid)
                        ? sid.ToString()
                        : string.Empty;

                    // Raise packet captured event
                    if (!string.IsNullOrEmpty(sessionId))
                    {
                        PacketCaptured?.Invoke(this, new PacketCapturedEventArgs
                        {
                            Packet = packet,
                            SessionId = sessionId!,
                            CaptureTimestamp = packet.Timestamp,
                            InterfaceId = packet.Metadata.TryGetValue("InterfaceId", out var iid)
                                ? iid.ToString()!
                                : string.Empty
                        });
                    }

                    return Task.FromResult(new ProcessingResult
                    {
                        Success = true
                    });
                }
            }
            catch (Exception ex)
            {
                return Task.FromResult(new ProcessingResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        /// <summary>
        /// Monitors and broadcasts statistics
        /// </summary>
        private async Task MonitorStatisticsAsync(
            CaptureSession session,
            CancellationToken cancellationToken)
        {
            var interval = session.Configuration.StatisticsUpdateInterval;

            while (session.IsRunning && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(interval, cancellationToken);

                    var snapshot = session.Statistics.CreateSnapshot();

                    StatisticsUpdated?.Invoke(this, new StatisticsUpdatedEventArgs
                    {
                        SessionId = session.SessionId,
                        Statistics = snapshot,
                        UpdateTimestamp = DateTime.UtcNow
                    });
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Continue monitoring despite errors
                }
            }
        }

        /// <summary>
        /// Handles session state changes
        /// </summary>
        private void OnSessionStateChanged(object? sender, SessionStateChangedEventArgs e)
        {
            // Additional state change handling can be added here
        }

        /// <summary>
        /// Handles session errors
        /// </summary>
        private void OnSessionError(object? sender, CaptureErrorEventArgs e)
        {
            CaptureError?.Invoke(this, e);
        }

        /// <summary>
        /// Pauses a capture session
        /// </summary>
        public async Task PauseCaptureAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (!_activeSessions.TryGetValue(sessionId, out var session))
            {
                throw new ArgumentException($"Session not found: {sessionId}");
            }

            await session.PauseAsync();
        }

        /// <summary>
        /// Resumes a capture session
        /// </summary>
        public async Task ResumeCaptureAsync(
            string sessionId,
            CancellationToken cancellationToken = default)
        {
            if (!_activeSessions.TryGetValue(sessionId, out var session))
            {
                throw new ArgumentException($"Session not found: {sessionId}");
            }

            await session.ResumeAsync();
        }

        /// <summary>
        /// Gets the state of a capture session
        /// </summary>
        public CaptureSessionState? GetSessionState(string sessionId)
        {
            if (_activeSessions.TryGetValue(sessionId, out var session))
            {
                return session.State;
            }
            return null;
        }

        /// <summary>
        /// Validates a capture filter
        /// </summary>
        public CaptureFilter ValidateFilter(string filterExpression)
        {
            return new CaptureFilter(filterExpression);
        }

        /// <summary>
        /// Creates a capture configuration with validation
        /// </summary>
        public async Task<CaptureConfiguration> CreateConfigurationAsync(
            string interfaceId,
            string? captureFilter = null,
            string? outputFilePath = null,
            CancellationToken cancellationToken = default)
        {
            // Validate interface exists
            var iface = await _interfaceDiscovery.GetInterfaceByIdAsync(interfaceId, cancellationToken);
            if (iface == null)
            {
                throw new ArgumentException($"Interface not found: {interfaceId}");
            }

            // Validate filter if provided
            if (!string.IsNullOrWhiteSpace(captureFilter))
            {
                var filter = new CaptureFilter(captureFilter);
                if (!filter.IsValid)
                {
                    throw new ArgumentException(
                        $"Invalid capture filter: {string.Join(", ", filter.ValidationErrors)}");
                }
            }

            return new CaptureConfiguration
            {
                InterfaceId = interfaceId,
                CaptureFilter = captureFilter,
                OutputFilePath = outputFilePath
            };
        }

        /// <summary>
        /// Gets performance metrics
        /// </summary>
        public string GetPerformanceReport()
        {
            return _performanceMonitor.GenerateReport();
        }

        /// <summary>
        /// Gets object pool statistics
        /// </summary>
        public ObjectPoolStatistics GetPoolStatistics()
        {
            return _bufferPool.Statistics;
        }

        public void Dispose()
        {
            if (_disposed) return;

            // Stop all sessions
            StopAllCapturesAsync().Wait(TimeSpan.FromSeconds(10));

            // Unsubscribe from session events and dispose sessions
            foreach (var session in _activeSessions.Values)
            {
                session.StateChanged -= OnSessionStateChanged;
                session.ErrorOccurred -= OnSessionError;
                session.Dispose();
            }
            _activeSessions.Clear();

            _packetProcessor.Dispose();
            _bufferPool.Dispose();
            _sessionLock.Dispose();
            _interfaceDiscovery.Dispose();

            _disposed = true;
        }
    }
}
