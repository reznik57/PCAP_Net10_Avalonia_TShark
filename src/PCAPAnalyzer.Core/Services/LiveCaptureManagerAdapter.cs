using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Capture;
using PCAPAnalyzer.Core.Capture.Events;
using PCAPAnalyzer.Core.Services.Capture;
using BackendCaptureModels = PCAPAnalyzer.Core.Capture.Models;
using UICaptureModels = PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Adapts LiveCaptureManager (backend) to ILiveCaptureService (UI) interface
    /// Bridges the architectural gap between backend capture management and UI consumption
    /// </summary>
    public sealed class LiveCaptureManagerAdapter : ILiveCaptureService, IDisposable
    {
        private readonly LiveCaptureManager _captureManager;
        private readonly NetworkInterfaceDiscovery _interfaceDiscovery;
        private readonly EventThrottler<StatisticsEventArgs> _statsThrottler;
        private bool _disposed;
        private UICaptureModels.CaptureSession? _currentSession;
        private string? _currentSessionId;

        // UI-facing events
        public event EventHandler<UICaptureModels.LivePacketData>? PacketCaptured;
        public event EventHandler<UICaptureModels.CaptureSessionStats>? StatisticsUpdated;
        public event EventHandler<UICaptureModels.CaptureStatus>? StatusChanged;

        /// <summary>
        /// Current capture session (null if no active session)
        /// </summary>
        public UICaptureModels.CaptureSession? CurrentSession => _currentSession;

        /// <summary>
        /// Initializes the adapter with default TShark path
        /// </summary>
        public LiveCaptureManagerAdapter() : this(null)
        {
        }

        /// <summary>
        /// Initializes the adapter with custom TShark path
        /// </summary>
        /// <param name="tsharkPath">Path to TShark executable</param>
        public LiveCaptureManagerAdapter(string? tsharkPath)
        {
            _captureManager = new LiveCaptureManager(tsharkPath);
            _interfaceDiscovery = new NetworkInterfaceDiscovery(tsharkPath);

            // Wire up backend events to adapter event handlers
            _captureManager.PacketCaptured += OnBackendPacketCaptured;
            _captureManager.StatisticsUpdated += OnBackendStatisticsUpdated;
            _captureManager.SessionStarted += OnBackendSessionStarted;
            _captureManager.SessionStopped += OnBackendSessionStopped;
            _captureManager.CaptureError += OnBackendCaptureError;

            // Throttle statistics updates to 500ms to prevent UI saturation
            _statsThrottler = new EventThrottler<StatisticsEventArgs>(TimeSpan.FromMilliseconds(500));
            _statsThrottler.ThrottledEvent += (s, e) => StatisticsUpdated?.Invoke(this, e.Stats);
        }

        /// <summary>
        /// Starts packet capture with the specified configuration
        /// </summary>
        public async Task<UICaptureModels.CaptureSession> StartCaptureAsync(
            UICaptureModels.CaptureConfiguration config,
            CancellationToken cancellationToken = default)
        {
            if (_currentSession?.IsActive == true)
            {
                throw new InvalidOperationException("A capture session is already active. Stop it before starting a new one.");
            }

            config.Validate();

            // Convert UI config to backend config
            var backendConfig = new BackendCaptureModels.CaptureConfiguration
            {
                InterfaceId = config.InterfaceId,
                CaptureFilter = config.CaptureFilter,
                PromiscuousMode = config.PromiscuousMode,
                SnapshotLength = config.SnapshotLength,
                MaxFileDuration = config.MaxDurationSeconds > 0
                    ? TimeSpan.FromSeconds(config.MaxDurationSeconds)
                    : TimeSpan.Zero,
                EnablePacketEvents = true,
                EnableStatistics = true,
                StatisticsUpdateInterval = TimeSpan.FromSeconds(1),
                OutputFilePath = System.IO.Path.Combine(config.OutputDirectory,
                    $"{config.FileNamePrefix}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pcapng")
            };

            // Start backend capture
            _currentSessionId = await _captureManager.StartCaptureAsync(backendConfig, cancellationToken);

            // Get interface details for session
            var iface = await _interfaceDiscovery.GetInterfaceByIdAsync(config.InterfaceId, cancellationToken);

            // Create UI-level session object
            _currentSession = new UICaptureModels.CaptureSession
            {
                SessionId = _currentSessionId,
                InterfaceName = iface?.Name ?? config.InterfaceId,
                CaptureFilter = config.CaptureFilter,
                Status = UICaptureModels.CaptureStatus.Capturing,
                StartTime = DateTime.UtcNow,
                Stats = new UICaptureModels.CaptureSessionStats()
            };

            if (!string.IsNullOrEmpty(backendConfig.OutputFilePath))
            {
                _currentSession.CaptureFiles.Add(backendConfig.OutputFilePath);
            }

            return _currentSession;
        }

        /// <summary>
        /// Stops the current capture session
        /// </summary>
        public async Task StopCaptureAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_currentSessionId))
            {
                return;
            }

            await _captureManager.StopCaptureAsync(_currentSessionId, cancellationToken);

            if (_currentSession is not null)
            {
                _currentSession.EndTime = DateTime.UtcNow;
                _currentSession.Status = UICaptureModels.CaptureStatus.Stopped;
            }

            _currentSessionId = null;
        }

        /// <summary>
        /// Pauses the current capture session
        /// </summary>
        public async Task PauseCaptureAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_currentSessionId))
            {
                throw new InvalidOperationException("No active capture session to pause");
            }

            await _captureManager.PauseCaptureAsync(_currentSessionId, cancellationToken);

            if (_currentSession is not null)
            {
                _currentSession.Status = UICaptureModels.CaptureStatus.Paused;
            }

            StatusChanged?.Invoke(this, UICaptureModels.CaptureStatus.Paused);
        }

        /// <summary>
        /// Resumes a paused capture session
        /// </summary>
        public async Task ResumeCaptureAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_currentSessionId))
            {
                throw new InvalidOperationException("No paused capture session to resume");
            }

            await _captureManager.ResumeCaptureAsync(_currentSessionId, cancellationToken);

            if (_currentSession is not null)
            {
                _currentSession.Status = UICaptureModels.CaptureStatus.Capturing;
            }

            StatusChanged?.Invoke(this, UICaptureModels.CaptureStatus.Capturing);
        }

        /// <summary>
        /// Gets the current capture statistics
        /// </summary>
        public async Task<UICaptureModels.CaptureSessionStats> GetCurrentStatisticsAsync(
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_currentSessionId))
            {
                return new UICaptureModels.CaptureSessionStats();
            }

            var snapshot = _captureManager.GetSessionStatistics(_currentSessionId);
            if (snapshot is null)
            {
                return new UICaptureModels.CaptureSessionStats();
            }

            return await Task.FromResult(ConvertToSessionStats(snapshot));
        }

        /// <summary>
        /// Gets all capture sessions (active and historical)
        /// Note: Currently only returns current session as backend doesn't maintain full history
        /// </summary>
        public async Task<List<UICaptureModels.CaptureSession>> GetSessionHistoryAsync(
            int maxSessions = 100,
            CancellationToken cancellationToken = default)
        {
            var sessions = new List<UICaptureModels.CaptureSession>();
            if (_currentSession is not null)
            {
                sessions.Add(_currentSession);
            }
            return await Task.FromResult(sessions);
        }

        /// <summary>
        /// Exports the current capture to a file
        /// </summary>
        public async Task<string> ExportCaptureAsync(
            string outputPath,
            CancellationToken cancellationToken = default)
        {
            if (_currentSession is null || _currentSession.CaptureFiles.Count == 0)
            {
                throw new InvalidOperationException("No capture files available to export");
            }

            // If single file, use it directly
            if (_currentSession.CaptureFiles.Count == 1)
            {
                return await Task.FromResult(_currentSession.CaptureFiles[0]);
            }

            // For multiple files, would need mergecap (not implemented in backend)
            throw new NotImplementedException("Multiple file merging not yet implemented in backend");
        }

        /// <summary>
        /// Cleans up old capture files based on retention policy
        /// Note: Backend doesn't currently implement cleanup policy
        /// </summary>
        public async Task CleanupOldCapturesAsync(CancellationToken cancellationToken = default)
        {
            // Backend doesn't track historical files yet
            await Task.CompletedTask;
        }

        // Event Handlers - Backend → UI Event Mapping

        /// <summary>
        /// Handles backend packet captured events and converts to UI format
        /// </summary>
        private void OnBackendPacketCaptured(object? sender, PacketCapturedEventArgs e)
        {
            try
            {
                var uiPacket = ConvertToLivePacketData(e);
                PacketCaptured?.Invoke(this, uiPacket);
            }
            catch
            {
                // Suppress exceptions to prevent capture disruption
            }
        }

        /// <summary>
        /// Handles backend statistics updates with throttling
        /// </summary>
        private void OnBackendStatisticsUpdated(object? sender, StatisticsUpdatedEventArgs e)
        {
            try
            {
                var uiStats = ConvertToSessionStats(e.Statistics);

                if (_currentSession is not null)
                {
                    _currentSession.Stats = uiStats;
                }

                // Throttle to prevent UI saturation
                _statsThrottler.Enqueue(this, new StatisticsEventArgs { Stats = uiStats });
            }
            catch
            {
                // Suppress exceptions to prevent capture disruption
            }
        }

        /// <summary>
        /// Handles backend session started events
        /// </summary>
        private void OnBackendSessionStarted(object? sender, SessionStartedEventArgs e)
        {
            StatusChanged?.Invoke(this, UICaptureModels.CaptureStatus.Capturing);
        }

        /// <summary>
        /// Handles backend session stopped events
        /// </summary>
        private void OnBackendSessionStopped(object? sender, SessionStoppedEventArgs e)
        {
            StatusChanged?.Invoke(this, UICaptureModels.CaptureStatus.Stopped);
        }

        /// <summary>
        /// Handles backend capture errors
        /// </summary>
        private void OnBackendCaptureError(object? sender, CaptureErrorEventArgs e)
        {
            if (_currentSession is not null)
            {
                _currentSession.Status = UICaptureModels.CaptureStatus.Failed;
                _currentSession.ErrorMessage = e.ErrorMessage;
            }

            StatusChanged?.Invoke(this, UICaptureModels.CaptureStatus.Failed);
        }

        // Type Conversion Helpers

        /// <summary>
        /// Converts backend PacketCapturedEventArgs to UI LivePacketData
        /// </summary>
        private UICaptureModels.LivePacketData ConvertToLivePacketData(PacketCapturedEventArgs e)
        {
            var metadata = e.Packet.Metadata;

            return new UICaptureModels.LivePacketData
            {
                SequenceNumber = e.Packet.PacketNumber,
                Timestamp = e.Packet.Timestamp,
                Length = metadata.TryGetValue("FrameLength", out var len) && len is int frameLen
                    ? frameLen
                    : e.Packet.Data.Length,
                CapturedLength = e.Packet.Data.Length,
                SourceMac = metadata.TryGetValue("SourceMAC", out var srcMac)
                    ? srcMac?.ToString()
                    : null,
                DestinationMac = metadata.TryGetValue("DestinationMAC", out var dstMac)
                    ? dstMac?.ToString()
                    : null,
                SourceIp = metadata.TryGetValue("SourceIP", out var srcIp)
                    ? srcIp?.ToString()
                    : null,
                DestinationIp = metadata.TryGetValue("DestinationIP", out var dstIp)
                    ? dstIp?.ToString()
                    : null,
                SourcePort = metadata.TryGetValue("SourcePort", out var srcPort) &&
                            int.TryParse(srcPort?.ToString(), out var sp)
                    ? sp
                    : null,
                DestinationPort = metadata.TryGetValue("DestinationPort", out var dstPort) &&
                                 int.TryParse(dstPort?.ToString(), out var dp)
                    ? dp
                    : null,
                Protocol = metadata.TryGetValue("Protocols", out var proto)
                    ? ExtractPrimaryProtocol(proto?.ToString() ?? string.Empty)
                    : string.Empty,
                ProtocolInfo = metadata.TryGetValue("Protocols", out var protoInfo)
                    ? protoInfo?.ToString()
                    : null,
                InterfaceId = e.InterfaceId
            };
        }

        /// <summary>
        /// Converts backend CaptureStatisticsSnapshot to UI CaptureSessionStats
        /// </summary>
        private UICaptureModels.CaptureSessionStats ConvertToSessionStats(
            BackendCaptureModels.CaptureStatisticsSnapshot snapshot)
        {
            return new UICaptureModels.CaptureSessionStats
            {
                TotalPackets = snapshot.PacketsCaptured,
                TotalBytes = snapshot.BytesReceived,
                PacketsDropped = snapshot.PacketsDropped,
                CurrentPacketsPerSecond = snapshot.CaptureRate,
                CurrentBytesPerSecond = snapshot.DataRate,
                LastUpdate = DateTime.UtcNow
            };
        }

        /// <summary>
        /// Extracts primary protocol from TShark protocol chain (e.g., "eth:ip:tcp" → "TCP")
        /// </summary>
        private string ExtractPrimaryProtocol(string protocolChain)
        {
            if (string.IsNullOrWhiteSpace(protocolChain))
                return string.Empty;

            var protocols = protocolChain.Split(':');
            var primary = protocols.LastOrDefault(p => !string.IsNullOrWhiteSpace(p));
            return primary?.ToUpperInvariant() ?? string.Empty;
        }

        /// <summary>
        /// Disposes the adapter and underlying resources
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;

            // Unsubscribe from backend events
            _captureManager.PacketCaptured -= OnBackendPacketCaptured;
            _captureManager.StatisticsUpdated -= OnBackendStatisticsUpdated;
            _captureManager.SessionStarted -= OnBackendSessionStarted;
            _captureManager.SessionStopped -= OnBackendSessionStopped;
            _captureManager.CaptureError -= OnBackendCaptureError;

            // Dispose resources
            _statsThrottler?.Dispose();
            _captureManager?.Dispose();
            _interfaceDiscovery?.Dispose();

            _disposed = true;
        }

        /// <summary>
        /// Helper class to wrap statistics for event throttling
        /// </summary>
        private class StatisticsEventArgs : EventArgs
        {
            public UICaptureModels.CaptureSessionStats Stats { get; init; } = new();
        }
    }
}
