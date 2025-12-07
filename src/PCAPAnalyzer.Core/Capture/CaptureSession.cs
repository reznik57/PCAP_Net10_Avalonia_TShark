using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Capture.Events;
using PCAPAnalyzer.Core.Capture.Models;

namespace PCAPAnalyzer.Core.Capture
{
    /// <summary>
    /// Represents an active packet capture session
    /// Manages the TShark process and session lifecycle
    /// </summary>
    public sealed class CaptureSession : IDisposable
    {
        private readonly string _sessionId;
        private readonly CaptureConfiguration _configuration;
        private readonly NetworkInterface _interface;
        private readonly CaptureStatistics _statistics;
        private Process? _tsharkProcess;
        private CaptureSessionState _state;
        private DateTime _startTime;
        private DateTime? _stopTime;
        private readonly SemaphoreSlim _stateLock = new(1, 1);
        private readonly CancellationTokenSource _cancellationSource;
        private Task? _monitorTask;
        private bool _disposed;
        private int _restartAttempts;

        /// <summary>
        /// Gets the session identifier
        /// </summary>
        public string SessionId => _sessionId;

        /// <summary>
        /// Gets the capture configuration
        /// </summary>
        public CaptureConfiguration Configuration => _configuration;

        /// <summary>
        /// Gets the network interface
        /// </summary>
        public NetworkInterface Interface => _interface;

        /// <summary>
        /// Gets the capture statistics
        /// </summary>
        public CaptureStatistics Statistics => _statistics;

        /// <summary>
        /// Gets the current session state
        /// </summary>
        public CaptureSessionState State => _state;

        /// <summary>
        /// Gets the session start time
        /// </summary>
        public DateTime StartTime => _startTime;

        /// <summary>
        /// Gets the session stop time (null if still running)
        /// </summary>
        public DateTime? StopTime => _stopTime;

        /// <summary>
        /// Gets the session duration
        /// </summary>
        public TimeSpan Duration
        {
            get
            {
                if (_state == CaptureSessionState.NotStarted)
                    return TimeSpan.Zero;
                var endTime = _stopTime ?? DateTime.UtcNow;
                return endTime - _startTime;
            }
        }

        /// <summary>
        /// Gets whether the session is running
        /// </summary>
        public bool IsRunning => _state == CaptureSessionState.Running;

        /// <summary>
        /// Gets the TShark process (for internal use by LiveCaptureManager)
        /// </summary>
        internal Process? GetTSharkProcess() => _tsharkProcess;

        /// <summary>
        /// Event raised when session state changes
        /// </summary>
        public event EventHandler<SessionStateChangedEventArgs>? StateChanged;

        /// <summary>
        /// Event raised when a capture error occurs
        /// </summary>
        public event EventHandler<CaptureErrorEventArgs>? ErrorOccurred;

        /// <summary>
        /// Initializes a new capture session
        /// </summary>
        public CaptureSession(
            CaptureConfiguration configuration,
            NetworkInterface networkInterface)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(networkInterface);
            _configuration = configuration;
            _interface = networkInterface;

            _sessionId = Guid.NewGuid().ToString("N");
            _statistics = new();
            _state = CaptureSessionState.NotStarted;
            _cancellationSource = new();

            _configuration.Validate();
        }

        /// <summary>
        /// Starts the capture session
        /// </summary>
        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            await _stateLock.WaitAsync(cancellationToken);
            try
            {
                if (_state != CaptureSessionState.NotStarted)
                {
                    throw new InvalidOperationException($"Cannot start session in state {_state}");
                }

                ChangeState(CaptureSessionState.Starting);

                // Build TShark command
                var arguments = BuildTSharkArguments();

                // Start TShark process
                var psi = new ProcessStartInfo
                {
                    FileName = _configuration.TSharkPath ?? "tshark",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true, // Required for graceful shutdown
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                _tsharkProcess = new Process { StartInfo = psi };
                _tsharkProcess.EnableRaisingEvents = true;
                _tsharkProcess.Exited += OnProcessExited;

                // Start the process
                if (!_tsharkProcess.Start())
                {
                    throw new InvalidOperationException("Failed to start TShark process");
                }

                _startTime = DateTime.UtcNow;

                // Start monitoring task
                _monitorTask = Task.Run(() => MonitorProcessAsync(_cancellationSource.Token), _cancellationSource.Token);

                ChangeState(CaptureSessionState.Running);
            }
            catch (Exception ex)
            {
                ChangeState(CaptureSessionState.Error);
                OnError(CaptureErrorType.ProcessError, $"Failed to start capture: {ex.Message}", ex);
                throw;
            }
            finally
            {
                _stateLock.Release();
            }
        }

        /// <summary>
        /// Stops the capture session
        /// </summary>
        public async Task StopAsync(SessionStopReason reason = SessionStopReason.UserRequested)
        {
            await _stateLock.WaitAsync();
            try
            {
                if (_state != CaptureSessionState.Running && _state != CaptureSessionState.Starting)
                {
                    return;
                }

                ChangeState(CaptureSessionState.Stopping);

                _stopTime = DateTime.UtcNow;

                // Cancel monitoring
                _cancellationSource.Cancel();

                // Stop TShark process gracefully
                if (_tsharkProcess is not null && !_tsharkProcess.HasExited)
                {
                    try
                    {
                        // TShark responds to Ctrl+C for graceful shutdown
                        // On Windows, we can use GenerateConsoleCtrlEvent
                        // On Unix, we send SIGTERM
                        if (OperatingSystem.IsWindows())
                        {
                            // Try to close stdin first
                            try
                            {
                                _tsharkProcess.StandardInput.Close();
                            }
                            catch { /* Best effort - process may already be closing */ }
                        }

                        // Wait for graceful exit
                        if (!_tsharkProcess.WaitForExit(5000))
                        {
                            // Force kill if not exited
                            _tsharkProcess.Kill();
                        }
                    }
                    catch (Exception ex)
                    {
                        OnError(CaptureErrorType.ProcessError, $"Error stopping process: {ex.Message}", ex);
                    }
                }

                // Wait for monitor task
                if (_monitorTask is not null)
                {
                    try
                    {
                        await _monitorTask;
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected
                    }
                }

                ChangeState(CaptureSessionState.Stopped);
            }
            finally
            {
                _stateLock.Release();
            }
        }

        /// <summary>
        /// Pauses the capture session
        /// </summary>
        public async Task PauseAsync()
        {
            await _stateLock.WaitAsync();
            try
            {
                if (_state != CaptureSessionState.Running)
                {
                    throw new InvalidOperationException($"Cannot pause session in state {_state}");
                }

                // Note: TShark doesn't support pause, so this is a logical pause
                // In a full implementation, this would stop accepting new packets
                ChangeState(CaptureSessionState.Paused);
            }
            finally
            {
                _stateLock.Release();
            }
        }

        /// <summary>
        /// Resumes the capture session
        /// </summary>
        public async Task ResumeAsync()
        {
            await _stateLock.WaitAsync();
            try
            {
                if (_state != CaptureSessionState.Paused)
                {
                    throw new InvalidOperationException($"Cannot resume session in state {_state}");
                }

                ChangeState(CaptureSessionState.Running);
            }
            finally
            {
                _stateLock.Release();
            }
        }

        /// <summary>
        /// Builds TShark command line arguments
        /// </summary>
        private string BuildTSharkArguments()
        {
            var args = new System.Text.StringBuilder();

            // Interface
            args.Append($"-i \"{EscapeArgument(_configuration.InterfaceId)}\"");

            // Capture filter
            if (!string.IsNullOrWhiteSpace(_configuration.CaptureFilter))
            {
                args.Append($" -f \"{EscapeArgument(_configuration.CaptureFilter)}\"");
            }

            // Promiscuous mode (note: -p in TShark DISABLES promiscuous mode)
            if (!_configuration.PromiscuousMode)
            {
                args.Append(" -p");
            }

            // Snapshot length
            if (_configuration.SnapshotLength > 0)
            {
                args.Append($" -s {_configuration.SnapshotLength}");
            }

            // Output file with dual output (to file AND stdout)
            if (!string.IsNullOrWhiteSpace(_configuration.OutputFilePath))
            {
                var format = _configuration.OutputFormat == CaptureFileFormat.Pcap ? "pcap" : "pcapng";
                args.Append($" -F {format} -w \"{EscapeArgument(_configuration.OutputFilePath)}\"");
            }

            // JSON output for real-time parsing
            args.Append(" -T json");

            // Line buffered output for real-time processing
            args.Append(" -l");

            // Export specific fields for efficient parsing
            args.Append(" -e frame.time_epoch");
            args.Append(" -e frame.len");
            args.Append(" -e frame.protocols");
            args.Append(" -e ip.src");
            args.Append(" -e ip.dst");
            args.Append(" -e ipv6.src");
            args.Append(" -e ipv6.dst");
            args.Append(" -e tcp.srcport");
            args.Append(" -e tcp.dstport");
            args.Append(" -e udp.srcport");
            args.Append(" -e udp.dstport");
            args.Append(" -e eth.src");
            args.Append(" -e eth.dst");

            // Additional arguments
            foreach (var arg in _configuration.AdditionalTSharkArgs)
            {
                args.Append($" {arg}");
            }

            return args.ToString();
        }

        /// <summary>
        /// Escapes command-line arguments for safe execution
        /// </summary>
        private static string EscapeArgument(string argument)
        {
            if (string.IsNullOrEmpty(argument))
                return argument;

            // Escape double quotes
            return argument.Replace("\"", "\\\"", StringComparison.Ordinal);
        }

        /// <summary>
        /// Monitors the TShark process
        /// </summary>
        private async Task MonitorProcessAsync(CancellationToken cancellationToken)
        {
            if (_tsharkProcess is null) return;

            try
            {
                while (!cancellationToken.IsCancellationRequested && !_tsharkProcess.HasExited)
                {
                    await Task.Delay(100, cancellationToken);

                    // Check for errors in stderr
                    if (_tsharkProcess.StandardError.Peek() > 0)
                    {
                        var errorLine = await _tsharkProcess.StandardError.ReadLineAsync(cancellationToken);
                        if (!string.IsNullOrEmpty(errorLine))
                        {
                            OnError(CaptureErrorType.ProcessError, errorLine, null);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected
            }
            catch (Exception ex)
            {
                OnError(CaptureErrorType.ProcessError, $"Monitor error: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Handles process exit
        /// </summary>
        private void OnProcessExited(object? sender, EventArgs e)
        {
            if (_state == CaptureSessionState.Stopping || _state == CaptureSessionState.Stopped)
            {
                return; // Expected exit
            }

            // Unexpected exit - try restart if configured
            if (_configuration.AutoRestart && _restartAttempts < _configuration.MaxRestartAttempts)
            {
                _restartAttempts++;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(1000); // Wait before restart
                        await StartAsync();
                    }
                    catch (Exception ex)
                    {
                        OnError(CaptureErrorType.ProcessError, $"Restart failed: {ex.Message}", ex);
                        ChangeState(CaptureSessionState.Error);
                    }
                });
            }
            else
            {
                ChangeState(CaptureSessionState.Error);
                OnError(CaptureErrorType.ProcessError, "TShark process exited unexpectedly", null);
            }
        }

        /// <summary>
        /// Changes session state and raises event
        /// </summary>
        private void ChangeState(CaptureSessionState newState)
        {
            var oldState = _state;
            _state = newState;

            StateChanged?.Invoke(this, new SessionStateChangedEventArgs
            {
                SessionId = _sessionId,
                OldState = oldState,
                NewState = newState,
                Timestamp = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Raises error event
        /// </summary>
        private void OnError(CaptureErrorType errorType, string message, Exception? exception)
        {
            ErrorOccurred?.Invoke(this, new CaptureErrorEventArgs
            {
                SessionId = _sessionId,
                ErrorType = errorType,
                ErrorMessage = message,
                Exception = exception,
                ErrorTimestamp = DateTime.UtcNow,
                IsRecoverable = _configuration.AutoRestart && _restartAttempts < _configuration.MaxRestartAttempts
            });
        }

        public void Dispose()
        {
            if (_disposed) return;

            if (_state == CaptureSessionState.Running)
            {
                StopAsync().Wait(TimeSpan.FromSeconds(5));
            }

            _cancellationSource.Cancel();
            _cancellationSource.Dispose();

            // Unsubscribe from process events to prevent memory leaks
            if (_tsharkProcess is not null)
            {
                _tsharkProcess.Exited -= OnProcessExited;
                _tsharkProcess.Dispose();
            }

            _stateLock.Dispose();

            _disposed = true;
        }
    }

    /// <summary>
    /// Capture session state
    /// </summary>
    public enum CaptureSessionState
    {
        NotStarted = 0,
        Starting = 1,
        Running = 2,
        Paused = 3,
        Stopping = 4,
        Stopped = 5,
        Error = 6
    }

    /// <summary>
    /// Event args for session state changed event
    /// </summary>
    public sealed class SessionStateChangedEventArgs : EventArgs
    {
        public string SessionId { get; init; } = string.Empty;
        public CaptureSessionState OldState { get; init; }
        public CaptureSessionState NewState { get; init; }
        public DateTime Timestamp { get; init; }
    }
}
