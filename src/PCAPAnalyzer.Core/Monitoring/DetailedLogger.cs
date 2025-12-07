using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Provides detailed logging with different levels and categories
    /// </summary>
    public class DetailedLogger : IDisposable
    {
        private static readonly Lazy<DetailedLogger> _instance = new(() => new DetailedLogger());
        public static DetailedLogger Instance => _instance.Value;

        private readonly ConcurrentQueue<LogEntry> _logQueue = [];
        private readonly Timer _flushTimer;
        private readonly string _logDirectory;
        private readonly Lock _writeLock = new();
        private StreamWriter? _currentLogWriter;
        private DateTime _currentLogDate;
        private bool _isDisposed;

        // Configuration
        public LogLevel MinimumLevel { get; set; } = LogLevel.Info;
        public bool EnableConsoleOutput { get; set; } = true;
        public bool EnableFileOutput { get; set; } = true;
        public int MaxLogFileSizeMB { get; set; } = 10;

        private DetailedLogger()
        {
            _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(_logDirectory);
            
            _flushTimer = new Timer(FlushLogs, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            
            InitializeLogFile();
        }

        private void InitializeLogFile()
        {
            if (!EnableFileOutput) return;

            lock (_writeLock)
            {
                _currentLogWriter?.Dispose();
                
                _currentLogDate = DateTime.Today;
                var logFileName = $"pcap_analyzer_{_currentLogDate:yyyy-MM-dd}.log";
                var logPath = Path.Combine(_logDirectory, logFileName);
                
                _currentLogWriter = new StreamWriter(logPath, append: true, Encoding.UTF8)
                {
                    AutoFlush = false
                };
            }
        }

        public void Log(LogLevel level, string category, string message, Exception? exception = null)
        {
            if (level < MinimumLevel) return;

            var entry = new LogEntry
            {
                Timestamp = DateTime.UtcNow,
                Level = level,
                Category = category,
                Message = message,
                Exception = exception,
                ThreadId = Environment.CurrentManagedThreadId
            };

            _logQueue.Enqueue(entry);

            // Immediate console output for errors
            if (EnableConsoleOutput && level >= LogLevel.Error)
            {
                WriteToConsole(entry);
            }

            // Immediate flush for critical messages
            if (level == LogLevel.Critical)
            {
                FlushLogs(null);
            }
        }

        // Convenience methods
        public void Debug(string category, string message) => Log(LogLevel.Debug, category, message);
        public void Info(string category, string message) => Log(LogLevel.Info, category, message);
        public void Warning(string category, string message) => Log(LogLevel.Warning, category, message);
        public void Error(string category, string message, Exception? ex = null) => Log(LogLevel.Error, category, message, ex);
        public void Critical(string category, string message, Exception? ex = null) => Log(LogLevel.Critical, category, message, ex);

        /// <summary>
        /// Log performance metrics
        /// </summary>
        public void LogPerformance(string operation, TimeSpan duration, Dictionary<string, object>? metrics = null)
        {
            var sb = new StringBuilder($"Operation: {operation}, Duration: {duration.TotalMilliseconds:F2}ms");
            
            if (metrics != null)
            {
                foreach (var metric in metrics)
                {
                    sb.Append($", {metric.Key}: {metric.Value}");
                }
            }

            Log(LogLevel.Info, "PERFORMANCE", sb.ToString());
        }

        /// <summary>
        /// Log packet processing metrics
        /// </summary>
        public void LogPacketMetrics(int processed, int total, TimeSpan elapsed)
        {
            var rate = elapsed.TotalSeconds > 0 ? processed / elapsed.TotalSeconds : 0;
            var message = $"Processed {processed}/{total} packets in {elapsed.TotalSeconds:F2}s ({rate:F0} packets/sec)";
            Log(LogLevel.Info, "PACKETS", message);
        }

        private void FlushLogs(object? state)
        {
            if (_isDisposed) return;

            var entriesToWrite = new List<LogEntry>();
            
            while (_logQueue.TryDequeue(out var entry))
            {
                entriesToWrite.Add(entry);
            }

            if (entriesToWrite.Count == 0) return;

            // Write to console if enabled
            if (EnableConsoleOutput)
            {
                foreach (var entry in entriesToWrite.Where(e => e.Level >= LogLevel.Info))
                {
                    WriteToConsole(entry);
                }
            }

            // Write to file if enabled
            if (EnableFileOutput)
            {
                WriteToFile(entriesToWrite);
            }
        }

        private void WriteToConsole(LogEntry entry)
        {
            var color = entry.Level switch
            {
                LogLevel.Debug => ConsoleColor.Gray,
                LogLevel.Info => ConsoleColor.White,
                LogLevel.Warning => ConsoleColor.Yellow,
                LogLevel.Error => ConsoleColor.Red,
                LogLevel.Critical => ConsoleColor.Magenta,
                _ => ConsoleColor.White
            };

            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            
            var levelStr = entry.Level.ToString().ToUpper().PadRight(8);
            DebugLogger.Log($"[{entry.Timestamp:HH:mm:ss}] [{levelStr}] [{entry.Category}] {entry.Message}");
            
            if (entry.Exception != null)
            {
                DebugLogger.Log($"  Exception: {entry.Exception}");
            }
            
            Console.ForegroundColor = originalColor;
        }

        private void WriteToFile(List<LogEntry> entries)
        {
            lock (_writeLock)
            {
                // Check if we need to rotate log file
                if (_currentLogDate != DateTime.Today)
                {
                    InitializeLogFile();
                }

                if (_currentLogWriter == null) return;

                foreach (var entry in entries)
                {
                    var line = FormatLogEntry(entry);
                    _currentLogWriter.WriteLine(line);
                    
                    if (entry.Exception != null)
                    {
                        _currentLogWriter.WriteLine($"  Exception: {entry.Exception}");
                    }
                }

                _currentLogWriter.Flush();

                // Check file size for rotation
                var fileInfo = new FileInfo(Path.Combine(_logDirectory, $"pcap_analyzer_{_currentLogDate:yyyy-MM-dd}.log"));
                if (fileInfo.Exists && fileInfo.Length > MaxLogFileSizeMB * 1024 * 1024)
                {
                    RotateLogFile();
                }
            }
        }

        private string FormatLogEntry(LogEntry entry)
        {
            return $"{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{entry.Level,-8}] [{entry.ThreadId,3}] [{entry.Category,-15}] {entry.Message}";
        }

        private void RotateLogFile()
        {
            lock (_writeLock)
            {
                _currentLogWriter?.Dispose();
                
                var baseFileName = $"pcap_analyzer_{_currentLogDate:yyyy-MM-dd}";
                var counter = 1;
                string newFileName;
                
                do
                {
                    newFileName = $"{baseFileName}_{counter:000}.log";
                    counter++;
                } while (File.Exists(Path.Combine(_logDirectory, newFileName)));

                var oldPath = Path.Combine(_logDirectory, $"{baseFileName}.log");
                var newPath = Path.Combine(_logDirectory, newFileName);
                
                File.Move(oldPath, newPath);
                
                InitializeLogFile();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _flushTimer?.Dispose();
                FlushLogs(null); // Final flush

                lock (_writeLock)
                {
                    _currentLogWriter?.Dispose();
                    _currentLogWriter = null;
                }
            }

            _isDisposed = true;
        }

        private class LogEntry
        {
            public DateTime Timestamp { get; set; }
            public LogLevel Level { get; set; }
            public string Category { get; set; } = "";
            public string Message { get; set; } = "";
            public Exception? Exception { get; set; }
            public int ThreadId { get; set; }
        }
    }

    public enum LogLevel
    {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Critical = 4
    }
}