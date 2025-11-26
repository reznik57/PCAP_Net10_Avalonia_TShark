using System;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Centralized logging helper that adds timestamps to all console output
/// </summary>
public static class TimestampLogger
{
    /// <summary>
    /// Logs a message with a timestamp prefix [HH:mm:ss.fff]
    /// </summary>
    public static void Log(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        DebugLogger.Log($"[{timestamp}] {message}");
    }

    /// <summary>
    /// Logs a formatted message with a timestamp prefix
    /// </summary>
    public static void Log(string format, params object[] args)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        var message = string.Format(format, args);
        DebugLogger.Log($"[{timestamp}] {message}");
    }
}
