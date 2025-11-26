using System;

namespace PCAPAnalyzer.Core.Utilities;

/// <summary>
/// Conditional debug logging utility - logs only when PCAP_DEBUG environment variable is set.
/// Prevents console flooding in production while allowing diagnostics during development.
/// </summary>
public static class DebugLogger
{
    private static readonly bool _isDebugEnabled = InitializeDebugMode();

    private static bool InitializeDebugMode()
    {
        var debugEnv = Environment.GetEnvironmentVariable("PCAP_DEBUG");
        var isEnabled = string.Equals(debugEnv, "1", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(debugEnv, "true", StringComparison.OrdinalIgnoreCase);

        if (isEnabled)
        {
            Console.WriteLine("[DebugLogger] ⚙️  Debug logging ENABLED (set PCAP_DEBUG=0 to disable)");
        }

        return isEnabled;
    }

    /// <summary>
    /// Logs a debug message if debug mode is enabled.
    /// </summary>
    public static void Log(string message)
    {
        if (_isDebugEnabled)
        {
            Console.WriteLine(message);
        }
    }

    /// <summary>
    /// Logs a formatted debug message if debug mode is enabled.
    /// </summary>
    public static void Log(string format, params object?[] args)
    {
        if (_isDebugEnabled)
        {
            Console.WriteLine(format, args);
        }
    }

    /// <summary>
    /// Logs a critical message (always shown, regardless of debug setting).
    /// Use for errors, warnings, and important status updates.
    /// </summary>
    public static void Critical(string message)
    {
        Console.WriteLine(message);
    }

    /// <summary>
    /// Logs a critical formatted message (always shown).
    /// </summary>
    public static void Critical(string format, params object?[] args)
    {
        Console.WriteLine(format, args);
    }

    /// <summary>
    /// Returns true if debug logging is currently enabled.
    /// </summary>
    public static bool IsEnabled => _isDebugEnabled;
}
