using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Quick statistics model for 8-metric grid display in FileAnalysisView.
/// Provides real-time snapshot of key analysis metrics during packet processing.
/// </summary>
public partial class QuickStatsModel : ObservableObject
{
    /// <summary>
    /// Total packets analyzed so far
    /// </summary>
    [ObservableProperty]
    private long _totalPackets;

    /// <summary>
    /// Total traffic volume in megabytes
    /// </summary>
    [ObservableProperty]
    private double _totalTrafficMB;

    /// <summary>
    /// Number of unique IP addresses encountered
    /// </summary>
    [ObservableProperty]
    private int _uniqueIPs;

    /// <summary>
    /// Number of unique ports (source and destination combined)
    /// </summary>
    [ObservableProperty]
    private int _uniquePorts;

    /// <summary>
    /// Number of unique conversations (IP:Port pairs)
    /// </summary>
    [ObservableProperty]
    private int _conversations;

    /// <summary>
    /// Number of security threats detected
    /// </summary>
    [ObservableProperty]
    private int _threats;

    /// <summary>
    /// Number of network anomalies detected
    /// </summary>
    [ObservableProperty]
    private int _anomalies;

    /// <summary>
    /// Number of unique protocols (TCP, UDP, ICMP, etc.)
    /// </summary>
    [ObservableProperty]
    private int _uniqueProtocols;

    /// <summary>
    /// Number of unique countries detected in traffic
    /// </summary>
    [ObservableProperty]
    private int _countries;

    /// <summary>
    /// Packet processing rate in packets per second
    /// </summary>
    [ObservableProperty]
    private long _processingRate;

    /// <summary>
    /// Reset all stats to zero
    /// </summary>
    public void Reset()
    {
        TotalPackets = 0;
        TotalTrafficMB = 0;
        UniqueIPs = 0;
        UniquePorts = 0;
        Conversations = 0;
        Threats = 0;
        Anomalies = 0;
        UniqueProtocols = 0;
        Countries = 0;
        ProcessingRate = 0;
    }

    // ==================== DIAGNOSTIC LOGGING ====================

    partial void OnTotalPacketsChanged(long value)
    {
        DebugLogger.Log($"[QuickStatsModel] 📦 TotalPackets changed to: {value:N0} (PropertyChanged should fire)");
    }

    partial void OnTotalTrafficMBChanged(double value)
    {
        DebugLogger.Log($"[QuickStatsModel] 💾 TotalTrafficMB changed to: {value:F2} MB (PropertyChanged should fire)");
    }

    partial void OnProcessingRateChanged(long value)
    {
        DebugLogger.Log($"[QuickStatsModel] ⚡ ProcessingRate changed to: {value:N0} pps (PropertyChanged should fire)");
    }

    partial void OnThreatsChanged(int value)
    {
        DebugLogger.Log($"[QuickStatsModel] 🛡️ Threats changed to: {value} (PropertyChanged should fire)");
    }

    partial void OnUniqueIPsChanged(int value)
    {
        DebugLogger.Log($"[QuickStatsModel] 🌐 UniqueIPs changed to: {value} (PropertyChanged should fire)");
    }
}
