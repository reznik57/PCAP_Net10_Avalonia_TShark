using System;
using Avalonia;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Provides cached access to theme color resources from C# code-behind.
/// Uses lazy loading with fallback colors if resources are unavailable.
/// </summary>
public static class ThemeColorHelper
{
    // Anomaly severity colors - cached on first access
    private static SolidColorBrush? _criticalBrush;
    private static SolidColorBrush? _highBrush;
    private static SolidColorBrush? _mediumBrush;
    private static SolidColorBrush? _lowBrush;
    private static SolidColorBrush? _defaultTextBrush;

    // VoiceQoS series colors - cached on first access
    private static SolidColorBrush? _qosPacketsBrush;
    private static SolidColorBrush? _latencyMinBrush;
    private static SolidColorBrush? _latencyP5Brush;
    private static SolidColorBrush? _latencyAvgBrush;
    private static SolidColorBrush? _latencyP95Brush;
    private static SolidColorBrush? _latencyMaxBrush;
    private static SolidColorBrush? _jitterMinBrush;
    private static SolidColorBrush? _jitterP5Brush;
    private static SolidColorBrush? _jitterAvgBrush;
    private static SolidColorBrush? _jitterP95Brush;
    private static SolidColorBrush? _jitterMaxBrush;
    private static SolidColorBrush? _separatorBrush;

    // ==================== ANOMALY SEVERITY COLORS ====================

    /// <summary>Critical severity (red) - matches ThreatCritical theme color</summary>
    public static SolidColorBrush CriticalBrush =>
        _criticalBrush ??= GetBrushFromColor("ThreatCritical", "#F85149");

    /// <summary>High severity (orange) - matches ThreatMedium theme color</summary>
    public static SolidColorBrush HighBrush =>
        _highBrush ??= GetBrushFromColor("ThreatMedium", "#F59E0B");

    /// <summary>Medium severity (yellow)</summary>
    public static SolidColorBrush MediumBrush =>
        _mediumBrush ??= GetBrushFromColor("FilterWarningText", "#FCD34D");

    /// <summary>Low severity (blue) - matches StatPackets theme color</summary>
    public static SolidColorBrush LowBrush =>
        _lowBrush ??= GetBrushFromColor("StatPackets", "#3B82F6");

    /// <summary>Default text color - matches PopupText theme color</summary>
    public static SolidColorBrush DefaultTextBrush =>
        _defaultTextBrush ??= GetBrushFromColor("PopupText", "#F0F6FC");

    // ==================== VOICEQOS SERIES COLORS ====================

    /// <summary>QoS Packets series (green)</summary>
    public static SolidColorBrush QosPacketsBrush =>
        _qosPacketsBrush ??= GetBrushFromColor("ColorSuccess", "#3FB950");

    /// <summary>Latency Min series (light blue)</summary>
    public static SolidColorBrush LatencyMinBrush =>
        _latencyMinBrush ??= GetBrushFromColor("PopupLink", "#58A6FF");

    /// <summary>Latency P5 series (sky blue)</summary>
    public static SolidColorBrush LatencyP5Brush =>
        _latencyP5Brush ??= GetBrushFromColor("MetricLatencyP5", "#87CEEB");

    /// <summary>Latency Avg series (medium blue)</summary>
    public static SolidColorBrush LatencyAvgBrush =>
        _latencyAvgBrush ??= GetBrushFromColor("MetricLatencyAvg", "#1F6FEB");

    /// <summary>Latency P95 series (steel blue)</summary>
    public static SolidColorBrush LatencyP95Brush =>
        _latencyP95Brush ??= GetBrushFromColor("MetricLatencyP95", "#4682B4");

    /// <summary>Latency Max series (dark blue)</summary>
    public static SolidColorBrush LatencyMaxBrush =>
        _latencyMaxBrush ??= GetBrushFromColor("MetricLatencyMax", "#0969DA");

    /// <summary>Jitter Min series (orange)</summary>
    public static SolidColorBrush JitterMinBrush =>
        _jitterMinBrush ??= GetBrushFromColor("MetricJitterMin", "#FFA657");

    /// <summary>Jitter P5 series (lemon)</summary>
    public static SolidColorBrush JitterP5Brush =>
        _jitterP5Brush ??= GetBrushFromColor("MetricJitterP5", "#FFFACD");

    /// <summary>Jitter Avg series (red)</summary>
    public static SolidColorBrush JitterAvgBrush =>
        _jitterAvgBrush ??= GetBrushFromColor("MetricJitterAvg", "#F85149");

    /// <summary>Jitter P95 series (tomato)</summary>
    public static SolidColorBrush JitterP95Brush =>
        _jitterP95Brush ??= GetBrushFromColor("MetricJitterP95", "#FF6347");

    /// <summary>Jitter Max series (dark red)</summary>
    public static SolidColorBrush JitterMaxBrush =>
        _jitterMaxBrush ??= GetBrushFromColor("MetricJitterMax", "#DA3633");

    /// <summary>Separator/muted text color</summary>
    public static SolidColorBrush SeparatorBrush =>
        _separatorBrush ??= GetBrushFromColor("PopupText", "#F0F6FC");

    // ==================== PROTOCOL COLORS ====================

    public static SolidColorBrush GetProtocolBrush(string protocol)
    {
        var upper = protocol?.ToUpperInvariant() ?? "";
        return upper switch
        {
            "TCP" => GetBrushFromColor("ProtocolTCP", "#3FB950"),
            "UDP" => GetBrushFromColor("ProtocolUDP", "#58A6FF"),
            "ICMP" => GetBrushFromColor("ProtocolICMP", "#F78166"),
            "HTTP" => GetBrushFromColor("ProtocolHTTP", "#A371F7"),
            "HTTPS" or "TLS" or "SSL" => GetBrushFromColor("ProtocolHTTPS", "#8B5CF6"),
            "DNS" => GetBrushFromColor("ProtocolDNS", "#FFA657"),
            "SSH" => GetBrushFromColor("ProtocolSSH", "#56D4DD"),
            "FTP" => GetBrushFromColor("ProtocolFTP", "#FF7B72"),
            "SMTP" => GetBrushFromColor("ProtocolSMTP", "#D29922"),
            "SIP" => GetBrushFromColor("ProtocolSIP", "#F97583"),
            "RTP" => GetBrushFromColor("ProtocolRTP", "#FFAB70"),
            "LDAP" => GetBrushFromColor("ProtocolLDAP", "#79C0FF"),
            "SMB" or "SMB2" => GetBrushFromColor("ProtocolSMB", "#7EE787"),
            "NTP" => GetBrushFromColor("ProtocolNTP", "#A5D6FF"),
            "DHCP" => GetBrushFromColor("ProtocolDHCP", "#FFC058"),
            _ => GetBrushFromColor("ProtocolDefault", "#6E7681")
        };
    }

    public static string GetProtocolColorHex(string protocol)
    {
        var upper = protocol?.ToUpperInvariant() ?? "";
        return upper switch
        {
            "TCP" => GetColorHex("ProtocolTCP", "#3FB950"),
            "UDP" => GetColorHex("ProtocolUDP", "#58A6FF"),
            "ICMP" => GetColorHex("ProtocolICMP", "#F78166"),
            "HTTP" => GetColorHex("ProtocolHTTP", "#A371F7"),
            "HTTPS" or "TLS" or "SSL" => GetColorHex("ProtocolHTTPS", "#8B5CF6"),
            "DNS" => GetColorHex("ProtocolDNS", "#FFA657"),
            "SSH" => GetColorHex("ProtocolSSH", "#56D4DD"),
            "FTP" => GetColorHex("ProtocolFTP", "#FF7B72"),
            "SMTP" => GetColorHex("ProtocolSMTP", "#D29922"),
            "SIP" => GetColorHex("ProtocolSIP", "#F97583"),
            "RTP" => GetColorHex("ProtocolRTP", "#FFAB70"),
            "LDAP" => GetColorHex("ProtocolLDAP", "#79C0FF"),
            "SMB" or "SMB2" => GetColorHex("ProtocolSMB", "#7EE787"),
            "NTP" => GetColorHex("ProtocolNTP", "#A5D6FF"),
            "DHCP" => GetColorHex("ProtocolDHCP", "#FFC058"),
            _ => GetColorHex("ProtocolDefault", "#6E7681")
        };
    }

    // ==================== SECURITY RATING COLORS ====================

    public static SolidColorBrush GetSecurityRatingBrush(string rating)
    {
        var lower = rating?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "secure" or "safe" => GetBrushFromColor("RatingSecure", "#4CAF50"),
            "low" => GetBrushFromColor("RatingLow", "#8BC34A"),
            "medium" => GetBrushFromColor("RatingMedium", "#FFA726"),
            "high" => GetBrushFromColor("RatingHigh", "#EF5350"),
            "critical" => GetBrushFromColor("RatingCritical", "#B71C1C"),
            _ => GetBrushFromColor("RatingUnknown", "#9E9E9E")
        };
    }

    public static string GetSecurityRatingColorHex(string rating)
    {
        var lower = rating?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "secure" or "safe" => GetColorHex("RatingSecure", "#4CAF50"),
            "low" => GetColorHex("RatingLow", "#8BC34A"),
            "medium" => GetColorHex("RatingMedium", "#FFA726"),
            "high" => GetColorHex("RatingHigh", "#EF5350"),
            "critical" => GetColorHex("RatingCritical", "#B71C1C"),
            _ => GetColorHex("RatingUnknown", "#9E9E9E")
        };
    }

    // ==================== TRAFFIC INTENSITY COLORS ====================

    public static SolidColorBrush GetTrafficIntensityBrush(double percentage)
    {
        return percentage switch
        {
            < 0.1 => GetBrushFromColor("TrafficNone", "#6B7280"),
            < 1.0 => GetBrushFromColor("TrafficLow", "#3B82F6"),
            < 5.0 => GetBrushFromColor("TrafficMedium", "#10B981"),
            < 10.0 => GetBrushFromColor("TrafficHigh", "#F59E0B"),
            _ => GetBrushFromColor("TrafficCritical", "#EF4444")
        };
    }

    public static Color GetTrafficIntensityColor(double percentage)
    {
        return percentage switch
        {
            < 0.1 => GetColor("TrafficNone", "#6B7280"),
            < 1.0 => GetColor("TrafficLow", "#3B82F6"),
            < 5.0 => GetColor("TrafficMedium", "#10B981"),
            < 10.0 => GetColor("TrafficHigh", "#F59E0B"),
            _ => GetColor("TrafficCritical", "#EF4444")
        };
    }

    // ==================== VALIDATION COLORS ====================

    public static SolidColorBrush ValidationValidBrush =>
        GetBrushFromColor("ValidationValid", "#30363D");

    public static SolidColorBrush ValidationInvalidBrush =>
        GetBrushFromColor("ValidationInvalid", "#EF4444");

    // ==================== HIGHLIGHT COLORS ====================

    public static string HighlightYellowHex => GetColorHex("HighlightYellow", "#FFD700");
    public static string HighlightOrangeHex => GetColorHex("HighlightOrange", "#FFA500");

    public static SolidColorBrush StreamHighlightBrush =>
        GetBrushFromColor("StreamHighlight", "#1A3B82F6");

    public static SolidColorBrush SelectionHighlightBrush =>
        GetBrushFromColor("SelectionHighlight", "#333B82F6");

    // ==================== THREAT SEVERITY COLORS ====================

    public static string GetThreatSeverityColorHex(string severity)
    {
        var lower = severity?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "critical" => GetColorHex("ThreatCritical", "#EF4444"),
            "high" => GetColorHex("ThreatHigh", "#F97316"),
            "medium" => GetColorHex("ThreatMedium", "#F59E0B"),
            "low" => GetColorHex("ThreatLow", "#3B82F6"),
            "info" => GetColorHex("ProtocolDefault", "#6B7280"),
            _ => GetColorHex("ProtocolDefault", "#6B7280")
        };
    }

    // ==================== QUICK FILTER MODE COLORS ====================

    public static SolidColorBrush GetQuickFilterBorderBrush(bool isIncludeMode) =>
        isIncludeMode
            ? GetBrushFromColor("QuickFilterIncludeBorder", "#10B981")
            : GetBrushFromColor("QuickFilterExcludeBorder", "#EF4444");

    public static SolidColorBrush GetQuickFilterBackgroundBrush(bool isIncludeMode) =>
        isIncludeMode
            ? GetBrushFromColor("QuickFilterIncludeBg", "#0D1620")
            : GetBrushFromColor("QuickFilterExcludeBg", "#1A0D0D");

    public static SolidColorBrush GetQuickFilterLabelTextBrush(bool isIncludeMode) =>
        isIncludeMode
            ? GetBrushFromColor("QuickFilterIncludeLabelText", "#7EE787")
            : GetBrushFromColor("QuickFilterExcludeLabelText", "#FF7B72");

    public static SolidColorBrush GetQuickFilterLabelBgBrush(bool isIncludeMode) =>
        isIncludeMode
            ? GetBrushFromColor("QuickFilterIncludeLabelBg", "#1A3D1A")
            : GetBrushFromColor("QuickFilterExcludeLabelBg", "#3D1A1A");

    public static SolidColorBrush GetQuickFilterLabelBorderBrush(bool isIncludeMode) =>
        isIncludeMode
            ? GetBrushFromColor("QuickFilterIncludeLabelBorder", "#2EA043")
            : GetBrushFromColor("QuickFilterExcludeLabelBorder", "#F85149");

    public static string GetQuickFilterBorderColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeBorder", "#10B981")
            : GetColorHex("QuickFilterExcludeBorder", "#EF4444");

    public static string GetQuickFilterBackgroundColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeBg", "#0D1620")
            : GetColorHex("QuickFilterExcludeBg", "#1A0D0D");

    public static string GetQuickFilterGlowColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeGlow", "#10B98140")
            : GetColorHex("QuickFilterExcludeGlow", "#EF444440");

    public static string GetQuickFilterLabelTextColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeLabelText", "#7EE787")
            : GetColorHex("QuickFilterExcludeLabelText", "#FF7B72");

    public static string GetQuickFilterLabelBgColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeLabelBg", "#1A3D1A")
            : GetColorHex("QuickFilterExcludeLabelBg", "#3D1A1A");

    public static string GetQuickFilterLabelBorderColorHex(bool isIncludeMode) =>
        isIncludeMode
            ? GetColorHex("QuickFilterIncludeLabelBorder", "#2EA043")
            : GetColorHex("QuickFilterExcludeLabelBorder", "#F85149");

    // ==================== COUNTDOWN/ALERT COLORS ====================

    public static SolidColorBrush GetCountdownBackgroundBrush(bool isActive) =>
        isActive
            ? GetBrushFromColor("CountdownActiveBg", "#E0B91C1C")
            : GetBrushFromColor("PopupBg", "#0D1117");

    public static SolidColorBrush GetCountdownBorderBrush(bool isActive) =>
        isActive
            ? GetBrushFromColor("CountdownActiveBorder", "#DC2626")
            : GetBrushFromColor("CountdownInactiveBorder", "#58A6FF");

    // ==================== ANALYSIS STAGE COLORS ====================

    public static SolidColorBrush GetStageFillBrush(string state)
    {
        var lower = state?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "active" => GetBrushFromColor("StageActiveFill", "#3B82F6"),
            "completed" => GetBrushFromColor("StageCompletedFill", "#22C55E"),
            "error" => GetBrushFromColor("StageErrorFill", "#EF4444"),
            _ => GetBrushFromColor("StagePendingFill", "#4B5563")
        };
    }

    public static SolidColorBrush GetStageTextBrush(string state)
    {
        var lower = state?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "active" => GetBrushFromColor("StageActiveText", "#93C5FD"),
            "completed" => GetBrushFromColor("StageCompletedText", "#22C55E"),
            "error" => GetBrushFromColor("StageErrorText", "#EF4444"),
            _ => GetBrushFromColor("StagePendingText", "#D1D5DB")
        };
    }

    public static string GetStageColorHex(string state)
    {
        var lower = state?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "active" => GetColorHex("StageActiveFill", "#58A6FF"),
            "completed" => GetColorHex("StageCompletedFill", "#238636"),
            "error" => GetColorHex("StageErrorFill", "#DA3633"),
            _ => GetColorHex("StagePendingFill", "#8B949E")
        };
    }

    // ==================== STATUS COLORS ====================

    public static string GetStatusColorHex(string status)
    {
        var lower = status?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "green" or "success" or "running" => GetColorHex("StatusGreen", "#4ADE80"),
            "blue" or "info" or "loading" => GetColorHex("StatusBlue", "#4A9FFF"),
            "yellow" or "warning" or "paused" => GetColorHex("StatusYellow", "#FFC107"),
            "red" or "error" or "failed" => GetColorHex("StatusRed", "#FF5252"),
            "orange" or "partial" => GetColorHex("StatusOrange", "#FFA657"),
            _ => GetColorHex("StatusGray", "#8B949E")
        };
    }

    // ==================== CHART COLORS ====================

    private static readonly string[] ChartColorKeys = new[]
    {
        "ChartBlue", "ChartGreen", "ChartAmber", "ChartRed", "ChartPurple",
        "ChartPink", "ChartCyan", "ChartLime", "ChartOrange", "ChartIndigo"
    };

    private static readonly string[] ChartColorFallbacks = new[]
    {
        "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6",
        "#EC4899", "#06B6D4", "#84CC16", "#F97316", "#6366F1"
    };

    public static string GetChartColorHex(int index)
    {
        var safeIndex = index % ChartColorKeys.Length;
        return GetColorHex(ChartColorKeys[safeIndex], ChartColorFallbacks[safeIndex]);
    }

    public static string[] GetChartColorPalette()
    {
        var result = new string[ChartColorKeys.Length];
        for (int i = 0; i < ChartColorKeys.Length; i++)
        {
            result[i] = GetColorHex(ChartColorKeys[i], ChartColorFallbacks[i]);
        }
        return result;
    }

    public static string ChartThroughputColorHex => GetColorHex("ChartBlue", "#3B82F6");
    public static string ChartPacketsColorHex => GetColorHex("ChartGreen", "#10B981");
    public static string ChartAnomaliesColorHex => GetColorHex("ChartAmber", "#F59E0B");
    public static string ChartThreatsColorHex => GetColorHex("ChartRed", "#EF4444");
    public static string ChartGrayHex => GetColorHex("ChartGray", "#6B7280");
    public static string ChartPurpleHex => GetColorHex("ChartPurple", "#8B5CF6");
    public static string ChartTealHex => GetColorHex("ChartTeal", "#14B8A6");

    // ==================== COMPARE VIEW COLORS ====================

    public static SolidColorBrush CompareFileABrush => GetBrushFromColor("CompareFileA", "#F85149");
    public static SolidColorBrush CompareFileBBrush => GetBrushFromColor("CompareFileB", "#3FB950");
    public static SolidColorBrush CompareBothBrush => GetBrushFromColor("CompareBoth", "#8B949E");

    public static SolidColorBrush GetCompareFileTintBrush(string source)
    {
        var lower = source?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "filea" or "a" => GetBrushFromColor("CompareFileATint", "#1A0D0D"),
            "fileb" or "b" => GetBrushFromColor("CompareFileBTint", "#0D1A0D"),
            _ => new SolidColorBrush(Colors.Transparent)
        };
    }

    // ==================== MAP TRAFFIC COLORS ====================

    public static string GetMapTrafficColorHex(double normalizedValue)
    {
        return normalizedValue switch
        {
            > 0.66 => GetColorHex("MapTrafficHigh", "#EF4444"),
            > 0.33 => GetColorHex("MapTrafficMedium", "#F97316"),
            > 0 => GetColorHex("MapTrafficLow", "#3B82F6"),
            _ => GetColorHex("MapTrafficNone", "#1C2128")
        };
    }

    public static Color GetMapTrafficColor(double normalizedValue)
    {
        return normalizedValue switch
        {
            > 0.66 => GetColor("MapTrafficHigh", "#EF4444"),
            > 0.33 => GetColor("MapTrafficMedium", "#F97316"),
            > 0 => GetColor("MapTrafficLow", "#3B82F6"),
            _ => GetColor("MapTrafficNone", "#1C2128")
        };
    }

    public static string MapTrafficNoneHex => GetColorHex("MapTrafficNone", "#1C2128");
    public static Color MapHighRiskColor => GetColor("MapHighRisk", "#DC2626");

    // ==================== ANOMALY SEVERITY COLORS (HEX) ====================

    public static string GetAnomalySeverityColorHex(string severity)
    {
        var lower = severity?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "critical" => GetColorHex("ThreatCritical", "#F85149"),
            "high" => GetColorHex("ThreatHigh", "#F0883E"),
            "medium" => GetColorHex("ThreatMedium", "#D29922"),
            "low" => GetColorHex("PopupLink", "#58A6FF"),
            _ => GetColorHex("PopupTextSecondary", "#8B949E")
        };
    }

    // ==================== CAPTURE STATUS COLORS ====================

    public static string GetCaptureStatusColorHex(string status)
    {
        var lower = status?.ToLowerInvariant() ?? "";
        return lower switch
        {
            "capturing" or "running" or "success" => GetColorHex("StatusGreen", "#3FB950"),
            "initializing" or "paused" or "warning" => GetColorHex("StatusOrange", "#FFA657"),
            "stopped" or "completed" or "idle" => GetColorHex("StatusGray", "#8B949E"),
            "failed" or "error" => GetColorHex("StatusRed", "#FF7B72"),
            _ => GetColorHex("StatusGray", "#6C757D")
        };
    }

    // ==================== QOS SEVERITY COLORS ====================

    /// <summary>
    /// Gets hex color for QoS severity display (latency/jitter).
    /// </summary>
    public static string GetQoSSeverityColorHex(string metricType, string severity)
    {
        var lowerType = metricType?.ToLowerInvariant() ?? "";
        var lowerSeverity = severity?.ToLowerInvariant() ?? "";

        if (lowerType == "latency")
        {
            return lowerSeverity switch
            {
                "critical" => GetColorHex("LatencyCritical", "#003366"),
                "high" => GetColorHex("LatencyHigh", "#1F6FEB"),
                _ => GetColorHex("LatencyMedium", "#87CEEB")
            };
        }
        else // jitter
        {
            return lowerSeverity switch
            {
                "critical" => GetColorHex("JitterCritical", "#DC143C"),
                "high" => GetColorHex("JitterHigh", "#FF8C00"),
                _ => GetColorHex("JitterMedium", "#FFD700")
            };
        }
    }

    // ==================== MAP COLORS ====================

    public static Color MapBorderColor => GetColor("MapBorder", "#374151");
    public static Color MapLandColor => GetColor("MapLand", "#4B5563");
    public static Color MapTextDimColor => GetColor("MapTextDim", "#9CA3AF");
    public static Color MapTextBrightColor => GetColor("MapTextBright", "#E5E7EB");

    // ==================== PERCENTAGE BAR ====================

    public static Color PercentageTrackColor => GetColor("PercentageTrack", "#484F58");

    /// <summary>
    /// Gets the percentage bar gradient colors based on percentage value.
    /// Hot (10%+): red to orange
    /// Warm (1-9.9%): orange to green
    /// Cool (0.1-0.9%): blue gradient
    /// Gray: 0%
    /// </summary>
    public static (Color start, Color end) GetPercentageGradientColors(double percentage)
    {
        return percentage switch
        {
            >= 10.0 => (GetColor("PercentageHotStart", "#F85149"), GetColor("PercentageHotEnd", "#F0883E")),
            >= 1.0 => (GetColor("PercentageWarmStart", "#F0883E"), GetColor("PercentageWarmEnd", "#3FB950")),
            >= 0.1 => (GetColor("PercentageCoolStart", "#58A6FF"), GetColor("PercentageCoolEnd", "#79C0FF")),
            _ => (PercentageTrackColor, PercentageTrackColor)
        };
    }

    // ==================== SERIES COLOR LOOKUP ====================

    /// <summary>
    /// Gets the appropriate brush for a VoiceQoS series by name.
    /// </summary>
    public static SolidColorBrush GetSeriesBrush(string seriesName)
    {
        return seriesName switch
        {
            "QoS Packets" => QosPacketsBrush,
            "Latency Min" => LatencyMinBrush,
            "Latency P5" => LatencyP5Brush,
            "Latency Avg" => LatencyAvgBrush,
            "Latency P95" => LatencyP95Brush,
            "Latency Max" => LatencyMaxBrush,
            "Jitter Min" => JitterMinBrush,
            "Jitter P5" => JitterP5Brush,
            "Jitter Avg" => JitterAvgBrush,
            "Jitter P95" => JitterP95Brush,
            "Jitter Max" => JitterMaxBrush,
            _ => DefaultTextBrush
        };
    }

    /// <summary>
    /// Gets the hex color string for a VoiceQoS series by name.
    /// Used for SkiaSharp color parsing.
    /// </summary>
    public static string GetSeriesColorHex(string seriesName)
    {
        return seriesName switch
        {
            "QoS Packets" => GetColorHex("ColorSuccess", "#3FB950"),
            "Latency Min" => GetColorHex("PopupLink", "#58A6FF"),
            "Latency P5" => GetColorHex("MetricLatencyP5", "#87CEEB"),
            "Latency Avg" => GetColorHex("MetricLatencyAvg", "#1F6FEB"),
            "Latency P95" => GetColorHex("MetricLatencyP95", "#4682B4"),
            "Latency Max" => GetColorHex("MetricLatencyMax", "#0969DA"),
            "Jitter Min" => GetColorHex("MetricJitterMin", "#FFA657"),
            "Jitter P5" => GetColorHex("MetricJitterP5", "#FFFACD"),
            "Jitter Avg" => GetColorHex("MetricJitterAvg", "#F85149"),
            "Jitter P95" => GetColorHex("MetricJitterP95", "#FF6347"),
            "Jitter Max" => GetColorHex("MetricJitterMax", "#DA3633"),
            _ => "#F0F6FC"
        };
    }

    // ==================== INTERNAL HELPERS ====================

    /// <summary>
    /// Attempts to resolve a Color resource from the theme, returns fallback Color if not found.
    /// </summary>
    public static Color GetColor(string resourceKey, string fallbackHex)
    {
        try
        {
            var app = Application.Current;
            if (app != null && app.Resources.TryGetResource(resourceKey, null, out var resource))
            {
                if (resource is Color color)
                    return color;
            }
        }
        catch
        {
            // Ignore resource resolution errors, use fallback
        }

        return Color.Parse(fallbackHex);
    }

    /// <summary>
    /// Attempts to resolve a Color resource from the theme, returns fallback if not found.
    /// </summary>
    private static SolidColorBrush GetBrushFromColor(string resourceKey, string fallbackHex)
    {
        try
        {
            var app = Application.Current;
            if (app != null && app.Resources.TryGetResource(resourceKey, null, out var resource))
            {
                if (resource is Color color)
                    return new SolidColorBrush(color);
                if (resource is SolidColorBrush brush)
                    return brush;
            }
        }
        catch
        {
            // Ignore resource resolution errors, use fallback
        }

        return new SolidColorBrush(Color.Parse(fallbackHex));
    }

    /// <summary>
    /// Attempts to resolve a Color resource from the theme, returns fallback hex if not found.
    /// </summary>
    public static string GetColorHex(string resourceKey, string fallbackHex)
    {
        try
        {
            var app = Application.Current;
            if (app != null && app.Resources.TryGetResource(resourceKey, null, out var resource))
            {
                if (resource is Color color)
                    return $"#{color.A:X2}{color.R:X2}{color.G:X2}{color.B:X2}";
            }
        }
        catch
        {
            // Ignore resource resolution errors, use fallback
        }

        return fallbackHex;
    }

    /// <summary>
    /// Clears cached brushes (useful if theme changes at runtime).
    /// </summary>
    public static void ClearCache()
    {
        _criticalBrush = null;
        _highBrush = null;
        _mediumBrush = null;
        _lowBrush = null;
        _defaultTextBrush = null;
        _qosPacketsBrush = null;
        _latencyMinBrush = null;
        _latencyP5Brush = null;
        _latencyAvgBrush = null;
        _latencyP95Brush = null;
        _latencyMaxBrush = null;
        _jitterMinBrush = null;
        _jitterP5Brush = null;
        _jitterAvgBrush = null;
        _jitterP95Brush = null;
        _jitterMaxBrush = null;
        _separatorBrush = null;
    }
}
