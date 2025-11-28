using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Security;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Converts protocol information to a color for visual identification in packet rows.
/// Uses L7 protocol if available, falls back to L4 protocol.
/// </summary>
public class ProtocolToColorConverter : IMultiValueConverter
{
    // Protocol color mappings (based on Wireshark-style coloring)
    private static readonly IBrush TcpBrush = new SolidColorBrush(Color.Parse("#3FB950"));      // Green
    private static readonly IBrush UdpBrush = new SolidColorBrush(Color.Parse("#58A6FF"));      // Blue
    private static readonly IBrush IcmpBrush = new SolidColorBrush(Color.Parse("#F78166"));     // Orange-red
    private static readonly IBrush HttpBrush = new SolidColorBrush(Color.Parse("#A371F7"));     // Purple
    private static readonly IBrush HttpsBrush = new SolidColorBrush(Color.Parse("#8B5CF6"));    // Deep purple
    private static readonly IBrush TlsBrush = new SolidColorBrush(Color.Parse("#C69026"));      // Gold
    private static readonly IBrush DnsBrush = new SolidColorBrush(Color.Parse("#FFA657"));      // Orange
    private static readonly IBrush SshBrush = new SolidColorBrush(Color.Parse("#56D4DD"));      // Teal
    private static readonly IBrush FtpBrush = new SolidColorBrush(Color.Parse("#FF7B72"));      // Red
    private static readonly IBrush SmtpBrush = new SolidColorBrush(Color.Parse("#D29922"));     // Yellow
    private static readonly IBrush SipBrush = new SolidColorBrush(Color.Parse("#F97583"));      // Pink
    private static readonly IBrush RtpBrush = new SolidColorBrush(Color.Parse("#FFAB70"));      // Light orange
    private static readonly IBrush DefaultBrush = new SolidColorBrush(Color.Parse("#6E7681"));  // Gray

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 2) return DefaultBrush;

        var l4Protocol = values[0] as Protocol? ?? Protocol.Unknown;
        var l7Protocol = values[1] as string;

        // First check L7 protocol for more specific coloring
        if (!string.IsNullOrEmpty(l7Protocol))
        {
            var l7Upper = l7Protocol.ToUpperInvariant();

            if (l7Upper.Contains("HTTP/", StringComparison.Ordinal) || l7Upper == "HTTP") return HttpBrush;
            if (l7Upper == "HTTPS" || l7Upper.Contains("TLS", StringComparison.Ordinal)) return HttpsBrush;
            if (l7Upper == "TLS" || l7Upper == "SSL") return TlsBrush;
            if (l7Upper == "DNS" || l7Upper == "MDNS") return DnsBrush;
            if (l7Upper == "SSH") return SshBrush;
            if (l7Upper.StartsWith("FTP", StringComparison.Ordinal)) return FtpBrush;
            if (l7Upper == "SMTP" || l7Upper == "IMAP" || l7Upper == "POP3") return SmtpBrush;
            if (l7Upper == "SIP") return SipBrush;
            if (l7Upper == "RTP" || l7Upper == "RTCP") return RtpBrush;
            if (l7Upper == "LDAP") return new SolidColorBrush(Color.Parse("#79C0FF"));
            if (l7Upper == "SMB" || l7Upper == "SMB2") return new SolidColorBrush(Color.Parse("#7EE787"));
            if (l7Upper == "NTP") return new SolidColorBrush(Color.Parse("#A5D6FF"));
            if (l7Upper == "DHCP") return new SolidColorBrush(Color.Parse("#FFC058"));
        }

        // Fall back to L4 protocol
        return l4Protocol switch
        {
            Protocol.TCP => TcpBrush,
            Protocol.UDP => UdpBrush,
            Protocol.ICMP => IcmpBrush,
            _ => DefaultBrush
        };
    }
}

/// <summary>
/// Single-value converter for simple protocol to color mapping (L4 only).
/// </summary>
public class SimpleProtocolToColorConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is Protocol protocol)
        {
            return protocol switch
            {
                Protocol.TCP => new SolidColorBrush(Color.Parse("#3FB950")),
                Protocol.UDP => new SolidColorBrush(Color.Parse("#58A6FF")),
                Protocol.ICMP => new SolidColorBrush(Color.Parse("#F78166")),
                _ => new SolidColorBrush(Color.Parse("#6E7681"))
            };
        }

        // Handle string protocol names
        if (value is string protocolStr)
        {
            return protocolStr.ToUpperInvariant() switch
            {
                "TCP" => new SolidColorBrush(Color.Parse("#3FB950")),
                "UDP" => new SolidColorBrush(Color.Parse("#58A6FF")),
                "ICMP" => new SolidColorBrush(Color.Parse("#F78166")),
                "HTTP" => new SolidColorBrush(Color.Parse("#A371F7")),
                "HTTPS" or "TLS" or "SSL" => new SolidColorBrush(Color.Parse("#8B5CF6")),
                "DNS" => new SolidColorBrush(Color.Parse("#FFA657")),
                "SSH" => new SolidColorBrush(Color.Parse("#56D4DD")),
                _ => new SolidColorBrush(Color.Parse("#6E7681"))
            };
        }

        return new SolidColorBrush(Color.Parse("#6E7681"));
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts packet info and selected stream key to a background color for stream highlighting.
/// Returns a highlighted brush if the packet belongs to the selected stream.
/// </summary>
public class StreamHighlightConverter : IMultiValueConverter
{
    private static readonly IBrush TransparentBrush = Brushes.Transparent;
    private static readonly IBrush StreamHighlightBrush = new SolidColorBrush(Color.Parse("#1A3B82F6")); // Subtle blue

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 2) return TransparentBrush;

        // PacketInfo is a struct - use pattern matching
        if (values[0] is not PacketInfo packet) return TransparentBrush;
        if (values[1] is not string selectedStreamKey || string.IsNullOrEmpty(selectedStreamKey))
            return TransparentBrush;

        var packetStreamKey = MainWindowPacketViewModel.GetNormalizedStreamKey(packet);

        if (string.Equals(packetStreamKey, selectedStreamKey, StringComparison.Ordinal))
            return StreamHighlightBrush;

        return TransparentBrush;
    }
}

/// <summary>
/// Converter for showing if a packet is the currently selected one.
/// </summary>
public class SelectedPacketConverter : IMultiValueConverter
{
    private static readonly IBrush TransparentBrush = Brushes.Transparent;
    private static readonly IBrush SelectedBrush = new SolidColorBrush(Color.Parse("#333B82F6")); // Blue for selected

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 2) return TransparentBrush;

        // PacketInfo is a struct - use pattern matching
        if (values[0] is not PacketInfo packet) return TransparentBrush;
        if (values[1] is not PacketInfo selectedPacket) return TransparentBrush;

        return packet.FrameNumber == selectedPacket.FrameNumber ? SelectedBrush : TransparentBrush;
    }
}

/// <summary>
/// Checks if a frame number is in the bookmarked frames collection.
/// </summary>
public class BookmarkVisibilityConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 2) return false;

        // Values: 0 = frame number, 1 = bookmarked frames collection
        if (values[0] is not uint frameNumber) return false;
        if (values[1] is not IReadOnlyCollection<uint> bookmarks) return false;

        return bookmarks.Contains(frameNumber);
    }
}

/// <summary>
/// Calculates time delta from first packet in the filtered dataset.
/// Shows elapsed time since first packet on the first page (absolute reference).
/// </summary>
public class TimeDeltaConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Count < 2) return "";

        // Values: 0 = packet timestamp, 1 = first packet timestamp (DateTime?)
        if (values[0] is not DateTime timestamp) return "";
        if (values[1] is not DateTime firstTimestamp) return "";

        var delta = timestamp - firstTimestamp;

        // Format based on magnitude
        if (delta.TotalSeconds < 1)
            return $"+{delta.TotalMilliseconds:F1}ms";
        if (delta.TotalMinutes < 1)
            return $"+{delta.TotalSeconds:F3}s";
        return $"+{delta.TotalMinutes:F1}m";
    }
}

/// <summary>
/// Converts port number to service name using the PortDatabase.
/// Falls back to port number if service is unknown.
/// Input: PacketInfo (uses destination port, falls back to source port)
/// </summary>
public class PortToServiceConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not PacketInfo packet) return "";

        // Already have L7 protocol? Use that
        if (!string.IsNullOrWhiteSpace(packet.L7Protocol))
            return packet.L7Protocol;

        // Try destination port first (more commonly the "service" port)
        var isTcp = packet.Protocol == Protocol.TCP;
        var port = packet.DestinationPort > 0 && packet.DestinationPort < 1024
            ? packet.DestinationPort
            : packet.SourcePort > 0 && packet.SourcePort < 1024
                ? packet.SourcePort
                : packet.DestinationPort > 0
                    ? packet.DestinationPort
                    : packet.SourcePort;

        if (port == 0) return packet.Protocol.ToString();

        var portInfo = PortDatabase.GetPortInfo(port, isTcp);
        return portInfo?.ServiceName ?? packet.Protocol.ToString();
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts port to service with risk indicator.
/// Shows: ServiceName (Risk) or just ServiceName for Low/Unknown risk.
/// </summary>
public class PortToServiceWithRiskConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not PacketInfo packet) return "";

        // Already have L7 protocol? Use that without risk (TShark identified it)
        if (!string.IsNullOrWhiteSpace(packet.L7Protocol))
            return packet.L7Protocol;

        // Try destination port first
        var isTcp = packet.Protocol == Protocol.TCP;
        var port = packet.DestinationPort > 0 && packet.DestinationPort < 1024
            ? packet.DestinationPort
            : packet.SourcePort > 0 && packet.SourcePort < 1024
                ? packet.SourcePort
                : packet.DestinationPort > 0
                    ? packet.DestinationPort
                    : packet.SourcePort;

        if (port == 0) return packet.Protocol.ToString();

        var portInfo = PortDatabase.GetPortInfo(port, isTcp);
        if (!portInfo.HasValue) return packet.Protocol.ToString();

        // Add risk indicator for high-risk ports
        return portInfo.Value.Risk switch
        {
            PortDatabase.PortRisk.Critical => $"{portInfo.Value.ServiceName} ⚠️",
            PortDatabase.PortRisk.High => $"{portInfo.Value.ServiceName} ⚡",
            _ => portInfo.Value.ServiceName
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts port risk level to a color for visual indication.
/// </summary>
public class PortRiskToColorConverter : IValueConverter
{
    private static readonly IBrush LowRiskBrush = new SolidColorBrush(Color.Parse("#4CAF50"));      // Green
    private static readonly IBrush MediumRiskBrush = new SolidColorBrush(Color.Parse("#FFA726"));   // Orange
    private static readonly IBrush HighRiskBrush = new SolidColorBrush(Color.Parse("#EF5350"));     // Red
    private static readonly IBrush CriticalRiskBrush = new SolidColorBrush(Color.Parse("#B71C1C")); // Dark Red
    private static readonly IBrush UnknownBrush = new SolidColorBrush(Color.Parse("#6E7681"));      // Gray

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not PacketInfo packet) return UnknownBrush;

        // Use the same port selection logic
        var isTcp = packet.Protocol == Protocol.TCP;
        var port = packet.DestinationPort > 0 && packet.DestinationPort < 1024
            ? packet.DestinationPort
            : packet.SourcePort > 0 && packet.SourcePort < 1024
                ? packet.SourcePort
                : packet.DestinationPort > 0
                    ? packet.DestinationPort
                    : packet.SourcePort;

        if (port == 0) return UnknownBrush;

        var portInfo = PortDatabase.GetPortInfo(port, isTcp);
        if (!portInfo.HasValue) return UnknownBrush;

        return portInfo.Value.Risk switch
        {
            PortDatabase.PortRisk.Low => LowRiskBrush,
            PortDatabase.PortRisk.Medium => MediumRiskBrush,
            PortDatabase.PortRisk.High => HighRiskBrush,
            PortDatabase.PortRisk.Critical => CriticalRiskBrush,
            _ => UnknownBrush
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Gets the full service description for tooltip display.
/// </summary>
public class PortToTooltipConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not PacketInfo packet) return null;

        var isTcp = packet.Protocol == Protocol.TCP;

        // Build comprehensive tooltip
        var lines = new System.Collections.Generic.List<string>();

        // Check destination port
        if (packet.DestinationPort > 0)
        {
            var destInfo = PortDatabase.GetPortInfo(packet.DestinationPort, isTcp);
            if (destInfo.HasValue)
            {
                lines.Add($"Dest Port {packet.DestinationPort}: {destInfo.Value.ServiceName}");
                lines.Add($"  {destInfo.Value.Description}");
                lines.Add($"  Risk: {destInfo.Value.Risk}");
                if (!string.IsNullOrEmpty(destInfo.Value.Recommendation))
                    lines.Add($"  ⚡ {destInfo.Value.Recommendation}");
            }
        }

        // Check source port (if different and well-known)
        if (packet.SourcePort > 0 && packet.SourcePort != packet.DestinationPort && packet.SourcePort < 1024)
        {
            var srcInfo = PortDatabase.GetPortInfo(packet.SourcePort, isTcp);
            if (srcInfo.HasValue)
            {
                if (lines.Count > 0) lines.Add("");
                lines.Add($"Src Port {packet.SourcePort}: {srcInfo.Value.ServiceName}");
                lines.Add($"  {srcInfo.Value.Description}");
            }
        }

        return lines.Count > 0 ? string.Join("\n", lines) : null;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
