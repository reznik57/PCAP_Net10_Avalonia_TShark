using System;
using System.Collections.Generic;
using System.Globalization;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Parses PacketInfo into hierarchical protocol layer structure.
/// Creates Wireshark-style protocol tree breakdown.
/// </summary>
public class ProtocolParser
{
    /// <summary>
    /// Parses packet into protocol tree hierarchy
    /// </summary>
    public List<ProtocolTreeItemViewModel> ParseProtocolTree(PacketInfo packet)
    {
        var tree = new List<ProtocolTreeItemViewModel>();

        // Frame layer
        var frameNode = CreateFrameLayer(packet);
        tree.Add(frameNode);

        // Ethernet layer (implied, not in PacketInfo)
        var ethernetNode = CreateEthernetLayer(packet);
        tree.Add(ethernetNode);

        // IP layer
        var ipNode = CreateIpLayer(packet);
        tree.Add(ipNode);

        // Transport layer (TCP/UDP/ICMP)
        var transportNode = CreateTransportLayer(packet);
        if (transportNode is not null)
        {
            tree.Add(transportNode);
        }

        // Application layer (if L7 protocol present)
        if (!string.IsNullOrWhiteSpace(packet.L7Protocol))
        {
            var appNode = CreateApplicationLayer(packet);
            tree.Add(appNode);
        }

        return tree;
    }

    /// <summary>
    /// Creates Frame layer node
    /// </summary>
    private ProtocolTreeItemViewModel CreateFrameLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "Frame",
            $"{packet.FrameNumber}: {packet.Length} bytes on wire",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Arrival Time", packet.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Frame Number", packet.FrameNumber.ToString("N0", CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Frame Length", $"{packet.Length} bytes", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Capture Length", $"{packet.Length} bytes", 1));

        return node;
    }

    /// <summary>
    /// Creates Ethernet layer node (inferred data)
    /// </summary>
    private ProtocolTreeItemViewModel CreateEthernetLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "Ethernet II",
            $"Src: (unknown), Dst: (unknown)",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Destination", "(MAC address not captured)", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Source", "(MAC address not captured)", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Type", "IPv4 (0x0800)", 1));

        return node;
    }

    /// <summary>
    /// Creates IP layer node
    /// </summary>
    private ProtocolTreeItemViewModel CreateIpLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "Internet Protocol Version 4",
            $"Src: {packet.SourceIP}, Dst: {packet.DestinationIP}",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Version", "4", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Header Length", "20 bytes (assumed)", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Total Length", packet.Length.ToString(CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Protocol", GetProtocolNumber(packet.Protocol), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Source Address", packet.SourceIP, 1));
        node.AddChild(new ProtocolTreeItemViewModel("Destination Address", packet.DestinationIP, 1));

        return node;
    }

    /// <summary>
    /// Creates Transport layer node (TCP/UDP/ICMP)
    /// </summary>
    private ProtocolTreeItemViewModel? CreateTransportLayer(PacketInfo packet)
    {
        return packet.Protocol switch
        {
            Protocol.TCP => CreateTcpLayer(packet),
            Protocol.UDP => CreateUdpLayer(packet),
            Protocol.ICMP => CreateIcmpLayer(packet),
            _ => null
        };
    }

    /// <summary>
    /// Creates TCP layer node with detailed TCP state
    /// </summary>
    private ProtocolTreeItemViewModel CreateTcpLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "Transmission Control Protocol",
            $"Src Port: {packet.SourcePort}, Dst Port: {packet.DestinationPort}",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Source Port", packet.SourcePort.ToString(CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Destination Port", packet.DestinationPort.ToString(CultureInfo.InvariantCulture), 1));

        if (packet.SeqNum > 0)
        {
            node.AddChild(new ProtocolTreeItemViewModel("Sequence Number", packet.SeqNum.ToString(CultureInfo.InvariantCulture), 1));
        }

        if (packet.AckNum > 0)
        {
            node.AddChild(new ProtocolTreeItemViewModel("Acknowledgment Number", packet.AckNum.ToString(CultureInfo.InvariantCulture), 1));
        }

        if (packet.TcpFlags > 0)
        {
            node.AddChild(CreateTcpFlagsNode(packet.TcpFlags));
        }

        if (packet.WindowSize > 0)
        {
            node.AddChild(new ProtocolTreeItemViewModel("Window Size", packet.WindowSize.ToString(CultureInfo.InvariantCulture), 1));
        }

        return node;
    }

    /// <summary>
    /// Creates TCP flags breakdown node
    /// </summary>
    private ProtocolTreeItemViewModel CreateTcpFlagsNode(ushort flags)
    {
        var flagsNode = new ProtocolTreeItemViewModel("Flags", $"0x{flags:X3}", 1);

        if ((flags & 0x20) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("URG", "Set", 2));
        if ((flags & 0x10) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("ACK", "Set", 2));
        if ((flags & 0x08) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("PSH", "Set", 2));
        if ((flags & 0x04) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("RST", "Set", 2));
        if ((flags & 0x02) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("SYN", "Set", 2));
        if ((flags & 0x01) != 0) flagsNode.AddChild(new ProtocolTreeItemViewModel("FIN", "Set", 2));

        return flagsNode;
    }

    /// <summary>
    /// Creates UDP layer node
    /// </summary>
    private ProtocolTreeItemViewModel CreateUdpLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "User Datagram Protocol",
            $"Src Port: {packet.SourcePort}, Dst Port: {packet.DestinationPort}",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Source Port", packet.SourcePort.ToString(CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Destination Port", packet.DestinationPort.ToString(CultureInfo.InvariantCulture), 1));
        node.AddChild(new ProtocolTreeItemViewModel("Length", packet.Length.ToString(CultureInfo.InvariantCulture), 1));

        return node;
    }

    /// <summary>
    /// Creates ICMP layer node
    /// </summary>
    private ProtocolTreeItemViewModel CreateIcmpLayer(PacketInfo packet)
    {
        var node = new ProtocolTreeItemViewModel(
            "Internet Control Message Protocol",
            $"{packet.Info ?? "ICMP"}",
            level: 0
        );

        node.AddChild(new ProtocolTreeItemViewModel("Type", "Unknown (not captured)", 1));
        node.AddChild(new ProtocolTreeItemViewModel("Code", "Unknown (not captured)", 1));

        return node;
    }

    /// <summary>
    /// Creates Application layer node (L7 protocol)
    /// </summary>
    private ProtocolTreeItemViewModel CreateApplicationLayer(PacketInfo packet)
    {
        var protocolName = packet.L7Protocol ?? "Application Data";
        var node = new ProtocolTreeItemViewModel(
            protocolName,
            "",
            level: 0
        );

        if (!string.IsNullOrWhiteSpace(packet.Info))
        {
            node.AddChild(new ProtocolTreeItemViewModel("Info", packet.Info, 1));
        }

        // Add encrypted data placeholder for secure protocols
        if (IsEncryptedProtocol(protocolName))
        {
            node.AddChild(new ProtocolTreeItemViewModel("Data", "[Encrypted Application Data]", 1));
        }

        return node;
    }

    /// <summary>
    /// Gets IP protocol number from Protocol enum
    /// </summary>
    private static string GetProtocolNumber(Protocol protocol)
    {
        return protocol switch
        {
            Protocol.ICMP => "ICMP (1)",
            Protocol.TCP => "TCP (6)",
            Protocol.UDP => "UDP (17)",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Checks if protocol uses encryption
    /// </summary>
    private static bool IsEncryptedProtocol(string protocol)
    {
        return protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
               protocol.Contains("SSL", StringComparison.OrdinalIgnoreCase) ||
               protocol.Equals("HTTPS", StringComparison.OrdinalIgnoreCase);
    }
}
