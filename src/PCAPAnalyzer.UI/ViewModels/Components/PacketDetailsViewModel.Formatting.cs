using System.Text;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Formatting helpers for PacketDetailsViewModel.
/// Contains FormatStreamStatistics and display formatters.
/// </summary>
public partial class PacketDetailsViewModel
{
    /// <summary>
    /// Formats stream analysis results into rich display text.
    /// </summary>
    private static string FormatStreamStatistics(PacketInfo currentPacket, StreamAnalysisResult analysis)
    {
        var sb = new StringBuilder();

        // Current Packet Info
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"  CURRENT PACKET: #{currentPacket.FrameNumber}");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"Length: {currentPacket.Length} bytes");
        sb.AppendLine($"Timestamp: {currentPacket.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine();

        // TCP Connection State (if TCP)
        if (currentPacket.Protocol == Protocol.TCP)
        {
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine("  TCP CONNECTION STATE");
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine($"State: {analysis.TcpState.State}");

            if (analysis.TcpState.Handshake is not null)
            {
                sb.AppendLine($"Handshake: {analysis.TcpState.Handshake.GetDisplayString()}");
                if (analysis.TcpState.Handshake.HandshakeDuration.HasValue)
                {
                    sb.AppendLine($"Handshake Duration: {analysis.TcpState.Handshake.HandshakeDuration.Value.TotalMilliseconds:F2} ms");
                }
            }

            sb.AppendLine($"Retransmissions: {analysis.TcpState.RetransmissionCount} packets");
            sb.AppendLine($"Window Scaling: {analysis.TcpState.WindowScaling.GetDisplayString()}");
            sb.AppendLine($"Flags: {analysis.TcpState.Flags.GetDisplayString()}");
            sb.AppendLine();
        }

        // Bandwidth Metrics
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  BANDWIDTH METRICS");
        sb.AppendLine("═══════════════════════════════════════════════════════");

        var totalMB = analysis.Bandwidth.TotalBytes / (1024.0 * 1024.0);
        var totalKB = analysis.Bandwidth.TotalBytes / 1024.0;

        if (totalMB >= 1.0)
            sb.AppendLine($"Total Data: {totalMB:F2} MB ({analysis.Bandwidth.TotalBytes:N0} bytes)");
        else if (totalKB >= 1.0)
            sb.AppendLine($"Total Data: {totalKB:F2} KB ({analysis.Bandwidth.TotalBytes:N0} bytes)");
        else
            sb.AppendLine($"Total Data: {analysis.Bandwidth.TotalBytes:N0} bytes");

        sb.AppendLine($"Duration: {analysis.Bandwidth.Duration.TotalSeconds:F2} seconds");
        sb.AppendLine($"Average Throughput: {analysis.Bandwidth.GetAverageThroughputDisplay()}");

        if (analysis.Bandwidth.Peak is not null)
        {
            sb.AppendLine($"Peak Throughput: {analysis.Bandwidth.Peak.GetDisplayString()} at {analysis.Bandwidth.Peak.Timestamp:HH:mm:ss.fff}");
        }

        sb.AppendLine($"Average Packet Size: {analysis.Bandwidth.AveragePacketSize:F1} bytes");
        sb.AppendLine($"Packet Rate: {analysis.Bandwidth.AveragePacketsPerSecond:F1} packets/sec");
        sb.AppendLine();

        // Timing Analysis (if RTT data available)
        if (analysis.Timing.HasRttData)
        {
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine("  TIMING ANALYSIS");
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine($"Average RTT: {analysis.Timing.AverageRttMs:F2} ms");

            if (analysis.Timing.MinRttSample is not null)
            {
                sb.AppendLine($"Min RTT: {analysis.Timing.MinRttMs:F2} ms (packet #{analysis.Timing.MinRttSample.RequestPacket} ↔ #{analysis.Timing.MinRttSample.ResponsePacket})");
            }

            if (analysis.Timing.MaxRttSample is not null)
            {
                sb.AppendLine($"Max RTT: {analysis.Timing.MaxRttMs:F2} ms (packet #{analysis.Timing.MaxRttSample.RequestPacket} ↔ #{analysis.Timing.MaxRttSample.ResponsePacket})");
            }

            if (analysis.Timing.JitterMs.HasValue)
            {
                sb.AppendLine($"Jitter: {analysis.Timing.JitterMs.Value:F2} ms");
            }

            sb.AppendLine();
        }

        sb.AppendLine($"Inter-Packet Delay: {analysis.Timing.AverageInterPacketDelayMs:F2} ms (avg)");
        sb.AppendLine();

        // Application Protocol
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  APPLICATION LAYER");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"Protocol: {analysis.Protocol.GetDisplayString()}");
        sb.AppendLine($"Description: {analysis.Protocol.Description}");

        if (analysis.Protocol.Details.Count > 0)
        {
            sb.AppendLine("Details:");
            foreach (var detail in analysis.Protocol.Details)
            {
                sb.AppendLine($"  {detail.Key}: {detail.Value}");
            }
        }

        return sb.ToString();
    }
}
