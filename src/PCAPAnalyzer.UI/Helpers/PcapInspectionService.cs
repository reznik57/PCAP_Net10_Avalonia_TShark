using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace PCAPAnalyzer.UI.Helpers;

public readonly record struct PcapInspectionProgress(double PercentComplete, long BytesRead, long PacketCount, double BytesPerSecond);

public readonly record struct PcapInspectionResult(bool Success, long PacketCount, long BytesRead, bool IsPcapNg, string? ErrorMessage);

/// <summary>
/// Lightweight PCAP/PCAPNG inspector that counts packets and reports byte-level progress without
/// spawning TShark. Used to provide early stage progress feedback while gathering capture metadata.
/// </summary>
public sealed class PcapInspectionService
{
    private static readonly byte[] ByteOrderMagicLittle = { 0x1A, 0x2B, 0x3C, 0x4D };
    private static readonly byte[] ByteOrderMagicBig = { 0x4D, 0x3C, 0x2B, 0x1A };

    public PcapInspectionResult Inspect(string path, IProgress<PcapInspectionProgress>? progress, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new PcapInspectionResult(false, 0, 0, false, "Capture file not found");
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 1 << 20, FileOptions.SequentialScan);

        if (stream.Length < 4)
        {
            return new PcapInspectionResult(false, 0, 0, false, "Capture too small to inspect");
        }

        Span<byte> magicSpan = stackalloc byte[4];
        if (!ReadExactly(stream, magicSpan))
        {
            return new PcapInspectionResult(false, 0, 0, false, "Unable to read capture header");
        }

        stream.Position = 0;
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(magicSpan);
        return magic switch
        {
            0x0A0D0D0A => InspectPcapNg(stream, progress, cancellationToken),
            0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1 => InspectClassicPcap(stream, progress, cancellationToken),
            _ => new PcapInspectionResult(false, 0, 0, false, $"Unrecognized capture format (magic 0x{magic:X8})")
        };
    }

    private static PcapInspectionResult InspectClassicPcap(FileStream stream, IProgress<PcapInspectionProgress>? progress, CancellationToken cancellationToken)
    {
        Span<byte> header = stackalloc byte[24];
        if (!ReadExactly(stream, header))
        {
            return new PcapInspectionResult(false, 0, 0, false, "Incomplete PCAP global header");
        }

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        var isLittleEndian = magic is 0xA1B2C3D4 or 0xA1B23C4D;
        var fileLength = stream.Length;
        long bytesRead = header.Length;
        long packetCount = 0;

        Span<byte> packetHeader = stackalloc byte[16];
        var totalStopwatch = Stopwatch.StartNew();
        var reportStopwatch = Stopwatch.StartNew();

        while (stream.Position < fileLength)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!ReadExactly(stream, packetHeader))
            {
                break; // Partial footer - treat as EOF
            }

            var capturedLength = isLittleEndian
                ? BinaryPrimitives.ReadUInt32LittleEndian(packetHeader.Slice(8, 4))
                : BinaryPrimitives.ReadUInt32BigEndian(packetHeader.Slice(8, 4));

            bytesRead += packetHeader.Length;
            packetCount++;

            var payloadSkip = Math.Min((long)capturedLength, Math.Max(0L, fileLength - stream.Position));
            stream.Seek(payloadSkip, SeekOrigin.Current);
            bytesRead += payloadSkip;

            if (progress is not null && reportStopwatch.ElapsedMilliseconds >= 200)
            {
                ReportProgress(progress, bytesRead, fileLength, packetCount, totalStopwatch.Elapsed);
                reportStopwatch.Restart();
            }
        }

        totalStopwatch.Stop();
        ReportProgress(progress, bytesRead, fileLength, packetCount, totalStopwatch.Elapsed, force: true);
        return new PcapInspectionResult(true, packetCount, Math.Min(bytesRead, fileLength), false, null);
    }

    private static PcapInspectionResult InspectPcapNg(FileStream stream, IProgress<PcapInspectionProgress>? progress, CancellationToken cancellationToken)
    {
        var fileLength = stream.Length;
        long bytesRead = 0;
        long packetCount = 0;
        bool? isLittleEndian = null;

        Span<byte> blockHeader = stackalloc byte[12];
        var totalStopwatch = Stopwatch.StartNew();
        var reportStopwatch = Stopwatch.StartNew();

        while (stream.Position < fileLength)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!ReadExactly(stream, blockHeader))
            {
                break;
            }

            bytesRead += blockHeader.Length;
            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(blockHeader[..4]);

            if (blockType == 0x0A0D0D0A)
            {
                // Section Header block - use contained byte-order magic to determine endianness
                var bomBytes = blockHeader.Slice(8, 4);
                if (bomBytes.SequenceEqual(ByteOrderMagicLittle))
                {
                    isLittleEndian = true;
                }
                else if (bomBytes.SequenceEqual(ByteOrderMagicBig))
                {
                    isLittleEndian = false;
                }
                else
                {
                    return new PcapInspectionResult(false, packetCount, bytesRead, true, "Invalid PCAPNG byte-order magic");
                }
            }
            else if (isLittleEndian is null)
            {
                return new PcapInspectionResult(false, packetCount, bytesRead, true, "PCAPNG section header missing");
            }

            var blockLength = isLittleEndian == true
                ? BinaryPrimitives.ReadUInt32LittleEndian(blockHeader.Slice(4, 4))
                : BinaryPrimitives.ReadUInt32BigEndian(blockHeader.Slice(4, 4));

            if (blockLength < 12)
            {
                return new PcapInspectionResult(false, packetCount, bytesRead, true, "Corrupt PCAPNG block length");
            }

            long remainingBytes = Math.Max(0L, (long)blockLength - 12L); // Exclude header and trailing length
            if (stream.Position + remainingBytes > fileLength)
            {
                remainingBytes = Math.Max(0L, fileLength - stream.Position);
            }

            // Count enhanced/simple packet blocks
            if (blockType is 0x00000006 or 0x00000003)
            {
                packetCount++;
            }

            stream.Seek(remainingBytes, SeekOrigin.Current);
            bytesRead += remainingBytes;

            if (progress is not null && reportStopwatch.ElapsedMilliseconds >= 200)
            {
                ReportProgress(progress, bytesRead, fileLength, packetCount, totalStopwatch.Elapsed);
                reportStopwatch.Restart();
            }
        }

        totalStopwatch.Stop();
        ReportProgress(progress, bytesRead, fileLength, packetCount, totalStopwatch.Elapsed, force: true);
        return new PcapInspectionResult(true, packetCount, Math.Min(bytesRead, fileLength), true, null);
    }

    private static void ReportProgress(IProgress<PcapInspectionProgress>? progress, long bytesRead, long fileLength, long packetCount, TimeSpan elapsed, bool force = false)
    {
        if (progress is null)
        {
            return;
        }

        var percent = fileLength > 0 ? Math.Clamp(bytesRead / (double)fileLength * 100.0, 0, 100) : 0;
        var rate = elapsed.TotalSeconds > 0 ? bytesRead / elapsed.TotalSeconds : 0;
        if (!force && percent <= 0)
        {
            return;
        }

        progress.Report(new PcapInspectionProgress(percent, Math.Min(bytesRead, fileLength), packetCount, rate));
    }

    private static bool ReadExactly(Stream stream, Span<byte> buffer)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = stream.Read(buffer[totalRead..]);
            if (read == 0)
            {
                return false;
            }
            totalRead += read;
        }

        return true;
    }
}
