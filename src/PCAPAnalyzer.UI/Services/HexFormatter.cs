using System;
using System.Collections.Generic;
using System.Text;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Formats raw byte data into hex dump display format.
/// Produces Wireshark-style hex dump with offset, hex bytes, and ASCII columns.
/// </summary>
public class HexFormatter
{
    private const int BytesPerRow = 16;

    /// <summary>
    /// Formats raw bytes into hex dump lines
    /// </summary>
    public List<HexDumpLineViewModel> FormatHexDump(ReadOnlySpan<byte> data)
    {
        var lines = new List<HexDumpLineViewModel>();

        for (int offset = 0; offset < data.Length; offset += BytesPerRow)
        {
            var line = FormatHexLine(data, offset);
            lines.Add(line);
        }

        return lines;
    }

    /// <summary>
    /// Formats a single row of hex dump
    /// </summary>
    private HexDumpLineViewModel FormatHexLine(ReadOnlySpan<byte> data, int offset)
    {
        var hexBuilder = new StringBuilder(BytesPerRow * 3);
        var asciiBuilder = new StringBuilder(BytesPerRow);

        int bytesInRow = Math.Min(BytesPerRow, data.Length - offset);

        // Build hex bytes with grouping
        for (int i = 0; i < BytesPerRow; i++)
        {
            if (i < bytesInRow)
            {
                byte b = data[offset + i];
                hexBuilder.Append($"{b:X2} ");

                // ASCII representation
                char c = (b >= 32 && b <= 126) ? (char)b : '.';
                asciiBuilder.Append(c);
            }
            else
            {
                // Padding for incomplete rows
                hexBuilder.Append("   ");
                asciiBuilder.Append(' ');
            }

            // Add extra space every 8 bytes for readability
            if (i == 7)
            {
                hexBuilder.Append(' ');
            }
        }

        return new HexDumpLineViewModel(
            offset: $"{offset:X8}",
            hexBytes: hexBuilder.ToString().TrimEnd(),
            ascii: asciiBuilder.ToString()
        );
    }

    /// <summary>
    /// Formats ReadOnlyMemory wrapper (alternative method)
    /// </summary>
    public List<HexDumpLineViewModel> FormatHexDump(ReadOnlyMemory<byte> data)
    {
        return FormatHexDump(data.Span);
    }
}
