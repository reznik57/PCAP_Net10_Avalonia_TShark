using System;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Converters;

/// <summary>
/// Validates IP address input and returns appropriate border brush.
/// Supports: single IP, comma-separated IPs, CIDR notation, wildcards.
/// Empty input is considered valid (no filter applied).
/// </summary>
public partial class IPValidationConverter : IValueConverter
{
    public static readonly IPValidationConverter Instance = new();

    // Valid border (default dark)
    private static readonly IBrush ValidBorder = new SolidColorBrush(Color.Parse("#30363D"));
    // Invalid border (red)
    private static readonly IBrush InvalidBorder = new SolidColorBrush(Color.Parse("#EF4444"));

    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}$")]
    private static partial Regex IPv4Regex();

    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")]
    private static partial Regex CIDRRegex();

    [GeneratedRegex(@"^(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*)$")]
    private static partial Regex WildcardRegex();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string input)
            return ValidBorder;

        // Empty is valid (no filter)
        if (string.IsNullOrWhiteSpace(input))
            return ValidBorder;

        // Check each comma-separated value
        var parts = input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var part in parts)
        {
            if (!IsValidIPEntry(part))
                return InvalidBorder;
        }

        return ValidBorder;
    }

    private static bool IsValidIPEntry(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
            return true;

        // Check for CIDR notation (e.g., 192.168.1.0/24)
        if (entry.Contains('/', StringComparison.Ordinal))
        {
            if (!CIDRRegex().IsMatch(entry))
                return false;

            var cidrParts = entry.Split('/');
            if (!IsValidIPv4(cidrParts[0]))
                return false;

            if (!int.TryParse(cidrParts[1], out var prefix) || prefix < 0 || prefix > 32)
                return false;

            return true;
        }

        // Check for wildcard notation (e.g., 192.168.*.*)
        if (entry.Contains('*', StringComparison.Ordinal))
        {
            return WildcardRegex().IsMatch(entry) && ValidateWildcardOctets(entry);
        }

        // Standard IPv4
        return IsValidIPv4(entry);
    }

    private static bool IsValidIPv4(string ip)
    {
        if (!IPv4Regex().IsMatch(ip))
            return false;

        var octets = ip.Split('.');
        foreach (var octet in octets)
        {
            if (!int.TryParse(octet, out var value) || value < 0 || value > 255)
                return false;
        }

        return true;
    }

    private static bool ValidateWildcardOctets(string ip)
    {
        var octets = ip.Split('.');
        foreach (var octet in octets)
        {
            if (octet == "*")
                continue;

            if (!int.TryParse(octet, out var value) || value < 0 || value > 255)
                return false;
        }
        return true;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Validates port range input and returns appropriate border brush.
/// Supports: single port, comma-separated ports, ranges (e.g., 80,443,8000-8100).
/// </summary>
public partial class PortValidationConverter : IValueConverter
{
    public static readonly PortValidationConverter Instance = new();

    private static readonly IBrush ValidBorder = new SolidColorBrush(Color.Parse("#30363D"));
    private static readonly IBrush InvalidBorder = new SolidColorBrush(Color.Parse("#EF4444"));

    [GeneratedRegex(@"^\d+(-\d+)?$")]
    private static partial Regex PortRangeRegex();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string input)
            return ValidBorder;

        if (string.IsNullOrWhiteSpace(input))
            return ValidBorder;

        var parts = input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var part in parts)
        {
            if (!IsValidPortEntry(part))
                return InvalidBorder;
        }

        return ValidBorder;
    }

    private static bool IsValidPortEntry(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
            return true;

        if (!PortRangeRegex().IsMatch(entry))
            return false;

        // Check if it's a range
        if (entry.Contains('-', StringComparison.Ordinal))
        {
            var rangeParts = entry.Split('-');
            if (rangeParts.Length != 2)
                return false;

            if (!int.TryParse(rangeParts[0], out var start) || !int.TryParse(rangeParts[1], out var end))
                return false;

            if (start < 0 || start > 65535 || end < 0 || end > 65535 || start > end)
                return false;
        }
        else
        {
            if (!int.TryParse(entry, out var port) || port < 0 || port > 65535)
                return false;
        }

        return true;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
