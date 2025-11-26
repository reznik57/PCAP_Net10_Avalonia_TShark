using FluentAssertions;
using PCAPAnalyzer.UI.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

/// <summary>
/// Unit tests for ProtocolColorService to ensure correct color assignments for network protocols.
/// Week 1 P1 Feature: Protocol Color Coding
/// </summary>
public class ProtocolColorServiceTests
{
    private readonly ProtocolColorService _service;

    public ProtocolColorServiceTests()
    {
        _service = new ProtocolColorService();
    }

    #region Known Protocol Color Tests

    [Theory]
    [InlineData("HTTP", "#A371F7")]
    [InlineData("HTTPS", "#8B5CF6")]
    [InlineData("DNS", "#FFA657")]
    [InlineData("TCP", "#3FB950")]
    [InlineData("UDP", "#58A6FF")]
    [InlineData("ICMP", "#F78166")]
    [InlineData("TLS", "#C69026")]
    [InlineData("SSL", "#C69026")]
    [InlineData("SSH", "#56D4DD")]
    [InlineData("FTP", "#FF7B72")]
    [InlineData("SMTP", "#D29922")]
    [InlineData("POP3", "#DCA732")]
    [InlineData("IMAP", "#E6B542")]
    public void GetProtocolColorHex_KnownProtocols_ReturnsCorrectColor(string protocol, string expectedColor)
    {
        // Act
        var actualColor = _service.GetProtocolColorHex(protocol);

        // Assert
        actualColor.Should().Be(expectedColor,
            because: $"protocol {protocol} should have a specific predefined color");
    }

    #endregion

    #region Unknown Protocol Tests

    [Fact]
    public void GetProtocolColorHex_UnknownProtocol_ReturnsDefaultColor()
    {
        // Arrange
        var unknownProtocol = "CUSTOM_PROTOCOL_XYZ";

        // Act
        var color = _service.GetProtocolColorHex(unknownProtocol);

        // Assert
        color.Should().Be("#6B7280",
            because: "unknown protocols should return the OTHER default color");
    }

    [Fact]
    public void GetProtocolColorHex_EmptyString_ReturnsDefaultColor()
    {
        // Act
        var color = _service.GetProtocolColorHex(string.Empty);

        // Assert
        color.Should().Be("#4B5563",
            because: "empty protocol names should return the UNKNOWN color");
    }

    [Fact]
    public void GetProtocolColorHex_NullProtocol_ReturnsDefaultColor()
    {
        // Act
        var color = _service.GetProtocolColorHex(null!);

        // Assert
        color.Should().Be("#4B5563",
            because: "null protocol names should return the UNKNOWN color");
    }

    #endregion

    #region Case Insensitivity Tests

    [Theory]
    [InlineData("http", "HTTP")]
    [InlineData("Http", "HTTP")]
    [InlineData("HtTp", "HTTP")]
    [InlineData("HTTP", "HTTP")]
    public void GetProtocolColorHex_CaseInsensitive_ReturnsSameColor(string protocol, string canonical)
    {
        // Act
        var actualColor = _service.GetProtocolColorHex(protocol);
        var expectedColor = _service.GetProtocolColorHex(canonical);

        // Assert
        actualColor.Should().Be(expectedColor,
            because: "protocol color lookup should be case-insensitive");
    }

    [Theory]
    [InlineData("dns", "DNS", "#FFA657")]
    [InlineData("tcp", "TCP", "#3FB950")]
    [InlineData("udp", "UDP", "#58A6FF")]
    [InlineData("ssh", "SSH", "#56D4DD")]
    public void GetProtocolColorHex_MixedCase_ReturnsCorrectColor(string protocol, string canonical, string expectedColor)
    {
        // Act
        var actualColor = _service.GetProtocolColorHex(protocol);

        // Assert
        actualColor.Should().Be(expectedColor,
            because: $"protocol {protocol} (canonical: {canonical}) should be case-insensitive");
    }

    #endregion

    #region Performance Tests

    [Fact]
    public void GetProtocolColorHex_CalledMultipleTimes_IsFast()
    {
        // Arrange
        var protocols = new[] { "HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP", "SSH", "FTP" };
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act: 10,000 lookups
        for (int i = 0; i < 10000; i++)
        {
            foreach (var protocol in protocols)
            {
                _ = _service.GetProtocolColorHex(protocol);
            }
        }
        stopwatch.Stop();

        // Assert: Should complete in < 100ms
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            because: "color lookups should be very fast (10,000 lookups < 100ms)");
    }

    [Fact]
    public void GetProtocolColorHex_SameProtocolRepeated_ConsistentResults()
    {
        // Arrange
        var protocol = "HTTP";

        // Act: Multiple calls
        var colors = Enumerable.Range(0, 100)
            .Select(_ => _service.GetProtocolColorHex(protocol))
            .ToList();

        // Assert: All results identical
        colors.Should().OnlyContain(c => c == "#A371F7",
            because: "repeated lookups of the same protocol should return consistent results");
    }

    #endregion

    #region Validation Tests

    [Fact]
    public void GetProtocolColor_AllDefinedProtocols_ReturnValidColorInfo()
    {
        // Arrange: Common protocols
        var protocols = new[]
        {
            "HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP",
            "TLS", "SSL", "SSH", "FTP", "SMTP", "POP3",
            "IMAP"
        };

        // Act & Assert
        foreach (var protocol in protocols)
        {
            var colorInfo = _service.GetProtocolColor(protocol);

            colorInfo.Should().NotBeNull($"protocol {protocol} should have color info");
            colorInfo.PrimaryColor.Should().MatchRegex("^#[0-9A-Fa-f]{6}$",
                $"protocol {protocol} primary color should be valid hex format");
            colorInfo.HoverColor.Should().MatchRegex("^#[0-9A-Fa-f]{6}$",
                $"protocol {protocol} hover color should be valid hex format");
            colorInfo.Description.Should().NotBeNullOrEmpty($"protocol {protocol} should have a description");
        }
    }

    [Fact]
    public void GetProtocolColorHex_AllColors_AreValidHex()
    {
        // Arrange: Sample all common protocols
        var protocols = new[]
        {
            "HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP", "TLS", "SSL",
            "SSH", "FTP", "SMTP", "POP3", "IMAP",
            "UNKNOWN_PROTOCOL" // Include default color
        };

        // Act & Assert
        foreach (var protocol in protocols)
        {
            var color = _service.GetProtocolColorHex(protocol);

            color.Should().MatchRegex("^#[0-9A-Fa-f]{6}$",
                $"color '{color}' for protocol '{protocol}' should match #RRGGBB format");
        }
    }

    [Fact]
    public void GetAllProtocolColors_ReturnsComprehensiveDictionary()
    {
        // Act
        var allColors = _service.GetAllProtocolColors();

        // Assert
        allColors.Should().NotBeEmpty("service should define protocol colors");
        allColors.Count.Should().BeGreaterThan(50, "service should have many protocols defined");
        allColors.Should().ContainKey("HTTP");
        allColors.Should().ContainKey("TCP");
        allColors.Should().ContainKey("DNS");
    }

    [Fact]
    public void GetCommonProtocolColors_ReturnsSubset()
    {
        // Act
        var commonColors = _service.GetCommonProtocolColors();

        // Assert
        commonColors.Should().NotBeEmpty();
        commonColors.Count.Should().BeLessThan(20, "common protocols should be a subset");
        commonColors.Should().ContainKey("HTTP");
        commonColors.Should().ContainKey("TCP");
        commonColors.Should().ContainKey("UDP");
        commonColors.Should().ContainKey("DNS");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void GetProtocolColorHex_WithNumericSuffix_PartialMatch()
    {
        // Arrange
        var protocolWithNumber = "HTTP/2";

        // Act
        var color = _service.GetProtocolColorHex(protocolWithNumber);

        // Assert
        color.Should().Be("#A371F7",
            because: "HTTP/2 contains HTTP and should match via partial matching");
    }

    [Fact]
    public void GetProtocolColorHex_VeryLongProtocolName_HandlesGracefully()
    {
        // Arrange
        var longProtocolName = new string('X', 1000);

        // Act
        var color = _service.GetProtocolColorHex(longProtocolName);

        // Assert
        color.Should().MatchRegex("^#[0-9A-Fa-f]{6}$",
            because: "service should handle any length protocol name gracefully");
    }

    [Fact]
    public void GetProtocolCategory_ReturnsCorrectCategories()
    {
        // Act & Assert
        _service.GetProtocolCategory("HTTP").Should().Be("Web");
        _service.GetProtocolCategory("TCP").Should().Be("Transport Layer");
        _service.GetProtocolCategory("IP").Should().Be("Network Layer");
        _service.GetProtocolCategory("SMTP").Should().Be("Email");
        _service.GetProtocolCategory("SSH").Should().Be("Remote Access");
        _service.GetProtocolCategory("MQTT").Should().Be("IoT");
        _service.GetProtocolCategory("UNKNOWN").Should().Be("Application Layer");
    }

    #endregion

    #region Color Readability Tests

    [Fact]
    public void GetProtocolColorHex_CommonProtocols_AreReadableOnDarkBackground()
    {
        // Arrange: Common protocols
        var protocols = new[]
        {
            "HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP",
            "TLS", "SSH", "FTP", "SMTP"
        };

        // Act & Assert: Check luminance for dark background readability
        foreach (var protocol in protocols)
        {
            var colorHex = _service.GetProtocolColorHex(protocol);
            var (r, g, b) = HexToRgb(colorHex);

            // Calculate relative luminance (simplified)
            var luminance = 0.299 * r + 0.587 * g + 0.114 * b;

            // Colors should be reasonably bright for dark background (#0D1117)
            luminance.Should().BeGreaterThan(50,
                $"protocol {protocol} color {colorHex} should be bright enough for dark background (luminance > 50)");
        }
    }

    private static (int r, int g, int b) HexToRgb(string hex)
    {
        hex = hex.TrimStart('#');
        var r = Convert.ToInt32(hex.Substring(0, 2), 16);
        var g = Convert.ToInt32(hex.Substring(2, 2), 16);
        var b = Convert.ToInt32(hex.Substring(4, 2), 16);
        return (r, g, b);
    }

    #endregion
}
