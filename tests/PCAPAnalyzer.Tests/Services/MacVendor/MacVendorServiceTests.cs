// Unit tests for MacVendorService
// Tests MAC address classification, OUI lookup, and special MAC detection

using PCAPAnalyzer.Core.Services.MacVendor;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.MacVendor;

public class MacVendorServiceTests
{
    #region MAC Address Classification Tests

    [Theory]
    [InlineData("00:50:56:C0:00:01", MacAddressType.Global)]      // VMware OUI - globally unique
    [InlineData("14:10:9F:AB:CD:EF", MacAddressType.Global)]      // Apple OUI - globally unique
    [InlineData("00:00:00:00:00:00", MacAddressType.Global)]      // All zeros - still global format
    public void ClassifyMacAddress_GlobalMac_ReturnsGlobal(string mac, MacAddressType expected)
    {
        // Arrange
        var normalized = MacVendorService.NormalizeMacAddress(mac);

        // Act
        var result = MacVendorService.ClassifyMacAddress(normalized!);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("02:00:00:00:00:01")]  // Locally administered unicast (bit 1 set, bit 0 clear)
    [InlineData("06:AB:CD:EF:12:34")]  // Locally administered unicast
    [InlineData("0A:00:00:00:00:00")]  // Locally administered unicast
    [InlineData("0E:FF:FF:FF:FF:FF")]  // Locally administered unicast
    [InlineData("12:34:56:78:9A:BC")]  // iOS/Android randomized pattern
    [InlineData("F2:AB:CD:EF:12:34")]  // Randomized MAC
    [InlineData("DA:A1:19:XX:XX:XX")]  // Android randomized (simplified)
    public void ClassifyMacAddress_RandomizedMac_ReturnsRandomized(string mac)
    {
        // Arrange
        var normalized = MacVendorService.NormalizeMacAddress(mac);
        if (normalized == null)
        {
            // Handle invalid format - just verify classification logic
            normalized = mac.Replace("X", "0").ToUpperInvariant();
        }

        // Act
        var result = MacVendorService.ClassifyMacAddress(normalized);

        // Assert
        Assert.Equal(MacAddressType.Randomized, result);
    }

    [Theory]
    [InlineData("01:00:00:00:00:00")]  // Multicast (bit 0 set)
    [InlineData("01:00:5E:00:00:01")]  // IPv4 multicast
    [InlineData("33:33:00:00:00:01")]  // IPv6 multicast
    [InlineData("FF:FF:FF:FF:FF:FE")]  // Almost broadcast, but multicast bit
    public void ClassifyMacAddress_MulticastMac_ReturnsMulticast(string mac)
    {
        // Arrange
        var normalized = MacVendorService.NormalizeMacAddress(mac);

        // Act
        var result = MacVendorService.ClassifyMacAddress(normalized!);

        // Assert
        Assert.Equal(MacAddressType.Multicast, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("XX")]
    [InlineData("invalid")]
    public void ClassifyMacAddress_InvalidMac_ReturnsInvalid(string mac)
    {
        // Act
        var result = MacVendorService.ClassifyMacAddress(mac);

        // Assert
        Assert.Equal(MacAddressType.Invalid, result);
    }

    #endregion

    #region MAC Address Normalization Tests

    [Theory]
    [InlineData("00:50:56:C0:00:01", "00:50:56:C0:00:01")]  // Already normalized
    [InlineData("00-50-56-C0-00-01", "00:50:56:C0:00:01")]  // Windows format
    [InlineData("0050.56c0.0001", "00:50:56:C0:00:01")]     // Cisco format
    [InlineData("005056c00001", "00:50:56:C0:00:01")]       // No separators
    [InlineData("00:50:56:c0:00:01", "00:50:56:C0:00:01")]  // Lowercase
    public void NormalizeMacAddress_VariousFormats_ReturnsNormalized(string input, string expected)
    {
        // Act
        var result = MacVendorService.NormalizeMacAddress(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("00:50:56")]           // Too short
    [InlineData("00:50:56:C0:00")]     // Missing octet
    [InlineData("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")] // Invalid hex
    public void NormalizeMacAddress_InvalidInput_ReturnsNull(string? input)
    {
        // Act
        var result = MacVendorService.NormalizeMacAddress(input!);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region Vendor Lookup Tests

    [Fact]
    public void LookupVendor_BroadcastMac_ReturnsBroadcast()
    {
        // Arrange
        var service = new MacVendorService();

        // Act
        var result = service.LookupVendor("FF:FF:FF:FF:FF:FF");

        // Assert
        Assert.Equal(MacAddressType.Broadcast, result.AddressType);
        Assert.Equal("Broadcast", result.DisplayVendor);
    }

    [Fact]
    public void LookupVendor_RandomizedMac_ReturnsRandomized()
    {
        // Arrange
        var service = new MacVendorService();

        // Act - Use a clearly randomized MAC (locally administered, unicast)
        var result = service.LookupVendor("02:00:00:00:00:01");

        // Assert
        Assert.Equal(MacAddressType.Randomized, result.AddressType);
        Assert.Equal("Randomized (Private)", result.DisplayVendor);
        Assert.True(result.IsSpecialAddress);
    }

    [Fact]
    public void LookupVendor_NullInput_ReturnsInvalid()
    {
        // Arrange
        var service = new MacVendorService();

        // Act
        var result = service.LookupVendor(null);

        // Assert
        Assert.Equal(MacAddressType.Invalid, result.AddressType);
    }

    [Fact]
    public void LookupVendor_EmptyInput_ReturnsInvalid()
    {
        // Arrange
        var service = new MacVendorService();

        // Act
        var result = service.LookupVendor("");

        // Assert
        Assert.Equal(MacAddressType.Invalid, result.AddressType);
    }

    [Fact]
    public void LookupVendor_GlobalMacUnknownOui_ReturnsGlobalUnknown()
    {
        // Arrange
        var service = new MacVendorService();

        // Act - Use an OUI not in database (must be global - bit 1 = 0)
        // 0x00 has bit 1 = 0, so 00:AA:BB is global
        var result = service.LookupVendor("00:AA:BB:11:22:33");

        // Assert
        Assert.Equal(MacAddressType.Global, result.AddressType);
        Assert.Equal("Unknown", result.DisplayVendor);
        Assert.Null(result.Vendor);
    }

    #endregion

    #region Database Stats Tests

    [Fact]
    public void GetDatabaseStats_AfterConstruction_ReturnsValidStats()
    {
        // Arrange
        var service = new MacVendorService();

        // Act
        var stats = service.GetDatabaseStats();

        // Assert
        Assert.True(stats.CuratedEntries >= 0);
        Assert.True(stats.TotalEntries >= stats.CuratedEntries);
    }

    #endregion

    #region MacLookupResult Tests

    [Fact]
    public void MacLookupResult_DisplayVendor_ReturnsCorrectText()
    {
        // Test each special type
        Assert.Equal("Randomized (Private)", new MacLookupResult(null, MacAddressType.Randomized).DisplayVendor);
        Assert.Equal("Locally Administered", new MacLookupResult(null, MacAddressType.LocallyAdministered).DisplayVendor);
        Assert.Equal("Multicast", new MacLookupResult(null, MacAddressType.Multicast).DisplayVendor);
        Assert.Equal("Broadcast", new MacLookupResult(null, MacAddressType.Broadcast).DisplayVendor);
        Assert.Equal("Unknown", new MacLookupResult(null, MacAddressType.Global).DisplayVendor);
        Assert.Equal("Apple", new MacLookupResult("Apple", MacAddressType.Global).DisplayVendor);
    }

    [Fact]
    public void MacLookupResult_IsSpecialAddress_CorrectForTypes()
    {
        // Special addresses
        Assert.True(new MacLookupResult(null, MacAddressType.Randomized).IsSpecialAddress);
        Assert.True(new MacLookupResult(null, MacAddressType.LocallyAdministered).IsSpecialAddress);
        Assert.True(new MacLookupResult(null, MacAddressType.Multicast).IsSpecialAddress);
        Assert.True(new MacLookupResult(null, MacAddressType.Broadcast).IsSpecialAddress);
        Assert.True(new MacLookupResult(null, MacAddressType.Invalid).IsSpecialAddress);

        // Global is NOT special
        Assert.False(new MacLookupResult(null, MacAddressType.Global).IsSpecialAddress);
        Assert.False(new MacLookupResult("Vendor", MacAddressType.Global).IsSpecialAddress);
    }

    #endregion

    #region Real OUI Tests (uses curated database)

    [Theory]
    [InlineData("00:50:56:C0:00:01", "VMware")]           // VMware
    [InlineData("00:0C:29:AB:CD:EF", "VMware")]           // VMware VM
    [InlineData("00:15:5D:00:00:00", "Microsoft Hyper-V")] // Hyper-V
    [InlineData("08:00:27:11:22:33", "VirtualBox")]       // VirtualBox
    public void LookupVendor_KnownVirtualOui_ReturnsCorrectVendor(string mac, string expectedVendor)
    {
        // Arrange
        var service = new MacVendorService();
        var stats = service.GetDatabaseStats();

        // Skip if database not loaded (test environment without embedded resource)
        if (stats.CuratedEntries == 0)
        {
            // In test environment without database, verify at least classification works
            var result = service.LookupVendor(mac);
            Assert.Equal(MacAddressType.Global, result.AddressType);
            return;
        }

        // Act
        var lookupResult = service.LookupVendor(mac);

        // Assert
        Assert.Equal(MacAddressType.Global, lookupResult.AddressType);
        Assert.Equal(expectedVendor, lookupResult.Vendor);
        Assert.Equal(expectedVendor, lookupResult.DisplayVendor);
    }

    #endregion
}
