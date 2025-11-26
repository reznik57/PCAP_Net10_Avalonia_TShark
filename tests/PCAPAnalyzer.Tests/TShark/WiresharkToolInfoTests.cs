using FluentAssertions;
using PCAPAnalyzer.TShark;

namespace PCAPAnalyzer.Tests.TShark;

/// <summary>
/// Tests for WiresharkToolInfo - path conversion and ProcessStartInfo creation.
/// </summary>
public class WiresharkToolInfoTests
{
    #region ConvertPathIfNeeded Tests

    [Theory]
    [InlineData(@"C:\Users\test\capture.pcap", "/mnt/c/Users/test/capture.pcap")]
    [InlineData(@"D:\Data\network.pcapng", "/mnt/d/Data/network.pcapng")]
    [InlineData(@"E:\Captures\test file.pcap", "/mnt/e/Captures/test file.pcap")]
    public void ConvertPathIfNeeded_WslMode_ConvertsWindowsPathToWsl(string windowsPath, string expectedWslPath)
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "tshark"
        };

        // Act
        var result = info.ConvertPathIfNeeded(windowsPath);

        // Assert
        result.Should().Be(expectedWslPath);
    }

    [Fact]
    public void ConvertPathIfNeeded_WslMode_HandlesLowercaseDriveLetter()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "tshark"
        };

        // Act
        var result = info.ConvertPathIfNeeded(@"c:\temp\test.pcap");

        // Assert
        result.Should().Be("/mnt/c/temp/test.pcap");
    }

    [Theory]
    [InlineData(@"C:\capture.pcap")]
    [InlineData(@"D:\test.pcap")]
    public void ConvertPathIfNeeded_NativeWindowsMode_ReturnsOriginalPath(string path)
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.NativeWindows,
            ExecutablePath = @"C:\Program Files\Wireshark\tshark.exe"
        };

        // Act
        var result = info.ConvertPathIfNeeded(path);

        // Assert
        result.Should().Be(path);
    }

    [Theory]
    [InlineData("/home/user/capture.pcap")]
    [InlineData("/var/log/network.pcap")]
    public void ConvertPathIfNeeded_DirectUnixMode_ReturnsOriginalPath(string path)
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.DirectUnix,
            ExecutablePath = "/usr/bin/tshark"
        };

        // Act
        var result = info.ConvertPathIfNeeded(path);

        // Assert
        result.Should().Be(path);
    }

    [Fact]
    public void ConvertPathIfNeeded_WslMode_HandlesPathWithoutDriveLetter()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "tshark"
        };

        // Act - path without drive letter shouldn't be converted
        var result = info.ConvertPathIfNeeded(@"\network\share\file.pcap");

        // Assert - returned as-is since no drive letter
        result.Should().Be(@"\network\share\file.pcap");
    }

    #endregion

    #region CreateProcessStartInfo Tests

    [Fact]
    public void CreateProcessStartInfo_NativeWindowsMode_SetsDirectExecutable()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.NativeWindows,
            ExecutablePath = @"C:\Program Files\Wireshark\tshark.exe"
        };

        // Act
        var psi = info.CreateProcessStartInfo("-r test.pcap -T fields");

        // Assert
        psi.FileName.Should().Be(@"C:\Program Files\Wireshark\tshark.exe");
        psi.Arguments.Should().Be("-r test.pcap -T fields");
        psi.UseShellExecute.Should().BeFalse();
        psi.RedirectStandardOutput.Should().BeTrue();
        psi.RedirectStandardError.Should().BeTrue();
        psi.CreateNoWindow.Should().BeTrue();
    }

    [Fact]
    public void CreateProcessStartInfo_WslMode_UsesWslWrapper()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "tshark"
        };

        // Act
        var psi = info.CreateProcessStartInfo("-r /mnt/c/test.pcap -T fields");

        // Assert
        psi.FileName.Should().Be("wsl.exe");
        psi.Arguments.Should().Contain("tshark");
        psi.Arguments.Should().Contain("-r /mnt/c/test.pcap -T fields");
    }

    [Fact]
    public void CreateProcessStartInfo_WslMode_QuotesPathWithSpaces()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "/usr/local/bin/my tshark"
        };

        // Act
        var psi = info.CreateProcessStartInfo("-v");

        // Assert
        psi.FileName.Should().Be("wsl.exe");
        psi.Arguments.Should().Contain("\"/usr/local/bin/my tshark\"");
    }

    [Fact]
    public void CreateProcessStartInfo_DirectUnixMode_SetsDirectExecutable()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.DirectUnix,
            ExecutablePath = "/usr/bin/tshark"
        };

        // Act
        var psi = info.CreateProcessStartInfo("-r capture.pcap");

        // Assert
        psi.FileName.Should().Be("/usr/bin/tshark");
        psi.Arguments.Should().Be("-r capture.pcap");
    }

    [Fact]
    public void CreateProcessStartInfo_AlwaysRedirectsOutputAndError()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.DirectUnix,
            ExecutablePath = "/usr/bin/tshark"
        };

        // Act
        var psi = info.CreateProcessStartInfo("-v");

        // Assert
        psi.RedirectStandardOutput.Should().BeTrue();
        psi.RedirectStandardError.Should().BeTrue();
        psi.StandardOutputEncoding.Should().Be(System.Text.Encoding.UTF8);
        psi.StandardErrorEncoding.Should().Be(System.Text.Encoding.UTF8);
    }

    #endregion

    #region WiresharkToolInfo Properties Tests

    [Fact]
    public void WiresharkToolInfo_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var info = new WiresharkToolInfo();

        // Assert
        info.IsAvailable.Should().BeFalse();
        info.Mode.Should().Be(WiresharkExecutionMode.Unavailable);
        info.ExecutablePath.Should().BeEmpty();
        info.Description.Should().BeEmpty();
    }

    [Fact]
    public void WiresharkExecutionMode_HasExpectedValues()
    {
        // Assert
        Enum.GetValues<WiresharkExecutionMode>().Should().HaveCount(4);
        ((int)WiresharkExecutionMode.Unavailable).Should().Be(0);
        ((int)WiresharkExecutionMode.NativeWindows).Should().Be(1);
        ((int)WiresharkExecutionMode.Wsl).Should().Be(2);
        ((int)WiresharkExecutionMode.DirectUnix).Should().Be(3);
    }

    #endregion
}
