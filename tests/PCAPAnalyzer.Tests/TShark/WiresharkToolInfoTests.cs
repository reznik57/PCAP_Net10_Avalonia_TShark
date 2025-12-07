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

    #region CreateProcessStartInfo Tests (Array-based for command injection safety)

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

        // Act - Now uses array-based arguments for security
        var psi = info.CreateProcessStartInfo("-r", "test.pcap", "-T", "fields");

        // Assert
        psi.FileName.Should().Be(@"C:\Program Files\Wireshark\tshark.exe");
        psi.ArgumentList.Should().ContainInOrder("-r", "test.pcap", "-T", "fields");
        psi.Arguments.Should().BeEmpty(); // Arguments is empty when using ArgumentList
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

        // Act - Now uses array-based arguments for security
        var psi = info.CreateProcessStartInfo("-r", "/mnt/c/test.pcap", "-T", "fields");

        // Assert
        psi.FileName.Should().Be("wsl.exe");
        psi.ArgumentList.Should().Contain("tshark");
        psi.ArgumentList.Should().Contain("-r");
        psi.ArgumentList.Should().Contain("/mnt/c/test.pcap");
    }

    [Fact]
    public void CreateProcessStartInfo_WslMode_HandlesPathWithSpaces()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.Wsl,
            ExecutablePath = "/usr/local/bin/my tshark"
        };

        // Act - Array-based: .NET handles escaping, no manual quoting needed
        var psi = info.CreateProcessStartInfo("-v");

        // Assert
        psi.FileName.Should().Be("wsl.exe");
        psi.ArgumentList.Should().Contain("/usr/local/bin/my tshark");
        psi.ArgumentList.Should().Contain("-v");
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

        // Act - Now uses array-based arguments for security
        var psi = info.CreateProcessStartInfo("-r", "capture.pcap");

        // Assert
        psi.FileName.Should().Be("/usr/bin/tshark");
        psi.ArgumentList.Should().ContainInOrder("-r", "capture.pcap");
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

    [Fact]
    public void CreateProcessStartInfo_PreventsCommandInjection()
    {
        // Arrange
        var info = new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.NativeWindows,
            ExecutablePath = @"C:\Program Files\Wireshark\tshark.exe"
        };

        // Act - Attempt command injection via malicious path
        var maliciousPath = "test.pcap\"; rm -rf /; \"";
        var psi = info.CreateProcessStartInfo("-r", maliciousPath);

        // Assert - The malicious string is treated as a single argument, not parsed as shell
        psi.ArgumentList.Should().Contain(maliciousPath);
        psi.ArgumentList.Should().HaveCount(2); // Just "-r" and the path
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
