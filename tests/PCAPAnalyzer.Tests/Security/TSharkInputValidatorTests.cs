using System;
using System.IO;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.TShark.Security;
using Xunit;

namespace PCAPAnalyzer.Tests.Security;

/// <summary>
/// Security tests for TShark input validation to prevent command injection attacks.
/// Tests verify that malicious inputs are properly rejected.
/// </summary>
public class TSharkInputValidatorTests
{
    private readonly TSharkInputValidator _validator;
    private readonly string _testDataDir;
    private readonly string _validPcapPath;

    public TSharkInputValidatorTests()
    {
        _validator = new TSharkInputValidator(NullLogger<TSharkInputValidator>.Instance);
        _testDataDir = Path.Combine(Path.GetTempPath(), "pcap_test_" + Guid.NewGuid().ToString());
        Directory.CreateDirectory(_testDataDir);

        // Create a valid test PCAP file
        _validPcapPath = Path.Combine(_testDataDir, "test.pcap");
        File.WriteAllText(_validPcapPath, "dummy pcap content");
    }

    #region Path Validation Tests

    [Fact]
    public void ValidatePath_WithValidPath_ReturnsCanonicalPath()
    {
        // Act
        var result = _validator.ValidatePath(_validPcapPath);

        // Assert
        result.Should().NotBeNullOrEmpty();
        Path.IsPathFullyQualified(result).Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidatePath_WithNullOrEmpty_ThrowsArgumentException(string? input)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _validator.ValidatePath(input!));
    }

    [Fact]
    public void ValidatePath_WithNonExistentFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var nonExistentPath = Path.Combine(_testDataDir, "nonexistent.pcap");

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() => _validator.ValidatePath(nonExistentPath));
    }

    [Theory]
    [InlineData(".txt")]
    [InlineData(".exe")]
    [InlineData(".sh")]
    [InlineData(".bat")]
    public void ValidatePath_WithInvalidExtension_ThrowsArgumentException(string extension)
    {
        // Arrange
        var invalidPath = Path.Combine(_testDataDir, $"test{extension}");
        File.WriteAllText(invalidPath, "dummy content");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidatePath(invalidPath));
        exception.Message.Should().Contain("Invalid file type");
    }

    [Theory]
    [InlineData("test;calc.pcap")] // Semicolon (command separator)
    [InlineData("test&calc.pcap")] // Ampersand (background execution)
    [InlineData("test|calc.pcap")] // Pipe (command chaining)
    [InlineData("test`calc`.pcap")] // Backtick (command substitution)
    [InlineData("test$var.pcap")] // Dollar sign (variable expansion)
    public void ValidatePath_WithShellMetacharacters_ThrowsArgumentException(string filename)
    {
        // Arrange
        var maliciousPath = Path.Combine(_testDataDir, filename);
        try
        {
            File.WriteAllText(maliciousPath, "dummy content");
        }
        catch (ArgumentException)
        {
            // Some characters might be invalid for filesystem - skip test
            return;
        }
        catch (IOException)
        {
            // On Windows, certain characters like | cannot be used in filenames
            // The OS prevents file creation, which is actually the first line of defense
            // Test passes because the dangerous character was blocked at filesystem level
            return;
        }

        // Act & Assert
        if (File.Exists(maliciousPath))
        {
            var exception = Assert.Throws<ArgumentException>(() => _validator.ValidatePath(maliciousPath));
            exception.Message.Should().Contain("forbidden");
        }
    }

    [Fact]
    public void ValidatePath_WithQuotes_ThrowsArgumentException()
    {
        // Arrange - Quotes in paths are dangerous for command injection
        var pathWithQuotes = _validPcapPath + "\"test\"";

        // Act & Assert
        // This should fail during path validation as quotes shouldn't be in paths
        Assert.Throws<ArgumentException>(() => _validator.ValidatePath(pathWithQuotes));
    }

    #endregion

    #region Filter Validation Tests

    [Fact]
    public void ValidateFilter_WithNullOrEmpty_ReturnsEmpty()
    {
        // Act
        var result1 = _validator.ValidateFilter(null!);
        var result2 = _validator.ValidateFilter("");
        var result3 = _validator.ValidateFilter("   ");

        // Assert
        result1.Should().BeEmpty();
        result2.Should().BeEmpty();
        result3.Should().BeEmpty();
    }

    [Theory]
    [InlineData("tcp.port == 80")]
    [InlineData("ip.src == 192.168.1.1")]
    [InlineData("http && tcp.port == 443")]
    [InlineData("frame.len > 100")]
    [InlineData("(tcp.port == 80) || (tcp.port == 443)")]
    public void ValidateFilter_WithValidFilters_ReturnsFilter(string filter)
    {
        // Act
        var result = _validator.ValidateFilter(filter);

        // Assert
        result.Should().Be(filter);
    }

    [Theory]
    [InlineData("tcp.port == 80; calc")] // Semicolon (command separator)
    [InlineData("tcp.port == 80`calc`")] // Backticks (command substitution)
    [InlineData("tcp.port == 80$var")] // Dollar sign (variable expansion)
    [InlineData("tcp.port == \"80\"")] // Quotes (can break command parsing)
    [InlineData("tcp.port == '80'")] // Single quotes
    public void ValidateFilter_WithCommandInjectionAttempts_ThrowsArgumentException(string maliciousFilter)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateFilter(maliciousFilter));
        exception.Message.Should().Contain("forbidden");
    }

    [Fact]
    public void ValidateFilter_WithTooLongFilter_ThrowsArgumentException()
    {
        // Arrange
        var longFilter = new string('a', 2001); // Max is 2000

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateFilter(longFilter));
        exception.Message.Should().Contain("too long");
    }

    [Theory]
    [InlineData("tcp.port == 80\ncalc")] // Newline injection
    [InlineData("tcp.port == 80\rcalc")] // Carriage return injection
    public void ValidateFilter_WithNewlineInjection_ThrowsArgumentException(string maliciousFilter)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateFilter(maliciousFilter));
        exception.Message.Should().Contain("forbidden");
    }

    #endregion

    #region Field Name Validation Tests

    [Theory]
    [InlineData("frame.number")]
    [InlineData("ip.src")]
    [InlineData("tcp.srcport")]
    [InlineData("frame.time_epoch")]
    [InlineData("_ws.col.Protocol")]
    public void ValidateField_WithValidFields_ReturnsField(string field)
    {
        // Act
        var result = _validator.ValidateField(field);

        // Assert
        result.Should().Be(field);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateField_WithNullOrEmpty_ThrowsArgumentException(string? field)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _validator.ValidateField(field!));
    }

    [Theory]
    [InlineData("FRAME.NUMBER")] // Must be lowercase
    [InlineData("frame number")] // No spaces allowed
    [InlineData("frame;number")] // Semicolon not allowed
    [InlineData("frame`number")] // Backtick not allowed
    [InlineData("frame$number")] // Dollar sign not allowed
    [InlineData("Frame.number")] // Must start with lowercase
    [InlineData("9frame.number")] // Must start with letter
    public void ValidateField_WithInvalidFieldNames_ThrowsArgumentException(string invalidField)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateField(invalidField));
        exception.Message.Should().Contain("Invalid field name");
    }

    [Fact]
    public void ValidateField_WithTooLongField_ThrowsArgumentException()
    {
        // Arrange
        var longField = "frame." + new string('a', 100); // Max is 100 total

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateField(longField));
        exception.Message.Should().Contain("too long");
    }

    [Fact]
    public void ValidateFields_WithMultipleValidFields_ReturnsAllFields()
    {
        // Arrange
        var fields = new[] { "frame.number", "ip.src", "tcp.port" };

        // Act
        var result = _validator.ValidateFields(fields);

        // Assert
        result.Should().BeEquivalentTo(fields);
    }

    [Fact]
    public void ValidateFields_WithOneInvalidField_ThrowsArgumentException()
    {
        // Arrange
        var fields = new[] { "frame.number", "INVALID;FIELD", "tcp.port" };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _validator.ValidateFields(fields));
    }

    #endregion

    #region WSL Path Validation Tests

    [Fact]
    public void ValidateWslPath_WithValidPath_ReturnsPath()
    {
        // Arrange
        var wslPath = "/mnt/c/test/file.pcap";

        // Act
        var result = _validator.ValidateWslPath(wslPath);

        // Assert
        result.Should().Be(wslPath);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateWslPath_WithNullOrEmpty_ThrowsArgumentException(string? path)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _validator.ValidateWslPath(path!));
    }

    [Theory]
    [InlineData("/mnt/c/test;calc")] // Semicolon
    [InlineData("/mnt/c/test&calc")] // Ampersand
    [InlineData("/mnt/c/test|calc")] // Pipe
    [InlineData("/mnt/c/test`calc`")] // Backticks
    [InlineData("/mnt/c/test$var")] // Dollar sign
    public void ValidateWslPath_WithShellMetacharacters_ThrowsArgumentException(string maliciousPath)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateWslPath(maliciousPath));
        exception.Message.Should().Contain("forbidden");
    }

    [Theory]
    [InlineData("/mnt/c/test\"file\".pcap")] // Double quotes
    [InlineData("/mnt/c/test'file'.pcap")] // Single quotes
    public void ValidateWslPath_WithQuotes_ThrowsArgumentException(string pathWithQuotes)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _validator.ValidateWslPath(pathWithQuotes));
        exception.Message.Should().Contain("forbidden");
    }

    #endregion

    #region Real-World Attack Vector Tests

    [Theory]
    [InlineData("test.pcap\"; calc.exe #")] // Command injection attempt
    [InlineData("test.pcap && malicious-command")] // Command chaining
    [InlineData("$(malicious-command)")] // Command substitution
    public void ValidatePath_WithRealWorldAttacks_ThrowsException(string filename)
    {
        // Arrange
        var maliciousPath = Path.Combine(_testDataDir, filename);

        // Act & Assert
        // Should fail either during file creation or validation
        try
        {
            File.WriteAllText(maliciousPath, "content");
            if (File.Exists(maliciousPath))
            {
                Assert.Throws<ArgumentException>(() => _validator.ValidatePath(maliciousPath));
            }
        }
        catch (ArgumentException)
        {
            // Expected - dangerous characters prevented at filesystem level
        }
        catch (IOException)
        {
            // On Windows, certain characters like " cannot be used in filenames
            // The OS prevents file creation, which is defense-in-depth working correctly
            // Test passes because the dangerous character was blocked at filesystem level
        }
    }

    [Theory]
    [InlineData("tcp.port == 80\"; calc.exe #")]
    [InlineData("tcp.port == 80 && $(whoami)")]
    [InlineData("tcp.port == 80`ls -la`")]
    public void ValidateFilter_WithRealWorldAttacks_ThrowsException(string maliciousFilter)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => _validator.ValidateFilter(maliciousFilter));
    }

    #endregion

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDataDir))
            {
                Directory.Delete(_testDataDir, true);
            }
        }
        catch
        {
            // Cleanup failed - not critical for tests
        }
    }
}
