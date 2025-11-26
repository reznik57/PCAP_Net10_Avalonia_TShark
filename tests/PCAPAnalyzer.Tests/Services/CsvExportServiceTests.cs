using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using PCAPAnalyzer.UI.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

/// <summary>
/// Comprehensive unit tests for CsvExportService including security validations
/// </summary>
public class CsvExportServiceTests : IDisposable
{
    private readonly CsvExportService _service;
    private readonly Mock<ILogger<CsvExportService>> _mockLogger;
    private readonly string _testDirectory;
    private readonly List<string> _createdFiles;

    public CsvExportServiceTests()
    {
        _mockLogger = new Mock<ILogger<CsvExportService>>();
        _testDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PCAPAnalyzer_Tests");
        _createdFiles = new List<string>();

        // Ensure test directory exists
        Directory.CreateDirectory(_testDirectory);

        // Create service with test directory allowed for testing
        var allowedDirs = new[]
        {
            _testDirectory, // Allow test directory
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath()
        };
        _service = new CsvExportService(_mockLogger.Object, allowedDirs);
    }

    public void Dispose()
    {
        // Cleanup test files
        foreach (var file in _createdFiles.Where(File.Exists))
        {
            try { File.Delete(file); } catch { /* Ignore cleanup errors */ }
        }

        // Cleanup test directory if empty
        try
        {
            if (Directory.Exists(_testDirectory) && !Directory.EnumerateFileSystemEntries(_testDirectory).Any())
            {
                Directory.Delete(_testDirectory);
            }
        }
        catch { /* Ignore cleanup errors */ }
    }

    private string GetTestFilePath(string filename) =>
        Path.Combine(_testDirectory, filename);

    private void TrackFile(string filePath) => _createdFiles.Add(filePath);

    #region Basic Export Tests

    [Fact]
    public async Task ExportToCsvAsync_WithValidData_CreatesFile()
    {
        // Arrange
        var testData = new[]
        {
            new { Name = "Alice", Age = 30, City = "New York" },
            new { Name = "Bob", Age = 25, City = "London" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Name"] = d => d.Name,
            ["Age"] = d => d.Age,
            ["City"] = d => d.City
        };

        var filePath = GetTestFilePath("test_basic.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("Name,Age,City");
        content.Should().Contain("Alice,30,New York");
        content.Should().Contain("Bob,25,London");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithEmptyData_CreatesFileWithHeadersOnly()
    {
        // Arrange
        var testData = Array.Empty<dynamic>();
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Column1"] = d => d.Value,
            ["Column2"] = d => d.Value
        };

        var filePath = GetTestFilePath("test_empty.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("Column1,Column2");
        content.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)).Should().HaveCount(1); // Only header
    }

    [Fact]
    public async Task ExportToCsvAsync_WithNullValues_HandlesGracefully()
    {
        // Arrange
        var testData = new[]
        {
            new { Name = "Alice", Value = (string?)null },
            new { Name = (string?)null, Value = "Test" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Name"] = d => d.Name,
            ["Value"] = d => d.Value
        };

        var filePath = GetTestFilePath("test_nulls.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("Alice,");
        content.Should().Contain(",Test");
    }

    #endregion

    #region Special Character Escaping Tests

    [Fact]
    public async Task ExportToCsvAsync_WithCommasInData_EscapesCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Name = "Smith, John", City = "New York, NY" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Name"] = d => d.Name,
            ["City"] = d => d.City
        };

        var filePath = GetTestFilePath("test_commas.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("\"Smith, John\"");
        content.Should().Contain("\"New York, NY\"");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithQuotesInData_EscapesCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Description = "He said \"Hello\" to me" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Description"] = d => d.Description
        };

        var filePath = GetTestFilePath("test_quotes.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("\"He said \"\"Hello\"\" to me\"");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithNewlinesInData_EscapesCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Text = "Line 1\nLine 2\rLine 3" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Text"] = d => d.Text
        };

        var filePath = GetTestFilePath("test_newlines.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("\"Line 1\nLine 2\rLine 3\"");
    }

    #endregion

    #region Security Tests - CSV Formula Injection

    [Fact]
    public async Task ExportToCsvAsync_WithFormulaStartingWithEquals_PreventsInjection()
    {
        // Arrange
        var testData = new[]
        {
            new { Formula = "=1+1" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Formula"] = d => d.Formula
        };

        var filePath = GetTestFilePath("test_formula_equals.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("'=1+1"); // Should be prefixed with single quote
    }

    [Fact]
    public async Task ExportToCsvAsync_WithFormulaStartingWithPlus_PreventsInjection()
    {
        // Arrange
        var testData = new[]
        {
            new { Formula = "+1+2" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Formula"] = d => d.Formula
        };

        var filePath = GetTestFilePath("test_formula_plus.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("'+1+2");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithFormulaStartingWithMinus_PreventsInjection()
    {
        // Arrange
        var testData = new[]
        {
            new { Formula = "-1-2" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Formula"] = d => d.Formula
        };

        var filePath = GetTestFilePath("test_formula_minus.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("'-1-2");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithFormulaStartingWithAt_PreventsInjection()
    {
        // Arrange
        var testData = new[]
        {
            new { Formula = "@SUM(1,2)" }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Formula"] = d => d.Formula
        };

        var filePath = GetTestFilePath("test_formula_at.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("'@SUM(1,2)");
    }

    #endregion

    #region Security Tests - Path Traversal

    [Fact]
    public async Task ExportToCsvAsync_WithPathTraversal_ThrowsUnauthorizedException()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Value"] = d => d.Value
        };

        var maliciousPath = Path.Combine(_testDirectory, "..", "..", "evil.csv");

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await _service.ExportToCsvAsync(testData, maliciousPath, columnMappings));
    }

    [Fact]
    public async Task ExportToCsvAsync_WithUnauthorizedDirectory_ThrowsUnauthorizedException()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Value"] = d => d.Value
        };

        // Try to export to system directory (unauthorized)
        var unauthorizedPath = Path.Combine("C:", "Windows", "test.csv");

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await _service.ExportToCsvAsync(testData, unauthorizedPath, columnMappings));
    }

    [Fact]
    public async Task ExportToCsvAsync_ToDocumentsFolder_Succeeds()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Value"] = d => d.Value
        };

        var documentsPath = GetTestFilePath("authorized_test.csv");
        TrackFile(documentsPath);

        // Act
        await _service.ExportToCsvAsync(testData, documentsPath, columnMappings);

        // Assert
        File.Exists(documentsPath).Should().BeTrue();
    }

    #endregion

    #region Security Tests - Resource Limits

    [Fact]
    public async Task ExportToCsvAsync_WithTooManyRows_ThrowsInvalidOperationException()
    {
        // Arrange
        var largeData = Enumerable.Range(0, 1_000_001) // Exceeds MaxExportRows (1,000,000)
            .Select(i => new { Index = i, Value = $"Row {i}" });

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Index"] = d => d.Index,
            ["Value"] = d => d.Value
        };

        var filePath = GetTestFilePath("test_too_large.csv");

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.ExportToCsvAsync(largeData, filePath, columnMappings));

        exception.Message.Should().Contain("Export limited to");
        exception.Message.Should().Contain("1,000,000");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithMaxAllowedRows_Succeeds()
    {
        // Arrange
        var maxData = Enumerable.Range(0, 1000) // Well within limits
            .Select(i => new { Index = i });

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Index"] = d => d.Index
        };

        var filePath = GetTestFilePath("test_max_rows.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(maxData, filePath, columnMappings);

        // Assert
        File.Exists(filePath).Should().BeTrue();
        var lines = File.ReadAllLines(filePath);
        lines.Should().HaveCount(1001); // 1000 data rows + 1 header
    }

    #endregion

    #region Data Type Formatting Tests

    [Fact]
    public async Task ExportToCsvAsync_WithDateTime_FormatsCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Timestamp = new DateTime(2025, 1, 16, 14, 30, 25, 123) }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Timestamp"] = d => d.Timestamp
        };

        var filePath = GetTestFilePath("test_datetime.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("2025-01-16 14:30:25.123");
    }

    [Fact]
    public async Task ExportToCsvAsync_WithDecimal_FormatsCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Value = 123.456789m }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Value"] = d => d.Value
        };

        var filePath = GetTestFilePath("test_decimal.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("123.46"); // Formatted to 2 decimal places
    }

    [Fact]
    public async Task ExportToCsvAsync_WithDouble_FormatsCorrectly()
    {
        // Arrange
        var testData = new[]
        {
            new { Percentage = 45.6789 }
        };

        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Percentage"] = d => d.Percentage
        };

        var filePath = GetTestFilePath("test_double.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Contain("45.68"); // Formatted to 2 decimal places
    }

    #endregion

    #region Validation Tests

    [Fact]
    public async Task ExportToCsvAsync_WithNullData_ThrowsArgumentNullException()
    {
        // Arrange
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Test"] = d => d.Value
        };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _service.ExportToCsvAsync<dynamic>(null!, GetTestFilePath("test.csv"), columnMappings));
    }

    [Fact]
    public async Task ExportToCsvAsync_WithEmptyFilePath_ThrowsArgumentException()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Value"] = d => d.Value
        };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await _service.ExportToCsvAsync(testData, "", columnMappings));
    }

    [Fact]
    public async Task ExportToCsvAsync_WithNullColumnMappings_ThrowsArgumentException()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await _service.ExportToCsvAsync(testData, GetTestFilePath("test.csv"), null!));
    }

    [Fact]
    public async Task ExportToCsvAsync_WithEmptyColumnMappings_ThrowsArgumentException()
    {
        // Arrange
        var testData = new[] { new { Value = "test" } };
        var emptyMappings = new Dictionary<string, Func<dynamic, object?>>();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await _service.ExportToCsvAsync(testData, GetTestFilePath("test.csv"), emptyMappings));
    }

    #endregion

    #region UTF-8 BOM Tests

    [Fact]
    public async Task ExportToCsvAsync_CreatesFileWithUtf8BOM()
    {
        // Arrange
        var testData = new[] { new { Text = "Hello 世界" } };
        var columnMappings = new Dictionary<string, Func<dynamic, object?>>
        {
            ["Text"] = d => d.Text
        };

        var filePath = GetTestFilePath("test_utf8.csv");
        TrackFile(filePath);

        // Act
        await _service.ExportToCsvAsync(testData, filePath, columnMappings);

        // Assert
        var bytes = await File.ReadAllBytesAsync(filePath);
        bytes.Should().StartWith(new byte[] { 0xEF, 0xBB, 0xBF }); // UTF-8 BOM
    }

    #endregion

    #region Helper Method Tests

    [Fact]
    public void GetSuggestedFileName_ReturnsFormattedName()
    {
        // Act
        var filename = _service.GetSuggestedFileName("TestData");

        // Assert
        filename.Should().StartWith("PCAP_TestData_");
        filename.Should().EndWith(".csv");
        filename.Should().MatchRegex(@"PCAP_TestData_\d{8}_\d{6}\.csv");
    }

    [Fact]
    public async Task ValidateAndPreparePathAsync_WithValidPath_ReturnsTrue()
    {
        // Arrange
        var validPath = GetTestFilePath("validation_test.csv");
        TrackFile(validPath);

        // Act
        var result = await _service.ValidateAndPreparePathAsync(validPath);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAndPreparePathAsync_WithUnauthorizedPath_ReturnsFalse()
    {
        // Arrange
        var unauthorizedPath = Path.Combine("C:", "Windows", "test.csv");

        // Act
        var result = await _service.ValidateAndPreparePathAsync(unauthorizedPath);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void GetFileFilter_ReturnsCorrectFilter()
    {
        // Act
        var filter = _service.GetFileFilter();

        // Assert
        filter.Should().Contain("CSV Files");
        filter.Should().Contain("*.csv");
    }

    #endregion
}
