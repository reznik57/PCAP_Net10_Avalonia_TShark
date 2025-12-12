using PCAPAnalyzer.Core.Extensions;
using Xunit;

namespace PCAPAnalyzer.Tests.Extensions;

public class StringEntropyExtensionsTests
{
    [Fact]
    public void CalculateEntropy_EmptyString_ReturnsZero()
    {
        // Arrange
        var text = "";

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateEntropy_NullString_ReturnsZero()
    {
        // Arrange
        string? text = null;

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateEntropy_ShortString_ReturnsZero()
    {
        // Arrange
        var text = "abc"; // Less than 4 chars

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateEntropy_AllSameCharacter_ReturnsZero()
    {
        // Arrange
        var text = "aaaaaaaaaa"; // All same character = 0 entropy

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateEntropy_TwoEqualCharacters_ReturnsOne()
    {
        // Arrange
        var text = "abababab"; // Equal distribution of 2 chars = 1 bit entropy

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.Equal(1.0, entropy, 0.01);
    }

    [Fact]
    public void CalculateEntropy_Base64LikeText_HighEntropy()
    {
        // Arrange
        var text = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"; // base64-like

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.True(entropy >= 3.5, $"Expected entropy >= 3.5, got {entropy}");
    }

    [Fact]
    public void CalculateEntropy_EnglishWord_LowerEntropy()
    {
        // Arrange
        var text = "computer"; // Normal English word

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        // English text typically has entropy around 3.0-4.0
        Assert.True(entropy < 4.0, $"Expected entropy < 4.0, got {entropy}");
    }

    [Fact]
    public void CalculateEntropy_HexString_HighEntropy()
    {
        // Arrange
        var text = "a1b2c3d4e5f6789012345678"; // Hex-like string

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        Assert.True(entropy >= 3.0, $"Expected entropy >= 3.0, got {entropy}");
    }

    [Fact]
    public void CalculateEntropy_IsCaseInsensitive()
    {
        // Arrange
        var lower = "abcdefgh";
        var upper = "ABCDEFGH";
        var mixed = "AbCdEfGh";

        // Act
        var entropyLower = lower.CalculateEntropy();
        var entropyUpper = upper.CalculateEntropy();
        var entropyMixed = mixed.CalculateEntropy();

        // Assert
        Assert.Equal(entropyLower, entropyUpper, 0.001);
        Assert.Equal(entropyLower, entropyMixed, 0.001);
    }

    [Fact]
    public void CalculateEntropy_IgnoresNonAlphanumeric()
    {
        // Arrange
        var withPunctuation = "abc-def.ghi_jkl";
        var without = "abcdefghijkl";

        // Act
        var entropyWith = withPunctuation.CalculateEntropy();
        var entropyWithout = without.CalculateEntropy();

        // Assert
        Assert.Equal(entropyWith, entropyWithout, 0.001);
    }

    [Fact]
    public void CalculateSubdomainEntropy_ExtractsSubdomain()
    {
        // Arrange
        var fullDomain = "encoded.data.evil.com";

        // Act
        var entropy = fullDomain.CalculateSubdomainEntropy();

        // Assert
        // Should calculate entropy of "encoded.data" (excluding evil.com)
        Assert.True(entropy > 0, "Expected positive entropy for subdomain");
    }

    [Fact]
    public void CalculateSubdomainEntropy_ShortDomain_ReturnsZero()
    {
        // Arrange
        var domain = "evil.com"; // Only 2 labels, no subdomain

        // Act
        var entropy = domain.CalculateSubdomainEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateSubdomainEntropy_NullString_ReturnsZero()
    {
        // Arrange
        string? domain = null;

        // Act
        var entropy = domain.CalculateSubdomainEntropy();

        // Assert
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateEntropy_SpanOverload_SameAsString()
    {
        // Arrange
        var text = "abcdefghijklmnop";
        var span = text.AsSpan();

        // Act
        var entropyString = text.CalculateEntropy();
        var entropySpan = span.CalculateEntropy();

        // Assert
        Assert.Equal(entropyString, entropySpan);
    }

    [Fact]
    public void CalculateEntropy_MaxEntropy_ForUniformDistribution()
    {
        // Arrange - all 36 alphanumeric chars equally distributed
        var text = "abcdefghijklmnopqrstuvwxyz0123456789";

        // Act
        var entropy = text.CalculateEntropy();

        // Assert
        // Max entropy for 36 symbols = log2(36) ≈ 5.17
        Assert.True(entropy > 5.0, $"Expected entropy > 5.0 for uniform distribution, got {entropy}");
    }

    [Fact]
    public void CalculateEntropy_ThreadSafe_ConcurrentCalls()
    {
        // Arrange
        var texts = new[]
        {
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo",
            "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ubw",
            "eHl6MTIzYWJjZGVmZ2hpamtsbW5vcHFycw"
        };

        // Act & Assert - no exceptions
        Parallel.For(0, 1000, i =>
        {
            var text = texts[i % texts.Length];
            var entropy = text.CalculateEntropy();
            Assert.True(entropy >= 0);
        });
    }
}
