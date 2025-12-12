using System;
using System.Runtime.CompilerServices;

namespace PCAPAnalyzer.Core.Extensions;

/// <summary>
/// Zero-allocation Shannon entropy calculation using Span&lt;T&gt;.
/// Used for DNS tunnel detection (high-entropy subdomain detection).
/// </summary>
public static class StringEntropyExtensions
{
    // Pre-allocated frequency buffer for 36 characters (a-z, 0-9)
    // Thread-local to avoid allocations while maintaining thread-safety
    [ThreadStatic]
    private static int[]? _frequencyBuffer;

    /// <summary>
    /// Calculates Shannon entropy of the input text (case-insensitive, alphanumeric only).
    /// Zero-allocation implementation using Span&lt;char&gt;.
    /// </summary>
    /// <param name="text">Input text to analyze</param>
    /// <returns>Entropy in bits (0.0 to ~4.7 for alphanumeric text)</returns>
    /// <remarks>
    /// Typical values:
    /// - English text: 3.5-4.0 bits
    /// - Random/encoded data: 4.5+ bits
    /// - DNS tunnel threshold: ≥3.5 bits
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double CalculateEntropy(this ReadOnlySpan<char> text)
    {
        if (text.Length < 4)
            return 0.0;

        // Get or create thread-local frequency buffer
        _frequencyBuffer ??= new int[36]; // a-z (26) + 0-9 (10)
        var frequencies = _frequencyBuffer.AsSpan();
        frequencies.Clear();

        int total = 0;

        // Count character frequencies (case-insensitive, alphanumeric only)
        foreach (var c in text)
        {
            int index = GetCharIndex(c);
            if (index >= 0)
            {
                frequencies[index]++;
                total++;
            }
        }

        if (total == 0)
            return 0.0;

        // Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
        double entropy = 0.0;
        double invTotal = 1.0 / total;

        foreach (var freq in frequencies)
        {
            if (freq > 0)
            {
                double probability = freq * invTotal;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return entropy;
    }

    /// <summary>
    /// Overload for string input (convenience method).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double CalculateEntropy(this string? text)
    {
        if (string.IsNullOrEmpty(text))
            return 0.0;

        return CalculateEntropy(text.AsSpan());
    }

    /// <summary>
    /// Extracts and calculates entropy of subdomain labels from a DNS query name.
    /// Excludes the TLD and base domain (e.g., for "abc123.data.evil.com", analyzes "abc123.data").
    /// </summary>
    /// <param name="dnsQueryName">Full DNS query name</param>
    /// <returns>Entropy of subdomain portion</returns>
    public static double CalculateSubdomainEntropy(this ReadOnlySpan<char> dnsQueryName)
    {
        if (dnsQueryName.Length < 5)
            return 0.0;

        // Find the subdomain portion (skip TLD and base domain)
        // Example: "encoded.data.tunnel.evil.com" → analyze "encoded.data.tunnel"
        int dotCount = 0;
        int lastDotIndex = -1;
        int secondLastDotIndex = -1;

        for (int i = dnsQueryName.Length - 1; i >= 0; i--)
        {
            if (dnsQueryName[i] == '.')
            {
                dotCount++;
                if (dotCount == 1)
                    lastDotIndex = i;
                else if (dotCount == 2)
                {
                    secondLastDotIndex = i;
                    break;
                }
            }
        }

        // Need at least 3 labels for meaningful subdomain analysis
        if (secondLastDotIndex <= 0)
            return 0.0;

        // Extract subdomain portion
        var subdomain = dnsQueryName[..secondLastDotIndex];
        return CalculateEntropy(subdomain);
    }

    /// <summary>
    /// Overload for string input.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double CalculateSubdomainEntropy(this string? dnsQueryName)
    {
        if (string.IsNullOrEmpty(dnsQueryName))
            return 0.0;

        return CalculateSubdomainEntropy(dnsQueryName.AsSpan());
    }

    /// <summary>
    /// Maps character to frequency array index (0-25 for a-z, 26-35 for 0-9).
    /// Returns -1 for non-alphanumeric characters.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetCharIndex(char c)
    {
        // Lowercase letters: a-z → 0-25
        if (c >= 'a' && c <= 'z')
            return c - 'a';

        // Uppercase letters: A-Z → 0-25
        if (c >= 'A' && c <= 'Z')
            return c - 'A';

        // Digits: 0-9 → 26-35
        if (c >= '0' && c <= '9')
            return 26 + (c - '0');

        return -1;
    }
}
