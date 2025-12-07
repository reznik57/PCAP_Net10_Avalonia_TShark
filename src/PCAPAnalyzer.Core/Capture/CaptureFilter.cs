using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PCAPAnalyzer.Core.Capture
{
    /// <summary>
    /// Berkeley Packet Filter (BPF) management and validation
    /// Provides validation, parsing, and optimization of BPF filter expressions
    /// </summary>
    public sealed partial class CaptureFilter
    {
        private readonly string _filterExpression;
        private readonly List<FilterToken> _tokens;

        /// <summary>
        /// Gets the filter expression
        /// </summary>
        public string Expression => _filterExpression;

        /// <summary>
        /// Gets whether the filter is valid
        /// </summary>
        public bool IsValid { get; private set; }

        /// <summary>
        /// Gets validation errors (empty if valid)
        /// </summary>
        public List<string> ValidationErrors { get; private set; } = [];

        /// <summary>
        /// Gets the parsed filter tokens
        /// </summary>
        public IReadOnlyList<FilterToken> Tokens => _tokens.AsReadOnly();

        /// <summary>
        /// Initializes a new capture filter
        /// </summary>
        /// <param name="filterExpression">BPF filter expression</param>
        public CaptureFilter(string filterExpression)
        {
            ArgumentNullException.ThrowIfNull(filterExpression);
            _filterExpression = filterExpression;
            _tokens = new List<FilterToken>();
            Validate();
        }

        /// <summary>
        /// Validates the BPF filter expression
        /// </summary>
        private void Validate()
        {
            ValidationErrors.Clear();
            IsValid = true;

            if (string.IsNullOrWhiteSpace(_filterExpression))
            {
                // Empty filter is valid (captures all)
                return;
            }

            try
            {
                // Tokenize the filter
                _tokens.AddRange(Tokenize(_filterExpression));

                // Check for basic syntax errors
                ValidateSyntax();

                // Check for balanced parentheses
                ValidateParentheses();

                // Check for valid keywords
                ValidateKeywords();

                // Check for valid operators
                ValidateOperators();
            }
            catch (Exception ex)
            {
                IsValid = false;
                ValidationErrors.Add($"Parsing error: {ex.Message}");
            }

            IsValid = ValidationErrors.Count == 0;
        }

        /// <summary>
        /// Tokenizes the filter expression
        /// </summary>
        private static IEnumerable<FilterToken> Tokenize(string expression)
        {
            var tokens = new List<FilterToken>();
            var regex = TokenRegex();
            var matches = regex.Matches(expression);

            foreach (Match match in matches)
            {
                if (match.Groups["keyword"].Success)
                {
                    tokens.Add(new FilterToken(FilterTokenType.Keyword, match.Value));
                }
                else if (match.Groups["operator"].Success)
                {
                    tokens.Add(new FilterToken(FilterTokenType.Operator, match.Value));
                }
                else if (match.Groups["value"].Success)
                {
                    tokens.Add(new FilterToken(FilterTokenType.Value, match.Value));
                }
                else if (match.Groups["paren"].Success)
                {
                    tokens.Add(new FilterToken(FilterTokenType.Parenthesis, match.Value));
                }
            }

            return tokens;
        }

        /// <summary>
        /// Validates syntax rules
        /// </summary>
        private void ValidateSyntax()
        {
            if (_tokens.Count == 0) return;

            // Check for consecutive operators
            for (int i = 0; i < _tokens.Count - 1; i++)
            {
                if (_tokens[i].Type == FilterTokenType.Operator &&
                    _tokens[i + 1].Type == FilterTokenType.Operator)
                {
                    ValidationErrors.Add($"Consecutive operators at position {i}: {_tokens[i].Value} {_tokens[i + 1].Value}");
                }
            }

            // Check for incomplete expressions
            if (_tokens[^1].Type == FilterTokenType.Operator)
            {
                ValidationErrors.Add("Filter expression ends with an operator");
            }
        }

        /// <summary>
        /// Validates parentheses are balanced
        /// </summary>
        private void ValidateParentheses()
        {
            int balance = 0;
            foreach (var token in _tokens.Where(t => t.Type == FilterTokenType.Parenthesis))
            {
                balance += token.Value == "(" ? 1 : -1;
                if (balance < 0)
                {
                    ValidationErrors.Add("Unbalanced parentheses: closing parenthesis without matching opening");
                    return;
                }
            }

            if (balance > 0)
            {
                ValidationErrors.Add("Unbalanced parentheses: unclosed opening parenthesis");
            }
        }

        /// <summary>
        /// Validates BPF keywords
        /// </summary>
        private void ValidateKeywords()
        {
            var validKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Protocol keywords
                "ip", "ip6", "arp", "rarp", "tcp", "udp", "icmp", "icmp6",
                // Direction keywords
                "src", "dst", "host", "net", "port", "portrange",
                // Type keywords
                "ether", "broadcast", "multicast",
                // Other keywords
                "gateway", "less", "greater", "proto", "protochain",
                "vlan", "mpls", "pppoed", "pppoes", "geneve", "vxlan"
            };

            foreach (var token in _tokens.Where(t => t.Type == FilterTokenType.Keyword))
            {
                if (!validKeywords.Contains(token.Value))
                {
                    ValidationErrors.Add($"Unknown keyword: {token.Value}");
                }
            }
        }

        /// <summary>
        /// Validates operators
        /// </summary>
        private void ValidateOperators()
        {
            var validOperators = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "and", "or", "not", "&&", "||", "!"
            };

            foreach (var token in _tokens.Where(t => t.Type == FilterTokenType.Operator))
            {
                if (!validOperators.Contains(token.Value))
                {
                    ValidationErrors.Add($"Unknown operator: {token.Value}");
                }
            }
        }

        /// <summary>
        /// Optimizes the filter expression
        /// </summary>
        public string Optimize()
        {
            if (!IsValid) return _filterExpression;

            // Replace && with 'and', || with 'or', ! with 'not'
            var optimized = _filterExpression
                .Replace("&&", "and", StringComparison.Ordinal)
                .Replace("||", "or", StringComparison.Ordinal)
                .Replace("!", "not", StringComparison.Ordinal);

            // Remove redundant whitespace
            optimized = WhitespaceRegex().Replace(optimized, " ").Trim();

            return optimized;
        }

        /// <summary>
        /// Creates a filter for a specific host
        /// </summary>
        public static CaptureFilter ForHost(string ipAddress)
        {
            return new CaptureFilter($"host {ipAddress}");
        }

        /// <summary>
        /// Creates a filter for a specific port
        /// </summary>
        public static CaptureFilter ForPort(int port)
        {
            return new CaptureFilter($"port {port}");
        }

        /// <summary>
        /// Creates a filter for a specific protocol
        /// </summary>
        public static CaptureFilter ForProtocol(string protocol)
        {
            return new CaptureFilter(protocol.ToLowerInvariant());
        }

        /// <summary>
        /// Creates a filter for a network range
        /// </summary>
        public static CaptureFilter ForNetwork(string network, int prefixLength)
        {
            return new CaptureFilter($"net {network}/{prefixLength}");
        }

        /// <summary>
        /// Combines filters with AND logic
        /// </summary>
        public static CaptureFilter And(CaptureFilter filter1, CaptureFilter filter2)
        {
            return new CaptureFilter($"({filter1.Expression}) and ({filter2.Expression})");
        }

        /// <summary>
        /// Combines filters with OR logic
        /// </summary>
        public static CaptureFilter Or(CaptureFilter filter1, CaptureFilter filter2)
        {
            return new CaptureFilter($"({filter1.Expression}) or ({filter2.Expression})");
        }

        /// <summary>
        /// Negates a filter
        /// </summary>
        public static CaptureFilter Not(CaptureFilter filter)
        {
            return new CaptureFilter($"not ({filter.Expression})");
        }

        /// <summary>
        /// Gets common filter presets
        /// </summary>
#pragma warning disable CA1034 // Do not nest type - Presets is intentionally nested for organizational clarity and discoverability
        public static class Presets
#pragma warning restore CA1034
        {
            public static CaptureFilter All => new CaptureFilter("");
            public static CaptureFilter TcpOnly => new CaptureFilter("tcp");
            public static CaptureFilter UdpOnly => new CaptureFilter("udp");
            public static CaptureFilter IcmpOnly => new CaptureFilter("icmp");
            public static CaptureFilter HttpTraffic => new CaptureFilter("tcp port 80 or tcp port 443");
            public static CaptureFilter DnsTraffic => new CaptureFilter("port 53");
            public static CaptureFilter SshTraffic => new CaptureFilter("tcp port 22");
            public static CaptureFilter BroadcastOnly => new CaptureFilter("broadcast");
            public static CaptureFilter MulticastOnly => new CaptureFilter("multicast");
            public static CaptureFilter Ipv4Only => new CaptureFilter("ip");
            public static CaptureFilter Ipv6Only => new CaptureFilter("ip6");
        }

        [GeneratedRegex(@"(?<keyword>ip6?|arp|rarp|tcp|udp|icmp6?|ether|src|dst|host|net|port|portrange|broadcast|multicast|gateway|less|greater|proto|protochain|vlan|mpls|pppoed?|pppoes|geneve|vxlan)|(?<operator>and|or|not|&&|\|\||!)|(?<value>[a-zA-Z0-9.:/_-]+)|(?<paren>[()])", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
        private static partial Regex TokenRegex();

        [GeneratedRegex(@"\s+", RegexOptions.Compiled)]
        private static partial Regex WhitespaceRegex();

        public override string ToString() => _filterExpression;
    }

    /// <summary>
    /// Filter token type
    /// </summary>
    public enum FilterTokenType
    {
        Keyword,
        Operator,
        Value,
        Parenthesis
    }

    /// <summary>
    /// Represents a filter token
    /// </summary>
    public sealed class FilterToken
    {
        public FilterTokenType Type { get; }
        public string Value { get; }

        public FilterToken(FilterTokenType type, string value)
        {
            Type = type;
            Value = value;
        }

        public override string ToString() => $"{Type}: {Value}";
    }
}
