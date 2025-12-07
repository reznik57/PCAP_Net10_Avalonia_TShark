using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Caching;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Caching decorator for SecurityFindingsGenerator.
    /// Wraps the original implementation with transparent caching to improve performance.
    /// </summary>
    public class CachedSecurityFindingsGenerator : ISecurityFindingsGenerator
    {
        private readonly SecurityFindingsGenerator _innerGenerator;
        private readonly ICacheService _cacheService;
        private readonly CacheKeyGenerator _keyGenerator;
        private readonly CacheConfiguration _configuration;
        private readonly ILogger<CachedSecurityFindingsGenerator> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachedSecurityFindingsGenerator"/> class.
        /// </summary>
        /// <param name="innerGenerator">The wrapped SecurityFindingsGenerator instance.</param>
        /// <param name="cacheService">Cache service for storing results.</param>
        /// <param name="keyGenerator">Generator for cache keys.</param>
        /// <param name="configuration">Cache configuration.</param>
        /// <param name="logger">Logger for diagnostics.</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public CachedSecurityFindingsGenerator(
            SecurityFindingsGenerator innerGenerator,
            ICacheService cacheService,
            CacheKeyGenerator keyGenerator,
            CacheConfiguration configuration,
            ILogger<CachedSecurityFindingsGenerator> logger)
        {
            ArgumentNullException.ThrowIfNull(innerGenerator);
            ArgumentNullException.ThrowIfNull(cacheService);
            ArgumentNullException.ThrowIfNull(keyGenerator);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(logger);
            _innerGenerator = innerGenerator;
            _cacheService = cacheService;
            _keyGenerator = keyGenerator;
            _configuration = configuration;
            _logger = logger;
        }

        /// <summary>
        /// Generates comprehensive security findings from network statistics and threats.
        /// Results are cached to improve performance on subsequent calls with same parameters.
        /// </summary>
        /// <param name="statistics">Network statistics containing packet analysis data.</param>
        /// <param name="threats">List of detected security threats.</param>
        /// <returns>Cached or freshly generated list of security findings.</returns>
        public async Task<List<SecurityFinding>> GenerateAsync(
            NetworkStatistics statistics,
            List<SecurityThreat> threats)
        {
            ArgumentNullException.ThrowIfNull(statistics);
            ArgumentNullException.ThrowIfNull(threats);

            // If caching is disabled, bypass cache entirely
            if (!_configuration.Enabled)
            {
                _logger.LogDebug("Cache disabled, generating security findings directly");
                return await _innerGenerator.GenerateAsync(statistics, threats);
            }

            try
            {
                // Generate cache key from input parameters
                var cacheKey = _keyGenerator.GenerateForSecurityFindings(statistics, threats);
                _logger.LogDebug("Generated cache key for security findings: {CacheKey}", cacheKey);

                // Check cache first
                var cachedResult = await _cacheService.GetAsync<List<SecurityFinding>>(cacheKey);
                if (cachedResult is not null)
                {
                    _logger.LogInformation(
                        "Cache hit for security findings generation (ThreatCount={ThreatCount}, Key={CacheKey})",
                        threats.Count,
                        cacheKey);
                    return cachedResult;
                }

                // Cache miss - generate findings using inner service
                _logger.LogInformation(
                    "Cache miss for security findings generation (ThreatCount={ThreatCount}), generating...",
                    threats.Count);

                var startTime = DateTime.UtcNow;
                var findings = await _innerGenerator.GenerateAsync(statistics, threats);
                var duration = DateTime.UtcNow - startTime;

                _logger.LogInformation(
                    "Generated {FindingCount} security findings in {Duration}ms",
                    findings.Count,
                    duration.TotalMilliseconds);

                // Store in cache for future requests
                var cacheOptions = new CacheOptions
                {
                    AbsoluteExpiration = TimeSpan.FromMinutes(10), // Security findings valid for 10 minutes
                    Priority = CacheItemPriority.High, // Expensive to regenerate
                    Size = EstimateSize(findings)
                };

                await _cacheService.SetAsync(cacheKey, findings, cacheOptions);
                _logger.LogDebug("Cached security findings with key: {CacheKey}", cacheKey);

                return findings;
            }
            catch (Exception ex)
            {
                // If caching fails, fall back to direct generation
                _logger.LogError(ex, "Error in cached security findings generation, falling back to direct generation");
                return await _innerGenerator.GenerateAsync(statistics, threats);
            }
        }

        /// <summary>
        /// Analyzes network usage for insecure services (FTP, Telnet, etc.).
        /// Results are cached per statistics signature.
        /// </summary>
        /// <param name="statistics">Network statistics containing port usage data.</param>
        /// <returns>Cached or freshly generated security findings for insecure services.</returns>
        public async Task<List<SecurityFinding>> AnalyzeInsecureServicesAsync(NetworkStatistics statistics)
        {
            ArgumentNullException.ThrowIfNull(statistics);

            // If caching is disabled, bypass cache
            if (!_configuration.Enabled)
            {
                return await _innerGenerator.AnalyzeInsecureServicesAsync(statistics);
            }

            try
            {
                // Use a subset of statistics for key generation (just port analysis)
                var cacheKey = _keyGenerator.GenerateGeneric(
                    "SecurityFindings",
                    "InsecureServices",
                    statistics.TotalPackets,
                    statistics.TopPorts?.Count ?? 0,
                    string.Join(",", statistics.TopPorts?.Select(p => $"{p.Port}:{p.PacketCount}") ?? Array.Empty<string>()));

                var cachedResult = await _cacheService.GetAsync<List<SecurityFinding>>(cacheKey);
                if (cachedResult is not null)
                {
                    _logger.LogDebug("Cache hit for insecure services analysis");
                    return cachedResult;
                }

                // Cache miss - analyze using inner service
                var findings = await _innerGenerator.AnalyzeInsecureServicesAsync(statistics);

                // Cache result
                var cacheOptions = new CacheOptions
                {
                    AbsoluteExpiration = TimeSpan.FromMinutes(10),
                    Priority = CacheItemPriority.Normal,
                    Size = EstimateSize(findings)
                };

                await _cacheService.SetAsync(cacheKey, findings, cacheOptions);
                return findings;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in cached insecure services analysis, falling back");
                return await _innerGenerator.AnalyzeInsecureServicesAsync(statistics);
            }
        }

        /// <summary>
        /// Analyzes network traffic for suspicious patterns (port scanning, data exfiltration).
        /// Results are cached per statistics signature.
        /// </summary>
        /// <param name="statistics">Network statistics containing conversation data.</param>
        /// <returns>Cached or freshly generated security findings for suspicious patterns.</returns>
        public async Task<List<SecurityFinding>> AnalyzeSuspiciousPatternsAsync(NetworkStatistics statistics)
        {
            ArgumentNullException.ThrowIfNull(statistics);

            // If caching is disabled, bypass cache
            if (!_configuration.Enabled)
            {
                return await _innerGenerator.AnalyzeSuspiciousPatternsAsync(statistics);
            }

            try
            {
                // Generate cache key based on conversation patterns
                var cacheKey = _keyGenerator.GenerateGeneric(
                    "SecurityFindings",
                    "SuspiciousPatterns",
                    statistics.TotalPackets,
                    statistics.TopConversations?.Count ?? 0,
                    statistics.TopConversations?.Sum(c => c.PacketCount) ?? 0);

                var cachedResult = await _cacheService.GetAsync<List<SecurityFinding>>(cacheKey);
                if (cachedResult is not null)
                {
                    _logger.LogDebug("Cache hit for suspicious patterns analysis");
                    return cachedResult;
                }

                // Cache miss - analyze using inner service
                var findings = await _innerGenerator.AnalyzeSuspiciousPatternsAsync(statistics);

                // Cache result
                var cacheOptions = new CacheOptions
                {
                    AbsoluteExpiration = TimeSpan.FromMinutes(10),
                    Priority = CacheItemPriority.Normal,
                    Size = EstimateSize(findings)
                };

                await _cacheService.SetAsync(cacheKey, findings, cacheOptions);
                return findings;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in cached suspicious patterns analysis, falling back");
                return await _innerGenerator.AnalyzeSuspiciousPatternsAsync(statistics);
            }
        }

        /// <summary>
        /// Estimates the memory size of a findings list for cache size tracking.
        /// Provides a rough estimate for size-bounded cache eviction.
        /// </summary>
        /// <param name="findings">List of security findings.</param>
        /// <returns>Estimated size in bytes.</returns>
        private static long EstimateSize(List<SecurityFinding> findings)
        {
            if (findings is null || findings.Count == 0)
                return 1024; // Minimum size

            // Rough estimate: 5KB per finding (includes all nested data)
            return findings.Count * 5 * 1024;
        }
    }
}
