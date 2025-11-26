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
    /// Caching decorator for RemediationPlanner.
    /// Wraps the original implementation with transparent caching to improve performance.
    /// </summary>
    public class CachedRemediationPlanner : IRemediationPlanner
    {
        private readonly RemediationPlanner _innerPlanner;
        private readonly ICacheService _cacheService;
        private readonly CacheKeyGenerator _keyGenerator;
        private readonly CacheConfiguration _configuration;
        private readonly ILogger<CachedRemediationPlanner> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachedRemediationPlanner"/> class.
        /// </summary>
        /// <param name="innerPlanner">The wrapped RemediationPlanner instance.</param>
        /// <param name="cacheService">Cache service for storing results.</param>
        /// <param name="keyGenerator">Generator for cache keys.</param>
        /// <param name="configuration">Cache configuration.</param>
        /// <param name="logger">Logger for diagnostics.</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public CachedRemediationPlanner(
            RemediationPlanner innerPlanner,
            ICacheService cacheService,
            CacheKeyGenerator keyGenerator,
            CacheConfiguration configuration,
            ILogger<CachedRemediationPlanner> logger)
        {
            _innerPlanner = innerPlanner ?? throw new ArgumentNullException(nameof(innerPlanner));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Generates a comprehensive remediation plan from security findings.
        /// Results are cached to improve performance on subsequent calls with same parameters.
        /// </summary>
        /// <param name="findings">Security findings requiring remediation.</param>
        /// <param name="recommendations">Additional recommendations for security improvements.</param>
        /// <returns>Cached or freshly generated structured remediation plan.</returns>
        public async Task<RemediationPlan> GenerateAsync(
            List<SecurityFinding> findings,
            List<Recommendation> recommendations)
        {
            if (findings == null)
                throw new ArgumentNullException(nameof(findings));
            if (recommendations == null)
                throw new ArgumentNullException(nameof(recommendations));

            // If caching is disabled, bypass cache entirely
            if (!_configuration.Enabled)
            {
                _logger.LogDebug("Cache disabled, generating remediation plan directly");
                return await _innerPlanner.GenerateAsync(findings, recommendations);
            }

            try
            {
                // Generate cache key from input parameters
                var cacheKey = _keyGenerator.GenerateForRemediationPlan(findings, recommendations);
                _logger.LogDebug("Generated cache key for remediation plan: {CacheKey}", cacheKey);

                // Check cache first
                var cachedResult = await _cacheService.GetAsync<RemediationPlan>(cacheKey);
                if (cachedResult != null)
                {
                    _logger.LogInformation(
                        "Cache hit for remediation plan generation (FindingCount={FindingCount}, RecommendationCount={RecommendationCount}, Key={CacheKey})",
                        findings.Count,
                        recommendations.Count,
                        cacheKey);
                    return cachedResult;
                }

                // Cache miss - generate plan using inner service
                _logger.LogInformation(
                    "Cache miss for remediation plan generation (FindingCount={FindingCount}, RecommendationCount={RecommendationCount}), generating...",
                    findings.Count,
                    recommendations.Count);

                var startTime = DateTime.UtcNow;
                var plan = await _innerPlanner.GenerateAsync(findings, recommendations);
                var duration = DateTime.UtcNow - startTime;

                _logger.LogInformation(
                    "Generated remediation plan with {PhaseCount} phases in {Duration}ms",
                    plan.Phases.Count,
                    duration.TotalMilliseconds);

                // Store in cache for future requests
                var cacheOptions = new CacheOptions
                {
                    AbsoluteExpiration = TimeSpan.FromMinutes(15), // Plans valid for 15 minutes
                    SlidingExpiration = TimeSpan.FromMinutes(10), // Extend if actively used
                    Priority = CacheItemPriority.Normal, // Less expensive than findings generation
                    Size = EstimateSize(plan)
                };

                await _cacheService.SetAsync(cacheKey, plan, cacheOptions);
                _logger.LogDebug("Cached remediation plan with key: {CacheKey}", cacheKey);

                return plan;
            }
            catch (Exception ex)
            {
                // If caching fails, fall back to direct generation
                _logger.LogError(ex, "Error in cached remediation plan generation, falling back to direct generation");
                return await _innerPlanner.GenerateAsync(findings, recommendations);
            }
        }

        /// <summary>
        /// Generates remediation steps for a specific insecure service.
        /// This method is not cached as it's lightweight and frequently called with different parameters.
        /// </summary>
        /// <param name="port">The port number of the insecure service.</param>
        /// <param name="serviceName">The name of the insecure service.</param>
        /// <returns>Detailed remediation step with priority and technical instructions.</returns>
        public RemediationStep GenerateServiceRemediationStep(int port, string serviceName)
        {
            // This method is lightweight and doesn't benefit significantly from caching
            // Also, the number of unique port/service combinations is small
            return _innerPlanner.GenerateServiceRemediationStep(port, serviceName);
        }

        /// <summary>
        /// Generates recommendations based on security findings and performance issues.
        /// Results are cached per unique combination of findings and issues.
        /// </summary>
        /// <param name="findings">Security findings to base recommendations on.</param>
        /// <param name="performanceIssues">Performance issues identified during analysis.</param>
        /// <returns>Cached or freshly generated list of prioritized recommendations.</returns>
        public async Task<List<Recommendation>> GenerateRecommendationsAsync(
            List<SecurityFinding> findings,
            List<PerformanceIssue> performanceIssues)
        {
            if (findings == null)
                throw new ArgumentNullException(nameof(findings));
            if (performanceIssues == null)
                throw new ArgumentNullException(nameof(performanceIssues));

            // If caching is disabled, bypass cache
            if (!_configuration.Enabled)
            {
                return await _innerPlanner.GenerateRecommendationsAsync(findings, performanceIssues);
            }

            try
            {
                // Generate cache key based on finding and performance issue summaries
                var cacheKey = _keyGenerator.GenerateGeneric(
                    "RemediationPlanner",
                    "Recommendations",
                    findings.Count,
                    findings.Count(f => f.Severity == SeverityLevel.Critical),
                    findings.Count(f => f.Severity == SeverityLevel.High),
                    performanceIssues.Count,
                    string.Join(",", findings.Select(f => f.Category).Distinct().OrderBy(c => c)));

                var cachedResult = await _cacheService.GetAsync<List<Recommendation>>(cacheKey);
                if (cachedResult != null)
                {
                    _logger.LogDebug("Cache hit for recommendations generation");
                    return cachedResult;
                }

                // Cache miss - generate recommendations using inner service
                _logger.LogDebug("Cache miss for recommendations generation, generating...");

                var recommendations = await _innerPlanner.GenerateRecommendationsAsync(findings, performanceIssues);

                // Cache result
                var cacheOptions = new CacheOptions
                {
                    AbsoluteExpiration = TimeSpan.FromMinutes(15),
                    SlidingExpiration = TimeSpan.FromMinutes(10),
                    Priority = CacheItemPriority.Normal,
                    Size = EstimateRecommendationsSize(recommendations)
                };

                await _cacheService.SetAsync(cacheKey, recommendations, cacheOptions);
                _logger.LogDebug("Cached {RecommendationCount} recommendations", recommendations.Count);

                return recommendations;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in cached recommendations generation, falling back");
                return await _innerPlanner.GenerateRecommendationsAsync(findings, performanceIssues);
            }
        }

        /// <summary>
        /// Estimates the memory size of a remediation plan for cache size tracking.
        /// Provides a rough estimate for size-bounded cache eviction.
        /// </summary>
        /// <param name="plan">Remediation plan.</param>
        /// <returns>Estimated size in bytes.</returns>
        private static long EstimateSize(RemediationPlan plan)
        {
            if (plan == null)
                return 1024; // Minimum size

            // Estimate based on phases and tasks
            var baseSize = 10 * 1024; // 10KB base
            var phaseSize = plan.Phases.Count * 5 * 1024; // 5KB per phase
            var taskSize = plan.TasksByPriority.Values.Sum(tasks => tasks.Count) * 2 * 1024; // 2KB per task

            return baseSize + phaseSize + taskSize;
        }

        /// <summary>
        /// Estimates the memory size of a recommendations list for cache size tracking.
        /// </summary>
        /// <param name="recommendations">List of recommendations.</param>
        /// <returns>Estimated size in bytes.</returns>
        private static long EstimateRecommendationsSize(List<Recommendation> recommendations)
        {
            if (recommendations == null || recommendations.Count == 0)
                return 1024; // Minimum size

            // Rough estimate: 3KB per recommendation
            return recommendations.Count * 3 * 1024;
        }
    }
}
