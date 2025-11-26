using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services.Cache
{
    /// <summary>
    /// No-op implementation of IAnalysisCacheService that disables caching.
    /// Used when cache is temporarily disabled or for testing fresh analysis performance.
    /// All cache operations immediately return "not found" without doing any work.
    /// </summary>
    public class NoOpAnalysisCacheService : IAnalysisCacheService
    {
        private static bool _loggedOnce;

        public NoOpAnalysisCacheService()
        {
            if (!_loggedOnce)
            {
                DebugLogger.Log("[NoOpAnalysisCacheService] ⚠️  CACHE DISABLED - All analysis will be performed fresh");
                DebugLogger.Log("[NoOpAnalysisCacheService] To re-enable: Set environment variable PCAP_ANALYZER_CACHE_ENABLED=1");
                _loggedOnce = true;
            }
        }

        public Task<string> ComputeCacheKeyAsync(string filePath, CancellationToken cancellationToken = default)
        {
            // Return dummy key (never actually used since IsCachedAsync always returns false)
            return Task.FromResult($"nocache_{filePath}");
        }

        public Task<bool> IsCachedAsync(string cacheKey, string analysisType, CancellationToken cancellationToken = default)
        {
            // Always return false - cache disabled
            return Task.FromResult(false);
        }

        public Task SaveThreatsAsync(string cacheKey, List<EnhancedSecurityThreat> threats, CancellationToken cancellationToken = default)
        {
            // No-op - don't save anything
            return Task.CompletedTask;
        }

        public Task<List<EnhancedSecurityThreat>?> LoadThreatsAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            // Always return null - cache disabled
            return Task.FromResult<List<EnhancedSecurityThreat>?>(null);
        }

        public Task SaveVoiceQoSAsync(string cacheKey, VoiceQoSAnalysisResult qosData, CancellationToken cancellationToken = default)
        {
            // No-op - don't save anything
            return Task.CompletedTask;
        }

        public Task<VoiceQoSAnalysisResult?> LoadVoiceQoSAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            // Always return null - cache disabled
            return Task.FromResult<VoiceQoSAnalysisResult?>(null);
        }

        public Task<int> ClearOldCacheAsync(int maxAgeDays = 30, CancellationToken cancellationToken = default)
        {
            // No-op - nothing to clear
            return Task.FromResult(0);
        }

        public Task<long> GetCacheSizeMBAsync(CancellationToken cancellationToken = default)
        {
            // Always return 0 - no cache
            return Task.FromResult(0L);
        }

        public Task<Dictionary<string, object>> GetCacheStatisticsAsync(CancellationToken cancellationToken = default)
        {
            // Return empty stats
            return Task.FromResult(new Dictionary<string, object>
            {
                { "Status", "Disabled" },
                { "TotalEntries", 0 },
                { "SizeMB", 0 }
            });
        }

        public Task DeleteCacheForFileAsync(string fileHash, CancellationToken cancellationToken = default)
        {
            // No-op - nothing to delete
            return Task.CompletedTask;
        }

        public Task OptimizeDatabaseAsync(CancellationToken cancellationToken = default)
        {
            // No-op - no database to optimize
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            // No-op - nothing to dispose
        }
    }
}
