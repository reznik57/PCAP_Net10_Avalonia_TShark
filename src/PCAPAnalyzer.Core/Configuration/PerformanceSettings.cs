namespace PCAPAnalyzer.Core.Configuration
{
    public static class PerformanceSettings
    {
        // Batch processing settings
        public const int BatchProcessingSize = 1000;
        
        // UI display settings
        public const int MaxPacketsInUI = 10000;
        
        // Update intervals
        public const int UIUpdateInterval = 100; // milliseconds
        
        // Memory management
        public const int GCInterval = 100000; // Trigger GC every 100k packets
    }
}