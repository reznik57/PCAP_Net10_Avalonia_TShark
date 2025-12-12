using System;
using System.Diagnostics;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Orchestration
{
    /// <summary>
    /// Coordinates progress reporting across multiple analysis phases to provide
    /// a smooth 0-100% progression with cumulative elapsed time.
    ///
    /// Uses time-based estimation for smooth, predictable progress regardless of
    /// packet processing rate variations.
    /// </summary>
    public sealed class ProgressCoordinator
    {
        private readonly IProgress<AnalysisProgress>? _parentProgress;
        private readonly Stopwatch _totalStopwatch;
        private long _totalPackets;
        private double _totalMegabytes;
        private int _threatsDetected;
        private long _currentPacketsAnalyzed; // Real-time packet count during analysis

        // Progress debouncing to prevent parallel task interference
        private int _lastReportedPercent = -1;
        private int _highWaterMarkPercent = -1; // Track highest % ever reported (never go backwards)
        private DateTime _lastReportTime = DateTime.MinValue;
        private readonly Lock _progressLock = new();
        private const int MIN_REPORT_INTERVAL_MS = 150; // Don't report more than every 150ms
        private bool _isComplete; // Prevent updates after completion

        // Console logging throttle - max once per second
        private DateTime _lastLogTime = DateTime.MinValue;
        private const int MIN_LOG_INTERVAL_MS = 1000; // Log max once per second

        // Phase weights (must sum to 75 for pre-tab phases) - UPDATED FOR PARALLEL EXECUTION
        // Key insight: Stats, Threats, VoiceQoS run IN PARALLEL, so they share a unified range
        // Actual timings from 3GB file: Loading=97s, Parallel(Stats/Threats/VoiceQoS)=139s, Tabs=50s
        private const int PHASE_COUNTING = 5;      // 0-5% (instant with capinfos)
        private const int PHASE_LOADING = 50;      // 5-55% (loading packets - bulk of time)
        private const int PHASE_PARALLEL = 18;     // 55-73% (Stats+Threats+VoiceQoS run in parallel)
        private const int PHASE_FINALIZING = 2;    // 73-75% (finalizing/caching)
        // PHASE_TABS = 25                         // 75-100% (tab population - see StageRanges)

        // Note: Legacy phase weights removed - parallel phases now use weighted progress in ReportParallelTaskProgress()

        /// <summary>
        /// Stage ranges for UI progress display. Maps stage keys to (Start%, End%) ranges.
        /// Used by FileAnalysisViewModel to calculate stage-relative percentages.
        /// UPDATED FOR PARALLEL EXECUTION: Stats+Threats+VoiceQoS run in parallel (55-73%)
        /// Progress within parallel phase is based on MINIMUM progress of all tasks
        /// </summary>
        public static readonly IReadOnlyDictionary<string, (int Start, int End)> StageRanges =
            new Dictionary<string, (int, int)>
            {
                { "count",    (0, 5) },     // Counting Packets: 0-5% (instant with capinfos)
                { "load",     (5, 55) },    // Loading Packets: 5-55% (50%)
                { "parallel", (55, 73) },   // Parallel Analysis: 55-73% (Stats+Threats+VoiceQoS)
                { "stats",    (55, 73) },   // Alias for parallel (backward compat)
                { "geoip",    (55, 73) },   // Alias for parallel (backward compat)
                { "flows",    (55, 73) },   // Alias for parallel (backward compat)
                { "finalize", (73, 75) },   // Finalizing: 73-75% (2%)
                { "tabs",     (75, 100) }   // Loading Tabs: 75-100% (25%)
            };

        /// <summary>
        /// Calculate stage-relative percentage (0-100%) from overall progress percentage.
        /// </summary>
        /// <param name="stageKey">Stage key (e.g., "count", "load", "stats")</param>
        /// <param name="overallPercent">Overall progress 0-100%</param>
        /// <returns>Stage-relative percentage 0-100%</returns>
        public static int CalculateStageRelativePercent(string stageKey, double overallPercent)
        {
            if (!StageRanges.TryGetValue(stageKey, out var range))
                return 0;

            if (overallPercent < range.Start) return 0;
            if (overallPercent >= range.End) return 100;

            var stageProgress = (overallPercent - range.Start) / (range.End - range.Start);
            return (int)(stageProgress * 100);
        }

        /// <summary>
        /// Find which stage is currently active based on overall progress percentage.
        /// Returns the stage key and the stage-relative percentage.
        /// </summary>
        /// <param name="overallPercent">Overall progress 0-100%</param>
        /// <returns>Tuple of (stageKey, stageRelativePercent) or (null, 0) if no match</returns>
        public static (string? StageKey, int StagePercent) GetActiveStageFromOverall(double overallPercent)
        {
            foreach (var kvp in StageRanges)
            {
                var (start, end) = kvp.Value;
                if (overallPercent >= start && overallPercent < end)
                {
                    var stageProgress = (overallPercent - start) / (end - start);
                    return (kvp.Key, (int)(stageProgress * 100));
                }
            }

            // At 100%, return last stage as complete
            if (overallPercent >= 100)
                return ("tabs", 100);

            return (null, 0);
        }

        // Phase timing tracking with individual stopwatches
        private readonly Dictionary<string, Stopwatch> _phaseStopwatches = [];
        private readonly Dictionary<string, TimeSpan> _phaseDurations = [];
        private string _currentPhase = "";

        // ═══════════════════════════════════════════════════════════════════════════════
        // PARALLEL PROGRESS TRACKING: Stats, Threats, VoiceQoS run simultaneously
        // Progress = MIN(statsProgress, threatsProgress, voiceQoSProgress)
        // This ensures progress only advances when ALL parallel tasks have advanced
        // ═══════════════════════════════════════════════════════════════════════════════
        private readonly Dictionary<string, int> _parallelTaskProgress = new()
        {
            { "Statistics", 0 },
            { "Threats", 0 },
            { "VoiceQoS", 0 }
        };
        private readonly Dictionary<string, bool> _parallelTaskComplete = new()
        {
            { "Statistics", false },
            { "Threats", false },
            { "VoiceQoS", false }
        };
        private readonly Lock _parallelLock = new();
        private bool _parallelPhaseStarted;
        private string _lastParallelDetail = "";

        // Time-based estimation (seconds per phase, scaled by file size)
        // UPDATED: Based on actual measurements from 3GB file analysis
        private double _estimatedCountingSeconds = 5.0;
        private double _estimatedLoadingSeconds = 20.0;
        private double _estimatedParallelSeconds = 30.0;  // Stats+Threats+VoiceQoS in parallel
        private double _estimatedStatisticsSeconds = 15.0;
        private double _estimatedThreatsSeconds = 10.0;
        private double _estimatedVoiceQoSSeconds = 5.0;
        private double _estimatedFinalizingSeconds = 2.0;

        public ProgressCoordinator(IProgress<AnalysisProgress>? parentProgress)
        {
            _parentProgress = parentProgress;
            _totalStopwatch = Stopwatch.StartNew();
        }

        /// <summary>
        /// Check if enough time has elapsed to allow another console log (1 second throttle).
        /// Returns true and updates timestamp if logging is allowed.
        /// </summary>
        private bool ShouldLogProgress()
        {
            var now = DateTime.Now;
            if ((now - _lastLogTime).TotalMilliseconds >= MIN_LOG_INTERVAL_MS)
            {
                _lastLogTime = now;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Initialize time estimates based on file size for smooth progress
        /// UPDATED: Based on actual measurements - 3GB file takes ~240s total
        /// </summary>
        public void InitializeTimeEstimates(double fileSizeMB)
        {
            // Scale estimates based on file size
            // Baseline: 500MB = 1x (more realistic baseline from measurements)
            // Actual 3GB file: Loading=97s, Parallel=139s, Tabs=50s
            var scaleFactor = Math.Max(0.5, Math.Min(10.0, fileSizeMB / 500.0));

            _estimatedCountingSeconds = 4.0 * scaleFactor;           // Fast with capinfos
            _estimatedLoadingSeconds = 30.0 * scaleFactor;           // TShark parsing
            _estimatedParallelSeconds = 45.0 * scaleFactor;          // Stats+Threats+VoiceQoS parallel
            _estimatedStatisticsSeconds = 45.0 * scaleFactor;        // Individual estimate (parallel)
            _estimatedThreatsSeconds = 40.0 * scaleFactor;           // Individual estimate (parallel)
            _estimatedVoiceQoSSeconds = 5.0 * scaleFactor;           // Usually fast
            _estimatedFinalizingSeconds = 2.0;                       // Fixed duration

            DebugLogger.Log($"[ProgressCoordinator] Time estimates for {fileSizeMB:F1}MB file (scale: {scaleFactor:F2}x):");
            DebugLogger.Log($"  Counting: {_estimatedCountingSeconds:F1}s, Loading: {_estimatedLoadingSeconds:F1}s");
            DebugLogger.Log($"  Parallel (Stats+Threats+VoiceQoS): {_estimatedParallelSeconds:F1}s, Finalizing: {_estimatedFinalizingSeconds:F1}s");
        }

        /// <summary>
        /// Get recorded phase durations for performance reporting
        /// </summary>
        public IReadOnlyDictionary<string, TimeSpan> PhaseDurations => _phaseDurations;

        public void SetTotalPackets(long totalPackets) => _totalPackets = totalPackets;
        public void SetTotalMegabytes(double totalMegabytes) => _totalMegabytes = totalMegabytes;
        public void IncrementThreats(int count) => _threatsDetected += count;
        public void SetCurrentPackets(long currentPackets) => _currentPacketsAnalyzed = currentPackets;

        /// <summary>
        /// Report progress for packet counting phase (0-35%)
        /// ✅ FIX: Reports 0% at phase start (not 35% which causes backwards jump)
        /// </summary>
        public void ReportCounting(string detail)
        {
            StartPhase("Counting Packets");
            // ✅ CRITICAL FIX: Report 0% at start, not PHASE_COUNTING (35%)
            // This prevents backwards jump: 35% (phase end) → 2% (actual progress)
            Report(0, 0, detail, "Counting Packets");
            DebugLogger.Log($"[ProgressCoordinator] 🎯 Counting phase started at 0%: {detail}");
        }

        /// <summary>
        /// Report progress for packet counting phase with percentage (0-35%)
        /// Allows TShark to report incremental counting progress with current packet count
        /// </summary>
        public void ReportCounting(int childPercent, string detail, long currentPackets = 0)
        {
            if (childPercent == 0) StartPhase("Counting Packets");

            if (currentPackets > 0)
                _currentPacketsAnalyzed = currentPackets;

            // Time-based progress for smooth counting (hybrid with child percent)
            var elapsed = GetPhaseElapsed("Counting Packets");
            var timeBasedPercent = Math.Min(99, (int)((elapsed / _estimatedCountingSeconds) * 100));

            // Use minimum to prevent jumps
            var phasePercent = Math.Min(childPercent, timeBasedPercent);

            var overallPercent = (phasePercent * PHASE_COUNTING / 100);

            // 🔍 DIAGNOSTIC: Log progress calculation details (throttled to 1/sec)
            if (ShouldLogProgress())
                DebugLogger.Log($"[ProgressCoordinator] 📊 Counting: child={childPercent}%, time={timeBasedPercent}%, phase={phasePercent}%, overall={overallPercent}%, packets={currentPackets:N0}");

            Report(overallPercent, 0, detail, "Counting Packets");
        }

        /// <summary>
        /// Report progress for packet loading phase (5-55%) - HYBRID (packet-based + time-based)
        /// ✅ FIX: Uses packet count when available, falls back to time-based estimation
        /// </summary>
        public void ReportLoading(int packetsLoaded, string detail)
        {
            if (packetsLoaded == 0) StartPhase("Loading Packets");

            _currentPacketsAnalyzed = packetsLoaded;

            // ✅ FIX: Use packet-based progress when total packets known, otherwise time-based
            int phasePercent;
            string? logMessage = null;
            if (_totalPackets > 0 && packetsLoaded > 0)
            {
                // Packet-based progress (accurate, smooth)
                var packetProgress = (double)packetsLoaded / _totalPackets;
                phasePercent = Math.Min(99, (int)(packetProgress * 100));
                logMessage = $"[ProgressCoordinator] 📊 Loading: packet-based {packetsLoaded:N0}/{_totalPackets:N0} = {phasePercent}%";
            }
            else
            {
                // Time-based progress fallback (when packet count unavailable)
                var elapsed = GetPhaseElapsed("Loading Packets");
                phasePercent = Math.Min(99, (int)((elapsed / _estimatedLoadingSeconds) * 100));
                logMessage = $"[ProgressCoordinator] 📊 Loading: time-based {elapsed:F1}s/{_estimatedLoadingSeconds:F1}s = {phasePercent}%";
            }

            // Throttled logging (max once per second)
            if (ShouldLogProgress() && logMessage is not null)
                DebugLogger.Log(logMessage);

            // Loading phase: 5-55% (50% range) - starts after PHASE_COUNTING
            var overallPercent = PHASE_COUNTING + (phasePercent * PHASE_LOADING / 100);

            // Use debounced Report method for consistency
            Report(overallPercent, 0, detail, "Loading Packets");
        }

        // Phase start offsets (calculated from cumulative weights)
        // UPDATED: Parallel phase (Stats+Threats+VoiceQoS) is unified at 55-73%
        private const int OFFSET_PARALLEL = PHASE_COUNTING + PHASE_LOADING;                   // 55%
        private const int OFFSET_FINALIZING = OFFSET_PARALLEL + PHASE_PARALLEL;               // 73%

        // ═══════════════════════════════════════════════════════════════════════════════
        // PARALLEL PROGRESS REPORTING
        // Stats, Threats, VoiceQoS run simultaneously - progress based on weighted average
        // ═══════════════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Report progress for a parallel task. Calculates unified progress across all parallel tasks.
        /// Progress advances based on weighted completion: Stats=50%, Threats=40%, VoiceQoS=10%
        /// </summary>
        private void ReportParallelTaskProgress(string taskName, int taskPercent, string detail, int? threatsFound = null)
        {
            if (!_parallelPhaseStarted)
            {
                StartPhase("Parallel Analysis");
                _parallelPhaseStarted = true;
            }

            // Update threat count if provided
            if (threatsFound.HasValue && threatsFound.Value > 0)
                _threatsDetected = threatsFound.Value;

            int overallPercent;
            string unifiedDetail;

            using (_parallelLock.EnterScope())
            {
                // Update this task's progress
                _parallelTaskProgress[taskName] = taskPercent;
                if (taskPercent >= 100)
                    _parallelTaskComplete[taskName] = true;

                // Calculate weighted progress (Stats=50%, Threats=40%, VoiceQoS=10%)
                // This reflects actual execution time: Stats is slowest, VoiceQoS is fastest
                var statsProgress = _parallelTaskProgress["Statistics"];
                var threatsProgress = _parallelTaskProgress["Threats"];
                var voiceQoSProgress = _parallelTaskProgress["VoiceQoS"];

                // Weighted average based on typical execution time
                var weightedProgress = (statsProgress * 0.50) + (threatsProgress * 0.40) + (voiceQoSProgress * 0.10);
                var parallelPercent = Math.Min(99, (int)weightedProgress);

                // Count completed tasks for detail message
                var completedCount = (_parallelTaskComplete["Statistics"] ? 1 : 0) +
                                      (_parallelTaskComplete["Threats"] ? 1 : 0) +
                                      (_parallelTaskComplete["VoiceQoS"] ? 1 : 0);

                // If all complete, set to 100%
                if (completedCount == 3)
                    parallelPercent = 100;

                // Map parallel progress (0-100%) to overall range (55-73%)
                overallPercent = OFFSET_PARALLEL + (parallelPercent * PHASE_PARALLEL / 100);

                // Build unified detail message showing all parallel task status
                _lastParallelDetail = detail;
                unifiedDetail = $"{detail} ({completedCount}/3 phases complete)";

                // Log progress periodically
                if (ShouldLogProgress())
                {
                    DebugLogger.Log($"[ProgressCoordinator] 📊 Parallel: Stats={statsProgress}%, Threats={threatsProgress}%, " +
                                      $"VoiceQoS={voiceQoSProgress}% → weighted={parallelPercent}% → overall={overallPercent}%");
                }
            }

            Report(overallPercent, 0, unifiedDetail, "Analyzing Traffic", taskName);
        }

        /// <summary>
        /// Report progress for statistics/GeoIP phase (parallel task 1/3)
        /// </summary>
        public void ReportStatistics(int childPercent, string detail, string? subPhase = null)
        {
            if (childPercent == 0) StartPhase("Analyzing Data");

            // Hybrid: cap progress with time-based estimate to prevent jumps
            var elapsed = GetPhaseElapsed("Analyzing Data");
            var timeBasedPercent = Math.Min(99, (int)((elapsed / _estimatedStatisticsSeconds) * 100));
            var phasePercent = Math.Max(childPercent, timeBasedPercent); // Use higher for parallel (they run together)

            ReportParallelTaskProgress("Statistics", phasePercent, detail);
        }

        /// <summary>
        /// Report progress for threat detection phase (parallel task 2/3)
        /// </summary>
        public void ReportThreats(int childPercent, string detail, int threatsFound = 0)
        {
            if (childPercent == 0) StartPhase("Threat Detection");

            // Hybrid: use time-based estimate for smoother progress
            var elapsed = GetPhaseElapsed("Threat Detection");
            var timeBasedPercent = Math.Min(99, (int)((elapsed / _estimatedThreatsSeconds) * 100));
            var phasePercent = Math.Max(childPercent, timeBasedPercent);

            ReportParallelTaskProgress("Threats", phasePercent, detail, threatsFound);
        }

        /// <summary>
        /// Report progress for VoiceQoS analysis phase (parallel task 3/3)
        /// </summary>
        public void ReportVoiceQoS(int childPercent, string detail)
        {
            if (childPercent == 0) StartPhase("VoiceQoS Analysis");

            // Hybrid: use time-based estimate
            var elapsed = GetPhaseElapsed("VoiceQoS Analysis");
            var timeBasedPercent = Math.Min(99, (int)((elapsed / _estimatedVoiceQoSSeconds) * 100));
            var phasePercent = Math.Max(childPercent, timeBasedPercent);

            ReportParallelTaskProgress("VoiceQoS", phasePercent, detail);
        }

        /// <summary>
        /// Report progress for finalizing phase (73-75%)
        /// </summary>
        public void ReportFinalizing(int childPercent, string detail)
        {
            if (childPercent == 0) StartPhase("Finalizing");
            // Finalizing phase: 73-75% (2% range)
            var overallPercent = OFFSET_FINALIZING + (childPercent * PHASE_FINALIZING / 100);
            Report(overallPercent, 0, detail, "Finalizing");
        }

        /// <summary>
        /// Report pipeline completion (75%) - Loading Tabs phase handles 75-100%
        /// </summary>
        public void ReportComplete(string detail)
        {
            _totalStopwatch.Stop();
            // Report 75% - Loading Tabs phase (75-100%) is handled separately
            Report(75, 0, detail, "Complete");
        }

        /// <summary>
        /// Mark the coordinator as fully complete - no more progress updates allowed.
        /// Called after all tabs are loaded.
        /// </summary>
        public void MarkComplete()
        {
            lock (_progressLock)
            {
                _isComplete = true;
            }
        }

        /// <summary>
        /// Reset the coordinator for a new analysis.
        /// </summary>
        public void Reset()
        {
            lock (_progressLock)
            {
                _isComplete = false;
                _lastReportedPercent = -1;
                _highWaterMarkPercent = -1;
                _lastReportTime = DateTime.MinValue;
                _currentPhase = "";
                _phaseStopwatches.Clear();
                _phaseDurations.Clear();
                _totalPackets = 0;
                _totalMegabytes = 0;
                _threatsDetected = 0;
                _currentPacketsAnalyzed = 0;
            }

            // Reset parallel progress tracking
            using (_parallelLock.EnterScope())
            {
                _parallelTaskProgress["Statistics"] = 0;
                _parallelTaskProgress["Threats"] = 0;
                _parallelTaskProgress["VoiceQoS"] = 0;
                _parallelTaskComplete["Statistics"] = false;
                _parallelTaskComplete["Threats"] = false;
                _parallelTaskComplete["VoiceQoS"] = false;
                _parallelPhaseStarted = false;
                _lastParallelDetail = "";
            }
        }

        /// <summary>
        /// Report Loading Tabs phase progress (75-100%)
        /// Called during tab population after pipeline completes.
        /// </summary>
        public void ReportTabLoading(int childPercent, string detail)
        {
            // Tab loading phase: 75-100% (25% range)
            var overallPercent = 75 + (childPercent * 25 / 100);
            Report(overallPercent, 0, detail, "Loading Tabs");
        }

        /// <summary>
        /// Report final completion (100%) - called after all tabs are loaded
        /// </summary>
        public void ReportFullCompletion(string detail)
        {
            Report(100, 0, detail, "Complete");
        }

        /// <summary>
        /// Create a child progress reporter for a specific phase
        /// </summary>
        public IProgress<AnalysisProgress> CreateChildProgress(AnalysisPhase phase)
        {
            return new Progress<AnalysisProgress>(childProgress =>
            {
                // Translate child progress to overall progress based on phase
                switch (phase)
                {
                    case AnalysisPhase.Statistics:
                        ReportStatistics(childProgress.Percent, childProgress.Detail, childProgress.SubPhase);
                        break;
                    case AnalysisPhase.Threats:
                        ReportThreats(childProgress.Percent, childProgress.Detail, childProgress.ThreatsDetected);
                        break;
                    case AnalysisPhase.VoiceQoS:
                        ReportVoiceQoS(childProgress.Percent, childProgress.Detail);
                        break;
                }
            });
        }

        private void Report(int basePercent, int range, string detail, string phase, string? subPhase = null)
        {
            var percent = range > 0 ? basePercent + range : basePercent;
            percent = Math.Min(100, percent);

            // Debounce progress reports to prevent UI flooding from parallel tasks
            lock (_progressLock)
            {
                // ✅ FIX: Prevent updates after completion (except for 100% completion itself)
                if (_isComplete && percent < 100)
                    return;

                var now = DateTime.Now;
                var timeSinceLastReport = (now - _lastReportTime).TotalMilliseconds;

                // ✅ FIX: Never report backwards - use high water mark
                // This prevents race conditions where parallel phases report lower %
                if (percent < _highWaterMarkPercent)
                {
                    percent = _highWaterMarkPercent; // Clamp to highest seen
                }

                // Only report if:
                // 1. Percent increased by at least 1, OR
                // 2. Sufficient time elapsed (150ms)
                if (percent <= _lastReportedPercent &&
                    timeSinceLastReport < MIN_REPORT_INTERVAL_MS)
                {
                    return; // Skip this update - too frequent or no progress
                }

                // Update high water mark
                if (percent > _highWaterMarkPercent)
                    _highWaterMarkPercent = percent;

                _lastReportedPercent = percent;
                _lastReportTime = now;

                _parentProgress?.Report(new AnalysisProgress
                {
                    Phase = phase,
                    Percent = percent,
                    Detail = detail,
                    SubPhase = subPhase,
                    PacketsAnalyzed = _currentPacketsAnalyzed, // Real-time packet count
                    TotalPackets = _totalPackets, // Total known (0 during counting, set after)
                    PacketsPerSecond = CalculatePacketsPerSecond(_currentPacketsAnalyzed),
                    MegabytesAnalyzed = 0, // FUTURE: Calculate from cumulative packet bytes
                    TotalMegabytes = _totalMegabytes,
                    ElapsedTime = _totalStopwatch.Elapsed,
                    RemainingTime = CalculateRemainingTime(percent),
                    ThreatsDetected = _threatsDetected
                });
            }
        }

        private void StartPhase(string phaseName)
        {
            lock (_progressLock)
            {
                // Start stopwatch for this phase (or resume if already started)
                if (!_phaseStopwatches.ContainsKey(phaseName))
                {
                    var sw = Stopwatch.StartNew();
                    _phaseStopwatches[phaseName] = sw;
                    DebugLogger.Log($"[ProgressCoordinator] Started phase: {phaseName}");
                }

                _currentPhase = phaseName;
            }
        }

        /// <summary>
        /// Stop timing for a specific phase (called when phase completes)
        /// </summary>
        public void StopPhase(string phaseName)
        {
            lock (_progressLock)
            {
                if (_phaseStopwatches.TryGetValue(phaseName, out var sw) && sw.IsRunning)
                {
                    sw.Stop();
                    _phaseDurations[phaseName] = sw.Elapsed;
                    DebugLogger.Log($"[ProgressCoordinator] Stopped phase: {phaseName} (took {sw.Elapsed.TotalSeconds:F1}s)");
                }
            }
        }

        /// <summary>
        /// Get elapsed time for a specific phase (in seconds)
        /// </summary>
        private double GetPhaseElapsed(string phaseName)
        {
            lock (_progressLock)
            {
                if (_phaseStopwatches.TryGetValue(phaseName, out var sw))
                {
                    return sw.Elapsed.TotalSeconds;
                }
                return 0.0;
            }
        }

        private long CalculatePacketsPerSecond(long packetsProcessed)
        {
            var elapsed = _totalStopwatch.Elapsed.TotalSeconds;
            return elapsed > 0 ? (long)(packetsProcessed / elapsed) : 0;
        }

        private TimeSpan CalculateRemainingTime(int currentPercent)
        {
            // Skip ETA for edge cases (no logging - these are normal conditions)
            if (currentPercent <= 0 || currentPercent >= 100)
                return TimeSpan.Zero;

            var elapsed = _totalStopwatch.Elapsed.TotalSeconds;

            // Need at least 1 second and 3% progress for reliable estimate
            if (elapsed < 1.0 || currentPercent < 3)
                return TimeSpan.Zero;

            var timePerPercent = elapsed / currentPercent;
            var remainingPercent = 100 - currentPercent;
            var remainingSeconds = timePerPercent * remainingPercent;

            // Cap maximum ETA at 2 hours (prevent unrealistic estimates)
            if (remainingSeconds > 7200)
                remainingSeconds = 7200;

            return TimeSpan.FromSeconds(remainingSeconds);
        }
    }

    /// <summary>
    /// Analysis phase identifiers for progress coordination
    /// </summary>
    public enum AnalysisPhase
    {
        Counting,
        Loading,
        Statistics,
        Threats,
        VoiceQoS,
        Finalizing
    }
}
