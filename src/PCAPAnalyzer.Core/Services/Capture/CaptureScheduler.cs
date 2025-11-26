using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Schedules and manages automated packet captures
/// </summary>
public sealed class CaptureScheduler : IDisposable
{
    private readonly ILogger<CaptureScheduler> _logger;
    private readonly ILiveCaptureService _captureService;
    private readonly ConcurrentDictionary<string, ScheduledCapture> _scheduledCaptures;
    private readonly ConcurrentDictionary<string, Timer> _captureTimers;
    private readonly SemaphoreSlim _scheduleLock = new(1, 1);
    private bool _disposed;

    public CaptureScheduler(ILogger<CaptureScheduler> logger, ILiveCaptureService captureService)
    {
        _logger = logger;
        _captureService = captureService;
        _scheduledCaptures = new ConcurrentDictionary<string, ScheduledCapture>();
        _captureTimers = new ConcurrentDictionary<string, Timer>();
    }

    /// <summary>
    /// Schedules a one-time capture
    /// </summary>
    public async Task<string> ScheduleOnceAsync(
        CaptureConfiguration config,
        DateTime startTime,
        CancellationToken cancellationToken = default)
    {
        await _scheduleLock.WaitAsync(cancellationToken);
        try
        {
            var schedule = new ScheduledCapture
            {
                Id = Guid.NewGuid().ToString(),
                Configuration = config,
                ScheduleType = ScheduleType.Once,
                StartTime = startTime,
                IsEnabled = true
            };

            _scheduledCaptures[schedule.Id] = schedule;

            // Calculate delay
            var delay = startTime - DateTime.UtcNow;
            if (delay.TotalMilliseconds < 0)
            {
                throw new ArgumentException("Start time must be in the future", nameof(startTime));
            }

            // Create timer
            var timer = new Timer(
                async _ => await ExecuteCaptureAsync(schedule.Id, CancellationToken.None),
                null,
                delay,
                Timeout.InfiniteTimeSpan);

            _captureTimers[schedule.Id] = timer;

            _logger.LogInformation("Scheduled one-time capture {Id} for {StartTime}", schedule.Id, startTime);

            return schedule.Id;
        }
        finally
        {
            _scheduleLock.Release();
        }
    }

    /// <summary>
    /// Schedules a recurring capture
    /// </summary>
    public async Task<string> ScheduleRecurringAsync(
        CaptureConfiguration config,
        TimeSpan interval,
        DateTime? firstRun = null,
        CancellationToken cancellationToken = default)
    {
        await _scheduleLock.WaitAsync(cancellationToken);
        try
        {
            var schedule = new ScheduledCapture
            {
                Id = Guid.NewGuid().ToString(),
                Configuration = config,
                ScheduleType = ScheduleType.Recurring,
                StartTime = firstRun ?? DateTime.UtcNow,
                Interval = interval,
                IsEnabled = true
            };

            _scheduledCaptures[schedule.Id] = schedule;

            // Calculate initial delay
            var initialDelay = schedule.StartTime - DateTime.UtcNow;
            if (initialDelay.TotalMilliseconds < 0)
            {
                initialDelay = TimeSpan.Zero;
            }

            // Create timer
            var timer = new Timer(
                async _ => await ExecuteCaptureAsync(schedule.Id, CancellationToken.None),
                null,
                initialDelay,
                interval);

            _captureTimers[schedule.Id] = timer;

            _logger.LogInformation("Scheduled recurring capture {Id} with interval {Interval}", schedule.Id, interval);

            return schedule.Id;
        }
        finally
        {
            _scheduleLock.Release();
        }
    }

    /// <summary>
    /// Schedules a daily capture at specific time
    /// </summary>
    public async Task<string> ScheduleDailyAsync(
        CaptureConfiguration config,
        TimeSpan timeOfDay,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var today = now.Date + timeOfDay;
        var firstRun = today > now ? today : today.AddDays(1);

        return await ScheduleRecurringAsync(config, TimeSpan.FromDays(1), firstRun, cancellationToken);
    }

    /// <summary>
    /// Schedules a capture triggered by specific conditions
    /// </summary>
    public async Task<string> ScheduleEventTriggeredAsync(
        CaptureConfiguration config,
        Func<Task<bool>> triggerCondition,
        TimeSpan checkInterval,
        CancellationToken cancellationToken = default)
    {
        await _scheduleLock.WaitAsync(cancellationToken);
        try
        {
            var schedule = new ScheduledCapture
            {
                Id = Guid.NewGuid().ToString(),
                Configuration = config,
                ScheduleType = ScheduleType.EventTriggered,
                StartTime = DateTime.UtcNow,
                Interval = checkInterval,
                TriggerCondition = triggerCondition,
                IsEnabled = true
            };

            _scheduledCaptures[schedule.Id] = schedule;

            // Create timer to check condition periodically
            var timer = new Timer(
                async _ => await CheckTriggerConditionAsync(schedule.Id, CancellationToken.None),
                null,
                TimeSpan.Zero,
                checkInterval);

            _captureTimers[schedule.Id] = timer;

            _logger.LogInformation("Scheduled event-triggered capture {Id}", schedule.Id);

            return schedule.Id;
        }
        finally
        {
            _scheduleLock.Release();
        }
    }

    /// <summary>
    /// Cancels a scheduled capture
    /// </summary>
    public async Task<bool> CancelScheduleAsync(string scheduleId, CancellationToken cancellationToken = default)
    {
        await _scheduleLock.WaitAsync(cancellationToken);
        try
        {
            if (_captureTimers.TryRemove(scheduleId, out var timer))
            {
                timer.Dispose();
            }

            if (_scheduledCaptures.TryRemove(scheduleId, out var schedule))
            {
                _logger.LogInformation("Cancelled scheduled capture {Id}", scheduleId);
                return true;
            }

            return false;
        }
        finally
        {
            _scheduleLock.Release();
        }
    }

    /// <summary>
    /// Enables or disables a scheduled capture
    /// </summary>
    public async Task<bool> SetScheduleEnabledAsync(string scheduleId, bool enabled, CancellationToken cancellationToken = default)
    {
        await _scheduleLock.WaitAsync(cancellationToken);
        try
        {
            if (_scheduledCaptures.TryGetValue(scheduleId, out var schedule))
            {
                schedule.IsEnabled = enabled;
                _logger.LogInformation("{Action} scheduled capture {Id}", enabled ? "Enabled" : "Disabled", scheduleId);
                return true;
            }

            return false;
        }
        finally
        {
            _scheduleLock.Release();
        }
    }

    /// <summary>
    /// Gets all scheduled captures
    /// </summary>
    public List<ScheduledCapture> GetScheduledCaptures()
    {
        return _scheduledCaptures.Values.ToList();
    }

    /// <summary>
    /// Gets a specific scheduled capture
    /// </summary>
    public ScheduledCapture? GetSchedule(string scheduleId)
    {
        _scheduledCaptures.TryGetValue(scheduleId, out var schedule);
        return schedule;
    }

    private async Task ExecuteCaptureAsync(string scheduleId, CancellationToken cancellationToken)
    {
        try
        {
            if (!_scheduledCaptures.TryGetValue(scheduleId, out var schedule) || !schedule.IsEnabled)
            {
                return;
            }

            _logger.LogInformation("Executing scheduled capture {Id}", scheduleId);

            schedule.LastRun = DateTime.UtcNow;
            schedule.RunCount++;

            // Check for conflicts
            if (_captureService.CurrentSession?.IsActive == true)
            {
                _logger.LogWarning("Cannot start scheduled capture {Id} - another capture is active", scheduleId);
                return;
            }

            // Start capture
            var session = await _captureService.StartCaptureAsync(schedule.Configuration, cancellationToken);

            schedule.LastSessionId = session.SessionId;

            // If one-time schedule, remove it after execution
            if (schedule.ScheduleType == ScheduleType.Once)
            {
                await CancelScheduleAsync(scheduleId, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing scheduled capture {Id}", scheduleId);
        }
    }

    private async Task CheckTriggerConditionAsync(string scheduleId, CancellationToken cancellationToken)
    {
        try
        {
            if (!_scheduledCaptures.TryGetValue(scheduleId, out var schedule) || !schedule.IsEnabled)
            {
                return;
            }

            if (schedule.TriggerCondition == null)
            {
                return;
            }

            var triggered = await schedule.TriggerCondition();
            if (triggered)
            {
                _logger.LogInformation("Trigger condition met for schedule {Id}", scheduleId);
                await ExecuteCaptureAsync(scheduleId, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking trigger condition for schedule {Id}", scheduleId);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        foreach (var timer in _captureTimers.Values)
        {
            timer.Dispose();
        }

        _captureTimers.Clear();
        _scheduleLock.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Represents a scheduled capture
/// </summary>
public class ScheduledCapture
{
    public string Id { get; set; } = string.Empty;
    public CaptureConfiguration Configuration { get; set; } = new();
    public ScheduleType ScheduleType { get; set; }
    public DateTime StartTime { get; set; }
    public TimeSpan? Interval { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime? LastRun { get; set; }
    public int RunCount { get; set; }
    public string? LastSessionId { get; set; }
    public Func<Task<bool>>? TriggerCondition { get; set; }
}

/// <summary>
/// Type of capture schedule
/// </summary>
public enum ScheduleType
{
    Once,
    Recurring,
    EventTriggered
}
