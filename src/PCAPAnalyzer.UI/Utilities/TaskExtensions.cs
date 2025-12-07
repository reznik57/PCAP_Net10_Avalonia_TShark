using System;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Extension methods for Task handling, including safe fire-and-forget patterns.
/// </summary>
public static class TaskExtensions
{
    /// <summary>
    /// Safely executes a task without awaiting, with proper error handling.
    /// Use for operations where you genuinely don't need the result.
    /// </summary>
    /// <param name="task">The task to execute.</param>
    /// <param name="onError">Optional error handler. If null, errors are logged.</param>
    /// <param name="continueOnCapturedContext">Whether to continue on captured context.</param>
    public static void FireAndForget(
        this Task task,
        Action<Exception>? onError = null,
        bool continueOnCapturedContext = false)
    {
        if (task is null) return;

        task.ContinueWith(
            t =>
            {
                if (t.IsFaulted && t.Exception is not null)
                {
                    var ex = t.Exception.GetBaseException();

                    if (onError is not null)
                    {
                        onError(ex);
                    }
                    else
                    {
                        DebugLogger.Log($"[FireAndForget] Unhandled exception: {ex.Message}");
                        DebugLogger.Log($"[FireAndForget] Stack trace: {ex.StackTrace}");
                    }
                }
            },
            continueOnCapturedContext
                ? TaskScheduler.FromCurrentSynchronizationContext()
                : TaskScheduler.Default);
    }

    /// <summary>
    /// Safely executes an async action without awaiting, with proper error handling.
    /// </summary>
    /// <param name="asyncAction">The async action to execute.</param>
    /// <param name="onError">Optional error handler.</param>
    public static void FireAndForget(
        this Func<Task> asyncAction,
        Action<Exception>? onError = null)
    {
        if (asyncAction is null) return;

        Task.Run(async () =>
        {
            try
            {
                await asyncAction();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (onError is not null)
                {
                    onError(ex);
                }
                else
                {
                    DebugLogger.Log($"[FireAndForget] Unhandled exception: {ex.Message}");
                }
            }
        });
    }

    /// <summary>
    /// Awaits a task with a timeout. Throws TimeoutException if timeout expires.
    /// </summary>
    /// <typeparam name="T">The result type.</typeparam>
    /// <param name="task">The task to await.</param>
    /// <param name="timeout">The timeout duration.</param>
    /// <returns>The task result.</returns>
    public static async Task<T> WithTimeout<T>(this Task<T> task, TimeSpan timeout)
    {
        using var cts = new System.Threading.CancellationTokenSource();
        var delayTask = Task.Delay(timeout, cts.Token);
        var completedTask = await Task.WhenAny(task, delayTask);

        if (completedTask == delayTask)
        {
            throw new TimeoutException($"Operation timed out after {timeout.TotalSeconds:F1} seconds");
        }

        cts.Cancel(); // Cancel the delay task
        return await task;
    }

    /// <summary>
    /// Awaits a task with a timeout. Throws TimeoutException if timeout expires.
    /// </summary>
    /// <param name="task">The task to await.</param>
    /// <param name="timeout">The timeout duration.</param>
    public static async Task WithTimeout(this Task task, TimeSpan timeout)
    {
        using var cts = new System.Threading.CancellationTokenSource();
        var delayTask = Task.Delay(timeout, cts.Token);
        var completedTask = await Task.WhenAny(task, delayTask);

        if (completedTask == delayTask)
        {
            throw new TimeoutException($"Operation timed out after {timeout.TotalSeconds:F1} seconds");
        }

        cts.Cancel();
        await task;
    }
}
