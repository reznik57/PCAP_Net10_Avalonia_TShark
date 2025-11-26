using System;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Provides debouncing capability for actions to prevent excessive execution.
/// Useful for filtering operations triggered by user input (e.g., TextBox text changes).
/// </summary>
public class DebouncedAction : IDisposable
{
    private readonly int _delayMilliseconds;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly object _lock = new();

    /// <summary>
    /// Creates a debounced action with specified delay
    /// </summary>
    /// <param name="delayMilliseconds">Delay in milliseconds before action executes</param>
    public DebouncedAction(int delayMilliseconds)
    {
        _delayMilliseconds = delayMilliseconds;
    }

    /// <summary>
    /// Debounce the action - cancels previous pending actions and schedules new one
    /// </summary>
    /// <param name="action">Action to execute after delay</param>
    public void Debounce(Action action)
    {
        lock (_lock)
        {
            // Cancel previous pending action
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = new CancellationTokenSource();

            var token = _cancellationTokenSource.Token;

            // Schedule new action
            Task.Delay(_delayMilliseconds, token).ContinueWith(t =>
            {
                if (!t.IsCanceled && !token.IsCancellationRequested)
                {
                    action();
                }
            }, TaskScheduler.Default);
        }
    }

    /// <summary>
    /// Dispose resources
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }
}
