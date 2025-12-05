using Avalonia.Threading;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Avalonia implementation of IDispatcherService.
/// Wraps Dispatcher.UIThread for production use.
/// </summary>
public sealed class AvaloniaDispatcherService : IDispatcherService
{
    /// <inheritdoc/>
    public Task InvokeAsync(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        return Dispatcher.UIThread.InvokeAsync(action).GetTask();
    }

    /// <inheritdoc/>
    public Task<T> InvokeAsync<T>(Func<T> func)
    {
        ArgumentNullException.ThrowIfNull(func);
        return Dispatcher.UIThread.InvokeAsync(func).GetTask();
    }

    /// <inheritdoc/>
    public void Post(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        Dispatcher.UIThread.Post(action);
    }

    /// <inheritdoc/>
    public bool CheckAccess()
    {
        return Dispatcher.UIThread.CheckAccess();
    }

    /// <inheritdoc/>
    public Task InvokeIfNeededAsync(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (Dispatcher.UIThread.CheckAccess())
        {
            action();
            return Task.CompletedTask;
        }

        return Dispatcher.UIThread.InvokeAsync(action).GetTask();
    }
}
