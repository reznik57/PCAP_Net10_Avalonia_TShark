namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Abstracts UI thread dispatching for testability.
/// Allows ViewModels to marshal calls to the UI thread without depending on Avalonia.Threading.
/// </summary>
public interface IDispatcherService
{
    /// <summary>
    /// Asynchronously invokes an action on the UI thread.
    /// </summary>
    /// <param name="action">The action to invoke.</param>
    /// <returns>A task that completes when the action has been executed.</returns>
    Task InvokeAsync(Action action);

    /// <summary>
    /// Asynchronously invokes a function on the UI thread and returns the result.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to invoke.</param>
    /// <returns>A task containing the result of the function.</returns>
    Task<T> InvokeAsync<T>(Func<T> func);

    /// <summary>
    /// Posts an action to be executed on the UI thread without waiting.
    /// Fire-and-forget pattern - use when you don't need to await completion.
    /// </summary>
    /// <param name="action">The action to post.</param>
    void Post(Action action);

    /// <summary>
    /// Checks if the current thread is the UI thread.
    /// </summary>
    /// <returns>True if on UI thread, false otherwise.</returns>
    bool CheckAccess();

    /// <summary>
    /// Invokes an action on the UI thread, or executes immediately if already on UI thread.
    /// </summary>
    /// <param name="action">The action to invoke.</param>
    /// <returns>A task that completes when the action has been executed.</returns>
    Task InvokeIfNeededAsync(Action action);
}
