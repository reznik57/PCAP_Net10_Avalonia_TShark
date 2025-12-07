using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Thread-safe wrapper for ObservableCollection that marshals all modifications to the UI thread.
/// Use for collections that may be updated from background threads.
/// </summary>
/// <typeparam name="T">The type of elements in the collection.</typeparam>
public class ThreadSafeObservableCollection<T> : ObservableCollection<T>
{
    private readonly IDispatcherService _dispatcher;

    public ThreadSafeObservableCollection(IDispatcherService dispatcher)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        _dispatcher = dispatcher;
    }

    public ThreadSafeObservableCollection(IDispatcherService dispatcher, IEnumerable<T> collection)
        : base(collection)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        _dispatcher = dispatcher;
    }

    /// <summary>
    /// Adds a range of items to the collection on the UI thread.
    /// </summary>
    public async Task AddRangeAsync(IEnumerable<T> items)
    {
        if (items is null) return;

        await _dispatcher.InvokeAsync(() =>
        {
            foreach (var item in items)
            {
                Add(item);
            }
        });
    }

    /// <summary>
    /// Clears the collection and adds new items on the UI thread.
    /// More efficient than separate Clear + AddRange for large datasets.
    /// </summary>
    public async Task ReplaceAllAsync(IEnumerable<T> items)
    {
        await _dispatcher.InvokeAsync(() =>
        {
            Clear();
            if (items is not null)
            {
                foreach (var item in items)
                {
                    Add(item);
                }
            }
        });
    }

    /// <summary>
    /// Adds an item on the UI thread.
    /// </summary>
    public async Task AddAsync(T item)
    {
        await _dispatcher.InvokeAsync(() => Add(item));
    }

    /// <summary>
    /// Removes an item on the UI thread.
    /// </summary>
    public async Task<bool> RemoveAsync(T item)
    {
        return await _dispatcher.InvokeAsync(() => Remove(item));
    }

    /// <summary>
    /// Clears the collection on the UI thread.
    /// </summary>
    public async Task ClearAsync()
    {
        await _dispatcher.InvokeAsync(Clear);
    }

    /// <summary>
    /// Posts an add operation without waiting (fire-and-forget).
    /// Use when you don't need to wait for completion.
    /// </summary>
    public void PostAdd(T item)
    {
        _dispatcher.Post(() => Add(item));
    }

    /// <summary>
    /// Posts a clear operation without waiting (fire-and-forget).
    /// </summary>
    public void PostClear()
    {
        _dispatcher.Post(Clear);
    }
}
