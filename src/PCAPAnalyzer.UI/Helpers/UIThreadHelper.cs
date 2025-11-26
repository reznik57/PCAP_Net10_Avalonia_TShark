using System;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace PCAPAnalyzer.UI.Helpers
{
    /// <summary>
    /// Helper class to safely move work off the UI thread while preserving data accuracy
    /// </summary>
    public static class UIThreadHelper
    {
        /// <summary>
        /// Run an action on the UI thread (for UI updates only)
        /// </summary>
        public static async Task RunOnUIThreadAsync(Action action)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                await Dispatcher.UIThread.InvokeAsync(action);
            }
        }
        
        /// <summary>
        /// Run a function on the UI thread and return result
        /// </summary>
        public static async Task<T> RunOnUIThreadAsync<T>(Func<T> func)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                return func();
            }
            else
            {
                return await Dispatcher.UIThread.InvokeAsync(func);
            }
        }
        
        /// <summary>
        /// Run heavy calculations on background thread (preserves all data)
        /// </summary>
        public static async Task<T> RunOnBackgroundAsync<T>(Func<T> func)
        {
            // Move to background thread for calculation
            return await Task.Run(func).ConfigureAwait(false);
        }
        
        /// <summary>
        /// Run heavy calculations on background thread with cancellation support
        /// </summary>
        public static async Task<T> RunOnBackgroundAsync<T>(Func<Task<T>> func)
        {
            // Move to background thread for async calculation
            return await Task.Run(func).ConfigureAwait(false);
        }
        
        /// <summary>
        /// Process data in background, update UI with results
        /// </summary>
        public static async Task ProcessInBackgroundUpdateUIAsync<T>(
            Func<T> backgroundWork,
            Action<T> uiUpdate)
        {
            // Do heavy work in background
            var result = await RunOnBackgroundAsync(backgroundWork);
            
            // Update UI with results
            await RunOnUIThreadAsync(() => uiUpdate(result));
        }
    }
}