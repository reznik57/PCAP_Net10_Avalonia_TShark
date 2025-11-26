using System;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Helpers
{
    /// <summary>
    /// Extension methods for thread-safe operations in Avalonia
    /// </summary>
    public static class ThreadingExtensions
    {
        /// <summary>
        /// Ensures the action runs on the UI thread
        /// </summary>
        public static async Task InvokeOnUIThreadAsync(this ObservableObject viewModel, Func<Task> action)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                await action();
            }
            else
            {
                await Dispatcher.UIThread.InvokeAsync(action);
            }
        }
        
        /// <summary>
        /// Ensures the action runs on the UI thread
        /// </summary>
        public static void InvokeOnUIThread(this ObservableObject viewModel, Action action)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(action);
            }
        }
        
        /// <summary>
        /// Safely updates a property on the UI thread
        /// </summary>
        public static void SetPropertySafe<T>(this ObservableObject viewModel, 
            Action<T> propertySetter, T value)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                propertySetter(value);
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(() => propertySetter(value));
            }
        }
    }
}