using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Optional base class for all ViewModels with common helpers.
    /// Inherits from ObservableObject for MVVM Toolkit support.
    /// </summary>
    public abstract class ViewModelBase : ObservableObject
    {
        /// <summary>
        /// Gets the dispatcher service for UI thread marshalling.
        /// Lazily initialized from DI container.
        /// </summary>
        protected IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
            ?? throw new InvalidOperationException("IDispatcherService not registered");
        private IDispatcherService? _dispatcher;

        /// <summary>
        /// Execute an action on the UI thread
        /// </summary>
        protected void RunOnUIThread(Action action)
        {
            if (Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.Post(action);
            }
        }

        /// <summary>
        /// Execute an action on the UI thread and wait for completion (fire-and-forget, non-blocking)
        /// </summary>
        protected void InvokeOnUIThread(Action action)
        {
            if (Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.Post(action);
            }
        }

        /// <summary>
        /// Execute an action on the UI thread and wait for completion (awaitable)
        /// </summary>
        protected async Task InvokeOnUIThreadAsync(Action action)
        {
            if (Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                await Dispatcher.InvokeAsync(action);
            }
        }
    }
}
