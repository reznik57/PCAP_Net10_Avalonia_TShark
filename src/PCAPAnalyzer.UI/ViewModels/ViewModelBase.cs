using System;
using System.Reactive.Concurrency;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.Services;
using ReactiveUI;

namespace PCAPAnalyzer.UI.ViewModels
{
    /// <summary>
    /// Base class for all ViewModels that ensures thread-safe property updates and command execution
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
        /// Thread-safe property update that ensures UI thread execution (fire-and-forget, non-blocking)
        /// Usage: SetPropertyThreadSafe(() => MyProperty = value);
        /// </summary>
        protected void SetPropertyThreadSafe(Action propertyUpdate)
        {
            // If we're on UI thread, proceed normally
            if (Dispatcher.CheckAccess())
            {
                propertyUpdate();
                return;
            }

            // If not on UI thread, marshal to UI thread (non-blocking)
            Dispatcher.Post(propertyUpdate);
        }

        /// <summary>
        /// Thread-safe property update that ensures UI thread execution (awaitable)
        /// Usage: await SetPropertyThreadSafeAsync(() => MyProperty = value);
        /// </summary>
        protected async Task SetPropertyThreadSafeAsync(Action propertyUpdate)
        {
            // If we're on UI thread, proceed normally
            if (Dispatcher.CheckAccess())
            {
                propertyUpdate();
                return;
            }

            // If not on UI thread, marshal to UI thread and await
            await Dispatcher.InvokeAsync(propertyUpdate);
        }
        
        /// <summary>
        /// Ensures the action runs on the UI thread
        /// </summary>
        protected void RunOnUIThread(Action action)
        {
            if (Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.InvokeAsync(action);
            }
        }
        
        /// <summary>
        /// Ensures the action runs on the UI thread and waits for completion (fire-and-forget, non-blocking)
        /// </summary>
        protected void RunOnUIThreadSync(Action action)
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
        /// Ensures the action runs on the UI thread and waits for completion (awaitable)
        /// </summary>
        protected async Task RunOnUIThreadSyncAsync(Action action)
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
        
        /// <summary>
        /// Creates a ReactiveCommand that always executes on the UI thread
        /// </summary>
        protected static ReactiveCommand<TParam?, TResult> CreateUICommand<TParam, TResult>(
            Func<TParam?, TResult> execute,
            IObservable<bool>? canExecute = null)
        {
            return ReactiveCommand.Create(
                execute,
                canExecute,
                RxApp.MainThreadScheduler); // Force UI thread scheduler
        }
        
        /// <summary>
        /// Creates an AsyncRelayCommand that ensures UI thread safety
        /// </summary>
        protected static ICommand CreateSafeAsyncCommand(Func<Task> execute)
        {
            return new AsyncRelayCommand(async () =>
            {
                var dispatcher = App.Services?.GetService<IDispatcherService>();
                // Ensure we start on UI thread
                if (dispatcher is not null && !dispatcher.CheckAccess())
                {
                    await dispatcher.InvokeAsync(async () => await execute());
                }
                else
                {
                    await execute();
                }
            });
        }

        /// <summary>
        /// Creates an AsyncRelayCommand with parameter that ensures UI thread safety
        /// </summary>
        protected static ICommand CreateSafeAsyncCommand<T>(Func<T?, Task> execute)
        {
            return new AsyncRelayCommand<T?>(async (param) =>
            {
                var dispatcher = App.Services?.GetService<IDispatcherService>();
                // Ensure we start on UI thread
                if (dispatcher is not null && !dispatcher.CheckAccess())
                {
                    await dispatcher.InvokeAsync(async () => await execute(param));
                }
                else
                {
                    await execute(param);
                }
            });
        }
    }
}