using System;
using System.Reactive.Concurrency;
using System.Windows.Input;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ReactiveUI;

namespace PCAPAnalyzer.UI.ViewModels
{
    /// <summary>
    /// Base class for all ViewModels that ensures thread-safe property updates and command execution
    /// </summary>
    public abstract class ViewModelBase : ObservableObject
    {
        /// <summary>
        /// Thread-safe property update that ensures UI thread execution
        /// Usage: SetPropertyThreadSafe(() => MyProperty = value);
        /// </summary>
        protected void SetPropertyThreadSafe(Action propertyUpdate)
        {
            // If we're on UI thread, proceed normally
            if (Dispatcher.UIThread.CheckAccess())
            {
                propertyUpdate();
                return;
            }
            
            // If not on UI thread, marshal to UI thread
            Dispatcher.UIThread.InvokeAsync(propertyUpdate).Wait();
        }
        
        /// <summary>
        /// Ensures the action runs on the UI thread
        /// </summary>
        protected void RunOnUIThread(Action action)
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
        /// Ensures the action runs on the UI thread and waits for completion
        /// </summary>
        protected void RunOnUIThreadSync(Action action)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(action).Wait();
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
                // Ensure we start on UI thread
                if (!Dispatcher.UIThread.CheckAccess())
                {
                    await Dispatcher.UIThread.InvokeAsync(async () => await execute());
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
                // Ensure we start on UI thread
                if (!Dispatcher.UIThread.CheckAccess())
                {
                    await Dispatcher.UIThread.InvokeAsync(async () => await execute(param));
                }
                else
                {
                    await execute(param);
                }
            });
        }
    }
}