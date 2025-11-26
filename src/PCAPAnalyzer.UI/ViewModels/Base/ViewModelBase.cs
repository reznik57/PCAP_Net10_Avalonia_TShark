using System;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Optional base class for all ViewModels with common helpers.
    /// Inherits from ObservableObject for MVVM Toolkit support.
    /// </summary>
    public abstract class ViewModelBase : ObservableObject
    {
        /// <summary>
        /// Execute an action on the UI thread
        /// </summary>
        protected void RunOnUIThread(Action action)
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                Dispatcher.UIThread.Post(action);
            }
        }

        /// <summary>
        /// Execute an action on the UI thread and wait for completion
        /// </summary>
        protected void InvokeOnUIThread(Action action)
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
    }
}
